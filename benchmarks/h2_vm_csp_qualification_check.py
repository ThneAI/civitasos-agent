"""Fail-closed checker for H.2 VM/CSP qualification evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from benchmarks.h2_multi_agent_backend_continuity_gate import WORKER_CASES


SCHEMA_VERSION = "h2-vm-csp-qualification-check:v1"
EVALUATION_SCHEMA_VERSION = "h2-vm-csp-cycle-evaluation:v1"
_CYCLE_PATTERN = re.compile(r"soak_(\d+)\.evaluation\.json$")


def check_qualification(
    *,
    run_root: Path,
    agent_root: Path,
    min_cycles: int = 144,
    min_checks_per_cycle: int = 36,
    min_duration_seconds: float = 0.0,
    require_service_restarts: bool = True,
) -> dict[str, Any]:
    run_root = _resolve(run_root, agent_root)
    failures: list[str] = []
    checks: dict[str, bool] = {}
    artifacts = {
        name: _read_json(run_root / name, failures)
        for name in (
            "preflight.json",
            "deployment.json",
            "services.json",
            "h2_vm_csp_smoke.json",
            "h2_vm_csp_soak.json",
            "h2_vm_csp_soak_checkpoint.json",
        )
    }
    for name, payload in artifacts.items():
        _require(checks, failures, f"{name}_present", payload is not None)
    _require_passed_artifacts(artifacts, checks=checks, failures=failures)

    evaluations = _load_evaluations(run_root / "remote_agent", failures)
    cycle_numbers = [cycle for cycle, _path, _payload in evaluations]
    total_check_count = sum(
        len(_object(payload.get("checks"))) for _cycle, _path, payload in evaluations
    )
    failed_check_count = sum(
        1
        for _cycle, _path, payload in evaluations
        for passed in _object(payload.get("checks")).values()
        if passed is not True
    )
    worker_counts = {worker: 0 for worker in WORKER_CASES}
    worker_identities = {worker: set() for worker in WORKER_CASES}
    event_counts = {event_kind: 0 for event_kind in WORKER_CASES.values()}
    local_cache_miss_count = 0
    for _cycle, _path, payload in evaluations:
        summaries = _object(payload.get("worker_summaries"))
        for worker, expected_kind in WORKER_CASES.items():
            summary = _object(summaries.get(worker))
            if not summary:
                continue
            worker_counts[worker] += 1
            worker_identities[worker].add(str(summary.get("agent_id") or ""))
            event_kind = str(summary.get("event_kind") or "")
            if event_kind == expected_kind:
                event_counts[event_kind] += 1
            if summary.get("local_db_existed_before") is False:
                local_cache_miss_count += 1

    soak = artifacts.get("h2_vm_csp_soak.json") or {}
    expected_cycles = int(soak.get("last_cycle") or 0)
    contiguous = cycle_numbers == list(range(1, expected_cycles + 1))
    duration_seconds = _float(soak.get("duration_seconds"))
    _require(checks, failures, "minimum_cycle_count", len(evaluations) >= min_cycles)
    _require(checks, failures, "cycle_numbers_contiguous", contiguous)
    _require(
        checks,
        failures,
        "all_cycle_evaluations_passed",
        bool(evaluations)
        and all(
            payload.get("schema_version") == EVALUATION_SCHEMA_VERSION
            and payload.get("passed") is True
            for _cycle, _path, payload in evaluations
        ),
    )
    _require(
        checks,
        failures,
        "minimum_check_count",
        total_check_count >= len(evaluations) * min_checks_per_cycle,
    )
    _require(checks, failures, "no_failed_cycle_checks", failed_check_count == 0)
    _require(
        checks,
        failures,
        "all_workers_present_each_cycle",
        all(count == len(evaluations) for count in worker_counts.values()),
    )
    _require(
        checks,
        failures,
        "worker_identities_stable",
        all(
            "" not in identities and len(identities) == 1
            for identities in worker_identities.values()
        ),
    )
    _require(
        checks,
        failures,
        "expected_backend_outcomes_each_cycle",
        all(count == len(evaluations) for count in event_counts.values()),
    )
    _require(
        checks,
        failures,
        "remote_csp_recovery_forced_each_cycle",
        local_cache_miss_count == len(evaluations) * len(WORKER_CASES),
    )
    if min_duration_seconds > 0:
        _require(
            checks,
            failures,
            "minimum_duration_seconds",
            duration_seconds >= min_duration_seconds,
        )
    else:
        checks["minimum_duration_seconds_not_required"] = True
    if require_service_restarts:
        _require(
            checks,
            failures,
            "csp_restart_scheduled",
            bool(soak.get("restart_csp_cycles")),
        )
        _require(
            checks,
            failures,
            "backend_restart_scheduled",
            bool(soak.get("restart_backend_cycles")),
        )
    else:
        checks["service_restarts_not_required"] = True

    identity_dir = run_root / "remote_agent" / "identity"
    seed_hex_hits = _scan_seed_hex(run_root)
    _require(checks, failures, "private_identity_directory_not_collected", not identity_dir.exists())
    _require(checks, failures, "seed_hex_not_collected", not seed_hex_hits)

    artifact_sha256 = {
        path.name: _sha256(path)
        for path in sorted(run_root.glob("*.json"))
        if path.name != "h2_vm_csp_qualification_check.json"
    }
    evaluation_sha256 = {
        str(path.relative_to(run_root)): _sha256(path)
        for _cycle, path, _payload in evaluations
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": not failures and all(checks.values()),
        "failure_reasons": failures,
        "run_root": str(run_root),
        "thresholds": {
            "min_cycles": min_cycles,
            "min_checks_per_cycle": min_checks_per_cycle,
            "min_duration_seconds": min_duration_seconds,
            "require_service_restarts": require_service_restarts,
        },
        "checks": checks,
        "metrics": {
            "evaluation_file_count": len(evaluations),
            "first_cycle": cycle_numbers[0] if cycle_numbers else None,
            "last_cycle": cycle_numbers[-1] if cycle_numbers else None,
            "total_check_count": total_check_count,
            "failed_check_count": failed_check_count,
            "duration_seconds": duration_seconds,
            "worker_recovery_counts": worker_counts,
            "backend_event_counts": event_counts,
            "local_cache_miss_recovery_count": local_cache_miss_count,
        },
        "security": {
            "private_identity_directory_collected": identity_dir.exists(),
            "seed_hex_hits": seed_hex_hits,
        },
        "artifact_sha256": artifact_sha256,
        "evaluation_sha256": evaluation_sha256,
        "non_claims": [
            "cycle_qualification_does_not_claim_production_evidence",
            "duration_below_86400_does_not_claim_strict_24h",
            "virtualbox_host_only_does_not_prove_wan_partition_tolerance",
            "no_llm_invocation",
        ],
    }


def _require_passed_artifacts(
    artifacts: dict[str, dict[str, Any] | None],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    for name in (
        "preflight.json",
        "deployment.json",
        "services.json",
        "h2_vm_csp_smoke.json",
        "h2_vm_csp_soak.json",
        "h2_vm_csp_soak_checkpoint.json",
    ):
        payload = artifacts.get(name)
        passed = bool(payload and (payload.get("passed") is True))
        _require(checks, failures, f"{name}_passed", passed)


def _load_evaluations(
    remote_root: Path,
    failures: list[str],
) -> list[tuple[int, Path, dict[str, Any]]]:
    evaluations: list[tuple[int, Path, dict[str, Any]]] = []
    for path in remote_root.glob("soak_*.evaluation.json"):
        match = _CYCLE_PATTERN.search(path.name)
        if match is None:
            continue
        payload = _read_json(path, failures)
        if payload is not None:
            evaluations.append((int(match.group(1)), path, payload))
    return sorted(evaluations)


def _scan_seed_hex(run_root: Path) -> list[str]:
    hits: list[str] = []
    for path in run_root.rglob("*.json"):
        try:
            if '"seed_hex"' in path.read_text(encoding="utf-8"):
                hits.append(str(path))
        except OSError:
            continue
    return hits


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"missing JSON artifact: {path}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"invalid JSON artifact {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"expected JSON object: {path}")
        return None
    return payload


def _require(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    passed: bool,
) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def _resolve(path: Path, root: Path) -> Path:
    return path if path.is_absolute() else (root / path).resolve()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--min-cycles", type=int, default=144)
    parser.add_argument("--min-checks-per-cycle", type=int, default=36)
    parser.add_argument("--min-duration-seconds", type=float, default=0.0)
    parser.add_argument("--no-require-service-restarts", action="store_true")
    args = parser.parse_args()
    report = check_qualification(
        run_root=args.run_root,
        agent_root=agent_root,
        min_cycles=args.min_cycles,
        min_checks_per_cycle=args.min_checks_per_cycle,
        min_duration_seconds=args.min_duration_seconds,
        require_service_restarts=not args.no_require_service_restarts,
    )
    output = args.output or (
        _resolve(args.run_root, agent_root) / "h2_vm_csp_qualification_check.json"
    )
    output = _resolve(output, agent_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
