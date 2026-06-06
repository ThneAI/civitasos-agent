"""H.2 cross-process identity, memory, and delayed-consequence gate.

The controlled drill launches two independent Python processes. The first
creates an Ed25519 identity, seeds relation experience, and performs the real
AgentRunner shutdown path. After that process exits, the parent records a
delayed failure. The second process restores the identity and local memory,
runs the real AgentRunner recovery path, and feeds the delayed failure through
the Runtime relation-expectation update.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h2-restart-continuity-gate:v1"
PHASE_SCHEMA_VERSION = "h2-restart-continuity-phase:v1"
DELAYED_EVENT_SCHEMA_VERSION = "h2-restart-delayed-consequence:v1"
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class _NoopLLM:
    """Minimal adapter object; the controlled drill never invokes an LLM."""


class _OfflineAgent:
    def __init__(self, agent_id: str, public_key_hex: str) -> None:
        self.agent_id = agent_id
        self.public_key_hex = public_key_hex

    def briefing(self) -> dict[str, Any]:
        return {"active_tasks": []}


def run_gate(
    *,
    run_root: Path,
    output: Path | None = None,
    overwrite: bool = False,
    min_delay_seconds: float = 0.02,
) -> dict[str, Any]:
    agent_root = Path(__file__).resolve().parents[1]
    run_root = _resolve(run_root, agent_root)
    output = run_root / "h2_restart_continuity_gate.json" if output is None else _resolve(output, agent_root)
    if run_root.exists() and any(run_root.iterdir()):
        if not overwrite:
            raise FileExistsError(f"refusing to overwrite non-empty run root: {run_root}")
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True, exist_ok=True)

    phase1 = _run_phase("seed", run_root=run_root, agent_root=agent_root)
    delayed_event_path = run_root / "delayed_consequence.json"
    if phase1["returncode"] == 0:
        time.sleep(max(float(min_delay_seconds), 0.0))
        phase1_report = _read_json(run_root / "phase1.json")
        delayed_event_path.write_text(
            json.dumps(
                _build_delayed_event(phase1_report),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        phase2 = _run_phase("recover", run_root=run_root, agent_root=agent_root)
    else:
        phase2 = {
            "returncode": None,
            "stdout_path": str(run_root / "phase2.stdout.log"),
            "stderr_path": str(run_root / "phase2.stderr.log"),
        }

    report = _evaluate_gate(
        run_root=run_root,
        phase1_process=phase1,
        phase2_process=phase2,
        delayed_event_path=delayed_event_path,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _run_phase(phase: str, *, run_root: Path, agent_root: Path) -> dict[str, Any]:
    stdout_path = run_root / f"phase{'1' if phase == 'seed' else '2'}.stdout.log"
    stderr_path = run_root / f"phase{'1' if phase == 'seed' else '2'}.stderr.log"
    env = os.environ.copy()
    workspace = agent_root.parent
    python_paths = [
        str(agent_root),
        str(workspace / "civitasos-runtime"),
        str(workspace / "civitasos-sdk" / "python"),
    ]
    if env.get("PYTHONPATH"):
        python_paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(python_paths)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.h2_restart_continuity_gate",
            "--run-root",
            str(run_root),
            "--phase",
            phase,
        ],
        cwd=agent_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    return {
        "returncode": completed.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _build_delayed_event(phase1: dict[str, Any]) -> dict[str, Any]:
    seed = phase1.get("seed", {})
    relation_id = str(seed.get("relation_id") or "")
    task_id = str(seed.get("task_id") or "")
    event_id = f"h2-delayed-failure:{task_id}"
    return {
        "schema_version": DELAYED_EVENT_SCHEMA_VERSION,
        "event_id": event_id,
        "event_kind": "post_delivery_failure",
        "task_id": task_id,
        "relation_id": relation_id,
        "subject": phase1.get("agent_id"),
        "observed_at": _now(),
        "source": "controlled_post_restart_outcome_probe",
        "evidence_ref": {
            "ref_id": f"controlled_outcome:{event_id}",
            "source": "h2_restart_continuity_gate",
        },
        "verifier_or_settlement_read": True,
        "non_claims": [
            "controlled_probe_not_production_evidence",
            "no_llm_invocation",
            "no_external_side_effect",
        ],
    }


def _phase_seed(run_root: Path) -> None:
    from civitasos import CivitasAgent
    from civitasos_runtime.memory import HybridMemory
    from civitasos_runtime.runner import AgentRunner

    identity_path = run_root / "identity" / "continuity_agent.identity.json"
    data_dir = run_root / "data"
    agent = CivitasAgent("http://127.0.0.1:9", auto_discover=False)
    public_key = agent.generate_keys()
    agent._agent_id = _did_from_public_key(public_key)  # noqa: SLF001 - controlled identity fixture
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    agent.save_identity(str(identity_path))

    peer_id = "did:civ:devnet:zH2ContinuityPeer"
    relation_id = f"rel:{agent.agent_id}:{peer_id}"
    relation_key = f"{relation_id}|{agent.agent_id}->{peer_id}|predicted"
    task_id = "H2_restart_continuity_task_01"
    prior = {
        "expected_trust": 0.72,
        "expected_delivery_quality": 0.72,
        "expected_cooperation": 0.70,
        "expected_betrayal_risk": 0.12,
        "expected_repair_probability": 0.55,
        "precision": 0.35,
    }

    runner = AgentRunner(llm=_NoopLLM(), data_dir=str(data_dir))
    runner._agent = _OfflineAgent(str(agent.agent_id), public_key)  # noqa: SLF001
    runner._memory = HybridMemory(agent=None, data_dir=data_dir)  # noqa: SLF001
    runner._memory.remember(  # noqa: SLF001
        "h2_continuity_seed",
        {
            "task_id": task_id,
            "relation_id": relation_id,
            "relation_key": relation_key,
            "agent_id": agent.agent_id,
            "peer_id": peer_id,
            "delivered_at": _now(),
        },
    )
    runner._memory.remember(  # noqa: SLF001
        f"relation_expectation:{relation_key}",
        {"expectation": prior, "source_event_ids": ["delivery:initial"]},
    )
    runner._memory.remember(  # noqa: SLF001
        "identity_iem_state",
        {
            "identity_id": agent.agent_id,
            "relation_expectation_matrix": {relation_key: prior},
            "history": ["delivery:initial"],
        },
    )
    asyncio.run(runner._shutdown_cleanup())  # noqa: SLF001

    memory = HybridMemory(agent=None, data_dir=data_dir)
    shutdown_state = memory.recall("shutdown_state")
    memory.close()
    report = {
        "schema_version": PHASE_SCHEMA_VERSION,
        "phase": "seed",
        "pid": os.getpid(),
        "phase_finished_at": _now(),
        "runtime_instance_id": runner._runtime_instance_id,  # noqa: SLF001
        "agent_id": agent.agent_id,
        "public_key_hex": public_key,
        "identity_file": str(identity_path),
        "identity_file_sha256": _sha256(identity_path),
        "identity_file_mode": stat.S_IMODE(identity_path.stat().st_mode),
        "memory_db": str(data_dir / "memory.db"),
        "shutdown_state": shutdown_state,
        "seed": {
            "task_id": task_id,
            "relation_id": relation_id,
            "relation_key": relation_key,
            "prior": prior,
        },
    }
    _write_json(run_root / "phase1.json", report)


def _phase_recover(run_root: Path) -> None:
    from civitasos import CivitasAgent
    from civitasos_runtime.memory import HybridMemory
    from civitasos_runtime.models import TickContext
    from civitasos_runtime.relation_expectation import apply_relation_matrix_expectation
    from civitasos_runtime.runner import AgentRunner

    identity_path = run_root / "identity" / "continuity_agent.identity.json"
    data_dir = run_root / "data"
    delayed_event = _read_json(run_root / "delayed_consequence.json")
    agent = CivitasAgent("http://127.0.0.1:9", auto_discover=False)
    public_key = agent.load_identity(str(identity_path))

    runner = AgentRunner(llm=_NoopLLM(), data_dir=str(data_dir))
    runner._agent = _OfflineAgent(str(agent.agent_id), public_key)  # noqa: SLF001
    runner._memory = HybridMemory(agent=None, data_dir=data_dir)  # noqa: SLF001
    continuity = asyncio.run(runner._recover())  # noqa: SLF001
    memory = runner._memory  # noqa: SLF001
    seed = memory.recall("h2_continuity_seed")
    iem_state = memory.recall("identity_iem_state")
    relation_key = str(seed.get("relation_key") or "") if isinstance(seed, dict) else ""
    prior_payload = memory.recall(f"relation_expectation:{relation_key}")
    prior = (
        prior_payload.get("expectation", {})
        if isinstance(prior_payload, dict)
        else {}
    )

    event_id = str(delayed_event.get("event_id") or "")
    relation_id = str(seed.get("relation_id") or "") if isinstance(seed, dict) else ""
    peer_id = str(seed.get("peer_id") or "") if isinstance(seed, dict) else ""
    task_id = str(seed.get("task_id") or "") if isinstance(seed, dict) else ""
    ctx = TickContext(
        briefing={
            "relation_context": {
                "relation_id": relation_id,
                "relation_pair": {
                    "requester": agent.agent_id,
                    "worker": peer_id,
                    "agents": [agent.agent_id, peer_id],
                },
                "recent_failures": [
                    {
                        "task_id": task_id,
                        "relation_id": relation_id,
                        "failed_at": delayed_event.get("observed_at"),
                        "event_id": event_id,
                    }
                ],
            }
        }
    )
    applied = apply_relation_matrix_expectation(
        ctx,
        local_identity=str(agent.agent_id),
        recall=memory.recall,
    )
    updated_payload = ctx.expectations.get("relation", {}).get(relation_key, {})
    updated = updated_payload.get("expectation", {}) if isinstance(updated_payload, dict) else {}
    action_bias = ctx.action_bias.get("relation", {}).get(relation_key, {})
    updates = [_jsonable(asdict(item)) for item in ctx.expectation_updates]
    if applied:
        memory.remember(f"relation_expectation:{relation_key}", updated_payload)
        memory.remember(
            "h2_delayed_consequence_state",
            {
                "event": delayed_event,
                "relation_key": relation_key,
                "before": prior,
                "after": updated,
                "action_bias": action_bias,
                "expectation_updates": updates,
                "history_preserved": bool(
                    isinstance(iem_state, dict)
                    and "delivery:initial" in iem_state.get("history", [])
                ),
            },
        )
    asyncio.run(runner._shutdown_cleanup())  # noqa: SLF001

    report = {
        "schema_version": PHASE_SCHEMA_VERSION,
        "phase": "recover",
        "pid": os.getpid(),
        "phase_started_at": runner._runtime_started_at,  # noqa: SLF001
        "phase_finished_at": _now(),
        "runtime_instance_id": runner._runtime_instance_id,  # noqa: SLF001
        "agent_id": agent.agent_id,
        "public_key_hex": public_key,
        "identity_file_sha256": _sha256(identity_path),
        "continuity": continuity,
        "recalled": {
            "continuity_seed": seed,
            "identity_iem_state": iem_state,
            "prior_relation_expectation": prior_payload,
        },
        "delayed_consequence": delayed_event,
        "consequence_applied": applied,
        "relation_update": {
            "relation_key": relation_key,
            "before": prior,
            "after": updated,
            "action_bias": action_bias,
            "expectation_updates": updates,
        },
    }
    _write_json(run_root / "phase2.json", report)


def _evaluate_gate(
    *,
    run_root: Path,
    phase1_process: dict[str, Any],
    phase2_process: dict[str, Any],
    delayed_event_path: Path,
) -> dict[str, Any]:
    phase1 = _read_json_optional(run_root / "phase1.json")
    phase2 = _read_json_optional(run_root / "phase2.json")
    event = _read_json_optional(delayed_event_path)
    checks: dict[str, bool] = {}
    failures: list[str] = []

    _check(checks, failures, "phase1_process_passed", phase1_process.get("returncode") == 0)
    _check(checks, failures, "phase2_process_passed", phase2_process.get("returncode") == 0)
    _check(checks, failures, "phase1_report_present", phase1 is not None)
    _check(checks, failures, "phase2_report_present", phase2 is not None)
    _check(checks, failures, "delayed_event_present", event is not None)
    if phase1 and phase2 and event:
        continuity = phase2.get("continuity") or {}
        recalled = phase2.get("recalled") or {}
        update = phase2.get("relation_update") or {}
        before = update.get("before") or {}
        after = update.get("after") or {}
        action_bias = update.get("action_bias") or {}
        updates = update.get("expectation_updates") or []
        seed = phase1.get("seed") or {}
        shutdown = phase1.get("shutdown_state") or {}
        _check(checks, failures, "separate_processes", phase1.get("pid") != phase2.get("pid"))
        _check(
            checks,
            failures,
            "separate_runtime_instances",
            phase1.get("runtime_instance_id") != phase2.get("runtime_instance_id"),
        )
        _check(
            checks,
            failures,
            "same_agent_id",
            bool(phase1.get("agent_id")) and phase1.get("agent_id") == phase2.get("agent_id"),
        )
        _check(
            checks,
            failures,
            "same_public_key",
            bool(phase1.get("public_key_hex"))
            and phase1.get("public_key_hex") == phase2.get("public_key_hex"),
        )
        _check(
            checks,
            failures,
            "identity_file_stable",
            phase1.get("identity_file_sha256") == phase2.get("identity_file_sha256"),
        )
        _check(checks, failures, "identity_file_private", phase1.get("identity_file_mode") == 0o600)
        _check(checks, failures, "runtime_identity_continuous", continuity.get("identity_continuous") is True)
        _check(
            checks,
            failures,
            "previous_runtime_recovered",
            continuity.get("previous_runtime_instance_id") == phase1.get("runtime_instance_id"),
        )
        _check(
            checks,
            failures,
            "prior_shutdown_recovered",
            shutdown.get("runtime_instance_id") == phase1.get("runtime_instance_id")
            and continuity.get("previous_shutdown_at") == shutdown.get("shutdown_at"),
        )
        _check(
            checks,
            failures,
            "continuity_seed_recalled",
            recalled.get("continuity_seed") is not None,
        )
        _check(
            checks,
            failures,
            "iem_state_recalled",
            recalled.get("identity_iem_state") is not None,
        )
        _check(
            checks,
            failures,
            "relation_expectation_recalled",
            recalled.get("prior_relation_expectation") is not None,
        )
        _check(
            checks,
            failures,
            "delayed_event_after_shutdown",
            _timestamp(event.get("observed_at")) > _timestamp(shutdown.get("shutdown_at")),
        )
        _check(
            checks,
            failures,
            "delayed_event_matches_prior_task",
            event.get("task_id") == seed.get("task_id")
            and event.get("relation_id") == seed.get("relation_id"),
        )
        _check(checks, failures, "delayed_consequence_applied", phase2.get("consequence_applied") is True)
        _check(
            checks,
            failures,
            "trust_reduced_after_failure",
            _float(after.get("expected_trust")) < _float(before.get("expected_trust")),
        )
        _check(
            checks,
            failures,
            "delivery_expectation_reduced_after_failure",
            _float(after.get("expected_delivery_quality"))
            < _float(before.get("expected_delivery_quality")),
        )
        _check(
            checks,
            failures,
            "betrayal_risk_increased_after_failure",
            _float(after.get("expected_betrayal_risk"))
            > _float(before.get("expected_betrayal_risk")),
        )
        _check(
            checks,
            failures,
            "future_behavior_biased",
            action_bias.get("verification_level") in {"elevated", "strict"}
            and _float(action_bias.get("required_stake_multiplier")) > 1.0,
        )
        _check(
            checks,
            failures,
            "normative_local_update_blocked",
            any(
                item.get("local_update_blocked") is True
                and str(item.get("constitution_verdict") or "").startswith("blocked:")
                for item in updates
                if isinstance(item, dict)
            ),
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "passed": not failures and all(checks.values()),
        "checks": checks,
        "failure_reasons": failures,
        "run_root": str(run_root),
        "phase1_process": phase1_process,
        "phase2_process": phase2_process,
        "evidence": {
            "phase1_report": str(run_root / "phase1.json"),
            "phase2_report": str(run_root / "phase2.json"),
            "delayed_consequence": str(delayed_event_path),
            "identity_file": str(run_root / "identity" / "continuity_agent.identity.json"),
            "memory_db": str(run_root / "data" / "memory.db"),
        },
        "non_claims": [
            "controlled_probe_not_seven_day_soak",
            "controlled_probe_not_production_evidence",
            "local_persistence_does_not_prove_remote_csp_recovery",
            "no_llm_invocation",
        ],
    }


def _check(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    passed: bool,
) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def _did_from_public_key(public_key_hex: str) -> str:
    payload = b"\xed\x01" + bytes.fromhex(public_key_hex)
    return f"did:civ:devnet:z{_base58_encode(payload)}"


def _base58_encode(data: bytes) -> str:
    zeros = len(data) - len(data.lstrip(b"\x00"))
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = _BASE58_ALPHABET[remainder] + encoded
    return "1" * zeros + (encoded or "1")


def _resolve(path: Path, root: Path) -> Path:
    return path if path.is_absolute() else (root / path).resolve()


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object required: {path}")
    return payload


def _read_json_optional(path: Path) -> dict[str, Any] | None:
    try:
        return _read_json(path)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timestamp(value: Any) -> datetime:
    text = str(value or "").replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if hasattr(value, "value"):
        return value.value
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--min-delay-seconds", type=float, default=0.02)
    parser.add_argument("--phase", choices=("seed", "recover"), help=argparse.SUPPRESS)
    return parser


def main() -> None:
    args = _parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    run_root = _resolve(args.run_root, agent_root)
    if args.phase == "seed":
        _phase_seed(run_root)
        return
    if args.phase == "recover":
        _phase_recover(run_root)
        return
    report = run_gate(
        run_root=run_root,
        output=args.output,
        overwrite=args.overwrite,
        min_delay_seconds=args.min_delay_seconds,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 3)


if __name__ == "__main__":
    main()
