"""H.2 release evidence checker.

Validates already-produced H2 artifacts without rerunning agents, backend, or
LLMs. This is the low-cost release check layer for H2: it fails closed when
the opt-in H2 gate is skipped, the outcome report regresses, or backend outcome
events are missing/truncated when required.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .h2_backend_outcome_export import (
    BackendOutcomeExportError,
    validate_backend_outcome_events_payload,
)


SCHEMA_VERSION = "h2-release-check:v1"
H2_REPORT_SCHEMA_VERSION = "h2-outcome-report:v1"


def check_h2_release(
    *,
    run_root: Path,
    outcome_report_path: Path | None,
    backend_outcome_events_path: Path | None,
    agent_root: Path,
    min_outcome_record_count: int,
    min_delayed_event_count: int,
    min_outcome_ledger_coverage_ratio: float,
    min_h1_evidence_ref_ratio: float,
    min_normative_local_update_blocked_ratio: float,
    min_delayed_verifier_coverage_ratio: float | None,
    require_backend_outcome_events: bool,
    allow_truncated_backend_outcome_events: bool,
) -> dict[str, Any]:
    run_root = _resolve_path(run_root, agent_root)
    outcome_report_path = (
        run_root / "h2_outcome_report.json"
        if outcome_report_path is None
        else _resolve_path(outcome_report_path, agent_root)
    )
    backend_outcome_events_path = (
        None if backend_outcome_events_path is None
        else _resolve_path(backend_outcome_events_path, agent_root)
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    evidence: dict[str, Any] = {
        "run_root": str(run_root),
        "outcome_report_path": str(outcome_report_path),
        "backend_outcome_events_path": (
            None if backend_outcome_events_path is None else str(backend_outcome_events_path)
        ),
    }

    summary = _read_json(run_root / "merge_summary.json", failures)
    outcome_report = _read_json(outcome_report_path, failures)
    _check_merge_summary(summary, checks=checks, failures=failures, evidence=evidence)
    _check_outcome_report(
        outcome_report,
        checks=checks,
        failures=failures,
        evidence=evidence,
        min_outcome_record_count=min_outcome_record_count,
        min_delayed_event_count=min_delayed_event_count,
        min_outcome_ledger_coverage_ratio=min_outcome_ledger_coverage_ratio,
        min_h1_evidence_ref_ratio=min_h1_evidence_ref_ratio,
        min_normative_local_update_blocked_ratio=min_normative_local_update_blocked_ratio,
        min_delayed_verifier_coverage_ratio=min_delayed_verifier_coverage_ratio,
    )
    _check_backend_outcome_events(
        outcome_report,
        explicit_path=backend_outcome_events_path,
        checks=checks,
        failures=failures,
        evidence=evidence,
        require_backend_outcome_events=require_backend_outcome_events,
        allow_truncated=allow_truncated_backend_outcome_events,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "passed": not failures and all(checks.values()),
        "checks": checks,
        "failure_reasons": failures,
        "thresholds": {
            "min_outcome_record_count": min_outcome_record_count,
            "min_delayed_event_count": min_delayed_event_count,
            "min_outcome_ledger_coverage_ratio": min_outcome_ledger_coverage_ratio,
            "min_h1_evidence_ref_ratio": min_h1_evidence_ref_ratio,
            "min_normative_local_update_blocked_ratio": min_normative_local_update_blocked_ratio,
            "min_delayed_verifier_coverage_ratio": min_delayed_verifier_coverage_ratio,
            "require_backend_outcome_events": require_backend_outcome_events,
            "allow_truncated_backend_outcome_events": allow_truncated_backend_outcome_events,
        },
        "evidence": evidence,
    }


def _check_merge_summary(
    summary: dict[str, Any] | None,
    *,
    checks: dict[str, bool],
    failures: list[str],
    evidence: dict[str, Any],
) -> None:
    if summary is None:
        _fail(checks, failures, "merge_summary_present", "missing merge_summary.json")
        return
    checks["merge_summary_present"] = True
    for gate_key in (
        "integrity_gate",
        "sentinel_gate",
        "ii2_gate",
        "g2_gate",
        "g3_gate",
        "h0_gate",
        "h1_gate",
        "h2_gate",
    ):
        _require_gate(summary, gate_key, checks=checks, failures=failures)
    h2_gate = _object(summary.get("h2_gate"))
    evidence["h2_gate"] = {
        "passed": bool(h2_gate.get("passed")),
        "skipped": bool(h2_gate.get("skipped")),
        "require_active": bool(h2_gate.get("require_active")),
        "report_path": h2_gate.get("report_path"),
        "g3_carry_through_passed": h2_gate.get("g3_carry_through_passed"),
        "h0_carry_through_passed": h2_gate.get("h0_carry_through_passed"),
        "h1_carry_through_passed": h2_gate.get("h1_carry_through_passed"),
    }
    _require_bool("h2_gate_require_active", bool(h2_gate.get("require_active")), checks=checks, failures=failures)
    _require_bool("h2_gate_not_skipped", not bool(h2_gate.get("skipped")), checks=checks, failures=failures)
    for name in ("g3_carry_through_passed", "h0_carry_through_passed", "h1_carry_through_passed"):
        _require_bool(f"h2_{name}", bool(h2_gate.get(name)), checks=checks, failures=failures)


def _check_outcome_report(
    report: dict[str, Any] | None,
    *,
    checks: dict[str, bool],
    failures: list[str],
    evidence: dict[str, Any],
    min_outcome_record_count: int,
    min_delayed_event_count: int,
    min_outcome_ledger_coverage_ratio: float,
    min_h1_evidence_ref_ratio: float,
    min_normative_local_update_blocked_ratio: float,
    min_delayed_verifier_coverage_ratio: float | None,
) -> None:
    if report is None:
        _fail(checks, failures, "outcome_report_present", "missing H2 outcome report")
        return
    checks["outcome_report_present"] = True
    _require_equal(
        "outcome_report_schema_version",
        report.get("schema_version"),
        H2_REPORT_SCHEMA_VERSION,
        checks=checks,
        failures=failures,
    )
    _require_bool("outcome_report_passed", bool(report.get("passed")), checks=checks, failures=failures)
    metrics = _object(report.get("metrics"))
    checks_payload = _object(report.get("checks"))
    evidence["outcome_report"] = {
        "passed": bool(report.get("passed")),
        "run_root": report.get("run_root"),
        "judge_report_path": report.get("judge_report_path"),
        "delayed_outcomes_path": report.get("delayed_outcomes_path"),
        "backend_outcome_events_path": report.get("backend_outcome_events_path"),
        "metrics": metrics,
        "checks": checks_payload,
    }
    for check_name, passed in checks_payload.items():
        _require_bool(f"outcome_report_check_{check_name}", bool(passed), checks=checks, failures=failures)
    _require_min(
        "outcome_record_count",
        _int(metrics.get("outcome_record_count")),
        min_outcome_record_count,
        checks=checks,
        failures=failures,
    )
    _require_min(
        "delayed_event_count",
        _int(metrics.get("delayed_event_count")),
        min_delayed_event_count,
        checks=checks,
        failures=failures,
    )
    _require_min(
        "outcome_ledger_coverage_ratio",
        _float(metrics.get("outcome_ledger_coverage_ratio")),
        min_outcome_ledger_coverage_ratio,
        checks=checks,
        failures=failures,
    )
    _require_min(
        "h1_evidence_ref_ratio",
        _float(metrics.get("h1_evidence_ref_ratio")),
        min_h1_evidence_ref_ratio,
        checks=checks,
        failures=failures,
    )
    _require_min(
        "normative_local_update_blocked_ratio",
        _float(metrics.get("normative_local_update_blocked_ratio")),
        min_normative_local_update_blocked_ratio,
        checks=checks,
        failures=failures,
    )
    if min_delayed_verifier_coverage_ratio is not None:
        _require_min(
            "delayed_verifier_coverage_ratio",
            _float(metrics.get("delayed_verifier_coverage_ratio")),
            min_delayed_verifier_coverage_ratio,
            checks=checks,
            failures=failures,
        )


def _check_backend_outcome_events(
    report: dict[str, Any] | None,
    *,
    explicit_path: Path | None,
    checks: dict[str, bool],
    failures: list[str],
    evidence: dict[str, Any],
    require_backend_outcome_events: bool,
    allow_truncated: bool,
) -> None:
    report_path = None if report is None else report.get("backend_outcome_events_path")
    path = explicit_path or (Path(str(report_path)) if report_path else None)
    if path is None:
        if require_backend_outcome_events:
            _fail(
                checks,
                failures,
                "backend_outcome_events_present",
                "missing required backend outcome events artifact path",
            )
        else:
            checks["backend_outcome_events_optional"] = True
        return
    evidence["backend_outcome_events_path"] = str(path)
    payload = _read_json(path, failures)
    if payload is None:
        _fail(checks, failures, "backend_outcome_events_present", f"missing backend outcome events artifact: {path}")
        return
    checks["backend_outcome_events_present"] = True
    try:
        validate_backend_outcome_events_payload(payload, allow_truncated=allow_truncated)
    except BackendOutcomeExportError as exc:
        _fail(checks, failures, "backend_outcome_events_valid", str(exc))
        return
    checks["backend_outcome_events_valid"] = True
    events = payload.get("events") if isinstance(payload.get("events"), list) else []
    evidence["backend_outcome_events"] = {
        "schema_version": payload.get("schema_version"),
        "source": payload.get("source"),
        "total": _int(payload.get("total")),
        "returned": _int(payload.get("returned")),
        "event_count": len(events),
        "filters": payload.get("filters"),
    }


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.exists():
        failures.append(f"missing JSON artifact: {path}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"invalid JSON artifact {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        failures.append(f"expected JSON object in {path}")
        return None
    return payload


def _require_gate(
    summary: dict[str, Any],
    key: str,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    gate = _object(summary.get(key))
    _require_bool(f"{key}_passed", bool(gate.get("passed")), checks=checks, failures=failures)


def _require_bool(name: str, value: bool, *, checks: dict[str, bool], failures: list[str]) -> None:
    checks[name] = value
    if not value:
        failures.append(f"{name} is false")


def _require_equal(
    name: str,
    value: object,
    expected: object,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    passed = value == expected
    checks[name] = passed
    if not passed:
        failures.append(f"{name} {value!r} != {expected!r}")


def _require_min(
    name: str,
    value: float | int | None,
    minimum: float | int,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    passed = value is not None and value >= minimum
    checks[name] = passed
    if not passed:
        failures.append(f"{name} {value} < {minimum}")


def _fail(checks: dict[str, bool], failures: list[str], name: str, reason: str) -> None:
    checks[name] = False
    failures.append(reason)


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--outcome-report", default="")
    parser.add_argument("--backend-outcome-events", default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--min-outcome-record-count", type=int, default=1)
    parser.add_argument("--min-delayed-event-count", type=int, default=0)
    parser.add_argument("--min-outcome-ledger-coverage-ratio", type=float, default=1.0)
    parser.add_argument("--min-h1-evidence-ref-ratio", type=float, default=1.0)
    parser.add_argument("--min-normative-local-update-blocked-ratio", type=float, default=1.0)
    parser.add_argument("--min-delayed-verifier-coverage-ratio", type=float, default=None)
    parser.add_argument("--require-backend-outcome-events", action="store_true")
    parser.add_argument("--allow-truncated-backend-outcome-events", action="store_true")
    args = parser.parse_args()

    report = check_h2_release(
        run_root=Path(args.run_root),
        outcome_report_path=Path(args.outcome_report) if args.outcome_report else None,
        backend_outcome_events_path=(
            Path(args.backend_outcome_events) if args.backend_outcome_events else None
        ),
        agent_root=agent_root,
        min_outcome_record_count=args.min_outcome_record_count,
        min_delayed_event_count=args.min_delayed_event_count,
        min_outcome_ledger_coverage_ratio=args.min_outcome_ledger_coverage_ratio,
        min_h1_evidence_ref_ratio=args.min_h1_evidence_ref_ratio,
        min_normative_local_update_blocked_ratio=args.min_normative_local_update_blocked_ratio,
        min_delayed_verifier_coverage_ratio=args.min_delayed_verifier_coverage_ratio,
        require_backend_outcome_events=args.require_backend_outcome_events,
        allow_truncated_backend_outcome_events=args.allow_truncated_backend_outcome_events,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        output = _resolve_path(Path(args.output), agent_root)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())