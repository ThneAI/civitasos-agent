"""H.2-E value calibration closure/readiness report.

Reads an existing H2 value calibration report and decides whether the evidence
is sufficient to enter the H.3 Goal Generator skeleton. This checker is
artifact-only: it does not start backend, agents, or LLMs, and it does not
mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h2-value-calibration-closure:v1"
VALUE_REPORT_SCHEMA_VERSION = "h2-value-calibration-report:v1"
BACKEND_REPEATED_PATTERN_SOURCE = "backend_task_pool_read_model"
BACKEND_REPEATED_PATTERN_SOURCES = {
    BACKEND_REPEATED_PATTERN_SOURCE,
    "backend_protocol_upgrade_read_model",
    "backend_economic_read_model",
}
STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS = [
    "post_delivery_dispute",
    "post_delivery_failure",
    "relation_repair_relapse",
    "governance_rollback",
    "economic_deviation",
]
DELAYED_CONSEQUENCE_EVIDENCE_SCHEMA_VERSION = (
    "h2-delayed-consequence-evidence-check:v1"
)


def build_h2_value_calibration_closure(
    *,
    value_report_path: Path,
    agent_root: Path,
    min_value_calibration_trace_coverage_ratio: float = 1.0,
    min_repeated_outcome_pattern_count: int = 1,
    min_backend_sourced_repeated_outcome_pattern_count: int = 1,
    required_repeated_outcome_event_kinds: list[str] | None = None,
    required_backend_sourced_repeated_outcome_event_kinds: list[str] | None = None,
    delayed_consequence_evidence_path: Path | None = None,
) -> dict[str, Any]:
    value_report_path = _resolve_path(value_report_path, agent_root)
    required_repeated_outcome_event_kinds = _normalize_event_kinds(
        required_repeated_outcome_event_kinds or []
    )
    required_backend_sourced_repeated_outcome_event_kinds = _normalize_event_kinds(
        required_backend_sourced_repeated_outcome_event_kinds or []
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    value_report = _read_json(value_report_path, failures)
    metrics: dict[str, Any] = {}
    value_checks: dict[str, Any] = {}
    value_thresholds: dict[str, Any] = {}
    delayed_consequence_evidence: dict[str, Any] = {}

    if value_report is None:
        _fail(checks, failures, "value_report_present", f"missing H2 value calibration report: {value_report_path}")
    else:
        checks["value_report_present"] = True
        _require_equal(
            "value_report_schema_version",
            value_report.get("schema_version"),
            VALUE_REPORT_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("value_report_passed", bool(value_report.get("passed")), checks=checks, failures=failures)
        metrics = _object(value_report.get("metrics"))
        value_checks = _object(value_report.get("checks"))
        value_thresholds = _object(value_report.get("thresholds"))
        _require_value_boundary_checks(value_checks, checks=checks, failures=failures)

    if delayed_consequence_evidence_path is not None:
        delayed_consequence_evidence_path = _resolve_path(
            delayed_consequence_evidence_path,
            agent_root,
        )
        delayed_consequence_evidence = (
            _read_json(delayed_consequence_evidence_path, failures) or {}
        )
        _require_equal(
            "delayed_consequence_evidence_schema_version",
            delayed_consequence_evidence.get("schema_version"),
            DELAYED_CONSEQUENCE_EVIDENCE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool(
            "delayed_consequence_evidence_passed",
            delayed_consequence_evidence.get("passed") is True,
            checks=checks,
            failures=failures,
        )
        _require_bool(
            "delayed_consequence_h3_readiness",
            _object(delayed_consequence_evidence.get("h3_readiness")).get("ready")
            is True,
            checks=checks,
            failures=failures,
        )
    else:
        checks["delayed_consequence_evidence_not_required"] = True

    repeated_event_kinds = _event_kinds(metrics.get("repeated_outcome_event_kinds"))
    backend_sourced_event_kinds = _backend_sourced_event_kinds(metrics)
    missing_repeated_event_kinds = _missing_event_kinds(
        required_repeated_outcome_event_kinds,
        repeated_event_kinds,
    )
    missing_backend_sourced_event_kinds = _missing_event_kinds(
        required_backend_sourced_repeated_outcome_event_kinds,
        backend_sourced_event_kinds,
    )

    _require_min(
        "value_calibration_trace_coverage_ratio",
        _float(metrics.get("value_calibration_trace_coverage_ratio")),
        min_value_calibration_trace_coverage_ratio,
        checks=checks,
        failures=failures,
    )
    _require_min(
        "repeated_outcome_pattern_count",
        _int(metrics.get("repeated_outcome_pattern_count")),
        min_repeated_outcome_pattern_count,
        checks=checks,
        failures=failures,
    )
    _require_min(
        "backend_sourced_repeated_outcome_pattern_count",
        _int(metrics.get("backend_sourced_repeated_outcome_pattern_count")),
        min_backend_sourced_repeated_outcome_pattern_count,
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "normative_local_mutation_forbidden",
        _int(metrics.get("normative_local_mutation_violation_count")) == 0,
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "desired_slow_drift_requires_repeated_pattern",
        _int(metrics.get("desired_slow_drift_without_repeated_pattern_count")) == 0,
        checks=checks,
        failures=failures,
    )
    _require_missing_event_kinds(
        "required_repeated_outcome_event_kinds",
        missing_repeated_event_kinds,
        checks=checks,
        failures=failures,
    )
    _require_missing_event_kinds(
        "required_backend_sourced_repeated_outcome_event_kinds",
        missing_backend_sourced_event_kinds,
        checks=checks,
        failures=failures,
    )

    passed = not failures and all(checks.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "value_report_path": str(value_report_path),
        "delayed_consequence_evidence_path": (
            str(delayed_consequence_evidence_path)
            if delayed_consequence_evidence_path is not None
            else None
        ),
        "thresholds": {
            "min_value_calibration_trace_coverage_ratio": min_value_calibration_trace_coverage_ratio,
            "min_repeated_outcome_pattern_count": min_repeated_outcome_pattern_count,
            "min_backend_sourced_repeated_outcome_pattern_count": min_backend_sourced_repeated_outcome_pattern_count,
            "required_repeated_outcome_event_kinds": required_repeated_outcome_event_kinds,
            "required_backend_sourced_repeated_outcome_event_kinds": required_backend_sourced_repeated_outcome_event_kinds,
        },
        "checks": checks,
        "evidence": {
            "value_report": {
                "passed": bool(value_report.get("passed")) if value_report else False,
                "outcome_report_path": value_report.get("outcome_report_path") if value_report else None,
                "thresholds": value_thresholds,
                "checks": value_checks,
                "metrics": metrics,
            },
            "repeated_outcome_event_kinds": repeated_event_kinds,
            "backend_sourced_repeated_outcome_event_kinds": backend_sourced_event_kinds,
            "missing_repeated_outcome_event_kinds": missing_repeated_event_kinds,
            "missing_backend_sourced_repeated_outcome_event_kinds": missing_backend_sourced_event_kinds,
            "delayed_consequence_evidence": delayed_consequence_evidence,
        },
        "h3_goal_generator_readiness": {
            "ready": passed,
            "decision": "ready_for_h3_goal_generator_skeleton" if passed else "blocked_before_h3",
            "next_stage": "H.3 Goal Generator skeleton",
            "allowed_scope": (
                "skeleton only; preserve H1/H2 gates and governance boundaries"
                if passed
                else "do not start H3 until backend-sourced repeated outcome evidence satisfies thresholds"
            ),
        },
        "closure_boundary": {
            "artifact_only": True,
            "runtime_mutation_allowed": False,
            "llm_training_allowed": False,
            "normative_local_mutation_allowed": False,
            "seed_patterns_count_as_h3_backend_readiness": False,
            "cross_day_delayed_consequence_required_when_configured": True,
        },
        "non_claims": [
            "does_not_claim_complete_long_term_value_learning",
            "does_not_authorize_normative_state_mutation",
            "does_not_replace_governance_or_arbitration",
            "does_not_train_models_or_start_runtime",
        ],
    }


def _require_value_boundary_checks(
    value_checks: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    for name in (
        "outcome_report_passed",
        "outcome_report_schema_version",
        "value_calibration_trace_coverage_ratio",
        "normative_local_mutation_forbidden",
        "desired_slow_drift_requires_repeated_pattern",
    ):
        _require_bool(f"value_report_check_{name}", bool(value_checks.get(name)), checks=checks, failures=failures)


def _backend_sourced_event_kinds(metrics: dict[str, Any]) -> list[str]:
    event_kinds: set[str] = set()
    patterns = metrics.get("repeated_outcome_patterns")
    if not isinstance(patterns, list):
        return []
    for pattern in patterns:
        if not isinstance(pattern, dict):
            continue
        sources = pattern.get("sources")
        if not isinstance(sources, list) or not any(
            str(source or "") in BACKEND_REPEATED_PATTERN_SOURCES for source in sources
        ):
            continue
        event_kind = str(pattern.get("event_kind") or "").strip()
        if event_kind:
            event_kinds.add(event_kind)
    return sorted(event_kinds)


def _event_kinds(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(item or "").strip() for item in value if str(item or "").strip()})


def _missing_event_kinds(required: list[str], observed: list[str]) -> list[str]:
    observed_set = set(observed)
    return [event_kind for event_kind in required if event_kind not in observed_set]


def _require_missing_event_kinds(
    name: str,
    missing: list[str],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    checks[name] = not missing
    if missing:
        failures.append(f"missing {name}: {', '.join(missing)}")


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


def _normalize_event_kinds(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        event_kind = str(value or "").strip()
        if not event_kind or event_kind in seen:
            continue
        seen.add(event_kind)
        out.append(event_kind)
    return out


def _require_bool(name: str, value: bool, *, checks: dict[str, bool], failures: list[str]) -> None:
    checks[name] = value
    if not value:
        failures.append(f"{name} failed")


def _require_equal(
    name: str,
    actual: object,
    expected: object,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    passed = actual == expected
    checks[name] = passed
    if not passed:
        failures.append(f"{name} expected {expected!r}, got {actual!r}")


def _require_min(
    name: str,
    actual: float | int | None,
    expected: float | int,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    passed = actual is not None and actual >= expected
    checks[name] = passed
    if not passed:
        failures.append(f"{name} below H2-E closure threshold: {actual!r} < {expected!r}")


def _fail(checks: dict[str, bool], failures: list[str], name: str, reason: str) -> None:
    checks[name] = False
    failures.append(reason)


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--value-report", required=True)
    parser.add_argument("--output", default="")
    parser.add_argument("--min-value-calibration-trace-coverage-ratio", type=float, default=1.0)
    parser.add_argument("--min-repeated-outcome-pattern-count", type=int, default=1)
    parser.add_argument("--min-backend-sourced-repeated-outcome-pattern-count", type=int, default=1)
    parser.add_argument("--require-repeated-outcome-event-kind", action="append", default=[])
    parser.add_argument("--require-backend-sourced-repeated-outcome-event-kind", action="append", default=[])
    parser.add_argument("--require-standard-repeated-outcome-event-kinds", action="store_true")
    parser.add_argument("--require-standard-backend-sourced-repeated-outcome-event-kinds", action="store_true")
    parser.add_argument("--delayed-consequence-evidence-report", default="")
    args = parser.parse_args()

    required_repeated = list(args.require_repeated_outcome_event_kind)
    required_backend = list(args.require_backend_sourced_repeated_outcome_event_kind)
    if args.require_standard_repeated_outcome_event_kinds:
        required_repeated.extend(STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS)
    if args.require_standard_backend_sourced_repeated_outcome_event_kinds:
        required_backend.extend(STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS)

    report = build_h2_value_calibration_closure(
        value_report_path=Path(args.value_report),
        agent_root=agent_root,
        min_value_calibration_trace_coverage_ratio=args.min_value_calibration_trace_coverage_ratio,
        min_repeated_outcome_pattern_count=args.min_repeated_outcome_pattern_count,
        min_backend_sourced_repeated_outcome_pattern_count=args.min_backend_sourced_repeated_outcome_pattern_count,
        required_repeated_outcome_event_kinds=required_repeated,
        required_backend_sourced_repeated_outcome_event_kinds=required_backend,
        delayed_consequence_evidence_path=(
            Path(args.delayed_consequence_evidence_report)
            if args.delayed_consequence_evidence_report
            else None
        ),
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
