"""H.2 value calibration diagnostic report.

Reads an existing H2 outcome report and summarizes whether post-delivery
outcomes are shaped into auditable value-calibration candidates. This script
does not start backend, agents, or LLMs, and it never mutates IEM state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h2-value-calibration-report:v1"
H2_OUTCOME_REPORT_SCHEMA_VERSION = "h2-outcome-report:v1"
BACKEND_REPEATED_PATTERN_SOURCES = {
    "backend_task_pool_read_model",
    "backend_protocol_upgrade_read_model",
    "backend_economic_read_model",
}


def build_h2_value_calibration_report(
    *,
    outcome_report_path: Path,
    agent_root: Path,
    min_value_calibration_trace_coverage_ratio: float = 1.0,
    min_repeated_outcome_pattern_count: int = 0,
    min_backend_sourced_repeated_outcome_pattern_count: int = 0,
    required_repeated_outcome_event_kinds: list[str] | None = None,
) -> dict[str, Any]:
    outcome_report_path = _resolve_path(outcome_report_path, agent_root)
    required_repeated_outcome_event_kinds = _normalize_event_kinds(required_repeated_outcome_event_kinds or [])
    failures: list[str] = []
    checks: dict[str, bool] = {}
    outcome_report = _read_json(outcome_report_path, failures)
    records: list[dict[str, Any]] = []
    if outcome_report is None:
        _fail(checks, failures, "outcome_report_present", f"missing H2 outcome report: {outcome_report_path}")
    else:
        _require_equal(
            "outcome_report_schema_version",
            outcome_report.get("schema_version"),
            H2_OUTCOME_REPORT_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("outcome_report_passed", bool(outcome_report.get("passed")), checks=checks, failures=failures)
        records = _records(outcome_report, failures)

    metrics = _metrics(records)
    _require_min(
        "value_calibration_trace_coverage_ratio",
        _float(metrics.get("value_calibration_trace_coverage_ratio")),
        min_value_calibration_trace_coverage_ratio,
        checks=checks,
        failures=failures,
    )
    _require_min(
        "repeated_outcome_pattern_count",
        _float(metrics.get("repeated_outcome_pattern_count")),
        float(min_repeated_outcome_pattern_count),
        checks=checks,
        failures=failures,
    )
    _require_min(
        "backend_sourced_repeated_outcome_pattern_count",
        _float(metrics.get("backend_sourced_repeated_outcome_pattern_count")),
        float(min_backend_sourced_repeated_outcome_pattern_count),
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
    _require_required_repeated_event_kinds(
        required_repeated_outcome_event_kinds,
        metrics=metrics,
        checks=checks,
        failures=failures,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "passed": not failures and all(checks.values()),
        "failure_reasons": failures,
        "outcome_report_path": str(outcome_report_path),
        "thresholds": {
            "min_value_calibration_trace_coverage_ratio": min_value_calibration_trace_coverage_ratio,
            "min_repeated_outcome_pattern_count": min_repeated_outcome_pattern_count,
            "min_backend_sourced_repeated_outcome_pattern_count": min_backend_sourced_repeated_outcome_pattern_count,
            "required_repeated_outcome_event_kinds": required_repeated_outcome_event_kinds,
        },
        "checks": checks,
        "metrics": metrics,
        "calibration_boundary": {
            "predicted_state": "fast calibration candidate from observed outcome evidence",
            "desired_state": "slow drift candidate only when repeated outcome evidence is present",
            "normative_state": "governance trace only; local mutation is forbidden",
        },
    }


def _records(outcome_report: dict[str, Any], failures: list[str]) -> list[dict[str, Any]]:
    records = outcome_report.get("records")
    if not isinstance(records, list):
        failures.append("H2 outcome report missing records array")
        return []
    return [record for record in records if isinstance(record, dict)]


def _metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(records)
    trace_records = 0
    predicted_candidates = 0
    predicted_record_count = 0
    desired_candidates = 0
    desired_with_repeated_pattern = 0
    desired_without_repeated_pattern = 0
    repeated_patterns: dict[tuple[str, str], dict[str, Any]] = {}
    normative_candidates = 0
    normative_mutation_blocked = 0
    normative_local_mutation_violations = 0
    normative_required_without_candidate = 0

    for record in records:
        candidates = _candidate_list(record)
        if candidates:
            trace_records += 1
        has_predicted_candidate = False
        has_normative_candidate = False
        for candidate in candidates:
            state = str(candidate.get("state") or "")
            if state == "Predicted":
                predicted_candidates += 1
                has_predicted_candidate = True
            elif state == "Desired":
                desired_candidates += 1
                if _desired_candidate_has_repeated_pattern(candidate):
                    desired_with_repeated_pattern += 1
                else:
                    desired_without_repeated_pattern += 1
                if _is_repeated_outcome_pattern_candidate(candidate):
                    _add_repeated_pattern(repeated_patterns, record=record, candidate=candidate)
            elif state == "Normative":
                normative_candidates += 1
                has_normative_candidate = True
                if _normative_candidate_is_blocked(candidate):
                    normative_mutation_blocked += 1
                else:
                    normative_local_mutation_violations += 1
        if has_predicted_candidate:
            predicted_record_count += 1
        normative_status = _object(record.get("normative_update_blocked_or_governed"))
        if normative_status.get("required") and not has_normative_candidate:
            normative_required_without_candidate += 1
            normative_local_mutation_violations += 1
        if normative_status and normative_status.get("local_mutation_allowed") is not False:
            normative_local_mutation_violations += 1

    repeated_event_kinds = sorted(
        {
            str(item.get("event_kind") or "")
            for item in repeated_patterns.values()
            if str(item.get("event_kind") or "")
        }
    )
    repeated_source_counts = _repeated_pattern_source_counts(repeated_patterns)
    return {
        "outcome_record_count": total,
        "value_calibration_trace_record_count": trace_records,
        "value_calibration_trace_coverage_ratio": _ratio(trace_records, total),
        "predicted_update_candidate_count": predicted_candidates,
        "predicted_update_record_count": predicted_record_count,
        "predicted_update_record_ratio": _ratio(predicted_record_count, total),
        "desired_slow_drift_candidate_count": desired_candidates,
        "desired_slow_drift_with_repeated_pattern_count": desired_with_repeated_pattern,
        "desired_slow_drift_without_repeated_pattern_count": desired_without_repeated_pattern,
        "desired_slow_drift_requires_repeated_pattern_ratio": _ratio(
            desired_with_repeated_pattern,
            desired_candidates,
            empty=1.0,
        ),
        "repeated_outcome_pattern_count": len(repeated_patterns),
        "backend_sourced_repeated_outcome_pattern_count": _backend_sourced_repeated_pattern_count(
            repeated_patterns
        ),
        "repeated_outcome_pattern_source_counts": repeated_source_counts,
        "repeated_outcome_event_kinds": repeated_event_kinds,
        "repeated_outcome_patterns": _repeated_patterns_payload(repeated_patterns),
        "normative_governance_trace_candidate_count": normative_candidates,
        "normative_mutation_blocked_count": normative_mutation_blocked,
        "normative_required_without_candidate_count": normative_required_without_candidate,
        "normative_local_mutation_violation_count": normative_local_mutation_violations,
    }


def _candidate_list(record: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = record.get("iem_update_candidates")
    if not isinstance(candidates, list):
        return []
    return [candidate for candidate in candidates if isinstance(candidate, dict)]


def _add_repeated_pattern(
    repeated_patterns: dict[tuple[str, str], dict[str, Any]],
    *,
    record: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    identity = _record_identity(record)
    event_kind = str(candidate.get("event_kind") or "unknown")
    key = (identity, event_kind)
    item = repeated_patterns.setdefault(
        key,
        {
            "identity": identity,
            "event_kind": event_kind,
            "max_pattern_count": 0,
            "candidate_count": 0,
            "record_ids": [],
            "sources": [],
        },
    )
    pattern_count = _int(candidate.get("pattern_count")) or 0
    item["max_pattern_count"] = max(int(item["max_pattern_count"]), pattern_count)
    item["candidate_count"] = int(item["candidate_count"]) + 1
    record_id = str(record.get("record_id") or "").strip()
    if record_id and record_id not in item["record_ids"]:
        item["record_ids"].append(record_id)
    for source in _record_delayed_event_sources(record, event_kind):
        if source not in item["sources"]:
            item["sources"].append(source)


def _repeated_patterns_payload(repeated_patterns: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            **item,
            "record_ids": sorted(str(record_id) for record_id in item.get("record_ids", [])),
            "sources": sorted(str(source) for source in item.get("sources", [])),
        }
        for _key, item in sorted(repeated_patterns.items())
    ]


def _record_delayed_event_sources(record: dict[str, Any], event_kind: str) -> list[str]:
    delayed_events = record.get("delayed_events")
    if not isinstance(delayed_events, list):
        return []
    sources: list[str] = []
    for event in delayed_events:
        if not isinstance(event, dict) or event.get("event_kind") != event_kind:
            continue
        source = str(event.get("source") or "unknown")
        if source not in sources:
            sources.append(source)
    return sources


def _repeated_pattern_source_counts(repeated_patterns: dict[tuple[str, str], dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in repeated_patterns.values():
        sources = item.get("sources", [])
        if not isinstance(sources, list) or not sources:
            counts["unknown"] = counts.get("unknown", 0) + 1
            continue
        for source in {str(value or "unknown") for value in sources}:
            counts[source] = counts.get(source, 0) + 1
    return dict(sorted(counts.items()))


def _backend_sourced_repeated_pattern_count(
    repeated_patterns: dict[tuple[str, str], dict[str, Any]]
) -> int:
    count = 0
    for item in repeated_patterns.values():
        sources = item.get("sources", [])
        if not isinstance(sources, list):
            continue
        if any(str(source or "") in BACKEND_REPEATED_PATTERN_SOURCES for source in sources):
            count += 1
    return count


def _desired_candidate_has_repeated_pattern(candidate: dict[str, Any]) -> bool:
    return candidate.get("requires_repeated_pattern") is True


def _is_repeated_outcome_pattern_candidate(candidate: dict[str, Any]) -> bool:
    if candidate.get("update_kind") != "delayed_repeated_pattern_slow_drift_candidate":
        return False
    pattern_count = _int(candidate.get("pattern_count"))
    return pattern_count is not None and pattern_count >= 2


def _normative_candidate_is_blocked(candidate: dict[str, Any]) -> bool:
    return candidate.get("local_mutation_allowed") is False and candidate.get("blocked_or_governed") is not False


def _record_identity(record: dict[str, Any]) -> str:
    for key in ("agent_alias", "agent_id", "record_id"):
        value = str(record.get(key) or "").strip()
        if value:
            return value
    return "unknown"


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"missing JSON artifact: {path}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"invalid JSON artifact {path}: {exc}")
        return None
    return payload if isinstance(payload, dict) else None


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


def _require_required_repeated_event_kinds(
    required_event_kinds: list[str],
    *,
    metrics: dict[str, Any],
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not required_event_kinds:
        checks["required_repeated_outcome_event_kinds"] = True
        return
    observed = {
        str(value or "")
        for value in metrics.get("repeated_outcome_event_kinds", [])
        if str(value or "")
    }
    missing = [event_kind for event_kind in required_event_kinds if event_kind not in observed]
    checks["required_repeated_outcome_event_kinds"] = not missing
    if missing:
        failures.append(f"missing required repeated outcome event kinds: {', '.join(missing)}")


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
    actual: float | None,
    expected: float,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    passed = actual is not None and actual >= expected
    checks[name] = passed
    if not passed:
        failures.append(f"{name} below H2 value calibration threshold: {actual!r} < {expected!r}")


def _require_bool(name: str, value: bool, *, checks: dict[str, bool], failures: list[str]) -> None:
    checks[name] = value
    if not value:
        failures.append(f"{name} failed")


def _fail(checks: dict[str, bool], failures: list[str], name: str, reason: str) -> None:
    checks[name] = False
    failures.append(reason)


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _ratio(numerator: int, denominator: int, *, empty: float = 0.0) -> float:
    return numerator / denominator if denominator else empty


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
    parser.add_argument("--outcome-report", required=True)
    parser.add_argument("--output", default="")
    parser.add_argument("--min-value-calibration-trace-coverage-ratio", type=float, default=1.0)
    parser.add_argument("--min-repeated-outcome-pattern-count", type=int, default=0)
    parser.add_argument("--min-backend-sourced-repeated-outcome-pattern-count", type=int, default=0)
    parser.add_argument("--require-repeated-outcome-event-kind", action="append", default=[])
    args = parser.parse_args()
    report = build_h2_value_calibration_report(
        outcome_report_path=Path(args.outcome_report),
        agent_root=agent_root,
        min_value_calibration_trace_coverage_ratio=args.min_value_calibration_trace_coverage_ratio,
        min_repeated_outcome_pattern_count=args.min_repeated_outcome_pattern_count,
        min_backend_sourced_repeated_outcome_pattern_count=args.min_backend_sourced_repeated_outcome_pattern_count,
        required_repeated_outcome_event_kinds=args.require_repeated_outcome_event_kind,
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
