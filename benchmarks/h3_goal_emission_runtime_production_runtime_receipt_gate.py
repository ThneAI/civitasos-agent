"""H.3 production runtime receipt gate.

This artifact-only layer reads the production runtime actuation gate and an
optional production runtime receipt artifact. It ensures runtime start receipts
cannot be reviewed until production runtime actuation has been independently
reviewed. It does not start runtime, write production receipts, call LLMs, or
mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_goal_emission_runtime_production_evidence_gate import NON_PRODUCTION_SOURCE_TOKENS
from benchmarks.h3_goal_emission_runtime_production_runtime_actuation_gate import (
    SCHEMA_VERSION as PRODUCTION_RUNTIME_ACTUATION_GATE_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-runtime-receipt-gate:v1"
PRODUCTION_RUNTIME_RECEIPT_SCHEMA_VERSION = "h3-goal-emission-runtime-production-runtime-receipt:v1"
ACCEPTED_PRODUCTION_RUNTIME_RECEIPT_STATUSES = frozenset({"recorded", "verified", "green", "ready"})
PRODUCTION_RUNTIME_RECEIPT_REQUIRED_FIELDS = [
    "receipt_id",
    "goal_id",
    "runtime_executor",
    "runtime_executor_role",
    "source",
    "status",
    "attestation_ref",
    "runtime_actuation_ref",
    "runtime_actuation_sha256",
    "runtime_start_ref",
    "runtime_process_ref",
    "started_at_ref",
    "health_probe_ref",
    "audit_sink_ref",
    "receipt_sink_ref",
]


def build_h3_goal_emission_runtime_production_runtime_receipt_gate(
    *,
    production_runtime_actuation_gate_path: Path,
    agent_root: Path,
    production_runtime_receipt_path: Path | None = None,
) -> dict[str, Any]:
    production_runtime_actuation_gate_path = _resolve_path(production_runtime_actuation_gate_path, agent_root)
    production_runtime_receipt_path = (
        _resolve_path(production_runtime_receipt_path, agent_root)
        if production_runtime_receipt_path
        else None
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    actuation_gate_report = _read_json(production_runtime_actuation_gate_path, failures)

    actuation_readiness: dict[str, Any] = {}
    actuation_boundary: dict[str, Any] = {}
    actuation_gaps: list[dict[str, Any]] = []
    actuation_summary: dict[str, Any] = {}
    if actuation_gate_report is None:
        _fail(
            checks,
            failures,
            "production_runtime_actuation_gate_present",
            f"missing H3 production runtime actuation gate: {production_runtime_actuation_gate_path}",
        )
    else:
        checks["production_runtime_actuation_gate_present"] = True
        _require_equal(
            "production_runtime_actuation_gate_schema_version",
            actuation_gate_report.get("schema_version"),
            PRODUCTION_RUNTIME_ACTUATION_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_runtime_actuation_gate_passed", bool(actuation_gate_report.get("passed")), checks=checks, failures=failures)
        actuation_readiness = _object(actuation_gate_report.get("readiness"))
        _require_actuation_readiness(actuation_readiness, checks=checks, failures=failures)
        actuation_boundary = _object(actuation_gate_report.get("runtime_production_actuation_boundary"))
        _require_actuation_boundary(actuation_boundary, checks=checks, failures=failures)
        actuation_surface = _object(actuation_gate_report.get("runtime_production_actuation_surface"))
        _require_equal(
            "production_runtime_actuation_surface_mode",
            actuation_surface.get("mode"),
            "production_runtime_actuation_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        actuation_gaps = _record_list(actuation_surface.get("production_runtime_actuation_gaps"))
        actuation_summary = _object(actuation_surface.get("production_runtime_actuation_summary"))
        _require_actuation_surface(actuation_summary, actuation_gaps, checks=checks, failures=failures)
        _require_non_claims(_record_text_list(actuation_gate_report.get("non_claims")), checks=checks, failures=failures)

    upstream_decision = str(actuation_readiness.get("decision") or "")
    actuation_reviewed = _actuation_reviewed(upstream_decision, actuation_summary, actuation_gaps)
    actuation_targets_present = bool(actuation_summary or actuation_gaps)
    receipt_records: list[dict[str, Any]] = []
    receipt_payload: dict[str, Any] | None = None
    receipt_sha256 = ""
    if production_runtime_receipt_path:
        receipt_payload, receipt_sha256 = _read_json_with_sha256(production_runtime_receipt_path, failures)
        checks["production_runtime_receipt_artifact_present"] = receipt_payload is not None
        if receipt_payload is not None:
            _require_bool("production_runtime_receipt_requires_actuation_review", actuation_reviewed, checks=checks, failures=failures)
            _require_equal(
                "production_runtime_receipt_schema_version",
                receipt_payload.get("schema_version"),
                PRODUCTION_RUNTIME_RECEIPT_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            receipt_records = _record_list(receipt_payload.get("production_runtime_receipt_records") or receipt_payload.get("receipt_records") or receipt_payload.get("records"))
            _require_bool("production_runtime_receipt_records_present", bool(receipt_records), checks=checks, failures=failures)
            _require_receipt_record_shape(receipt_records, actuation_summary, checks=checks, failures=failures)
    else:
        checks["production_runtime_receipt_optional_absent"] = True

    receipt_summary: dict[str, Any] = {}
    receipt_gaps: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        receipt_summary, receipt_gaps = _build_receipt_summary(
            receipt_path=production_runtime_receipt_path,
            receipt_sha256=receipt_sha256,
            actuation_reviewed=actuation_reviewed,
            actuation_summary=actuation_summary,
            actuation_gaps=actuation_gaps,
            receipt_records=receipt_records,
        )

    metrics = {
        "production_runtime_actuation_gap_count": len(actuation_gaps),
        "production_runtime_actuation_reviewed_count": int(bool(actuation_summary)),
        "production_runtime_receipt_record_count": len(receipt_records),
        "production_runtime_receipt_gap_count": len(receipt_gaps),
        "production_runtime_receipt_ready_count": 0,
        "production_runtime_execution_ready_count": 0,
        "agent_loop_start_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("production_runtime_receipt_not_written_by_gate", metrics["production_runtime_receipt_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_blocked", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("agent_loop_start_blocked", metrics["agent_loop_start_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _receipt_decision(
        passed=passed,
        actuation_targets_present=actuation_targets_present,
        actuation_reviewed=actuation_reviewed,
        receipt_path_present=bool(production_runtime_receipt_path),
        receipt_summary=receipt_summary,
        receipt_gaps=receipt_gaps,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_runtime_actuation_gate_path": str(production_runtime_actuation_gate_path),
        "production_runtime_receipt_path": str(production_runtime_receipt_path) if production_runtime_receipt_path else None,
        "checks": checks,
        "readiness": {
            "production_runtime_receipt_evaluated": passed,
            "production_runtime_receipt_artifact_present": passed and bool(receipt_summary),
            "production_runtime_receipt_artifact_complete": passed and bool(receipt_summary) and not receipt_gaps,
            "production_runtime_receipt_ready": False,
            "production_runtime_execution_ready": False,
            "decision": decision,
            "upstream_runtime_actuation_decision": upstream_decision,
            "allowed_scope": _allowed_scope(
                passed=passed,
                actuation_targets_present=actuation_targets_present,
                actuation_reviewed=actuation_reviewed,
                receipt_path_present=bool(production_runtime_receipt_path),
                receipt_summary=receipt_summary,
                receipt_gaps=receipt_gaps,
            ),
        },
        "runtime_production_receipt_boundary": {
            "artifact_only": True,
            "production_runtime_receipt_review_allowed": passed,
            "production_runtime_receipt_write_allowed": False,
            "production_runtime_execution_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_receipt_policy": {
            "runtime_actuation_gate_schema": PRODUCTION_RUNTIME_ACTUATION_GATE_SCHEMA_VERSION,
            "runtime_receipt_schema": PRODUCTION_RUNTIME_RECEIPT_SCHEMA_VERSION,
            "required_runtime_receipt_fields": PRODUCTION_RUNTIME_RECEIPT_REQUIRED_FIELDS,
            "accepted_runtime_receipt_statuses": sorted(ACCEPTED_PRODUCTION_RUNTIME_RECEIPT_STATUSES),
            "forbidden_runtime_receipt_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "required_runtime_actuation_decision": "production_runtime_actuation_reviewed_no_runtime_start",
            "blocked_after_runtime_receipt_review": [
                "runtime_receipt_reviewed -> runtime_started_by_this_gate",
                "runtime_receipt_reviewed -> production_runtime_execution_receipt_written_by_this_gate",
                "runtime_receipt_reviewed -> agent_loop_started",
            ],
        },
        "runtime_production_receipt_surface": {
            "mode": "production_runtime_receipt_review_only_no_runtime",
            "production_runtime_receipt_summary": receipt_summary,
            "production_runtime_receipt_gap_count": len(receipt_gaps),
            "production_runtime_receipt_gaps": receipt_gaps,
            "source_runtime_actuation_decision": upstream_decision,
            "source_production_runtime_actuation_summary": actuation_summary,
            "source_production_runtime_actuation_gaps": actuation_gaps,
        },
        "metrics": metrics,
        "evidence": {
            "production_runtime_actuation_readiness": actuation_readiness,
            "production_runtime_actuation_boundary": actuation_boundary,
        },
        "non_claims": [
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_runtime_receipt_review_as_runtime_start",
        ],
    }


def _require_actuation_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "blocked_before_runtime_production_runtime_actuation",
        "production_runtime_actuation_not_required_no_execution_targets",
        "production_runtime_actuation_blocked_upstream_execution",
        "production_runtime_actuation_blocked_pending_actuation_artifact",
        "production_runtime_actuation_gap_detected",
        "production_runtime_actuation_reviewed_no_runtime_start",
    }
    _require_bool("production_runtime_actuation_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_runtime_actuation_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_runtime_actuation_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_actuation_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_runtime_actuation_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
        "production_runtime_actuation_allowed",
        "production_runtime_execution_allowed",
        "production_runtime_receipt_allowed",
        "agent_loop_start_allowed",
        "llm_planning_allowed",
        "external_system_mutation_allowed",
        "iem_value_mutation_allowed",
        "normative_local_mutation_allowed",
    ):
        _require_bool(f"production_runtime_actuation_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_actuation_surface(summary: dict[str, Any], gaps: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_runtime_actuation_gap_or_summary_present", bool(summary or gaps), checks=checks, failures=failures)
    if summary:
        _require_equal(
            "production_runtime_actuation_summary_state",
            summary.get("state"),
            "production_runtime_actuation_reviewed_no_runtime_start",
            checks=checks,
            failures=failures,
        )
        _require_bool("production_runtime_actuation_summary_actuation_blocked", summary.get("production_runtime_actuation_ready") is False, checks=checks, failures=failures)
        _require_bool("production_runtime_actuation_summary_execution_blocked", summary.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
        _require_bool("production_runtime_actuation_summary_receipt_blocked", summary.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)
    if gaps:
        _require_bool("production_runtime_actuation_gaps_state_valid", all(str(gap.get("state") or "").startswith("production_runtime_actuation") for gap in gaps), checks=checks, failures=failures)


def _require_non_claims(non_claims: list[str], *, checks: dict[str, bool], failures: list[str]) -> None:
    required = {
        "does_not_treat_runtime_actuation_review_as_runtime_start",
        "does_not_start_runtime_or_agent_loop",
        "does_not_mutate_iem_or_normative_state",
    }
    _require_bool("production_runtime_actuation_non_claims_preserved", required.issubset(set(non_claims)), checks=checks, failures=failures)


def _require_receipt_record_shape(records: list[dict[str, Any]], actuation_summary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_runtime_receipt_common_fields_present", all(_receipt_fields_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_status_accepted", all(str(record.get("status") or "") in ACCEPTED_PRODUCTION_RUNTIME_RECEIPT_STATUSES for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_sources_production", all(not _non_production_source(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_template_flags_absent", all(not record.get("template_only") and record.get("valid_production_runtime_receipt") is not False for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_record_runtime_flags_blocked", all(record.get("production_runtime_receipt_write_allowed") is not True and record.get("production_runtime_execution_allowed") is not True and record.get("agent_loop_start_allowed") is not True for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_records_match_actuation_goals", all(_record_matches_actuation_goal(record, actuation_summary) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_records_match_actuation_sha256", all(str(record.get("runtime_actuation_sha256") or "") == str(actuation_summary.get("actuation_sha256") or "") for record in records), checks=checks, failures=failures)


def _build_receipt_summary(
    *,
    receipt_path: Path | None,
    receipt_sha256: str,
    actuation_reviewed: bool,
    actuation_summary: dict[str, Any],
    actuation_gaps: list[dict[str, Any]],
    receipt_records: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not actuation_reviewed:
        return {}, _actuation_blocking_gaps(actuation_gaps)
    if receipt_path is None:
        return {}, _receipt_missing_gaps(actuation_summary, receipt_records, "production runtime receipt artifact is absent")
    missing_gaps = _receipt_missing_gaps(actuation_summary, receipt_records, "submitted runtime receipt artifact is missing actuation goal receipt")
    receipt_goal_ids = sorted({str(record.get("goal_id") or "") for record in receipt_records if record.get("goal_id")})
    summary = {
        "state": "production_runtime_receipt_reviewed_no_receipt_write",
        "receipt_path": str(receipt_path),
        "receipt_sha256": receipt_sha256,
        "receipt_schema_version": PRODUCTION_RUNTIME_RECEIPT_SCHEMA_VERSION,
        "receipt_record_count": len(receipt_records),
        "receipt_goal_ids": receipt_goal_ids,
        "receipt_refs": [str(record.get("receipt_id") or "") for record in receipt_records],
        "source_runtime_actuation_sha256": str(actuation_summary.get("actuation_sha256") or ""),
        "production_runtime_receipt_ready": False,
        "production_runtime_execution_ready": False,
    }
    return summary, missing_gaps


def _receipt_decision(
    *,
    passed: bool,
    actuation_targets_present: bool,
    actuation_reviewed: bool,
    receipt_path_present: bool,
    receipt_summary: dict[str, Any],
    receipt_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_runtime_production_runtime_receipt"
    if not actuation_targets_present:
        return "production_runtime_receipt_not_required_no_actuation_targets"
    if not actuation_reviewed:
        return "production_runtime_receipt_blocked_upstream_actuation"
    if not receipt_path_present:
        return "production_runtime_receipt_blocked_pending_receipt_artifact"
    if receipt_summary and receipt_gaps:
        return "production_runtime_receipt_gap_detected"
    return "production_runtime_receipt_reviewed_no_receipt_write"


def _allowed_scope(
    *,
    passed: bool,
    actuation_targets_present: bool,
    actuation_reviewed: bool,
    receipt_path_present: bool,
    receipt_summary: dict[str, Any],
    receipt_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not review production runtime receipt until actuation and receipt schemas are valid"
    if not actuation_targets_present:
        return "no production runtime receipt target is available"
    if not actuation_reviewed:
        return "runtime actuation is not reviewed; runtime receipt remains blocked"
    if not receipt_path_present:
        return "runtime actuation is reviewed, but runtime receipt artifact is absent; receipt review remains blocked"
    if receipt_summary and receipt_gaps:
        return "runtime receipt artifact has missing actuation goal receipts; runtime receipt remains blocked"
    return "runtime receipt reviewed only; this gate still does not write receipts or start runtime"


def _actuation_reviewed(upstream_decision: str, summary: dict[str, Any], gaps: list[dict[str, Any]]) -> bool:
    return upstream_decision == "production_runtime_actuation_reviewed_no_runtime_start" and bool(summary) and not gaps


def _actuation_blocking_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not gaps:
        return []
    return [
        {
            "goal_id": gap.get("goal_id"),
            "state": "production_runtime_receipt_blocked_by_actuation_gap",
            "gap_reason": "production runtime actuation has not been reviewed",
            "source_actuation_gap_reason": gap.get("gap_reason"),
        }
        for gap in gaps
    ]


def _receipt_missing_gaps(summary: dict[str, Any], records: list[dict[str, Any]], reason: str) -> list[dict[str, Any]]:
    actuation_goal_ids = [str(goal_id) for goal_id in summary.get("actuation_goal_ids") or [] if goal_id]
    receipt_goal_ids = {str(record.get("goal_id") or "") for record in records}
    missing_goal_ids = [goal_id for goal_id in actuation_goal_ids if goal_id not in receipt_goal_ids]
    if not missing_goal_ids:
        return []
    return [
        {
            "state": "production_runtime_receipt_gap",
            "gap_reason": reason,
            "missing_receipt_goal_ids": missing_goal_ids,
            "source_runtime_actuation_sha256": summary.get("actuation_sha256"),
        }
    ]


def _receipt_fields_present(record: dict[str, Any]) -> bool:
    return all(bool(record.get(field)) for field in PRODUCTION_RUNTIME_RECEIPT_REQUIRED_FIELDS)


def _record_matches_actuation_goal(record: dict[str, Any], summary: dict[str, Any]) -> bool:
    return str(record.get("goal_id") or "") in {str(goal_id) for goal_id in summary.get("actuation_goal_ids") or []}


def _non_production_source(record: dict[str, Any]) -> bool:
    if record.get("synthetic_fixture") is True or record.get("local_controlled_fixture") is True:
        return True
    source = str(record.get("source") or "").lower()
    return any(token in source for token in NON_PRODUCTION_SOURCE_TOKENS)


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


def _read_json_with_sha256(path: Path, failures: list[str]) -> tuple[dict[str, Any] | None, str]:
    if not path.exists():
        failures.append(f"missing JSON artifact: {path}")
        return None, ""
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        failures.append(f"invalid JSON artifact {path}: {exc}")
        return None, digest
    if not isinstance(payload, dict):
        failures.append(f"expected JSON object in {path}")
        return None, digest
    return payload, digest


def _record_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _record_text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require_bool(name: str, value: bool, *, checks: dict[str, bool], failures: list[str]) -> None:
    checks[name] = value
    if not value:
        failures.append(f"{name} failed")


def _require_equal(name: str, actual: object, expected: object, *, checks: dict[str, bool], failures: list[str]) -> None:
    passed = actual == expected
    checks[name] = passed
    if not passed:
        failures.append(f"{name} expected {expected!r}, got {actual!r}")


def _fail(checks: dict[str, bool], failures: list[str], name: str, reason: str) -> None:
    checks[name] = False
    failures.append(reason)


def _resolve_path(path: Path | None, agent_root: Path) -> Path:
    assert path is not None
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-runtime-actuation-gate", required=True)
    parser.add_argument("--production-runtime-receipt", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_runtime_receipt_gate(
        production_runtime_actuation_gate_path=Path(args.production_runtime_actuation_gate),
        agent_root=agent_root,
        production_runtime_receipt_path=Path(args.production_runtime_receipt) if args.production_runtime_receipt else None,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        output = _resolve_path(Path(args.output), agent_root)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if report.get("passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())