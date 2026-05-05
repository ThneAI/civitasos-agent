"""H.3 production runtime execution gate.

This artifact-only layer reads the production runtime execution handoff gate and
an optional production runtime execution artifact. It ensures production runtime
execution cannot be reviewed until the handoff layer has been independently
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
from benchmarks.h3_goal_emission_runtime_production_runtime_execution_handoff_gate import (
    SCHEMA_VERSION as PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-runtime-execution-gate:v1"
PRODUCTION_RUNTIME_EXECUTION_SCHEMA_VERSION = "h3-goal-emission-runtime-production-runtime-execution:v1"
ACCEPTED_PRODUCTION_RUNTIME_EXECUTION_STATUSES = frozenset({"approved", "execution_ready", "green", "ready"})
PRODUCTION_RUNTIME_EXECUTION_REQUIRED_FIELDS = [
    "execution_id",
    "goal_id",
    "runtime_executor",
    "runtime_executor_role",
    "source",
    "status",
    "attestation_ref",
    "runtime_execution_handoff_ref",
    "runtime_execution_handoff_sha256",
    "final_change_ticket_ref",
    "final_dual_operator_ack_ref",
    "final_kill_switch_ref",
    "final_rollback_checkpoint_ref",
    "final_monitoring_green_ref",
    "final_audit_sink_ref",
    "receipt_sink_ref",
]


def build_h3_goal_emission_runtime_production_runtime_execution_gate(
    *,
    production_runtime_execution_handoff_gate_path: Path,
    agent_root: Path,
    production_runtime_execution_path: Path | None = None,
) -> dict[str, Any]:
    production_runtime_execution_handoff_gate_path = _resolve_path(production_runtime_execution_handoff_gate_path, agent_root)
    production_runtime_execution_path = (
        _resolve_path(production_runtime_execution_path, agent_root)
        if production_runtime_execution_path
        else None
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    handoff_gate_report = _read_json(production_runtime_execution_handoff_gate_path, failures)

    handoff_readiness: dict[str, Any] = {}
    handoff_boundary: dict[str, Any] = {}
    handoff_gaps: list[dict[str, Any]] = []
    handoff_summary: dict[str, Any] = {}
    if handoff_gate_report is None:
        _fail(
            checks,
            failures,
            "production_runtime_execution_handoff_gate_present",
            f"missing H3 production runtime execution handoff gate: {production_runtime_execution_handoff_gate_path}",
        )
    else:
        checks["production_runtime_execution_handoff_gate_present"] = True
        _require_equal(
            "production_runtime_execution_handoff_gate_schema_version",
            handoff_gate_report.get("schema_version"),
            PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_runtime_execution_handoff_gate_passed", bool(handoff_gate_report.get("passed")), checks=checks, failures=failures)
        handoff_readiness = _object(handoff_gate_report.get("readiness"))
        _require_handoff_readiness(handoff_readiness, checks=checks, failures=failures)
        handoff_boundary = _object(handoff_gate_report.get("runtime_production_execution_handoff_boundary"))
        _require_handoff_boundary(handoff_boundary, checks=checks, failures=failures)
        handoff_surface = _object(handoff_gate_report.get("runtime_production_execution_handoff_surface"))
        _require_equal(
            "production_runtime_execution_handoff_surface_mode",
            handoff_surface.get("mode"),
            "production_runtime_execution_handoff_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        handoff_gaps = _record_list(handoff_surface.get("production_runtime_execution_handoff_gaps"))
        handoff_summary = _object(handoff_surface.get("production_runtime_execution_handoff_summary"))
        _require_handoff_surface(handoff_summary, handoff_gaps, checks=checks, failures=failures)
        _require_non_claims(_record_text_list(handoff_gate_report.get("non_claims")), checks=checks, failures=failures)

    upstream_decision = str(handoff_readiness.get("decision") or "")
    handoff_reviewed = _handoff_reviewed(upstream_decision, handoff_summary, handoff_gaps)
    handoff_targets_present = bool(handoff_summary or handoff_gaps)
    execution_records: list[dict[str, Any]] = []
    execution_payload: dict[str, Any] | None = None
    execution_sha256 = ""
    if production_runtime_execution_path:
        execution_payload, execution_sha256 = _read_json_with_sha256(production_runtime_execution_path, failures)
        checks["production_runtime_execution_artifact_present"] = execution_payload is not None
        if execution_payload is not None:
            _require_bool("production_runtime_execution_requires_handoff_review", handoff_reviewed, checks=checks, failures=failures)
            _require_equal(
                "production_runtime_execution_schema_version",
                execution_payload.get("schema_version"),
                PRODUCTION_RUNTIME_EXECUTION_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            execution_records = _record_list(execution_payload.get("production_runtime_execution_records") or execution_payload.get("execution_records") or execution_payload.get("records"))
            _require_bool("production_runtime_execution_records_present", bool(execution_records), checks=checks, failures=failures)
            _require_execution_record_shape(execution_records, handoff_summary, checks=checks, failures=failures)
    else:
        checks["production_runtime_execution_optional_absent"] = True

    execution_summary: dict[str, Any] = {}
    execution_gaps: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        execution_summary, execution_gaps = _build_execution_summary(
            execution_path=production_runtime_execution_path,
            execution_sha256=execution_sha256,
            handoff_reviewed=handoff_reviewed,
            handoff_summary=handoff_summary,
            handoff_gaps=handoff_gaps,
            execution_records=execution_records,
        )

    metrics = {
        "production_runtime_execution_handoff_gap_count": len(handoff_gaps),
        "production_runtime_execution_handoff_reviewed_count": int(bool(handoff_summary)),
        "production_runtime_execution_record_count": len(execution_records),
        "production_runtime_execution_gap_count": len(execution_gaps),
        "production_runtime_execution_ready_count": 0,
        "production_runtime_receipt_ready_count": 0,
        "agent_loop_start_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("production_runtime_execution_not_started_by_gate", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_blocked", metrics["production_runtime_receipt_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("agent_loop_start_blocked", metrics["agent_loop_start_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _execution_decision(
        passed=passed,
        handoff_targets_present=handoff_targets_present,
        handoff_reviewed=handoff_reviewed,
        execution_path_present=bool(production_runtime_execution_path),
        execution_summary=execution_summary,
        execution_gaps=execution_gaps,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_runtime_execution_handoff_gate_path": str(production_runtime_execution_handoff_gate_path),
        "production_runtime_execution_path": str(production_runtime_execution_path) if production_runtime_execution_path else None,
        "checks": checks,
        "readiness": {
            "production_runtime_execution_evaluated": passed,
            "production_runtime_execution_artifact_present": passed and bool(execution_summary),
            "production_runtime_execution_artifact_complete": passed and bool(execution_summary) and not execution_gaps,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "upstream_runtime_execution_handoff_decision": upstream_decision,
            "allowed_scope": _allowed_scope(
                passed=passed,
                handoff_targets_present=handoff_targets_present,
                handoff_reviewed=handoff_reviewed,
                execution_path_present=bool(production_runtime_execution_path),
                execution_summary=execution_summary,
                execution_gaps=execution_gaps,
            ),
        },
        "runtime_production_execution_boundary": {
            "artifact_only": True,
            "production_runtime_execution_review_allowed": passed,
            "production_runtime_execution_allowed": False,
            "production_runtime_receipt_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_execution_policy": {
            "runtime_execution_handoff_schema": PRODUCTION_RUNTIME_EXECUTION_HANDOFF_GATE_SCHEMA_VERSION,
            "runtime_execution_schema": PRODUCTION_RUNTIME_EXECUTION_SCHEMA_VERSION,
            "required_runtime_execution_fields": PRODUCTION_RUNTIME_EXECUTION_REQUIRED_FIELDS,
            "accepted_runtime_execution_statuses": sorted(ACCEPTED_PRODUCTION_RUNTIME_EXECUTION_STATUSES),
            "forbidden_runtime_execution_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "required_runtime_execution_handoff_decision": "production_runtime_execution_handoff_reviewed_no_runtime_execution",
            "blocked_after_runtime_execution_review": [
                "runtime_execution_reviewed -> runtime_started_by_this_gate",
                "runtime_execution_reviewed -> production_runtime_execution_receipt_written",
                "runtime_execution_reviewed -> agent_loop_started",
            ],
        },
        "runtime_production_execution_surface": {
            "mode": "production_runtime_execution_review_only_no_runtime",
            "production_runtime_execution_summary": execution_summary,
            "production_runtime_execution_gap_count": len(execution_gaps),
            "production_runtime_execution_gaps": execution_gaps,
            "source_runtime_execution_handoff_decision": upstream_decision,
            "source_production_runtime_execution_handoff_summary": handoff_summary,
            "source_production_runtime_execution_handoff_gaps": handoff_gaps,
        },
        "metrics": metrics,
        "evidence": {
            "production_runtime_execution_handoff_readiness": handoff_readiness,
            "production_runtime_execution_handoff_boundary": handoff_boundary,
        },
        "non_claims": [
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_runtime_execution_review_as_runtime_start",
        ],
    }


def _require_handoff_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "blocked_before_runtime_production_execution_handoff",
        "production_runtime_execution_handoff_not_required_no_permission_targets",
        "production_runtime_execution_handoff_blocked_upstream_executor_permission",
        "production_runtime_execution_handoff_blocked_pending_handoff_artifact",
        "production_runtime_execution_handoff_gap_detected",
        "production_runtime_execution_handoff_reviewed_no_runtime_execution",
    }
    _require_bool("production_runtime_execution_handoff_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_handoff_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_handoff_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_handoff_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_runtime_execution_handoff_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
        "production_runtime_execution_handoff_allowed",
        "production_runtime_execution_allowed",
        "production_runtime_receipt_allowed",
        "agent_loop_start_allowed",
        "llm_planning_allowed",
        "external_system_mutation_allowed",
        "iem_value_mutation_allowed",
        "normative_local_mutation_allowed",
    ):
        _require_bool(f"production_runtime_execution_handoff_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_handoff_surface(summary: dict[str, Any], gaps: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_runtime_execution_handoff_gap_or_summary_present", bool(summary or gaps), checks=checks, failures=failures)
    if summary:
        _require_equal(
            "production_runtime_execution_handoff_summary_state",
            summary.get("state"),
            "production_runtime_execution_handoff_reviewed_no_runtime_execution",
            checks=checks,
            failures=failures,
        )
        _require_bool("production_runtime_execution_handoff_summary_handoff_blocked", summary.get("production_runtime_execution_handoff_ready") is False, checks=checks, failures=failures)
        _require_bool("production_runtime_execution_handoff_summary_execution_blocked", summary.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
        _require_bool("production_runtime_execution_handoff_summary_receipt_blocked", summary.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)
    if gaps:
        _require_bool("production_runtime_execution_handoff_gaps_state_valid", all(str(gap.get("state") or "").startswith("production_runtime_execution_handoff") for gap in gaps), checks=checks, failures=failures)


def _require_non_claims(non_claims: list[str], *, checks: dict[str, bool], failures: list[str]) -> None:
    required = {
        "does_not_treat_runtime_execution_handoff_review_as_runtime_execution_permission",
        "does_not_start_runtime_or_agent_loop",
        "does_not_mutate_iem_or_normative_state",
    }
    _require_bool("production_runtime_execution_handoff_non_claims_preserved", required.issubset(set(non_claims)), checks=checks, failures=failures)


def _require_execution_record_shape(records: list[dict[str, Any]], handoff_summary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_runtime_execution_common_fields_present", all(_execution_fields_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_status_accepted", all(str(record.get("status") or "") in ACCEPTED_PRODUCTION_RUNTIME_EXECUTION_STATUSES for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_sources_production", all(not _non_production_source(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_template_flags_absent", all(not record.get("template_only") and record.get("valid_production_runtime_execution") is not False for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_record_runtime_flags_blocked", all(record.get("production_runtime_execution_allowed") is not True and record.get("production_runtime_receipt_allowed") is not True and record.get("agent_loop_start_allowed") is not True for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_records_match_handoff_goals", all(_record_matches_handoff_goal(record, handoff_summary) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_records_match_handoff_sha256", all(str(record.get("runtime_execution_handoff_sha256") or "") == str(handoff_summary.get("handoff_sha256") or "") for record in records), checks=checks, failures=failures)


def _build_execution_summary(
    *,
    execution_path: Path | None,
    execution_sha256: str,
    handoff_reviewed: bool,
    handoff_summary: dict[str, Any],
    handoff_gaps: list[dict[str, Any]],
    execution_records: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not handoff_reviewed:
        return {}, _handoff_blocking_gaps(handoff_gaps)
    if execution_path is None:
        return {}, _execution_missing_gaps(handoff_summary, execution_records, "production runtime execution artifact is absent")
    missing_gaps = _execution_missing_gaps(handoff_summary, execution_records, "submitted runtime execution artifact is missing handoff goal execution")
    execution_goal_ids = sorted({str(record.get("goal_id") or "") for record in execution_records if record.get("goal_id")})
    summary = {
        "state": "production_runtime_execution_reviewed_no_runtime_start",
        "execution_path": str(execution_path),
        "execution_sha256": execution_sha256,
        "execution_schema_version": PRODUCTION_RUNTIME_EXECUTION_SCHEMA_VERSION,
        "execution_record_count": len(execution_records),
        "execution_goal_ids": execution_goal_ids,
        "execution_refs": [str(record.get("execution_id") or "") for record in execution_records],
        "source_runtime_execution_handoff_sha256": str(handoff_summary.get("handoff_sha256") or ""),
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }
    return summary, missing_gaps


def _execution_decision(
    *,
    passed: bool,
    handoff_targets_present: bool,
    handoff_reviewed: bool,
    execution_path_present: bool,
    execution_summary: dict[str, Any],
    execution_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_runtime_production_runtime_execution"
    if not handoff_targets_present:
        return "production_runtime_execution_not_required_no_handoff_targets"
    if not handoff_reviewed:
        return "production_runtime_execution_blocked_upstream_handoff"
    if not execution_path_present:
        return "production_runtime_execution_blocked_pending_execution_artifact"
    if execution_summary and execution_gaps:
        return "production_runtime_execution_gap_detected"
    return "production_runtime_execution_reviewed_no_runtime_start"


def _allowed_scope(
    *,
    passed: bool,
    handoff_targets_present: bool,
    handoff_reviewed: bool,
    execution_path_present: bool,
    execution_summary: dict[str, Any],
    execution_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not review production runtime execution until handoff and execution schemas are valid"
    if not handoff_targets_present:
        return "no production runtime execution target is available"
    if not handoff_reviewed:
        return "runtime execution handoff is not reviewed; runtime execution remains blocked"
    if not execution_path_present:
        return "runtime execution handoff is reviewed, but runtime execution artifact is absent; runtime execution remains blocked"
    if execution_summary and execution_gaps:
        return "runtime execution artifact has missing handoff goal executions; runtime execution remains blocked"
    return "runtime execution reviewed only; this gate still does not start runtime"


def _handoff_reviewed(upstream_decision: str, summary: dict[str, Any], gaps: list[dict[str, Any]]) -> bool:
    return upstream_decision == "production_runtime_execution_handoff_reviewed_no_runtime_execution" and bool(summary) and not gaps


def _handoff_blocking_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not gaps:
        return []
    return [
        {
            "goal_id": gap.get("goal_id"),
            "state": "production_runtime_execution_blocked_by_handoff_gap",
            "gap_reason": "production runtime execution handoff has not been reviewed",
            "source_handoff_gap_reason": gap.get("gap_reason"),
        }
        for gap in gaps
    ]


def _execution_missing_gaps(summary: dict[str, Any], records: list[dict[str, Any]], reason: str) -> list[dict[str, Any]]:
    handoff_goal_ids = [str(goal_id) for goal_id in summary.get("handoff_goal_ids") or [] if goal_id]
    execution_goal_ids = {str(record.get("goal_id") or "") for record in records}
    missing_goal_ids = [goal_id for goal_id in handoff_goal_ids if goal_id not in execution_goal_ids]
    if not missing_goal_ids:
        return []
    return [
        {
            "state": "production_runtime_execution_gap",
            "gap_reason": reason,
            "missing_execution_goal_ids": missing_goal_ids,
            "source_runtime_execution_handoff_sha256": summary.get("handoff_sha256"),
        }
    ]


def _execution_fields_present(record: dict[str, Any]) -> bool:
    return all(bool(record.get(field)) for field in PRODUCTION_RUNTIME_EXECUTION_REQUIRED_FIELDS)


def _record_matches_handoff_goal(record: dict[str, Any], summary: dict[str, Any]) -> bool:
    return str(record.get("goal_id") or "") in {str(goal_id) for goal_id in summary.get("handoff_goal_ids") or []}


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
    parser.add_argument("--production-runtime-execution-handoff-gate", required=True)
    parser.add_argument("--production-runtime-execution", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_runtime_execution_gate(
        production_runtime_execution_handoff_gate_path=Path(args.production_runtime_execution_handoff_gate),
        agent_root=agent_root,
        production_runtime_execution_path=Path(args.production_runtime_execution) if args.production_runtime_execution else None,
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
