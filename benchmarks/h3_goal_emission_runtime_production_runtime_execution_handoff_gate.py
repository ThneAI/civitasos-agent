"""H.3 runtime production execution handoff gate.

This artifact-only layer reads the production executor permission gate and an
optional production runtime execution handoff artifact. It ensures runtime
handoff cannot be reviewed until executor permission has been independently
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
from benchmarks.h3_goal_emission_runtime_production_executor_permission_gate import (
    SCHEMA_VERSION as PRODUCTION_EXECUTOR_PERMISSION_GATE_SCHEMA_VERSION,
)


SCHEMA_VERSION = "h3-goal-emission-runtime-production-runtime-execution-handoff-gate:v1"
PRODUCTION_RUNTIME_EXECUTION_HANDOFF_SCHEMA_VERSION = "h3-goal-emission-runtime-production-runtime-execution-handoff:v1"
ACCEPTED_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_STATUSES = frozenset({"approved", "handoff_ready", "green", "ready"})
PRODUCTION_RUNTIME_EXECUTION_HANDOFF_REQUIRED_FIELDS = [
    "handoff_id",
    "goal_id",
    "runtime_executor",
    "runtime_executor_role",
    "source",
    "status",
    "attestation_ref",
    "executor_permission_ref",
    "executor_permission_sha256",
    "change_ticket_ref",
    "dual_operator_ack_ref",
    "kill_switch_ref",
    "rollback_checkpoint_ref",
    "monitoring_green_ref",
    "audit_sink_ref",
    "runtime_window_ref",
    "receipt_sink_ref",
]


def build_h3_goal_emission_runtime_production_runtime_execution_handoff_gate(
    *,
    production_executor_permission_gate_path: Path,
    agent_root: Path,
    production_runtime_execution_handoff_path: Path | None = None,
) -> dict[str, Any]:
    production_executor_permission_gate_path = _resolve_path(production_executor_permission_gate_path, agent_root)
    production_runtime_execution_handoff_path = (
        _resolve_path(production_runtime_execution_handoff_path, agent_root)
        if production_runtime_execution_handoff_path
        else None
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    permission_gate_report = _read_json(production_executor_permission_gate_path, failures)

    permission_readiness: dict[str, Any] = {}
    permission_boundary: dict[str, Any] = {}
    permission_gaps: list[dict[str, Any]] = []
    permission_summary: dict[str, Any] = {}
    if permission_gate_report is None:
        _fail(
            checks,
            failures,
            "production_executor_permission_gate_present",
            f"missing H3 runtime production executor permission gate: {production_executor_permission_gate_path}",
        )
    else:
        checks["production_executor_permission_gate_present"] = True
        _require_equal(
            "production_executor_permission_gate_schema_version",
            permission_gate_report.get("schema_version"),
            PRODUCTION_EXECUTOR_PERMISSION_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("production_executor_permission_gate_passed", bool(permission_gate_report.get("passed")), checks=checks, failures=failures)
        permission_readiness = _object(permission_gate_report.get("readiness"))
        _require_permission_readiness(permission_readiness, checks=checks, failures=failures)
        permission_boundary = _object(permission_gate_report.get("runtime_production_executor_permission_boundary"))
        _require_permission_boundary(permission_boundary, checks=checks, failures=failures)
        permission_surface = _object(permission_gate_report.get("runtime_production_executor_permission_surface"))
        _require_equal(
            "production_executor_permission_surface_mode",
            permission_surface.get("mode"),
            "production_executor_permission_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        permission_gaps = _record_list(permission_surface.get("production_executor_permission_gaps"))
        permission_summary = _object(permission_surface.get("production_executor_permission_summary"))
        _require_permission_surface(permission_summary, permission_gaps, checks=checks, failures=failures)
        _require_non_claims(_record_text_list(permission_gate_report.get("non_claims")), checks=checks, failures=failures)

    upstream_decision = str(permission_readiness.get("decision") or "")
    permission_reviewed = _permission_reviewed(upstream_decision, permission_summary, permission_gaps)
    permission_targets_present = bool(permission_summary or permission_gaps)
    handoff_records: list[dict[str, Any]] = []
    handoff_payload: dict[str, Any] | None = None
    handoff_sha256 = ""
    if production_runtime_execution_handoff_path:
        handoff_payload, handoff_sha256 = _read_json_with_sha256(production_runtime_execution_handoff_path, failures)
        checks["production_runtime_execution_handoff_artifact_present"] = handoff_payload is not None
        if handoff_payload is not None:
            _require_bool("production_runtime_execution_handoff_requires_permission_review", permission_reviewed, checks=checks, failures=failures)
            _require_equal(
                "production_runtime_execution_handoff_schema_version",
                handoff_payload.get("schema_version"),
                PRODUCTION_RUNTIME_EXECUTION_HANDOFF_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            handoff_records = _record_list(handoff_payload.get("production_runtime_execution_handoff_records") or handoff_payload.get("handoff_records") or handoff_payload.get("records"))
            _require_bool("production_runtime_execution_handoff_records_present", bool(handoff_records), checks=checks, failures=failures)
            _require_handoff_record_shape(handoff_records, permission_summary, checks=checks, failures=failures)
    else:
        checks["production_runtime_execution_handoff_optional_absent"] = True

    handoff_summary: dict[str, Any] = {}
    handoff_gaps: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        handoff_summary, handoff_gaps = _build_handoff_summary(
            handoff_path=production_runtime_execution_handoff_path,
            handoff_sha256=handoff_sha256,
            permission_reviewed=permission_reviewed,
            permission_summary=permission_summary,
            permission_gaps=permission_gaps,
            handoff_records=handoff_records,
        )

    metrics = {
        "production_executor_permission_gap_count": len(permission_gaps),
        "production_executor_permission_reviewed_count": int(bool(permission_summary)),
        "production_runtime_execution_handoff_record_count": len(handoff_records),
        "production_runtime_execution_handoff_gap_count": len(handoff_gaps),
        "production_runtime_execution_handoff_ready_count": 0,
        "production_runtime_execution_ready_count": 0,
        "production_runtime_receipt_ready_count": 0,
        "agent_loop_start_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("production_runtime_execution_handoff_not_granted_by_gate", metrics["production_runtime_execution_handoff_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_blocked", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_receipt_blocked", metrics["production_runtime_receipt_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("agent_loop_start_blocked", metrics["agent_loop_start_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _handoff_decision(
        passed=passed,
        permission_targets_present=permission_targets_present,
        permission_reviewed=permission_reviewed,
        handoff_path_present=bool(production_runtime_execution_handoff_path),
        handoff_summary=handoff_summary,
        handoff_gaps=handoff_gaps,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "production_executor_permission_gate_path": str(production_executor_permission_gate_path),
        "production_runtime_execution_handoff_path": str(production_runtime_execution_handoff_path) if production_runtime_execution_handoff_path else None,
        "checks": checks,
        "readiness": {
            "production_runtime_execution_handoff_evaluated": passed,
            "production_runtime_execution_handoff_present": passed and bool(handoff_summary),
            "production_runtime_execution_handoff_complete": passed and bool(handoff_summary) and not handoff_gaps,
            "production_runtime_execution_handoff_ready": False,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "upstream_executor_permission_decision": upstream_decision,
            "allowed_scope": _allowed_scope(
                passed=passed,
                permission_targets_present=permission_targets_present,
                permission_reviewed=permission_reviewed,
                handoff_path_present=bool(production_runtime_execution_handoff_path),
                handoff_summary=handoff_summary,
                handoff_gaps=handoff_gaps,
            ),
        },
        "runtime_production_execution_handoff_boundary": {
            "artifact_only": True,
            "production_runtime_execution_handoff_review_allowed": passed,
            "production_runtime_execution_handoff_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_runtime_receipt_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_execution_handoff_policy": {
            "executor_permission_schema": PRODUCTION_EXECUTOR_PERMISSION_GATE_SCHEMA_VERSION,
            "runtime_execution_handoff_schema": PRODUCTION_RUNTIME_EXECUTION_HANDOFF_SCHEMA_VERSION,
            "required_runtime_execution_handoff_fields": PRODUCTION_RUNTIME_EXECUTION_HANDOFF_REQUIRED_FIELDS,
            "accepted_runtime_execution_handoff_statuses": sorted(ACCEPTED_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_STATUSES),
            "forbidden_runtime_execution_handoff_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "required_executor_permission_decision": "production_executor_permission_reviewed_no_runtime_execution",
            "blocked_after_runtime_execution_handoff_review": [
                "runtime_execution_handoff_reviewed -> runtime_started_by_this_gate",
                "runtime_execution_handoff_reviewed -> production_runtime_execution_receipt_written",
                "runtime_execution_handoff_reviewed -> agent_loop_started",
            ],
        },
        "runtime_production_execution_handoff_surface": {
            "mode": "production_runtime_execution_handoff_review_only_no_runtime",
            "production_runtime_execution_handoff_summary": handoff_summary,
            "production_runtime_execution_handoff_gap_count": len(handoff_gaps),
            "production_runtime_execution_handoff_gaps": handoff_gaps,
            "source_executor_permission_decision": upstream_decision,
            "source_production_executor_permission_summary": permission_summary,
            "source_production_executor_permission_gaps": permission_gaps,
        },
        "metrics": metrics,
        "evidence": {
            "production_executor_permission_readiness": permission_readiness,
            "production_executor_permission_boundary": permission_boundary,
        },
        "non_claims": [
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_runtime_execution_handoff_review_as_runtime_execution_permission",
        ],
    }


def _require_permission_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "blocked_before_runtime_production_executor_permission",
        "production_executor_permission_not_required_no_alignment_targets",
        "production_executor_permission_blocked_upstream_goal_alignment",
        "production_executor_permission_blocked_pending_permission_artifact",
        "production_executor_permission_gap_detected",
        "production_executor_permission_reviewed_no_runtime_execution",
    }
    _require_bool("production_executor_permission_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("production_executor_permission_runtime_execution_blocked", readiness.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("production_executor_permission_runtime_receipt_blocked", readiness.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)


def _require_permission_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_executor_permission_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in (
        "production_executor_permission_allowed",
        "production_runtime_execution_allowed",
        "production_runtime_receipt_allowed",
        "agent_loop_start_allowed",
        "llm_planning_allowed",
        "external_system_mutation_allowed",
        "iem_value_mutation_allowed",
        "normative_local_mutation_allowed",
    ):
        _require_bool(f"production_executor_permission_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_permission_surface(summary: dict[str, Any], gaps: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_executor_permission_gap_or_summary_present", bool(summary or gaps), checks=checks, failures=failures)
    if summary:
        _require_equal(
            "production_executor_permission_summary_state",
            summary.get("state"),
            "production_executor_permission_reviewed_no_runtime_execution",
            checks=checks,
            failures=failures,
        )
        _require_bool("production_executor_permission_summary_permission_blocked", summary.get("production_executor_permission_ready") is False, checks=checks, failures=failures)
        _require_bool("production_executor_permission_summary_execution_blocked", summary.get("production_runtime_execution_ready") is False, checks=checks, failures=failures)
        _require_bool("production_executor_permission_summary_receipt_blocked", summary.get("production_runtime_receipt_ready") is False, checks=checks, failures=failures)
    if gaps:
        _require_bool("production_executor_permission_gaps_state_valid", all(str(gap.get("state") or "").startswith("production_executor_permission") for gap in gaps), checks=checks, failures=failures)


def _require_non_claims(non_claims: list[str], *, checks: dict[str, bool], failures: list[str]) -> None:
    required = {
        "does_not_grant_production_executor_permission",
        "does_not_treat_executor_permission_review_as_runtime_execution_permission",
        "does_not_mutate_iem_or_normative_state",
    }
    _require_bool("production_executor_permission_non_claims_preserved", required.issubset(set(non_claims)), checks=checks, failures=failures)


def _require_handoff_record_shape(records: list[dict[str, Any]], permission_summary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_runtime_execution_handoff_common_fields_present", all(_handoff_fields_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_handoff_status_accepted", all(str(record.get("status") or "") in ACCEPTED_PRODUCTION_RUNTIME_EXECUTION_HANDOFF_STATUSES for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_handoff_sources_production", all(not _non_production_source(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_handoff_template_flags_absent", all(not record.get("template_only") and record.get("valid_production_runtime_execution_handoff") is not False for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_handoff_record_runtime_flags_blocked", all(record.get("production_runtime_execution_handoff_allowed") is not True and record.get("production_runtime_execution_allowed") is not True and record.get("production_runtime_receipt_allowed") is not True for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_handoff_records_match_permitted_goals", all(_record_matches_permitted_goal(record, permission_summary) for record in records), checks=checks, failures=failures)
    _require_bool("production_runtime_execution_handoff_records_match_permission_sha256", all(str(record.get("executor_permission_sha256") or "") == str(permission_summary.get("permission_sha256") or "") for record in records), checks=checks, failures=failures)


def _build_handoff_summary(
    *,
    handoff_path: Path | None,
    handoff_sha256: str,
    permission_reviewed: bool,
    permission_summary: dict[str, Any],
    permission_gaps: list[dict[str, Any]],
    handoff_records: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not permission_reviewed:
        return {}, _permission_blocking_gaps(permission_gaps)
    if handoff_path is None:
        return {}, _handoff_missing_gaps(permission_summary, handoff_records, "production runtime execution handoff artifact is absent")
    missing_gaps = _handoff_missing_gaps(permission_summary, handoff_records, "submitted runtime handoff artifact is missing permitted goal handoff")
    handoff_goal_ids = sorted({str(record.get("goal_id") or "") for record in handoff_records if record.get("goal_id")})
    summary = {
        "state": "production_runtime_execution_handoff_reviewed_no_runtime_execution",
        "handoff_path": str(handoff_path),
        "handoff_sha256": handoff_sha256,
        "handoff_schema_version": PRODUCTION_RUNTIME_EXECUTION_HANDOFF_SCHEMA_VERSION,
        "handoff_record_count": len(handoff_records),
        "handoff_goal_ids": handoff_goal_ids,
        "handoff_refs": [str(record.get("handoff_id") or "") for record in handoff_records],
        "source_executor_permission_sha256": str(permission_summary.get("permission_sha256") or ""),
        "production_runtime_execution_handoff_ready": False,
        "production_runtime_execution_ready": False,
        "production_runtime_receipt_ready": False,
    }
    return summary, missing_gaps


def _handoff_decision(
    *,
    passed: bool,
    permission_targets_present: bool,
    permission_reviewed: bool,
    handoff_path_present: bool,
    handoff_summary: dict[str, Any],
    handoff_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_runtime_production_execution_handoff"
    if not permission_targets_present:
        return "production_runtime_execution_handoff_not_required_no_permission_targets"
    if not permission_reviewed:
        return "production_runtime_execution_handoff_blocked_upstream_executor_permission"
    if not handoff_path_present:
        return "production_runtime_execution_handoff_blocked_pending_handoff_artifact"
    if handoff_summary and handoff_gaps:
        return "production_runtime_execution_handoff_gap_detected"
    return "production_runtime_execution_handoff_reviewed_no_runtime_execution"


def _allowed_scope(
    *,
    passed: bool,
    permission_targets_present: bool,
    permission_reviewed: bool,
    handoff_path_present: bool,
    handoff_summary: dict[str, Any],
    handoff_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not review production runtime execution handoff until executor permission and handoff schemas are valid"
    if not permission_targets_present:
        return "no production runtime execution handoff target is available"
    if not permission_reviewed:
        return "executor permission is not reviewed; runtime execution remains blocked"
    if not handoff_path_present:
        return "executor permission is reviewed, but runtime execution handoff artifact is absent; runtime execution remains blocked"
    if handoff_summary and handoff_gaps:
        return "runtime handoff artifact has missing permitted goal handoffs; runtime execution remains blocked"
    return "runtime execution handoff reviewed only; runtime execution remains blocked"


def _permission_reviewed(upstream_decision: str, summary: dict[str, Any], gaps: list[dict[str, Any]]) -> bool:
    return upstream_decision == "production_executor_permission_reviewed_no_runtime_execution" and bool(summary) and not gaps


def _permission_blocking_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not gaps:
        return []
    return [
        {
            "goal_id": gap.get("goal_id"),
            "state": "production_runtime_execution_handoff_blocked_by_executor_permission_gap",
            "gap_reason": "production executor permission has not been reviewed",
            "source_permission_gap_reason": gap.get("gap_reason"),
        }
        for gap in gaps
    ]


def _handoff_missing_gaps(summary: dict[str, Any], records: list[dict[str, Any]], reason: str) -> list[dict[str, Any]]:
    permitted_goal_ids = [str(goal_id) for goal_id in summary.get("permitted_goal_ids") or [] if goal_id]
    handoff_goal_ids = {str(record.get("goal_id") or "") for record in records}
    missing_goal_ids = [goal_id for goal_id in permitted_goal_ids if goal_id not in handoff_goal_ids]
    if not missing_goal_ids:
        return []
    return [
        {
            "state": "production_runtime_execution_handoff_gap",
            "gap_reason": reason,
            "missing_handoff_goal_ids": missing_goal_ids,
            "source_executor_permission_sha256": summary.get("permission_sha256"),
        }
    ]


def _handoff_fields_present(record: dict[str, Any]) -> bool:
    return all(bool(record.get(field)) for field in PRODUCTION_RUNTIME_EXECUTION_HANDOFF_REQUIRED_FIELDS)


def _record_matches_permitted_goal(record: dict[str, Any], summary: dict[str, Any]) -> bool:
    return str(record.get("goal_id") or "") in {str(goal_id) for goal_id in summary.get("permitted_goal_ids") or []}


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
    parser.add_argument("--production-executor-permission-gate", required=True)
    parser.add_argument("--production-runtime-execution-handoff", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_runtime_execution_handoff_gate(
        production_executor_permission_gate_path=Path(args.production_executor_permission_gate),
        agent_root=agent_root,
        production_runtime_execution_handoff_path=Path(args.production_runtime_execution_handoff) if args.production_runtime_execution_handoff else None,
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