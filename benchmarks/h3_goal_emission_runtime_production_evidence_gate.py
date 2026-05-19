"""H.3 runtime production evidence gate.

This artifact-only gate reads the controlled runtime executor report and optional
production evidence records. It turns missing production evidence into an
auditable gap report and never starts runtime, writes receipts, calls LLMs, or
mutates IEM/value state.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-runtime-production-evidence-gate:v1"
RUNTIME_EXECUTOR_SCHEMA_VERSION = "h3-goal-emission-runtime-executor:v1"
PRODUCTION_EVIDENCE_SCHEMA_VERSION = "h3-goal-emission-runtime-production-evidence:v1"
REQUIRED_PRODUCTION_EVIDENCE_KINDS = [
    "external_human_review_approval",
    "governance_runtime_execution_approval",
    "challenge_r2r_rollback_attestation",
    "activation_artifact_chain_attestation",
    "runtime_safety_envelope",
    "rollout_window_approval",
    "live_monitoring_attestation",
    "rollback_drill_attestation",
    "operator_oncall_ack",
    "kill_switch_attestation",
    "runtime_start_change_ticket",
    "runtime_start_dual_operator_ack",
    "runtime_start_final_monitoring_green",
    "runtime_start_final_kill_switch_check",
    "runtime_start_rollback_checkpoint",
    "runtime_start_audit_sink_ready",
]
PRODUCTION_EVIDENCE_COMMON_FIELDS = [
    "artifact_id",
    "goal_id",
    "evidence_kind",
    "reviewer",
    "reviewer_role",
    "source",
    "status",
    "attestation_ref",
]
PRODUCTION_EVIDENCE_KIND_REF_FIELDS = {
    "external_human_review_approval": "human_review_ref",
    "governance_runtime_execution_approval": "governance_ref",
    "challenge_r2r_rollback_attestation": "r2r_rollback_ref",
    "activation_artifact_chain_attestation": "activation_chain_ref",
    "runtime_safety_envelope": "runtime_safety_ref",
    "rollout_window_approval": "rollout_window_ref",
    "live_monitoring_attestation": "live_monitoring_ref",
    "rollback_drill_attestation": "rollback_drill_ref",
    "operator_oncall_ack": "operator_oncall_ref",
    "kill_switch_attestation": "kill_switch_ref",
    "runtime_start_change_ticket": "change_ticket_ref",
    "runtime_start_dual_operator_ack": "dual_operator_ack_ref",
    "runtime_start_final_monitoring_green": "final_monitoring_ref",
    "runtime_start_final_kill_switch_check": "final_kill_switch_ref",
    "runtime_start_rollback_checkpoint": "rollback_checkpoint_ref",
    "runtime_start_audit_sink_ready": "audit_sink_ref",
}
ACCEPTED_PRODUCTION_STATUSES = {
    "approved",
    "ready",
    "green",
    "armed",
    "acknowledged",
    "attested",
    "complete",
}
NON_PRODUCTION_SOURCE_TOKENS = ("fixture", "synthetic", "mock", "test", "local")


def build_h3_goal_emission_runtime_production_evidence_gate(
    *,
    runtime_executor_path: Path,
    agent_root: Path,
    production_evidence_path: Path | None = None,
) -> dict[str, Any]:
    runtime_executor_path = _resolve_path(runtime_executor_path, agent_root)
    production_evidence_path = _resolve_path(production_evidence_path, agent_root) if production_evidence_path else None
    checks: dict[str, bool] = {}
    failures: list[str] = []
    executor_report = _read_json(runtime_executor_path, failures)

    executor_readiness: dict[str, Any] = {}
    executor_boundary: dict[str, Any] = {}
    executor_surface: dict[str, Any] = {}
    receipts: list[dict[str, Any]] = []
    blocked_executor_packets: list[dict[str, Any]] = []
    if executor_report is None:
        _fail(checks, failures, "runtime_executor_present", f"missing H3 runtime executor report: {runtime_executor_path}")
    else:
        checks["runtime_executor_present"] = True
        _require_equal(
            "runtime_executor_schema_version",
            executor_report.get("schema_version"),
            RUNTIME_EXECUTOR_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("runtime_executor_passed", bool(executor_report.get("passed")), checks=checks, failures=failures)
        executor_readiness = _object(executor_report.get("readiness"))
        _require_executor_readiness(executor_readiness, checks=checks, failures=failures)
        executor_boundary = _object(executor_report.get("runtime_executor_boundary"))
        _require_executor_boundary(executor_boundary, checks=checks, failures=failures)
        executor_surface = _object(executor_report.get("runtime_executor_surface"))
        receipts = _record_list(executor_report.get("runtime_execution_receipts"))
        blocked_executor_packets = _record_list(executor_surface.get("blocked_runtime_execution_packets"))
        _require_receipt_shape(receipts, checks=checks, failures=failures)
        _require_blocked_packet_shape(blocked_executor_packets, checks=checks, failures=failures)

    production_records, production_payload = _load_production_evidence(production_evidence_path, failures)
    non_production_payload = _is_non_production_payload(production_payload, production_records)
    if production_evidence_path:
        checks["production_evidence_present"] = production_payload is not None
        if production_payload is not None:
            _require_equal(
                "production_evidence_schema_version",
                production_payload.get("schema_version"),
                PRODUCTION_EVIDENCE_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            _require_bool("production_evidence_records_present", bool(production_records), checks=checks, failures=failures)
            _require_bool("production_evidence_not_fixture_or_local", not non_production_payload, checks=checks, failures=failures)
            _require_production_record_shape(production_records, checks=checks, failures=failures)
            _require_bool(
                "production_evidence_auth_context_evidence_grade",
                _auth_contexts_evidence_grade(production_payload, production_records),
                checks=checks,
                failures=failures,
            )
    else:
        checks["production_evidence_optional_absent"] = True

    local_receipts = [receipt for receipt in receipts if receipt.get("execution_origin") == "local_controlled"]
    production_receipts = [receipt for receipt in receipts if receipt.get("execution_origin") == "production"]
    production_packets = [packet for packet in blocked_executor_packets if packet.get("execution_origin") == "production"]
    target_goal_ids = _ordered_goal_ids([*local_receipts, *production_packets])
    reviewed_packets: list[dict[str, Any]] = []
    evidence_gaps: list[dict[str, Any]] = []
    rejected_records: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        reviewed_packets, evidence_gaps, rejected_records = _evaluate_targets(
            target_goal_ids,
            local_receipts,
            production_packets,
            production_records,
        )

    metrics = {
        "target_goal_count": len(target_goal_ids),
        "local_controlled_runtime_receipt_count": len(local_receipts),
        "production_runtime_receipt_count": len(production_receipts),
        "production_origin_blocked_packet_count": len(production_packets),
        "production_evidence_record_count": len(production_records),
        "reviewed_production_evidence_packet_count": len(reviewed_packets),
        "production_evidence_gap_count": len(evidence_gaps),
        "rejected_production_evidence_record_count": len(rejected_records),
        "production_runtime_execution_ready_count": 0,
        "production_runtime_receipt_ready_count": 0,
        "llm_call_ready_count": 0,
        "external_system_mutation_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("production_receipts_absent", metrics["production_runtime_receipt_count"] == 0, checks=checks, failures=failures)
    _require_bool("production_runtime_execution_blocked", metrics["production_runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("external_mutations_blocked", metrics["external_system_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _evidence_decision(passed, local_receipts, production_packets, reviewed_packets, evidence_gaps)
    production_evidence_complete = passed and bool(reviewed_packets) and not evidence_gaps and not rejected_records
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "runtime_executor_path": str(runtime_executor_path),
        "production_evidence_path": str(production_evidence_path) if production_evidence_path else None,
        "checks": checks,
        "readiness": {
            "runtime_production_evidence_gate_evaluated": passed,
            "local_controlled_runtime_execution_receipts_present": bool(local_receipts),
            "production_origin_runtime_execution_packets_present": bool(production_packets),
            "production_evidence_complete": production_evidence_complete,
            "production_runtime_execution_ready": False,
            "production_runtime_receipt_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, local_receipts, production_packets, reviewed_packets, evidence_gaps),
        },
        "runtime_production_evidence_boundary": {
            "artifact_only": True,
            "production_evidence_review_allowed": production_evidence_complete,
            "local_controlled_evidence_counted_as_production": False,
            "production_runtime_execution_allowed": False,
            "production_runtime_receipt_allowed": False,
            "agent_loop_start_allowed": False,
            "llm_planning_allowed": False,
            "external_system_mutation_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_production_evidence_policy": {
            "requires_real_production_evidence": True,
            "required_production_evidence_kinds": REQUIRED_PRODUCTION_EVIDENCE_KINDS,
            "forbidden_evidence_sources": list(NON_PRODUCTION_SOURCE_TOKENS),
            "forbidden_auth_contexts": [
                "auth_method=demo_login",
                "evidence_allowed=false",
            ],
            "blocked_after_evidence_review": [
                "production_evidence_reviewed -> production_runtime_execution_allowed",
                "production_evidence_reviewed -> production_runtime_receipt_written",
                "production_evidence_reviewed -> external_system_mutation",
            ],
        },
        "runtime_production_evidence_surface": {
            "mode": "production_evidence_gap_review_only_no_runtime",
            "reviewed_production_evidence_packet_count": len(reviewed_packets),
            "reviewed_production_evidence_packets": reviewed_packets,
            "production_evidence_gap_count": len(evidence_gaps),
            "production_evidence_gaps": evidence_gaps,
            "rejected_production_evidence_record_count": len(rejected_records),
            "rejected_production_evidence_records": rejected_records,
            "local_controlled_non_production_receipts": local_receipts,
            "production_origin_blocked_executor_packets": production_packets,
        },
        "metrics": metrics,
        "evidence": {
            "executor_readiness": executor_readiness,
            "executor_boundary": executor_boundary,
            "executor_surface": executor_surface,
        },
        "non_claims": [
            "does_not_start_runtime_or_agent_loop",
            "does_not_write_runtime_execution_receipts",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_external_systems",
            "does_not_mutate_iem_or_normative_state",
            "does_not_count_local_controlled_receipts_as_production_evidence",
            "does_not_treat_complete_evidence_review_as_runtime_execution_permission",
        ],
    }


def _require_executor_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    known_decisions = {
        "runtime_execution_completed_with_receipts",
        "runtime_execution_blocked_pending_local_executor_ack",
        "runtime_execution_blocked_requires_production_executor_evidence",
        "runtime_execution_blocked_no_execution_packets",
    }
    _require_bool("runtime_executor_decision_known", readiness.get("decision") in known_decisions, checks=checks, failures=failures)
    _require_bool("runtime_executor_no_production_completion", readiness.get("production_runtime_execution_completed") is not True, checks=checks, failures=failures)


def _require_executor_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("executor_boundary_production_receipt_not_written", boundary.get("production_runtime_receipt_write_performed") is not True, checks=checks, failures=failures)
    _require_bool("executor_boundary_production_receipt_not_allowed", boundary.get("production_runtime_receipt_allowed") is not True, checks=checks, failures=failures)
    _require_bool("executor_boundary_agent_loop_not_started", boundary.get("agent_loop_started") is False, checks=checks, failures=failures)
    _require_bool("executor_boundary_llm_not_called", boundary.get("llm_called") is False, checks=checks, failures=failures)
    _require_bool("executor_boundary_external_not_mutated", boundary.get("external_system_mutated") is False, checks=checks, failures=failures)
    _require_bool("executor_boundary_iem_blocked", boundary.get("iem_value_mutation_allowed") is False, checks=checks, failures=failures)
    _require_bool("executor_boundary_normative_blocked", boundary.get("normative_local_mutation_allowed") is False, checks=checks, failures=failures)


def _require_receipt_shape(receipts: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not receipts:
        checks["runtime_execution_receipts_shape_valid"] = True
        return
    _require_bool("runtime_execution_receipt_origin_valid", all(receipt.get("execution_origin") in {"local_controlled", "production"} for receipt in receipts), checks=checks, failures=failures)
    _require_bool("runtime_execution_receipt_side_effects_safe", all(_receipt_side_effects_safe(_object(receipt.get("side_effects"))) for receipt in receipts), checks=checks, failures=failures)


def _require_blocked_packet_shape(packets: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not packets:
        checks["blocked_runtime_execution_packets_shape_valid"] = True
        return
    _require_bool("blocked_runtime_execution_packet_origin_valid", all(packet.get("execution_origin") in {"production", "local_controlled", "unknown"} for packet in packets), checks=checks, failures=failures)
    _require_bool("blocked_runtime_execution_packet_goal_present", all(bool(packet.get("goal_id")) for packet in packets), checks=checks, failures=failures)


def _require_production_record_shape(records: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("production_evidence_common_fields_present", all(_common_fields_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_kind_known", all(record.get("evidence_kind") in REQUIRED_PRODUCTION_EVIDENCE_KINDS for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_status_accepted", all(str(record.get("status") or "") in ACCEPTED_PRODUCTION_STATUSES for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_kind_refs_present", all(_kind_ref_present(record) for record in records), checks=checks, failures=failures)
    _require_bool("production_evidence_sources_production", all(not _non_production_source(record) for record in records), checks=checks, failures=failures)


def _evaluate_targets(
    goal_ids: list[str],
    local_receipts: list[dict[str, Any]],
    production_packets: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    reviewed_packets: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    local_goal_ids = {str(receipt.get("goal_id")) for receipt in local_receipts}
    production_goal_ids = {str(packet.get("goal_id")) for packet in production_packets}
    records_by_goal: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        goal_id = str(record.get("goal_id") or "")
        records_by_goal.setdefault(goal_id, []).append(record)
    for goal_id in goal_ids:
        goal_records = records_by_goal.get(goal_id, [])
        present_kinds = {str(record.get("evidence_kind")) for record in goal_records}
        missing = [kind for kind in REQUIRED_PRODUCTION_EVIDENCE_KINDS if kind not in present_kinds]
        if goal_id in local_goal_ids and goal_id not in production_goal_ids:
            gaps.append(
                {
                    "goal_id": goal_id,
                    "state": "production_evidence_gap",
                    "gap_reason": "local controlled execution receipt is not production evidence",
                    "missing_production_evidence_kinds": REQUIRED_PRODUCTION_EVIDENCE_KINDS,
                }
            )
            continue
        if missing:
            gaps.append(
                {
                    "goal_id": goal_id,
                    "state": "production_evidence_gap",
                    "gap_reason": "missing required production evidence records",
                    "missing_production_evidence_kinds": missing,
                }
            )
            continue
        reviewed_packets.append(
            {
                "production_evidence_packet_id": f"h3-runtime-production-evidence:{goal_id}",
                "goal_id": goal_id,
                "state": "production_evidence_reviewed_no_runtime_execution",
                "production_evidence_refs": {record["evidence_kind"]: record["artifact_id"] for record in goal_records},
                "gate_status": {
                    "production_evidence_complete": True,
                    "production_runtime_execution_ready": False,
                    "production_runtime_receipt_ready": False,
                },
            }
        )
    for record in records:
        goal_id = str(record.get("goal_id") or "")
        if goal_id not in set(goal_ids):
            rejected.append(
                {
                    "artifact_id": record.get("artifact_id"),
                    "goal_id": goal_id,
                    "evidence_kind": record.get("evidence_kind"),
                    "state": "production_evidence_rejected",
                    "rejected_reason": "evidence goal_id is not present in runtime executor targets",
                }
            )
    return reviewed_packets, gaps, rejected


def _evidence_decision(
    passed: bool,
    local_receipts: list[dict[str, Any]],
    production_packets: list[dict[str, Any]],
    reviewed_packets: list[dict[str, Any]],
    evidence_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_runtime_production_evidence_gate"
    if local_receipts and not production_packets:
        return "production_evidence_blocked_local_controlled_only"
    if reviewed_packets and not evidence_gaps:
        return "production_evidence_reviewed_no_runtime_execution"
    if production_packets and evidence_gaps:
        return "production_evidence_gap_detected"
    if production_packets:
        return "production_evidence_blocked_missing_artifacts"
    return "production_evidence_blocked_no_runtime_execution_targets"


def _allowed_scope(
    passed: bool,
    local_receipts: list[dict[str, Any]],
    production_packets: list[dict[str, Any]],
    reviewed_packets: list[dict[str, Any]],
    evidence_gaps: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not proceed until runtime executor and production evidence schemas are valid"
    if local_receipts and not production_packets:
        return "local controlled receipt may be audited, but it is not production execution evidence"
    if reviewed_packets and not evidence_gaps:
        return "production evidence reviewed only; runtime execution remains blocked"
    if production_packets:
        return "production-origin runtime execution packets remain blocked pending complete production evidence"
    return "no runtime execution targets available"


def _receipt_side_effects_safe(side_effects: dict[str, Any]) -> bool:
    return (
        side_effects.get("llm_calls", 0) == 0
        and side_effects.get("external_system_mutations", 0) == 0
        and side_effects.get("iem_mutations", 0) == 0
        and side_effects.get("normative_mutations", 0) == 0
    )


def _load_production_evidence(path: Path | None, failures: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if path is None:
        return [], None
    payload = _read_json(path, failures)
    if payload is None:
        return [], None
    return _record_list(payload.get("production_evidence_records") or payload.get("records")), payload


def _is_non_production_payload(payload: dict[str, Any] | None, records: list[dict[str, Any]]) -> bool:
    if payload is None:
        return False
    fixture_policy = _object(payload.get("fixture_policy"))
    if fixture_policy.get("synthetic_fixture") is True or fixture_policy.get("local_controlled_fixture") is True:
        return True
    return any(_non_production_source(record) for record in records)


def _common_fields_present(record: dict[str, Any]) -> bool:
    return all(bool(record.get(field)) for field in PRODUCTION_EVIDENCE_COMMON_FIELDS)


def _kind_ref_present(record: dict[str, Any]) -> bool:
    ref_field = PRODUCTION_EVIDENCE_KIND_REF_FIELDS.get(str(record.get("evidence_kind") or ""))
    return bool(ref_field and record.get(ref_field))


def _non_production_source(record: dict[str, Any]) -> bool:
    if record.get("synthetic_fixture") is True or record.get("local_controlled_fixture") is True:
        return True
    source = str(record.get("source") or "").lower()
    return any(token in source for token in NON_PRODUCTION_SOURCE_TOKENS)


def _auth_contexts_evidence_grade(payload: dict[str, Any], records: list[dict[str, Any]]) -> bool:
    contexts = [
        _object(payload.get("auth_context")),
        _object(payload.get("runtime_auth_context")),
    ]
    for record in records:
        contexts.append(_object(record.get("auth_context")))
        contexts.append(_object(record.get("runtime_auth_context")))
    return all(_auth_context_evidence_grade(context) for context in contexts if context)


def _auth_context_evidence_grade(context: dict[str, Any]) -> bool:
    auth_method = str(context.get("auth_method") or "").strip().lower()
    if auth_method == "demo_login":
        return False
    if context.get("evidence_allowed") is False:
        return False
    return True


def _ordered_goal_ids(records: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    goal_ids: list[str] = []
    for record in records:
        goal_id = str(record.get("goal_id") or "")
        if goal_id and goal_id not in seen:
            seen.add(goal_id)
            goal_ids.append(goal_id)
    return goal_ids


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


def _record_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


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
    parser.add_argument("--runtime-executor", required=True)
    parser.add_argument("--production-evidence", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_production_evidence_gate(
        runtime_executor_path=Path(args.runtime_executor),
        agent_root=agent_root,
        production_evidence_path=Path(args.production_evidence) if args.production_evidence else None,
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
