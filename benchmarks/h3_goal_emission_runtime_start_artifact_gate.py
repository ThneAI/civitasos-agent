"""H.3 goal emission runtime start artifact gate.

This artifact-only gate reads H.3 runtime start review packets and optional
runtime start artifact records. It validates final runtime-start control
completeness and provenance, but it never starts runtime, emits goals,
generates executable plans, calls LLMs, or mutates IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-runtime-start-artifact-gate:v1"
RUNTIME_START_GATE_SCHEMA_VERSION = "h3-goal-emission-runtime-start-gate:v1"
RUNTIME_START_ARTIFACTS_SCHEMA_VERSION = "h3-goal-emission-runtime-start-artifacts:v1"
REQUIRED_RUNTIME_START_CONTROL_KINDS = [
    "runtime_start_change_ticket",
    "runtime_start_dual_operator_ack",
    "runtime_start_final_monitoring_green",
    "runtime_start_final_kill_switch_check",
    "runtime_start_rollback_checkpoint",
    "runtime_start_audit_sink_ready",
]
RUNTIME_START_BLOCKING_FLAGS = [
    "runtime_start_allowed",
    "runtime_activation_allowed",
    "runtime_execution_allowed",
    "activation_allowed",
    "goal_emission_allowed",
    "emitted_goal_allowed",
    "executable_plan_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]
EXECUTION_POLICY_FLAGS = [
    "goal_emission_allowed",
    "executable_plan_allowed",
    "runtime_execution_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]
PRODUCTION_START_COMMON_FIELDS = [
    "artifact_id",
    "reviewer",
    "reviewer_role",
    "source",
    "attestation_ref",
]
PRODUCTION_START_KIND_REF_FIELDS = {
    "runtime_start_change_ticket": "change_ticket_ref",
    "runtime_start_dual_operator_ack": "dual_operator_ack_ref",
    "runtime_start_final_monitoring_green": "final_monitoring_ref",
    "runtime_start_final_kill_switch_check": "final_kill_switch_ref",
    "runtime_start_rollback_checkpoint": "rollback_checkpoint_ref",
    "runtime_start_audit_sink_ready": "audit_sink_ref",
}


def build_h3_goal_emission_runtime_start_artifact_gate(
    *,
    runtime_start_gate_path: Path,
    agent_root: Path,
    runtime_start_artifacts_path: Path | None = None,
) -> dict[str, Any]:
    runtime_start_gate_path = _resolve_path(runtime_start_gate_path, agent_root)
    runtime_start_artifacts_path = (
        _resolve_path(runtime_start_artifacts_path, agent_root)
        if runtime_start_artifacts_path
        else None
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    start_gate = _read_json(runtime_start_gate_path, failures)

    start_readiness: dict[str, Any] = {}
    start_boundary: dict[str, Any] = {}
    start_packets: list[dict[str, Any]] = []
    blocked_start_candidates: list[dict[str, Any]] = []
    if start_gate is None:
        _fail(
            checks,
            failures,
            "runtime_start_gate_present",
            f"missing H3 runtime start gate: {runtime_start_gate_path}",
        )
    else:
        checks["runtime_start_gate_present"] = True
        _require_equal(
            "runtime_start_gate_schema_version",
            start_gate.get("schema_version"),
            RUNTIME_START_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("runtime_start_gate_passed", bool(start_gate.get("passed")), checks=checks, failures=failures)
        start_readiness = _object(start_gate.get("readiness"))
        _require_start_readiness(start_readiness, checks=checks, failures=failures)
        start_boundary = _object(start_gate.get("runtime_start_boundary"))
        _require_start_boundary(start_boundary, checks=checks, failures=failures)
        surface = _object(start_gate.get("runtime_start_surface"))
        _require_equal(
            "runtime_start_surface_mode",
            surface.get("mode"),
            "runtime_start_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        start_packets = _record_list(surface.get("runtime_start_review_packets"))
        blocked_start_candidates = _record_list(surface.get("blocked_runtime_start_candidates"))
        _require_start_packet_consistency(start_readiness, start_packets, blocked_start_candidates, checks=checks, failures=failures)
        _require_start_packet_shape(start_packets, checks=checks, failures=failures)
        _require_blocked_start_shape(blocked_start_candidates, checks=checks, failures=failures)

    start_artifacts, start_artifact_payload = _load_runtime_start_artifacts(runtime_start_artifacts_path, failures)
    synthetic_start_fixture = _is_synthetic_start_fixture(start_artifact_payload, start_artifacts)
    local_controlled_start_fixture = _is_local_controlled_start_fixture(start_artifact_payload, start_artifacts)
    if runtime_start_artifacts_path:
        checks["runtime_start_artifacts_present"] = start_artifact_payload is not None
        if start_artifact_payload is not None:
            _require_equal(
                "runtime_start_artifacts_schema_version",
                start_artifact_payload.get("schema_version"),
                RUNTIME_START_ARTIFACTS_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            _require_bool("runtime_start_artifacts_records_present", bool(start_artifacts), checks=checks, failures=failures)
            _require_start_artifact_shape(
                start_artifacts,
                synthetic_start_fixture=synthetic_start_fixture,
                local_controlled_start_fixture=local_controlled_start_fixture,
                checks=checks,
                failures=failures,
            )
    else:
        checks["runtime_start_artifacts_optional_absent"] = True

    reviewed_packets: list[dict[str, Any]] = []
    pending_packets: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        reviewed_packets, pending_packets = _evaluate_start_packets(
            start_packets,
            start_artifacts,
            synthetic_start_fixture,
            local_controlled_start_fixture,
        )
    elif start_packets:
        pending_packets = [_pending_packet(packet, {}) for packet in start_packets]

    metrics = {
        "runtime_start_review_packet_count": len(start_packets),
        "runtime_start_artifact_record_count": len(start_artifacts),
        "reviewed_runtime_start_packet_count": len(reviewed_packets),
        "pending_runtime_start_packet_count": len(pending_packets),
        "blocked_runtime_start_candidate_count": len(blocked_start_candidates),
        "synthetic_runtime_start_fixture_count": 1 if synthetic_start_fixture else 0,
        "local_controlled_runtime_start_fixture_count": 1 if local_controlled_start_fixture else 0,
        "runtime_start_ready_count": 0,
        "runtime_activation_ready_count": 0,
        "runtime_execution_ready_count": 0,
        "activation_ready_count": 0,
        "emitted_goal_count": 0,
        "executable_goal_ready_count": 0,
    }
    _require_bool("runtime_start_blocked", metrics["runtime_start_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_activation_blocked", metrics["runtime_activation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_execution_blocked", metrics["runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("activation_blocked", metrics["activation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("goal_emission_blocked", metrics["emitted_goal_count"] == 0, checks=checks, failures=failures)
    _require_bool("execution_blocked", metrics["executable_goal_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _artifact_decision(
        passed,
        start_packets,
        reviewed_packets,
        pending_packets,
        blocked_start_candidates,
        synthetic_start_fixture,
        local_controlled_start_fixture,
    )
    production_start_complete = passed and bool(reviewed_packets) and not pending_packets and not synthetic_start_fixture and not local_controlled_start_fixture
    local_start_complete = passed and bool(reviewed_packets) and not pending_packets and local_controlled_start_fixture
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "runtime_start_gate_path": str(runtime_start_gate_path),
        "runtime_start_artifacts_path": str(runtime_start_artifacts_path) if runtime_start_artifacts_path else None,
        "checks": checks,
        "readiness": {
            "runtime_start_artifact_gate_evaluated": passed,
            "runtime_start_artifacts_complete": passed and bool(reviewed_packets) and not pending_packets,
            "production_runtime_start_artifacts_complete": production_start_complete,
            "synthetic_runtime_start_artifacts_complete": passed and bool(reviewed_packets) and not pending_packets and synthetic_start_fixture,
            "local_controlled_runtime_start_artifacts_complete": local_start_complete,
            "runtime_start_ready": False,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
            "activation_ready": False,
            "emitted_goal_ready": False,
            "executable_goal_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, reviewed_packets, pending_packets, blocked_start_candidates),
        },
        "runtime_start_artifact_boundary": {
            "artifact_only": True,
            "runtime_start_artifact_review_allowed": passed and bool(reviewed_packets),
            "production_runtime_start_artifact_review_allowed": production_start_complete,
            "synthetic_runtime_start_artifact_surface_allowed": passed and bool(reviewed_packets) and synthetic_start_fixture,
            "local_controlled_runtime_start_artifact_surface_allowed": local_start_complete,
            "runtime_start_allowed": False,
            "runtime_activation_allowed": False,
            "runtime_execution_allowed": False,
            "activation_allowed": False,
            "goal_emission_allowed": False,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_start_artifact_policy": {
            "required_runtime_start_control_kinds": REQUIRED_RUNTIME_START_CONTROL_KINDS,
            "accepted_runtime_start_artifacts": {
                "runtime_start_change_ticket": "approved_for_runtime_start",
                "runtime_start_dual_operator_ack": "acknowledged",
                "runtime_start_final_monitoring_green": "green",
                "runtime_start_final_kill_switch_check": "armed",
                "runtime_start_rollback_checkpoint": "ready",
                "runtime_start_audit_sink_ready": "ready",
            },
            "production_start_common_fields": PRODUCTION_START_COMMON_FIELDS,
            "production_start_kind_ref_fields": PRODUCTION_START_KIND_REF_FIELDS,
            "blocked_after_artifact_review": [
                "runtime_start_artifacts_reviewed -> runtime_start_allowed",
                "runtime_start_allowed -> runtime_execution_started",
                "runtime_execution_started -> executable_plan_execution",
            ],
        },
        "runtime_start_artifact_surface": {
            "mode": "runtime_start_artifacts_review_only_no_runtime",
            "reviewed_runtime_start_packet_count": len(reviewed_packets),
            "reviewed_runtime_start_packets": reviewed_packets,
            "pending_runtime_start_packet_count": len(pending_packets),
            "pending_runtime_start_packets": pending_packets,
            "blocked_runtime_start_candidate_count": len(blocked_start_candidates),
            "blocked_runtime_start_candidates": blocked_start_candidates,
            "runtime_executions": [],
            "emitted_goals": [],
        },
        "metrics": metrics,
        "evidence": {
            "runtime_start_readiness": start_readiness,
            "runtime_start_boundary": start_boundary,
            "runtime_start_artifact_summary": _artifact_summary(start_artifacts),
            "synthetic_runtime_start_fixture": synthetic_start_fixture,
            "local_controlled_runtime_start_fixture": local_controlled_start_fixture,
        },
        "non_claims": [
            "does_not_activate_goal_emission",
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_runtime_start_artifact_review_as_runtime_start",
            "does_not_treat_missing_runtime_start_artifacts_as_runtime_start",
            "does_not_treat_synthetic_fixture_as_production_runtime_start",
            "does_not_treat_local_controlled_fixture_as_production_runtime_start",
        ],
    }


def _require_start_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    valid_decisions = {
        "runtime_start_blocked_no_reviewed_runtime_activation_artifacts",
        "runtime_start_blocked_pending_runtime_activation_artifacts",
        "runtime_start_blocked_synthetic_or_blocked_runtime_activation",
        "runtime_start_review_packets_ready_no_runtime",
    }
    _require_bool("runtime_start_gate_decision_known", str(readiness.get("decision") or "") in valid_decisions, checks=checks, failures=failures)
    _require_bool("runtime_start_gate_runtime_start_blocked", readiness.get("runtime_start_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_start_gate_runtime_activation_blocked", readiness.get("runtime_activation_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_start_gate_runtime_execution_blocked", readiness.get("runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_start_gate_activation_blocked", readiness.get("activation_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_start_gate_emitted_goal_blocked", readiness.get("emitted_goal_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_start_gate_executable_goal_blocked", readiness.get("executable_goal_ready") is False, checks=checks, failures=failures)


def _require_start_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("runtime_start_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in RUNTIME_START_BLOCKING_FLAGS:
        _require_bool(f"runtime_start_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_start_packet_consistency(
    readiness: dict[str, Any],
    packets: list[dict[str, Any]],
    blocked_candidates: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    decision = str(readiness.get("decision") or "")
    review_ready = decision == "runtime_start_review_packets_ready_no_runtime"
    _require_bool("runtime_start_packet_decision_consistent", bool(packets) == review_ready, checks=checks, failures=failures)
    if review_ready:
        _require_bool("runtime_start_packet_readiness_consistent", readiness.get("runtime_start_review_packets_ready") is True, checks=checks, failures=failures)
    if decision in {"runtime_start_blocked_pending_runtime_activation_artifacts", "runtime_start_blocked_synthetic_or_blocked_runtime_activation"}:
        _require_bool("blocked_runtime_start_candidate_decision_consistent", bool(blocked_candidates), checks=checks, failures=failures)


def _require_start_packet_shape(packets: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not packets:
        checks["runtime_start_packets_optional_or_present"] = True
        return
    _require_bool("runtime_start_packet_state_valid", all(packet.get("state") == "runtime_start_review_required" for packet in packets), checks=checks, failures=failures)
    _require_bool("runtime_start_packet_controls_declared", all(_required_start_controls_declared(packet) for packet in packets), checks=checks, failures=failures)
    _require_bool("runtime_start_packet_execution_disabled", all(_execution_policy_disabled(_object(packet.get("execution_policy"))) for packet in packets), checks=checks, failures=failures)
    _require_bool("runtime_start_packet_runtime_blocked", all(_packet_runtime_blocked(packet) for packet in packets), checks=checks, failures=failures)


def _require_blocked_start_shape(candidates: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not candidates:
        checks["blocked_runtime_start_candidates_optional_or_present"] = True
        return
    _require_bool("blocked_runtime_start_candidate_state_valid", all(candidate.get("state") == "runtime_start_blocked" for candidate in candidates), checks=checks, failures=failures)


def _require_start_artifact_shape(
    records: list[dict[str, Any]],
    *,
    synthetic_start_fixture: bool,
    local_controlled_start_fixture: bool,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("runtime_start_artifact_kinds_known", all(str(record.get("artifact_kind") or "") in REQUIRED_RUNTIME_START_CONTROL_KINDS for record in records), checks=checks, failures=failures)
    _require_bool("runtime_start_artifact_execution_disabled", all(_start_record_execution_disabled(record) for record in records), checks=checks, failures=failures)
    _require_bool("runtime_start_artifact_targets_present", all(str(record.get("runtime_start_packet_id") or record.get("goal_id") or "").strip() for record in records), checks=checks, failures=failures)
    if synthetic_start_fixture:
        _require_bool("runtime_start_artifact_synthetic_fixture_marked", all(record.get("synthetic_fixture") is True for record in records), checks=checks, failures=failures)
        return
    _require_bool("runtime_start_artifact_not_synthetic_fixture", all(record.get("synthetic_fixture") is not True for record in records), checks=checks, failures=failures)
    _require_bool("runtime_start_artifact_common_provenance_present", all(_string_fields_present(record, PRODUCTION_START_COMMON_FIELDS) for record in records), checks=checks, failures=failures)
    _require_bool("runtime_start_artifact_kind_specific_provenance_present", all(_kind_specific_ref_present(record) for record in records), checks=checks, failures=failures)
    if local_controlled_start_fixture:
        _require_bool("runtime_start_artifact_local_controlled_source_marked", all(_local_controlled_source(record) for record in records), checks=checks, failures=failures)
        return
    _require_bool("runtime_start_artifact_source_not_fixture", all(_production_source_eligible(record) for record in records), checks=checks, failures=failures)


def _load_runtime_start_artifacts(path: Path | None, failures: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if path is None:
        return [], None
    payload = _read_json(path, failures)
    if payload is None:
        return [], None
    records = payload.get("records")
    if not isinstance(records, list):
        failures.append(f"runtime start artifact file missing records array: {path}")
        return [], payload
    return [record for record in records if isinstance(record, dict)], payload


def _evaluate_start_packets(
    packets: list[dict[str, Any]],
    records: list[dict[str, Any]],
    synthetic_start_fixture: bool,
    local_controlled_start_fixture: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    reviewed: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for packet in packets:
        artifacts = _artifacts_for_packet(packet, records)
        status = _start_artifact_status(artifacts)
        if all(status.values()):
            reviewed.append(_reviewed_packet(packet, artifacts, synthetic_start_fixture, local_controlled_start_fixture))
        else:
            pending.append(_pending_packet(packet, status))
    return reviewed, pending


def _start_artifact_status(artifacts: dict[str, dict[str, Any]]) -> dict[str, bool]:
    return {kind: _artifact_accepts_runtime_start(kind, artifacts.get(kind)) for kind in REQUIRED_RUNTIME_START_CONTROL_KINDS}


def _artifacts_for_packet(packet: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    packet_id = str(packet.get("runtime_start_packet_id") or "")
    goal_id = str(packet.get("goal_id") or "")
    out: dict[str, dict[str, Any]] = {}
    for record in records:
        record_packet_id = str(record.get("runtime_start_packet_id") or "")
        record_goal_id = str(record.get("goal_id") or "")
        if record_packet_id != packet_id and record_goal_id != goal_id:
            continue
        artifact_kind = str(record.get("artifact_kind") or "")
        if artifact_kind in REQUIRED_RUNTIME_START_CONTROL_KINDS and artifact_kind not in out:
            out[artifact_kind] = record
    return out


def _artifact_accepts_runtime_start(kind: str, record: dict[str, Any] | None) -> bool:
    if not isinstance(record, dict):
        return False
    if kind == "runtime_start_change_ticket":
        return record.get("decision") == "approved_for_runtime_start"
    if kind == "runtime_start_dual_operator_ack":
        return record.get("status") == "acknowledged"
    if kind == "runtime_start_final_monitoring_green":
        return record.get("status") == "green"
    if kind == "runtime_start_final_kill_switch_check":
        return record.get("status") == "armed"
    if kind == "runtime_start_rollback_checkpoint":
        return record.get("status") == "ready"
    if kind == "runtime_start_audit_sink_ready":
        return record.get("status") == "ready"
    return False


def _reviewed_packet(
    packet: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    synthetic_start_fixture: bool,
    local_controlled_start_fixture: bool,
) -> dict[str, Any]:
    goal_id = str(packet.get("goal_id") or "unknown")
    production_ready = not synthetic_start_fixture and not local_controlled_start_fixture
    return {
        "artifact_review_id": f"h3-runtime-start-artifact-review:{goal_id}",
        "runtime_start_packet_id": packet.get("runtime_start_packet_id"),
        "runtime_activation_artifact_review_id": packet.get("runtime_activation_artifact_review_id"),
        "runtime_activation_packet_id": packet.get("runtime_activation_packet_id"),
        "activation_packet_id": packet.get("activation_packet_id"),
        "preflight_id": packet.get("preflight_id"),
        "approval_id": packet.get("approval_id"),
        "goal_id": goal_id,
        "state": "runtime_start_artifacts_reviewed_no_runtime",
        "synthetic_runtime_start_fixture": synthetic_start_fixture,
        "local_controlled_runtime_start_fixture": local_controlled_start_fixture,
        "production_runtime_start_artifacts_ready": production_ready,
        "local_controlled_runtime_start_artifacts_ready": local_controlled_start_fixture,
        "runtime_start_artifact_refs": _artifact_refs(artifacts),
        "execution_policy": {flag: False for flag in EXECUTION_POLICY_FLAGS},
        "gate_status": {
            "runtime_start_artifacts_complete": True,
            "runtime_start_ready": False,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
        },
        "blocked_transitions": [
            {
                "transition": "runtime_start_artifacts_reviewed -> runtime_start_allowed",
                "reason": "runtime start requires a later explicit production start gate",
            },
            {
                "transition": "runtime_start_allowed -> runtime_execution_started",
                "reason": "runtime execution remains disabled in H3 runtime start artifact gate",
            },
        ],
    }


def _pending_packet(packet: dict[str, Any], status: dict[str, bool]) -> dict[str, Any]:
    if not status:
        status = {kind: False for kind in REQUIRED_RUNTIME_START_CONTROL_KINDS}
    missing = [kind for kind in REQUIRED_RUNTIME_START_CONTROL_KINDS if not status.get(kind)]
    return {
        "runtime_start_packet_id": packet.get("runtime_start_packet_id"),
        "goal_id": packet.get("goal_id"),
        "state": "runtime_start_review_required",
        "runtime_start_artifacts_complete": False,
        "missing_or_rejected_runtime_start_artifacts": missing,
        "blocked_transition": {
            "transition": "runtime_start_review_required -> runtime_start_artifacts_reviewed",
            "reason": "missing or rejected required runtime start control artifacts",
        },
    }


def _artifact_decision(
    passed: bool,
    start_packets: list[dict[str, Any]],
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_candidates: list[dict[str, Any]],
    synthetic_start_fixture: bool,
    local_controlled_start_fixture: bool,
) -> str:
    if not passed:
        return "blocked_before_h3_goal_emission_runtime_start_artifact_gate"
    if reviewed_packets and not pending_packets:
        if synthetic_start_fixture:
            return "synthetic_runtime_start_artifacts_reviewed_no_runtime"
        if local_controlled_start_fixture:
            return "local_controlled_runtime_start_artifacts_reviewed_no_runtime"
        return "production_runtime_start_artifacts_reviewed_no_runtime"
    if reviewed_packets:
        if synthetic_start_fixture:
            return "partial_synthetic_runtime_start_artifacts_reviewed_no_runtime"
        if local_controlled_start_fixture:
            return "partial_local_controlled_runtime_start_artifacts_reviewed_no_runtime"
        return "partial_runtime_start_artifacts_reviewed_no_runtime"
    if pending_packets or start_packets:
        return "runtime_start_artifacts_blocked_pending_required_artifacts"
    if blocked_candidates:
        return "runtime_start_artifacts_blocked_synthetic_or_blocked_start"
    return "runtime_start_artifacts_blocked_no_runtime_start_packets"


def _allowed_scope(
    passed: bool,
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not evaluate runtime start artifacts until runtime start gate and artifacts are valid"
    if reviewed_packets and not pending_packets:
        return "runtime start artifact review only; runtime start and execution remain blocked"
    if pending_packets:
        return "runtime start packets remain pending required runtime start control artifacts"
    if blocked_candidates:
        return "blocked runtime start candidates only; no runtime start artifacts can advance"
    return "runtime start packets are not ready; runtime start artifacts remain blocked"


def _artifact_refs(artifacts: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {kind: str(record.get("artifact_id") or f"{kind}:inline") for kind, record in sorted(artifacts.items())}


def _artifact_summary(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        artifact_kind = str(record.get("artifact_kind") or "unknown")
        counts[artifact_kind] = counts.get(artifact_kind, 0) + 1
    return dict(sorted(counts.items()))


def _is_synthetic_start_fixture(payload: dict[str, Any] | None, records: list[dict[str, Any]]) -> bool:
    if isinstance(payload, dict):
        fixture_policy = _object(payload.get("fixture_policy"))
        if fixture_policy.get("synthetic_runtime_start_fixture") is True:
            return True
        if fixture_policy.get("not_valid_for_production_runtime_start") is True:
            return True
    return any(record.get("synthetic_fixture") is True for record in records)


def _is_local_controlled_start_fixture(payload: dict[str, Any] | None, records: list[dict[str, Any]]) -> bool:
    if isinstance(payload, dict):
        local_policy = _object(payload.get("local_fixture_policy"))
        if local_policy.get("local_controlled_execution_fixture") is True:
            return True
        if local_policy.get("not_external_production_deployment") is True:
            return True
    return any(_local_controlled_source(record) for record in records)


def _local_controlled_source(record: dict[str, Any]) -> bool:
    source = str(record.get("source") or "").strip().lower()
    return source.startswith("h3_local_") or source.startswith("local_")


def _required_start_controls_declared(packet: dict[str, Any]) -> bool:
    required = _object(packet.get("required_runtime_start_controls"))
    return all(kind in required for kind in REQUIRED_RUNTIME_START_CONTROL_KINDS)


def _packet_runtime_blocked(packet: dict[str, Any]) -> bool:
    gate_status = _object(packet.get("gate_status"))
    return (
        gate_status.get("runtime_start_ready") is False
        and gate_status.get("runtime_activation_ready") is False
        and gate_status.get("runtime_execution_ready") is False
    )


def _execution_policy_disabled(policy: dict[str, Any]) -> bool:
    return all(policy.get(flag) is False for flag in EXECUTION_POLICY_FLAGS)


def _start_record_execution_disabled(record: dict[str, Any]) -> bool:
    return all(record.get(flag) is False for flag in RUNTIME_START_BLOCKING_FLAGS)


def _string_fields_present(record: dict[str, Any], fields: list[str]) -> bool:
    return all(str(record.get(field) or "").strip() for field in fields)


def _kind_specific_ref_present(record: dict[str, Any]) -> bool:
    artifact_kind = str(record.get("artifact_kind") or "")
    ref_field = PRODUCTION_START_KIND_REF_FIELDS.get(artifact_kind)
    return bool(ref_field and str(record.get(ref_field) or "").strip())


def _production_source_eligible(record: dict[str, Any]) -> bool:
    source = str(record.get("source") or "").strip().lower()
    return bool(source and "fixture" not in source and not source.startswith("h3_local_") and not source.startswith("local_"))


def _record_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


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


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-start-gate", required=True)
    parser.add_argument("--runtime-start-artifacts", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_start_artifact_gate(
        runtime_start_gate_path=Path(args.runtime_start_gate),
        agent_root=agent_root,
        runtime_start_artifacts_path=Path(args.runtime_start_artifacts) if args.runtime_start_artifacts else None,
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