"""H.3 goal emission runtime activation artifact gate.

This artifact-only gate reads H.3 runtime activation review packets and optional
runtime activation artifact records. It validates artifact completeness and
provenance but does not activate runtime, emit goals, generate executable plans,
start runtime components, call LLMs, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-runtime-activation-artifact-gate:v1"
RUNTIME_ACTIVATION_GATE_SCHEMA_VERSION = "h3-goal-emission-runtime-activation-gate:v1"
RUNTIME_ACTIVATION_ARTIFACTS_SCHEMA_VERSION = "h3-goal-emission-runtime-activation-artifacts:v1"
REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS = [
    "runtime_safety_envelope",
    "rollout_window_approval",
    "live_monitoring_attestation",
    "rollback_drill_attestation",
    "operator_oncall_ack",
    "kill_switch_attestation",
    "post_activation_audit_plan",
]
RUNTIME_BLOCKING_FLAGS = [
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
PRODUCTION_RUNTIME_COMMON_FIELDS = [
    "artifact_id",
    "reviewer",
    "reviewer_role",
    "source",
    "attestation_ref",
]
PRODUCTION_RUNTIME_KIND_REF_FIELDS = {
    "runtime_safety_envelope": "runtime_safety_ref",
    "rollout_window_approval": "rollout_window_ref",
    "live_monitoring_attestation": "live_monitoring_ref",
    "rollback_drill_attestation": "rollback_drill_ref",
    "operator_oncall_ack": "operator_oncall_ref",
    "kill_switch_attestation": "kill_switch_ref",
    "post_activation_audit_plan": "post_activation_audit_ref",
}


def build_h3_goal_emission_runtime_activation_artifact_gate(
    *,
    runtime_activation_gate_path: Path,
    agent_root: Path,
    runtime_activation_artifacts_path: Path | None = None,
) -> dict[str, Any]:
    runtime_activation_gate_path = _resolve_path(runtime_activation_gate_path, agent_root)
    runtime_activation_artifacts_path = (
        _resolve_path(runtime_activation_artifacts_path, agent_root)
        if runtime_activation_artifacts_path
        else None
    )
    checks: dict[str, bool] = {}
    failures: list[str] = []
    runtime_gate = _read_json(runtime_activation_gate_path, failures)

    runtime_readiness: dict[str, Any] = {}
    runtime_boundary: dict[str, Any] = {}
    runtime_packets: list[dict[str, Any]] = []
    blocked_runtime_candidates: list[dict[str, Any]] = []
    if runtime_gate is None:
        _fail(
            checks,
            failures,
            "runtime_activation_gate_present",
            f"missing H3 runtime activation gate: {runtime_activation_gate_path}",
        )
    else:
        checks["runtime_activation_gate_present"] = True
        _require_equal(
            "runtime_activation_gate_schema_version",
            runtime_gate.get("schema_version"),
            RUNTIME_ACTIVATION_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("runtime_activation_gate_passed", bool(runtime_gate.get("passed")), checks=checks, failures=failures)
        runtime_readiness = _object(runtime_gate.get("readiness"))
        _require_runtime_readiness(runtime_readiness, checks=checks, failures=failures)
        runtime_boundary = _object(runtime_gate.get("runtime_activation_boundary"))
        _require_runtime_boundary(runtime_boundary, checks=checks, failures=failures)
        surface = _object(runtime_gate.get("runtime_activation_surface"))
        _require_equal(
            "runtime_activation_surface_mode",
            surface.get("mode"),
            "runtime_activation_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        runtime_packets = _record_list(surface.get("runtime_activation_review_packets"))
        blocked_runtime_candidates = _record_list(surface.get("blocked_runtime_activation_candidates"))
        _require_runtime_packet_consistency(
            runtime_readiness,
            runtime_packets,
            checks=checks,
            failures=failures,
        )
        _require_runtime_packet_shape(runtime_packets, checks=checks, failures=failures)
        _require_blocked_runtime_shape(blocked_runtime_candidates, checks=checks, failures=failures)

    runtime_artifacts, runtime_artifact_payload = _load_runtime_activation_artifacts(
        runtime_activation_artifacts_path,
        failures,
    )
    synthetic_runtime_fixture = _is_synthetic_runtime_fixture(runtime_artifact_payload, runtime_artifacts)
    if runtime_activation_artifacts_path:
        checks["runtime_activation_artifacts_present"] = runtime_artifact_payload is not None
        if runtime_artifact_payload is not None:
            _require_equal(
                "runtime_activation_artifacts_schema_version",
                runtime_artifact_payload.get("schema_version"),
                RUNTIME_ACTIVATION_ARTIFACTS_SCHEMA_VERSION,
                checks=checks,
                failures=failures,
            )
            _require_bool(
                "runtime_activation_artifacts_records_present",
                bool(runtime_artifacts),
                checks=checks,
                failures=failures,
            )
            _require_runtime_artifact_shape(
                runtime_artifacts,
                synthetic_runtime_fixture=synthetic_runtime_fixture,
                checks=checks,
                failures=failures,
            )
    else:
        checks["runtime_activation_artifacts_optional_absent"] = True

    reviewed_packets: list[dict[str, Any]] = []
    pending_packets: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        reviewed_packets, pending_packets = _evaluate_runtime_packets(
            runtime_packets,
            runtime_artifacts,
            synthetic_runtime_fixture,
        )
    elif runtime_packets:
        pending_packets = [_pending_packet(packet, {}) for packet in runtime_packets]

    metrics = {
        "runtime_activation_review_packet_count": len(runtime_packets),
        "runtime_activation_artifact_record_count": len(runtime_artifacts),
        "reviewed_runtime_activation_packet_count": len(reviewed_packets),
        "pending_runtime_activation_packet_count": len(pending_packets),
        "blocked_runtime_activation_candidate_count": len(blocked_runtime_candidates),
        "synthetic_runtime_activation_fixture_count": 1 if synthetic_runtime_fixture else 0,
        "runtime_activation_ready_count": 0,
        "runtime_execution_ready_count": 0,
        "activation_ready_count": 0,
        "emitted_goal_count": 0,
        "executable_goal_ready_count": 0,
    }
    _require_bool("runtime_activation_blocked", metrics["runtime_activation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_execution_blocked", metrics["runtime_execution_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("activation_blocked", metrics["activation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("goal_emission_blocked", metrics["emitted_goal_count"] == 0, checks=checks, failures=failures)
    _require_bool("execution_blocked", metrics["executable_goal_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _artifact_decision(
        passed,
        runtime_packets,
        reviewed_packets,
        pending_packets,
        blocked_runtime_candidates,
        synthetic_runtime_fixture,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "runtime_activation_gate_path": str(runtime_activation_gate_path),
        "runtime_activation_artifacts_path": str(runtime_activation_artifacts_path) if runtime_activation_artifacts_path else None,
        "checks": checks,
        "readiness": {
            "runtime_activation_artifact_gate_evaluated": passed,
            "runtime_activation_artifacts_complete": passed and bool(reviewed_packets) and not pending_packets,
            "production_runtime_activation_artifacts_complete": (
                passed and bool(reviewed_packets) and not pending_packets and not synthetic_runtime_fixture
            ),
            "synthetic_runtime_activation_artifacts_complete": (
                passed and bool(reviewed_packets) and not pending_packets and synthetic_runtime_fixture
            ),
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
            "activation_ready": False,
            "emitted_goal_ready": False,
            "executable_goal_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, reviewed_packets, pending_packets, blocked_runtime_candidates),
        },
        "runtime_activation_artifact_boundary": {
            "artifact_only": True,
            "runtime_activation_artifact_review_allowed": passed and bool(reviewed_packets),
            "production_runtime_activation_artifact_review_allowed": (
                passed and bool(reviewed_packets) and not pending_packets and not synthetic_runtime_fixture
            ),
            "synthetic_runtime_activation_artifact_surface_allowed": (
                passed and bool(reviewed_packets) and synthetic_runtime_fixture
            ),
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
        "runtime_activation_artifact_policy": {
            "required_runtime_activation_artifact_kinds": REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS,
            "accepted_runtime_activation_artifacts": {
                "runtime_safety_envelope": "approved",
                "rollout_window_approval": "approved_for_runtime_activation",
                "live_monitoring_attestation": "ready",
                "rollback_drill_attestation": "passed",
                "operator_oncall_ack": "acknowledged",
                "kill_switch_attestation": "armed",
                "post_activation_audit_plan": "ready",
            },
            "production_runtime_common_fields": PRODUCTION_RUNTIME_COMMON_FIELDS,
            "production_runtime_kind_ref_fields": PRODUCTION_RUNTIME_KIND_REF_FIELDS,
            "blocked_after_artifact_review": [
                "runtime_activation_artifacts_reviewed -> runtime_activation_allowed",
                "runtime_activation_allowed -> executable_plan_generated",
                "executable_plan_generated -> runtime_execution_started",
            ],
        },
        "runtime_activation_artifact_surface": {
            "mode": "runtime_activation_artifacts_review_only_no_runtime",
            "reviewed_runtime_activation_packet_count": len(reviewed_packets),
            "reviewed_runtime_activation_packets": reviewed_packets,
            "pending_runtime_activation_packet_count": len(pending_packets),
            "pending_runtime_activation_packets": pending_packets,
            "blocked_runtime_activation_candidate_count": len(blocked_runtime_candidates),
            "blocked_runtime_activation_candidates": blocked_runtime_candidates,
            "runtime_executions": [],
            "emitted_goals": [],
        },
        "metrics": metrics,
        "evidence": {
            "runtime_activation_readiness": runtime_readiness,
            "runtime_activation_boundary": runtime_boundary,
            "runtime_activation_artifact_summary": _runtime_artifact_summary(runtime_artifacts),
            "synthetic_runtime_activation_fixture": synthetic_runtime_fixture,
        },
        "non_claims": [
            "does_not_activate_goal_emission",
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_runtime_artifact_review_as_runtime_start",
            "does_not_treat_missing_runtime_artifacts_as_runtime_activation",
            "does_not_treat_synthetic_fixture_as_production_runtime_activation",
        ],
    }


def _require_runtime_readiness(
    readiness: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    valid_decisions = {
        "runtime_activation_blocked_no_reviewed_activation_artifacts",
        "runtime_activation_blocked_pending_activation_artifacts",
        "runtime_activation_blocked_synthetic_or_blocked_activation",
        "runtime_activation_review_packets_ready_no_runtime",
    }
    _require_bool(
        "runtime_activation_gate_decision_known",
        str(readiness.get("decision") or "") in valid_decisions,
        checks=checks,
        failures=failures,
    )
    _require_bool("runtime_activation_gate_runtime_activation_blocked", readiness.get("runtime_activation_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_activation_gate_runtime_execution_blocked", readiness.get("runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_activation_gate_activation_blocked", readiness.get("activation_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_activation_gate_emitted_goal_blocked", readiness.get("emitted_goal_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_activation_gate_executable_goal_blocked", readiness.get("executable_goal_ready") is False, checks=checks, failures=failures)


def _require_runtime_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("runtime_activation_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in RUNTIME_BLOCKING_FLAGS:
        _require_bool(f"runtime_activation_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_runtime_packet_consistency(
    readiness: dict[str, Any],
    packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    review_ready = str(readiness.get("decision") or "") == "runtime_activation_review_packets_ready_no_runtime"
    _require_bool(
        "runtime_activation_packet_decision_consistent",
        bool(packets) == review_ready,
        checks=checks,
        failures=failures,
    )
    if review_ready:
        _require_bool(
            "runtime_activation_packet_readiness_consistent",
            readiness.get("runtime_activation_review_packets_ready") is True,
            checks=checks,
            failures=failures,
        )


def _require_runtime_packet_shape(
    packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not packets:
        checks["runtime_activation_packets_optional_or_present"] = True
        return
    _require_bool(
        "runtime_activation_packet_state_valid",
        all(packet.get("state") == "runtime_activation_review_required" for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_activation_packet_required_artifacts_declared",
        all(_required_runtime_artifacts_declared(packet) for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_activation_packet_execution_disabled",
        all(_execution_policy_disabled(_object(packet.get("execution_policy"))) for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_activation_packet_runtime_blocked",
        all(_object(packet.get("gate_status")).get("runtime_activation_ready") is False for packet in packets),
        checks=checks,
        failures=failures,
    )


def _require_blocked_runtime_shape(
    candidates: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not candidates:
        checks["blocked_runtime_activation_candidates_optional_or_present"] = True
        return
    _require_bool(
        "blocked_runtime_activation_candidate_state_valid",
        all(candidate.get("state") == "runtime_activation_blocked" for candidate in candidates),
        checks=checks,
        failures=failures,
    )


def _require_runtime_artifact_shape(
    records: list[dict[str, Any]],
    *,
    synthetic_runtime_fixture: bool,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool(
        "runtime_activation_artifact_kinds_known",
        all(str(record.get("artifact_kind") or "") in REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_activation_artifact_execution_disabled",
        all(_runtime_record_execution_disabled(record) for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_activation_artifact_targets_present",
        all(str(record.get("runtime_activation_packet_id") or record.get("goal_id") or "").strip() for record in records),
        checks=checks,
        failures=failures,
    )
    if synthetic_runtime_fixture:
        _require_bool(
            "runtime_activation_artifact_synthetic_fixture_marked",
            all(record.get("synthetic_fixture") is True for record in records),
            checks=checks,
            failures=failures,
        )
        return
    _require_bool(
        "runtime_activation_artifact_not_synthetic_fixture",
        all(record.get("synthetic_fixture") is not True for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_activation_artifact_common_provenance_present",
        all(_string_fields_present(record, PRODUCTION_RUNTIME_COMMON_FIELDS) for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_activation_artifact_kind_specific_provenance_present",
        all(_kind_specific_ref_present(record) for record in records),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_activation_artifact_source_not_fixture",
        all(_production_source_eligible(record) for record in records),
        checks=checks,
        failures=failures,
    )


def _load_runtime_activation_artifacts(
    runtime_activation_artifacts_path: Path | None,
    failures: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if runtime_activation_artifacts_path is None:
        return [], None
    payload = _read_json(runtime_activation_artifacts_path, failures)
    if payload is None:
        return [], None
    records = payload.get("records")
    if not isinstance(records, list):
        failures.append(f"runtime activation artifact file missing records array: {runtime_activation_artifacts_path}")
        return [], payload
    return [record for record in records if isinstance(record, dict)], payload


def _evaluate_runtime_packets(
    packets: list[dict[str, Any]],
    records: list[dict[str, Any]],
    synthetic_runtime_fixture: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    reviewed: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    for packet in packets:
        artifacts = _artifacts_for_packet(packet, records)
        status = _runtime_artifact_status(artifacts)
        if all(status.values()):
            reviewed.append(_reviewed_packet(packet, artifacts, synthetic_runtime_fixture))
        else:
            pending.append(_pending_packet(packet, status))
    return reviewed, pending


def _runtime_artifact_status(artifacts: dict[str, dict[str, Any]]) -> dict[str, bool]:
    return {
        kind: _artifact_accepts_runtime_activation(kind, artifacts.get(kind))
        for kind in REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS
    }


def _artifacts_for_packet(
    packet: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    runtime_activation_packet_id = str(packet.get("runtime_activation_packet_id") or "")
    goal_id = str(packet.get("goal_id") or "")
    out: dict[str, dict[str, Any]] = {}
    for record in records:
        record_packet_id = str(record.get("runtime_activation_packet_id") or "")
        record_goal_id = str(record.get("goal_id") or "")
        if record_packet_id != runtime_activation_packet_id and record_goal_id != goal_id:
            continue
        artifact_kind = str(record.get("artifact_kind") or "")
        if artifact_kind in REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS and artifact_kind not in out:
            out[artifact_kind] = record
    return out


def _artifact_accepts_runtime_activation(kind: str, record: dict[str, Any] | None) -> bool:
    if not isinstance(record, dict):
        return False
    if kind == "runtime_safety_envelope":
        return record.get("status") == "approved"
    if kind == "rollout_window_approval":
        return record.get("decision") == "approved_for_runtime_activation"
    if kind == "live_monitoring_attestation":
        return record.get("status") == "ready"
    if kind == "rollback_drill_attestation":
        return record.get("status") == "passed"
    if kind == "operator_oncall_ack":
        return record.get("status") == "acknowledged"
    if kind == "kill_switch_attestation":
        return record.get("status") == "armed"
    if kind == "post_activation_audit_plan":
        return record.get("status") == "ready"
    return False


def _reviewed_packet(
    packet: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    synthetic_runtime_fixture: bool,
) -> dict[str, Any]:
    goal_id = str(packet.get("goal_id") or "unknown")
    return {
        "artifact_review_id": f"h3-runtime-activation-artifact-review:{goal_id}",
        "runtime_activation_packet_id": packet.get("runtime_activation_packet_id"),
        "activation_packet_id": packet.get("activation_packet_id"),
        "artifact_review_source_id": packet.get("artifact_review_id"),
        "preflight_id": packet.get("preflight_id"),
        "approval_id": packet.get("approval_id"),
        "goal_id": goal_id,
        "state": "runtime_activation_artifacts_reviewed_no_runtime",
        "synthetic_runtime_activation_fixture": synthetic_runtime_fixture,
        "production_runtime_activation_artifacts_ready": not synthetic_runtime_fixture,
        "runtime_activation_artifact_refs": _artifact_refs(artifacts),
        "execution_policy": {flag: False for flag in EXECUTION_POLICY_FLAGS},
        "gate_status": {
            "runtime_activation_artifacts_complete": True,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
        },
        "blocked_transitions": [
            {
                "transition": "runtime_activation_artifacts_reviewed -> runtime_activation_allowed",
                "reason": "runtime activation requires a later explicit production runtime start gate",
            },
            {
                "transition": "runtime_activation_allowed -> runtime_execution_started",
                "reason": "runtime execution remains disabled in H3 runtime activation artifact gate",
            },
        ],
    }


def _pending_packet(packet: dict[str, Any], status: dict[str, bool]) -> dict[str, Any]:
    if not status:
        status = {kind: False for kind in REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS}
    missing = [kind for kind in REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS if not status.get(kind)]
    return {
        "runtime_activation_packet_id": packet.get("runtime_activation_packet_id"),
        "goal_id": packet.get("goal_id"),
        "state": "runtime_activation_review_required",
        "runtime_activation_artifacts_complete": False,
        "missing_or_rejected_runtime_activation_artifacts": missing,
        "blocked_transition": {
            "transition": "runtime_activation_review_required -> runtime_activation_artifacts_reviewed",
            "reason": "missing or rejected required runtime activation artifacts",
        },
    }


def _artifact_decision(
    passed: bool,
    runtime_packets: list[dict[str, Any]],
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_runtime_candidates: list[dict[str, Any]],
    synthetic_runtime_fixture: bool,
) -> str:
    if not passed:
        return "blocked_before_h3_goal_emission_runtime_activation_artifact_gate"
    if reviewed_packets and not pending_packets:
        if synthetic_runtime_fixture:
            return "synthetic_runtime_activation_artifacts_reviewed_no_runtime"
        return "production_runtime_activation_artifacts_reviewed_no_runtime"
    if reviewed_packets:
        if synthetic_runtime_fixture:
            return "partial_synthetic_runtime_activation_artifacts_reviewed_no_runtime"
        return "partial_runtime_activation_artifacts_reviewed_no_runtime"
    if pending_packets or runtime_packets:
        return "runtime_activation_artifacts_blocked_pending_required_artifacts"
    if blocked_runtime_candidates:
        return "runtime_activation_artifacts_blocked_synthetic_or_blocked_activation"
    return "runtime_activation_artifacts_blocked_no_runtime_activation_packets"


def _allowed_scope(
    passed: bool,
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_runtime_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not evaluate runtime activation artifacts until runtime activation gate and artifacts are valid"
    if reviewed_packets and not pending_packets:
        return "runtime activation artifact review only; runtime activation and execution remain blocked"
    if pending_packets:
        return "runtime activation packets remain pending required runtime activation artifacts"
    if blocked_runtime_candidates:
        return "blocked runtime activation candidates only; no runtime activation artifacts can advance"
    return "runtime activation packets are not ready; runtime activation artifacts remain blocked"


def _artifact_refs(artifacts: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {
        kind: str(record.get("artifact_id") or f"{kind}:inline")
        for kind, record in sorted(artifacts.items())
    }


def _runtime_artifact_summary(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        artifact_kind = str(record.get("artifact_kind") or "unknown")
        counts[artifact_kind] = counts.get(artifact_kind, 0) + 1
    return dict(sorted(counts.items()))


def _is_synthetic_runtime_fixture(payload: dict[str, Any] | None, records: list[dict[str, Any]]) -> bool:
    if isinstance(payload, dict):
        fixture_policy = _object(payload.get("fixture_policy"))
        if fixture_policy.get("synthetic_runtime_activation_fixture") is True:
            return True
        if fixture_policy.get("not_valid_for_production_runtime_activation") is True:
            return True
    return any(record.get("synthetic_fixture") is True for record in records)


def _required_runtime_artifacts_declared(packet: dict[str, Any]) -> bool:
    required = _object(packet.get("required_runtime_activation_artifacts"))
    return all(kind in required for kind in REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS)


def _execution_policy_disabled(policy: dict[str, Any]) -> bool:
    return all(policy.get(flag) is False for flag in EXECUTION_POLICY_FLAGS)


def _runtime_record_execution_disabled(record: dict[str, Any]) -> bool:
    return all(record.get(flag) is False for flag in RUNTIME_BLOCKING_FLAGS)


def _string_fields_present(record: dict[str, Any], fields: list[str]) -> bool:
    return all(str(record.get(field) or "").strip() for field in fields)


def _kind_specific_ref_present(record: dict[str, Any]) -> bool:
    artifact_kind = str(record.get("artifact_kind") or "")
    ref_field = PRODUCTION_RUNTIME_KIND_REF_FIELDS.get(artifact_kind)
    return bool(ref_field and str(record.get(ref_field) or "").strip())


def _production_source_eligible(record: dict[str, Any]) -> bool:
    source = str(record.get("source") or "").strip().lower()
    return bool(source and "fixture" not in source)


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


def _fail(checks: dict[str, bool], failures: list[str], name: str, reason: str) -> None:
    checks[name] = False
    failures.append(reason)


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _resolve_path(path: Path | None, agent_root: Path) -> Path:
    assert path is not None
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-activation-gate", required=True)
    parser.add_argument("--runtime-activation-artifacts", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_activation_artifact_gate(
        runtime_activation_gate_path=Path(args.runtime_activation_gate),
        agent_root=agent_root,
        runtime_activation_artifacts_path=Path(args.runtime_activation_artifacts)
        if args.runtime_activation_artifacts
        else None,
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