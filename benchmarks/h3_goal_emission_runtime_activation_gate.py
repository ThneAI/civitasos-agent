"""H.3 goal emission runtime activation gate skeleton.

This artifact-only gate reads H.3 goal emission activation artifact review
reports and prepares runtime activation review packets only when production
activation artifacts have been reviewed. It does not activate emission, emit
goals, generate executable plans, start runtime components, call LLMs, or mutate
IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-runtime-activation-gate:v1"
ACTIVATION_ARTIFACT_GATE_SCHEMA_VERSION = "h3-goal-emission-activation-artifact-gate:v1"
EXECUTION_POLICY_FLAGS = [
    "goal_emission_allowed",
    "executable_plan_allowed",
    "runtime_execution_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]
BOUNDARY_BLOCKING_FLAGS = [
    "activation_allowed",
    "goal_emission_allowed",
    "emitted_goal_allowed",
    "executable_plan_allowed",
    "runtime_execution_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]
REQUIRED_RUNTIME_ACTIVATION_ARTIFACTS = [
    "runtime_safety_envelope",
    "rollout_window_approval",
    "live_monitoring_attestation",
    "rollback_drill_attestation",
    "operator_oncall_ack",
    "kill_switch_attestation",
    "post_activation_audit_plan",
]


def build_h3_goal_emission_runtime_activation_gate(
    *,
    activation_artifact_gate_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    activation_artifact_gate_path = _resolve_path(activation_artifact_gate_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    artifact_gate = _read_json(activation_artifact_gate_path, failures)

    artifact_readiness: dict[str, Any] = {}
    artifact_boundary: dict[str, Any] = {}
    reviewed_packets: list[dict[str, Any]] = []
    pending_packets: list[dict[str, Any]] = []
    blocked_candidates: list[dict[str, Any]] = []
    if artifact_gate is None:
        _fail(
            checks,
            failures,
            "activation_artifact_gate_present",
            f"missing H3 activation artifact gate: {activation_artifact_gate_path}",
        )
    else:
        checks["activation_artifact_gate_present"] = True
        _require_equal(
            "activation_artifact_gate_schema_version",
            artifact_gate.get("schema_version"),
            ACTIVATION_ARTIFACT_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("activation_artifact_gate_passed", bool(artifact_gate.get("passed")), checks=checks, failures=failures)
        artifact_readiness = _object(artifact_gate.get("readiness"))
        _require_artifact_readiness(artifact_readiness, checks=checks, failures=failures)
        artifact_boundary = _object(artifact_gate.get("activation_artifact_boundary"))
        _require_artifact_boundary(artifact_boundary, checks=checks, failures=failures)
        surface = _object(artifact_gate.get("activation_artifact_surface"))
        _require_equal(
            "activation_artifact_surface_mode",
            surface.get("mode"),
            "activation_artifacts_review_only_no_activation",
            checks=checks,
            failures=failures,
        )
        reviewed_packets = _record_list(surface.get("reviewed_activation_packets"))
        pending_packets = _record_list(surface.get("pending_activation_packets"))
        blocked_candidates = _record_list(surface.get("blocked_activation_candidates"))
        _require_reviewed_packet_consistency(artifact_readiness, reviewed_packets, pending_packets, checks=checks, failures=failures)
        _require_reviewed_packet_shape(reviewed_packets, checks=checks, failures=failures)
        _require_pending_packet_shape(pending_packets, checks=checks, failures=failures)
        _require_blocked_candidate_shape(blocked_candidates, checks=checks, failures=failures)

    runtime_packets: list[dict[str, Any]] = []
    blocked_runtime_candidates: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        for packet in reviewed_packets:
            if packet.get("production_activation_artifacts_ready") is True and packet.get("synthetic_activation_fixture") is not True:
                runtime_packets.append(_runtime_activation_packet(packet))
            else:
                blocked_runtime_candidates.append(_blocked_runtime_candidate(packet, "synthetic activation artifacts cannot enter runtime activation"))
        blocked_runtime_candidates.extend(_blocked_runtime_candidate(packet, "activation artifacts are incomplete") for packet in pending_packets)
        blocked_runtime_candidates.extend(_blocked_runtime_candidate(candidate, candidate.get("blocked_reason") or "activation is blocked") for candidate in blocked_candidates)

    metrics = {
        "reviewed_activation_packet_count": len(reviewed_packets),
        "pending_activation_packet_count": len(pending_packets),
        "blocked_activation_candidate_count": len(blocked_candidates),
        "runtime_activation_review_packet_count": len(runtime_packets),
        "blocked_runtime_activation_candidate_count": len(blocked_runtime_candidates),
        "activation_ready_count": 0,
        "emitted_goal_count": 0,
        "executable_goal_ready_count": 0,
        "runtime_activation_ready_count": 0,
        "runtime_execution_ready_count": 0,
    }
    _require_bool("activation_blocked", metrics["activation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("goal_emission_blocked", metrics["emitted_goal_count"] == 0, checks=checks, failures=failures)
    _require_bool("execution_blocked", metrics["executable_goal_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_activation_blocked", metrics["runtime_activation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_execution_blocked", metrics["runtime_execution_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _runtime_decision(passed, runtime_packets, pending_packets, blocked_candidates, blocked_runtime_candidates)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "activation_artifact_gate_path": str(activation_artifact_gate_path),
        "checks": checks,
        "readiness": {
            "runtime_activation_gate_evaluated": passed,
            "runtime_activation_review_packets_ready": passed and bool(runtime_packets),
            "runtime_activation_ready": False,
            "activation_ready": False,
            "emitted_goal_ready": False,
            "executable_goal_ready": False,
            "runtime_execution_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, runtime_packets, pending_packets, blocked_runtime_candidates),
        },
        "runtime_activation_boundary": {
            "artifact_only": True,
            "runtime_activation_review_packets_allowed": passed and bool(runtime_packets),
            "runtime_activation_allowed": False,
            "activation_allowed": False,
            "goal_emission_allowed": False,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "runtime_activation_policy": {
            "required_runtime_activation_artifacts": REQUIRED_RUNTIME_ACTIVATION_ARTIFACTS,
            "requires_production_activation_artifacts_reviewed": True,
            "rejects_synthetic_activation_artifacts": True,
            "requires_later_runtime_start_gate": True,
            "blocked_after_runtime_review": [
                "runtime_activation_review_required -> runtime_activation_allowed",
                "runtime_activation_allowed -> executable_plan_generated",
                "executable_plan_generated -> runtime_execution_started",
            ],
        },
        "runtime_activation_surface": {
            "mode": "runtime_activation_review_only_no_runtime",
            "runtime_activation_review_packet_count": len(runtime_packets),
            "runtime_activation_review_packets": runtime_packets,
            "blocked_runtime_activation_candidate_count": len(blocked_runtime_candidates),
            "blocked_runtime_activation_candidates": blocked_runtime_candidates,
            "emitted_goals": [],
            "runtime_executions": [],
        },
        "metrics": metrics,
        "evidence": {
            "activation_artifact_readiness": artifact_readiness,
            "activation_artifact_boundary": artifact_boundary,
        },
        "non_claims": [
            "does_not_activate_goal_emission",
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_runtime_review_as_runtime_start",
        ],
    }


def _require_artifact_readiness(
    readiness: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    valid_decisions = {
        "activation_artifacts_blocked_no_activation_packets",
        "activation_artifacts_blocked_synthetic_or_blocked_emission",
        "activation_artifacts_blocked_pending_required_artifacts",
        "production_activation_artifacts_reviewed_no_activation",
        "synthetic_activation_artifacts_reviewed_no_activation",
        "partial_activation_artifacts_reviewed_no_activation",
        "partial_synthetic_activation_artifacts_reviewed_no_activation",
    }
    _require_bool(
        "activation_artifact_gate_decision_known",
        str(readiness.get("decision") or "") in valid_decisions,
        checks=checks,
        failures=failures,
    )
    _require_bool("activation_artifact_gate_activation_blocked", readiness.get("activation_ready") is False, checks=checks, failures=failures)
    _require_bool("activation_artifact_gate_emitted_goal_blocked", readiness.get("emitted_goal_ready") is False, checks=checks, failures=failures)
    _require_bool("activation_artifact_gate_executable_goal_blocked", readiness.get("executable_goal_ready") is False, checks=checks, failures=failures)
    _require_bool("activation_artifact_gate_runtime_blocked", readiness.get("runtime_execution_ready") is False, checks=checks, failures=failures)


def _require_artifact_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("activation_artifact_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in BOUNDARY_BLOCKING_FLAGS:
        _require_bool(f"activation_artifact_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_reviewed_packet_consistency(
    readiness: dict[str, Any],
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    decision = str(readiness.get("decision") or "")
    reviewed_decision = "activation_artifacts_reviewed_no_activation" in decision
    pending_decision = decision == "activation_artifacts_blocked_pending_required_artifacts"
    _require_bool(
        "reviewed_packet_decision_consistent",
        bool(reviewed_packets) == reviewed_decision,
        checks=checks,
        failures=failures,
    )
    if pending_decision:
        _require_bool("pending_packet_decision_consistent", bool(pending_packets), checks=checks, failures=failures)


def _require_reviewed_packet_shape(
    packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not packets:
        checks["reviewed_activation_packets_optional_or_present"] = True
        return
    _require_bool(
        "reviewed_activation_packet_state_valid",
        all(packet.get("state") == "activation_artifacts_reviewed_no_activation" for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "reviewed_activation_packet_execution_disabled",
        all(_execution_policy_disabled(_object(packet.get("execution_policy"))) for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "reviewed_activation_packet_runtime_blocked",
        all(_object(packet.get("gate_status")).get("runtime_execution_ready") is False for packet in packets),
        checks=checks,
        failures=failures,
    )


def _require_pending_packet_shape(
    packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not packets:
        checks["pending_activation_packets_optional_or_present"] = True
        return
    _require_bool(
        "pending_activation_packet_state_valid",
        all(packet.get("state") == "goal_emission_activation_review_required" for packet in packets),
        checks=checks,
        failures=failures,
    )


def _require_blocked_candidate_shape(
    candidates: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not candidates:
        checks["blocked_activation_candidates_optional_or_present"] = True
        return
    _require_bool(
        "blocked_activation_candidate_state_valid",
        all(candidate.get("state") == "goal_emission_activation_blocked" for candidate in candidates),
        checks=checks,
        failures=failures,
    )


def _runtime_activation_packet(packet: dict[str, Any]) -> dict[str, Any]:
    goal_id = str(packet.get("goal_id") or "unknown")
    return {
        "runtime_activation_packet_id": f"h3-runtime-activation-review:{goal_id}",
        "artifact_review_id": packet.get("artifact_review_id"),
        "activation_packet_id": packet.get("activation_packet_id"),
        "preflight_id": packet.get("preflight_id"),
        "approval_id": packet.get("approval_id"),
        "goal_id": goal_id,
        "state": "runtime_activation_review_required",
        "production_activation_artifacts_ready": True,
        "required_runtime_activation_artifacts": {
            artifact: "required_before_runtime_activation" for artifact in REQUIRED_RUNTIME_ACTIVATION_ARTIFACTS
        },
        "activation_artifact_refs": _object(packet.get("activation_artifact_refs")),
        "execution_policy": {flag: False for flag in EXECUTION_POLICY_FLAGS},
        "gate_status": {
            "runtime_activation_review_ready": True,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
        },
        "blocked_transitions": [
            {
                "transition": "runtime_activation_review_required -> runtime_activation_allowed",
                "reason": "runtime activation requires a later explicit runtime start gate",
            },
            {
                "transition": "runtime_activation_allowed -> runtime_execution_started",
                "reason": "runtime execution remains disabled in H3 runtime activation gate",
            },
        ],
    }


def _blocked_runtime_candidate(candidate: dict[str, Any], reason: object) -> dict[str, Any]:
    return {
        "goal_id": candidate.get("goal_id"),
        "activation_packet_id": candidate.get("activation_packet_id"),
        "state": "runtime_activation_blocked",
        "blocked_reason": str(reason or "runtime activation is blocked"),
        "synthetic_activation_fixture": candidate.get("synthetic_activation_fixture") is True,
    }


def _runtime_decision(
    passed: bool,
    runtime_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_candidates: list[dict[str, Any]],
    blocked_runtime_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_h3_goal_emission_runtime_activation_gate"
    if runtime_packets:
        return "runtime_activation_review_packets_ready_no_runtime"
    if pending_packets:
        return "runtime_activation_blocked_pending_activation_artifacts"
    if blocked_candidates or blocked_runtime_candidates:
        return "runtime_activation_blocked_synthetic_or_blocked_activation"
    return "runtime_activation_blocked_no_reviewed_activation_artifacts"


def _allowed_scope(
    passed: bool,
    runtime_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_runtime_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not evaluate runtime activation until activation artifact gate is valid"
    if runtime_packets:
        return "runtime activation review packets only; no runtime activation or execution"
    if pending_packets:
        return "activation artifacts are incomplete; runtime activation remains blocked"
    if blocked_runtime_candidates:
        return "blocked runtime activation candidates only; no runtime activation"
    return "reviewed activation artifacts are not ready; runtime activation remains blocked"


def _execution_policy_disabled(policy: dict[str, Any]) -> bool:
    return all(policy.get(flag) is False for flag in EXECUTION_POLICY_FLAGS)


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


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--activation-artifact-gate", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_activation_gate(
        activation_artifact_gate_path=Path(args.activation_artifact_gate),
        agent_root=agent_root,
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