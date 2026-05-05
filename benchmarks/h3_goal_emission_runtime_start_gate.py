"""H.3 goal emission runtime start gate skeleton.

This artifact-only gate reads H.3 runtime activation artifact review output. It
may create runtime-start review packets from production-reviewed runtime
activation artifacts, but it never starts runtime, emits goals, generates
executable plans, calls LLMs, or mutates IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-runtime-start-gate:v1"
RUNTIME_ACTIVATION_ARTIFACT_GATE_SCHEMA_VERSION = "h3-goal-emission-runtime-activation-artifact-gate:v1"
REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS = [
    "runtime_safety_envelope",
    "rollout_window_approval",
    "live_monitoring_attestation",
    "rollback_drill_attestation",
    "operator_oncall_ack",
    "kill_switch_attestation",
    "post_activation_audit_plan",
]
REQUIRED_RUNTIME_START_CONTROLS = [
    "runtime_start_change_ticket",
    "runtime_start_dual_operator_ack",
    "runtime_start_final_monitoring_green",
    "runtime_start_final_kill_switch_check",
    "runtime_start_rollback_checkpoint",
    "runtime_start_audit_sink_ready",
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


def build_h3_goal_emission_runtime_start_gate(
    *,
    runtime_activation_artifact_gate_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    runtime_activation_artifact_gate_path = _resolve_path(runtime_activation_artifact_gate_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    artifact_gate = _read_json(runtime_activation_artifact_gate_path, failures)

    artifact_readiness: dict[str, Any] = {}
    artifact_boundary: dict[str, Any] = {}
    reviewed_packets: list[dict[str, Any]] = []
    pending_packets: list[dict[str, Any]] = []
    blocked_runtime_activation_candidates: list[dict[str, Any]] = []
    if artifact_gate is None:
        _fail(
            checks,
            failures,
            "runtime_activation_artifact_gate_present",
            f"missing H3 runtime activation artifact gate: {runtime_activation_artifact_gate_path}",
        )
    else:
        checks["runtime_activation_artifact_gate_present"] = True
        _require_equal(
            "runtime_activation_artifact_gate_schema_version",
            artifact_gate.get("schema_version"),
            RUNTIME_ACTIVATION_ARTIFACT_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool(
            "runtime_activation_artifact_gate_passed",
            bool(artifact_gate.get("passed")),
            checks=checks,
            failures=failures,
        )
        artifact_readiness = _object(artifact_gate.get("readiness"))
        _require_artifact_readiness(artifact_readiness, checks=checks, failures=failures)
        artifact_boundary = _object(artifact_gate.get("runtime_activation_artifact_boundary"))
        _require_artifact_boundary(artifact_boundary, checks=checks, failures=failures)
        surface = _object(artifact_gate.get("runtime_activation_artifact_surface"))
        _require_equal(
            "runtime_activation_artifact_surface_mode",
            surface.get("mode"),
            "runtime_activation_artifacts_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        reviewed_packets = _record_list(surface.get("reviewed_runtime_activation_packets"))
        pending_packets = _record_list(surface.get("pending_runtime_activation_packets"))
        blocked_runtime_activation_candidates = _record_list(surface.get("blocked_runtime_activation_candidates"))
        _require_reviewed_packet_shape(reviewed_packets, checks=checks, failures=failures)
        _require_pending_packet_shape(pending_packets, checks=checks, failures=failures)
        _require_blocked_candidate_shape(blocked_runtime_activation_candidates, checks=checks, failures=failures)
        _require_artifact_packet_consistency(
            artifact_readiness,
            reviewed_packets,
            pending_packets,
            blocked_runtime_activation_candidates,
            checks=checks,
            failures=failures,
        )

    runtime_start_packets: list[dict[str, Any]] = []
    blocked_runtime_start_candidates: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        runtime_start_packets, blocked_runtime_start_candidates = _evaluate_runtime_start_packets(
            reviewed_packets,
            pending_packets,
            blocked_runtime_activation_candidates,
        )
    else:
        blocked_runtime_start_candidates = [_blocked_from_reviewed(packet, "invalid upstream runtime activation artifact gate") for packet in reviewed_packets]

    metrics = {
        "reviewed_runtime_activation_packet_count": len(reviewed_packets),
        "pending_runtime_activation_packet_count": len(pending_packets),
        "blocked_runtime_activation_candidate_count": len(blocked_runtime_activation_candidates),
        "runtime_start_review_packet_count": len(runtime_start_packets),
        "blocked_runtime_start_candidate_count": len(blocked_runtime_start_candidates),
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
    decision = _runtime_start_decision(
        passed,
        runtime_start_packets,
        pending_packets,
        blocked_runtime_activation_candidates,
        blocked_runtime_start_candidates,
        reviewed_packets,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "runtime_activation_artifact_gate_path": str(runtime_activation_artifact_gate_path),
        "checks": checks,
        "readiness": {
            "runtime_start_gate_evaluated": passed,
            "runtime_start_review_packets_ready": passed and bool(runtime_start_packets),
            "runtime_start_ready": False,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
            "activation_ready": False,
            "emitted_goal_ready": False,
            "executable_goal_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, runtime_start_packets, pending_packets, blocked_runtime_start_candidates),
        },
        "runtime_start_boundary": {
            "artifact_only": True,
            "runtime_start_review_packets_allowed": passed and bool(runtime_start_packets),
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
        "runtime_start_policy": {
            "required_runtime_start_controls": REQUIRED_RUNTIME_START_CONTROLS,
            "input_required_runtime_activation_artifacts": REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS,
            "blocked_after_review": [
                "runtime_start_review_required -> runtime_start_allowed",
                "runtime_start_allowed -> runtime_execution_started",
                "runtime_execution_started -> executable_plan_execution",
            ],
        },
        "runtime_start_surface": {
            "mode": "runtime_start_review_only_no_runtime",
            "runtime_start_review_packet_count": len(runtime_start_packets),
            "runtime_start_review_packets": runtime_start_packets,
            "blocked_runtime_start_candidate_count": len(blocked_runtime_start_candidates),
            "blocked_runtime_start_candidates": blocked_runtime_start_candidates,
            "runtime_executions": [],
            "emitted_goals": [],
        },
        "metrics": metrics,
        "evidence": {
            "runtime_activation_artifact_readiness": artifact_readiness,
            "runtime_activation_artifact_boundary": artifact_boundary,
        },
        "non_claims": [
            "does_not_activate_goal_emission",
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_runtime_start_review_as_runtime_start",
            "does_not_treat_runtime_activation_artifact_review_as_runtime_start",
            "does_not_treat_synthetic_fixture_as_runtime_start_readiness",
        ],
    }


def _require_artifact_readiness(
    readiness: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    valid_decisions = {
        "runtime_activation_artifacts_blocked_no_runtime_activation_packets",
        "runtime_activation_artifacts_blocked_synthetic_or_blocked_activation",
        "runtime_activation_artifacts_blocked_pending_required_artifacts",
        "production_runtime_activation_artifacts_reviewed_no_runtime",
        "synthetic_runtime_activation_artifacts_reviewed_no_runtime",
        "partial_runtime_activation_artifacts_reviewed_no_runtime",
        "partial_synthetic_runtime_activation_artifacts_reviewed_no_runtime",
    }
    _require_bool(
        "runtime_activation_artifact_decision_known",
        str(readiness.get("decision") or "") in valid_decisions,
        checks=checks,
        failures=failures,
    )
    _require_bool("runtime_activation_artifact_runtime_activation_blocked", readiness.get("runtime_activation_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_activation_artifact_runtime_execution_blocked", readiness.get("runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_activation_artifact_activation_blocked", readiness.get("activation_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_activation_artifact_emitted_goal_blocked", readiness.get("emitted_goal_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_activation_artifact_executable_goal_blocked", readiness.get("executable_goal_ready") is False, checks=checks, failures=failures)


def _require_artifact_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("runtime_activation_artifact_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in RUNTIME_BLOCKING_FLAGS:
        _require_bool(f"runtime_activation_artifact_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_reviewed_packet_shape(
    packets: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not packets:
        checks["reviewed_runtime_activation_packets_optional_or_present"] = True
        return
    _require_bool(
        "reviewed_runtime_activation_packet_state_valid",
        all(packet.get("state") == "runtime_activation_artifacts_reviewed_no_runtime" for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "reviewed_runtime_activation_packet_execution_disabled",
        all(_execution_policy_disabled(_object(packet.get("execution_policy"))) for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "reviewed_runtime_activation_packet_runtime_blocked",
        all(_reviewed_packet_runtime_blocked(packet) for packet in packets),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "reviewed_runtime_activation_packet_refs_complete",
        all(_runtime_activation_artifact_refs_complete(_object(packet.get("runtime_activation_artifact_refs"))) for packet in packets),
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
        checks["pending_runtime_activation_packets_optional_or_present"] = True
        return
    _require_bool(
        "pending_runtime_activation_packet_state_valid",
        all(packet.get("state") == "runtime_activation_review_required" for packet in packets),
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
        checks["blocked_runtime_activation_candidates_optional_or_present"] = True
        return
    _require_bool(
        "blocked_runtime_activation_candidate_state_valid",
        all(candidate.get("state") == "runtime_activation_blocked" for candidate in candidates),
        checks=checks,
        failures=failures,
    )


def _require_artifact_packet_consistency(
    readiness: dict[str, Any],
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_candidates: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    decision = str(readiness.get("decision") or "")
    production_ready = decision == "production_runtime_activation_artifacts_reviewed_no_runtime"
    synthetic_ready = decision == "synthetic_runtime_activation_artifacts_reviewed_no_runtime"
    pending = decision == "runtime_activation_artifacts_blocked_pending_required_artifacts"
    synthetic_or_blocked = decision == "runtime_activation_artifacts_blocked_synthetic_or_blocked_activation"
    _require_bool(
        "runtime_activation_artifact_reviewed_packet_decision_consistent",
        bool(reviewed_packets) == (production_ready or synthetic_ready or decision.startswith("partial_")),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_activation_artifact_pending_packet_decision_consistent",
        bool(pending_packets) == pending or (decision.startswith("partial_") and bool(pending_packets)),
        checks=checks,
        failures=failures,
    )
    if synthetic_or_blocked:
        _require_bool(
            "runtime_activation_artifact_blocked_candidate_decision_consistent",
            bool(blocked_candidates),
            checks=checks,
            failures=failures,
        )


def _evaluate_runtime_start_packets(
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_runtime_activation_candidates: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    runtime_start_packets: list[dict[str, Any]] = []
    blocked_start: list[dict[str, Any]] = []
    for packet in reviewed_packets:
        if packet.get("production_runtime_activation_artifacts_ready") is True and packet.get("synthetic_runtime_activation_fixture") is not True:
            runtime_start_packets.append(_runtime_start_packet(packet))
        else:
            blocked_start.append(_blocked_from_reviewed(packet, "runtime activation artifacts are synthetic or not production-ready"))
    for packet in pending_packets:
        blocked_start.append(_blocked_from_pending(packet))
    for candidate in blocked_runtime_activation_candidates:
        blocked_start.append(_blocked_from_candidate(candidate))
    return runtime_start_packets, blocked_start


def _runtime_start_packet(packet: dict[str, Any]) -> dict[str, Any]:
    goal_id = str(packet.get("goal_id") or "unknown")
    return {
        "runtime_start_packet_id": f"h3-runtime-start-review:{goal_id}",
        "runtime_activation_artifact_review_id": packet.get("artifact_review_id"),
        "runtime_activation_packet_id": packet.get("runtime_activation_packet_id"),
        "activation_packet_id": packet.get("activation_packet_id"),
        "preflight_id": packet.get("preflight_id"),
        "approval_id": packet.get("approval_id"),
        "goal_id": goal_id,
        "state": "runtime_start_review_required",
        "production_runtime_activation_artifacts_ready": True,
        "required_runtime_start_controls": {
            control: "required_before_runtime_start" for control in REQUIRED_RUNTIME_START_CONTROLS
        },
        "runtime_activation_artifact_refs": packet.get("runtime_activation_artifact_refs") or {},
        "execution_policy": {flag: False for flag in EXECUTION_POLICY_FLAGS},
        "gate_status": {
            "runtime_start_review_ready": True,
            "runtime_start_ready": False,
            "runtime_activation_ready": False,
            "runtime_execution_ready": False,
        },
        "blocked_transitions": [
            {
                "transition": "runtime_start_review_required -> runtime_start_allowed",
                "reason": "runtime start requires a later explicit production runtime start artifact gate",
            },
            {
                "transition": "runtime_start_allowed -> runtime_execution_started",
                "reason": "runtime execution remains disabled in H3 runtime start gate",
            },
        ],
    }


def _blocked_from_reviewed(packet: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "goal_id": packet.get("goal_id"),
        "runtime_activation_artifact_review_id": packet.get("artifact_review_id"),
        "state": "runtime_start_blocked",
        "blocked_reason": reason,
        "runtime_start_allowed": False,
        "runtime_execution_allowed": False,
    }


def _blocked_from_pending(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "goal_id": packet.get("goal_id"),
        "runtime_activation_packet_id": packet.get("runtime_activation_packet_id"),
        "state": "runtime_start_blocked",
        "blocked_reason": "runtime activation artifacts are still pending required records",
        "runtime_start_allowed": False,
        "runtime_execution_allowed": False,
    }


def _blocked_from_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "goal_id": candidate.get("goal_id"),
        "activation_packet_id": candidate.get("activation_packet_id"),
        "state": "runtime_start_blocked",
        "blocked_reason": candidate.get("blocked_reason") or "runtime activation candidate is blocked",
        "runtime_start_allowed": False,
        "runtime_execution_allowed": False,
    }


def _runtime_start_decision(
    passed: bool,
    runtime_start_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_runtime_activation_candidates: list[dict[str, Any]],
    blocked_runtime_start_candidates: list[dict[str, Any]],
    reviewed_packets: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_h3_goal_emission_runtime_start_gate"
    if runtime_start_packets:
        return "runtime_start_review_packets_ready_no_runtime"
    if pending_packets:
        return "runtime_start_blocked_pending_runtime_activation_artifacts"
    if blocked_runtime_activation_candidates or blocked_runtime_start_candidates:
        return "runtime_start_blocked_synthetic_or_blocked_runtime_activation"
    if reviewed_packets:
        return "runtime_start_blocked_synthetic_or_blocked_runtime_activation"
    return "runtime_start_blocked_no_reviewed_runtime_activation_artifacts"


def _allowed_scope(
    passed: bool,
    runtime_start_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_runtime_start_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not evaluate runtime start until runtime activation artifact gate is valid"
    if runtime_start_packets:
        return "runtime start review packets only; runtime start and execution remain blocked"
    if pending_packets:
        return "runtime start blocked until runtime activation artifacts are reviewed"
    if blocked_runtime_start_candidates:
        return "blocked runtime start candidates only; no runtime start review can advance"
    return "runtime activation artifacts are not reviewed; runtime start remains blocked"


def _reviewed_packet_runtime_blocked(packet: dict[str, Any]) -> bool:
    gate_status = _object(packet.get("gate_status"))
    return gate_status.get("runtime_activation_ready") is False and gate_status.get("runtime_execution_ready") is False


def _runtime_activation_artifact_refs_complete(refs: dict[str, Any]) -> bool:
    return all(str(refs.get(kind) or "").strip() for kind in REQUIRED_RUNTIME_ACTIVATION_ARTIFACT_KINDS)


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
    parser.add_argument("--runtime-activation-artifact-gate", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_start_gate(
        runtime_activation_artifact_gate_path=Path(args.runtime_activation_artifact_gate),
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