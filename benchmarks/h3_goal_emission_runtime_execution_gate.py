"""H.3 goal emission runtime execution gate.

This is the first H.3 gate that can authorize a bounded runtime execution
packet. It reads production-reviewed runtime start artifacts, requires an
explicit operator acknowledgement, and emits execution packets for a later
executor. It does not itself execute packets, call LLMs, generate executable
plans, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-runtime-execution-gate:v1"
RUNTIME_START_ARTIFACT_GATE_SCHEMA_VERSION = "h3-goal-emission-runtime-start-artifact-gate:v1"
REQUIRED_RUNTIME_START_CONTROL_KINDS = [
    "runtime_start_change_ticket",
    "runtime_start_dual_operator_ack",
    "runtime_start_final_monitoring_green",
    "runtime_start_final_kill_switch_check",
    "runtime_start_rollback_checkpoint",
    "runtime_start_audit_sink_ready",
]
UPSTREAM_BLOCKING_FLAGS = [
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
    "runtime_start_allowed",
    "runtime_execution_allowed",
    "goal_emission_allowed",
    "emitted_goal_allowed",
    "executable_plan_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]


def build_h3_goal_emission_runtime_execution_gate(
    *,
    runtime_start_artifact_gate_path: Path,
    agent_root: Path,
    ack_runtime_execution: bool = False,
    allow_local_controlled_execution: bool = False,
) -> dict[str, Any]:
    runtime_start_artifact_gate_path = _resolve_path(runtime_start_artifact_gate_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    start_artifact_gate = _read_json(runtime_start_artifact_gate_path, failures)

    start_artifact_readiness: dict[str, Any] = {}
    start_artifact_boundary: dict[str, Any] = {}
    reviewed_start_packets: list[dict[str, Any]] = []
    pending_start_packets: list[dict[str, Any]] = []
    blocked_start_candidates: list[dict[str, Any]] = []
    if start_artifact_gate is None:
        _fail(
            checks,
            failures,
            "runtime_start_artifact_gate_present",
            f"missing H3 runtime start artifact gate: {runtime_start_artifact_gate_path}",
        )
    else:
        checks["runtime_start_artifact_gate_present"] = True
        _require_equal(
            "runtime_start_artifact_gate_schema_version",
            start_artifact_gate.get("schema_version"),
            RUNTIME_START_ARTIFACT_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool(
            "runtime_start_artifact_gate_passed",
            bool(start_artifact_gate.get("passed")),
            checks=checks,
            failures=failures,
        )
        start_artifact_readiness = _object(start_artifact_gate.get("readiness"))
        _require_start_artifact_readiness(start_artifact_readiness, checks=checks, failures=failures)
        start_artifact_boundary = _object(start_artifact_gate.get("runtime_start_artifact_boundary"))
        _require_start_artifact_boundary(start_artifact_boundary, checks=checks, failures=failures)
        surface = _object(start_artifact_gate.get("runtime_start_artifact_surface"))
        _require_equal(
            "runtime_start_artifact_surface_mode",
            surface.get("mode"),
            "runtime_start_artifacts_review_only_no_runtime",
            checks=checks,
            failures=failures,
        )
        reviewed_start_packets = _record_list(surface.get("reviewed_runtime_start_packets"))
        pending_start_packets = _record_list(surface.get("pending_runtime_start_packets"))
        blocked_start_candidates = _record_list(surface.get("blocked_runtime_start_candidates"))
        _require_reviewed_start_packet_shape(reviewed_start_packets, checks=checks, failures=failures)
        _require_pending_start_packet_shape(pending_start_packets, checks=checks, failures=failures)
        _require_blocked_start_shape(blocked_start_candidates, checks=checks, failures=failures)
        _require_start_artifact_packet_consistency(
            start_artifact_readiness,
            reviewed_start_packets,
            pending_start_packets,
            blocked_start_candidates,
            checks=checks,
            failures=failures,
        )

    execution_packets: list[dict[str, Any]] = []
    pending_ack_packets: list[dict[str, Any]] = []
    blocked_execution_candidates: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        execution_packets, pending_ack_packets, blocked_execution_candidates = _evaluate_execution_packets(
            reviewed_start_packets,
            pending_start_packets,
            blocked_start_candidates,
            ack_runtime_execution,
            allow_local_controlled_execution,
        )
    else:
        blocked_execution_candidates = [
            _blocked_from_reviewed(packet, "invalid upstream runtime start artifact gate")
            for packet in reviewed_start_packets
        ]

    metrics = {
        "reviewed_runtime_start_packet_count": len(reviewed_start_packets),
        "pending_runtime_start_packet_count": len(pending_start_packets),
        "blocked_runtime_start_candidate_count": len(blocked_start_candidates),
        "runtime_execution_packet_count": len(execution_packets),
        "pending_runtime_execution_ack_count": len(pending_ack_packets),
        "blocked_runtime_execution_candidate_count": len(blocked_execution_candidates),
        "runtime_start_ready_count": len(execution_packets),
        "runtime_execution_ready_count": len(execution_packets),
        "runtime_execution_started_count": 0,
        "runtime_execution_completed_count": 0,
        "executable_plan_ready_count": 0,
        "llm_call_ready_count": 0,
        "iem_mutation_ready_count": 0,
        "normative_mutation_ready_count": 0,
    }
    _require_bool("executable_plan_blocked", metrics["executable_plan_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("llm_calls_blocked", metrics["llm_call_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("iem_mutation_blocked", metrics["iem_mutation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("normative_mutation_blocked", metrics["normative_mutation_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _execution_decision(
        passed,
        execution_packets,
        pending_ack_packets,
        pending_start_packets,
        blocked_start_candidates,
        blocked_execution_candidates,
    )
    runtime_execution_allowed = passed and bool(execution_packets)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "runtime_start_artifact_gate_path": str(runtime_start_artifact_gate_path),
        "checks": checks,
        "readiness": {
            "runtime_execution_gate_evaluated": passed,
            "production_runtime_start_artifacts_complete": _production_start_complete(start_artifact_readiness),
            "local_controlled_runtime_start_artifacts_complete": _local_start_complete(start_artifact_readiness),
            "runtime_execution_acknowledged": ack_runtime_execution,
            "local_controlled_runtime_execution_allowed_by_flag": allow_local_controlled_execution,
            "runtime_start_ready": runtime_execution_allowed,
            "runtime_execution_ready": runtime_execution_allowed,
            "runtime_execution_started": False,
            "runtime_execution_completed": False,
            "executable_plan_ready": False,
            "llm_planning_ready": False,
            "iem_value_mutation_ready": False,
            "normative_local_mutation_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, execution_packets, pending_ack_packets, pending_start_packets, blocked_execution_candidates),
        },
        "runtime_execution_boundary": {
            "artifact_only": not runtime_execution_allowed,
            "controlled_runtime_execution_packet_allowed": runtime_execution_allowed,
            "production_runtime_execution_packet_allowed": runtime_execution_allowed and _all_packets_origin(execution_packets, "production"),
            "local_controlled_runtime_execution_packet_allowed": runtime_execution_allowed and _any_packet_origin(execution_packets, "local_controlled"),
            "runtime_start_allowed": runtime_execution_allowed,
            "runtime_execution_allowed": runtime_execution_allowed,
            "runtime_execution_performed": False,
            "goal_emission_allowed": runtime_execution_allowed,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
            "external_system_mutation_allowed": False,
        },
        "runtime_execution_policy": {
            "requires_production_runtime_start_artifacts": True,
            "requires_allow_local_controlled_execution_for_local_inputs": True,
            "requires_runtime_execution_ack": True,
            "ack_flag": "--ack-runtime-execution",
            "local_controlled_ack_flag": "--allow-local-controlled-execution",
            "allowed_action": "record_h3_controlled_runtime_execution_receipt",
            "forbidden_actions": [
                "llm_planning",
                "iem_value_mutation",
                "normative_local_mutation",
                "external_system_mutation",
                "arbitrary_shell_command",
            ],
        },
        "runtime_execution_surface": {
            "mode": "controlled_runtime_execution_packet_gate",
            "runtime_execution_packet_count": len(execution_packets),
            "runtime_execution_packets": execution_packets,
            "pending_runtime_execution_ack_count": len(pending_ack_packets),
            "pending_runtime_execution_ack_packets": pending_ack_packets,
            "blocked_runtime_execution_candidate_count": len(blocked_execution_candidates),
            "blocked_runtime_execution_candidates": blocked_execution_candidates,
            "runtime_execution_receipts": [],
        },
        "metrics": metrics,
        "evidence": {
            "runtime_start_artifact_readiness": start_artifact_readiness,
            "runtime_start_artifact_boundary": start_artifact_boundary,
        },
        "non_claims": [
            "does_not_execute_runtime_packets",
            "does_not_start_agent_loop",
            "does_not_call_llms_or_train_models",
            "does_not_generate_arbitrary_executable_plans",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_synthetic_start_artifacts_as_execution_ready",
            "does_not_treat_local_controlled_start_artifacts_as_production_execution_ready",
            "does_not_execute_without_explicit_runtime_execution_ack",
        ],
    }


def _require_start_artifact_readiness(readiness: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    valid_decisions = {
        "runtime_start_artifacts_blocked_no_runtime_start_packets",
        "runtime_start_artifacts_blocked_synthetic_or_blocked_start",
        "runtime_start_artifacts_blocked_pending_required_artifacts",
        "production_runtime_start_artifacts_reviewed_no_runtime",
        "synthetic_runtime_start_artifacts_reviewed_no_runtime",
        "partial_runtime_start_artifacts_reviewed_no_runtime",
        "partial_synthetic_runtime_start_artifacts_reviewed_no_runtime",
        "local_controlled_runtime_start_artifacts_reviewed_no_runtime",
        "partial_local_controlled_runtime_start_artifacts_reviewed_no_runtime",
    }
    _require_bool("runtime_start_artifact_decision_known", str(readiness.get("decision") or "") in valid_decisions, checks=checks, failures=failures)
    _require_bool("runtime_start_artifact_runtime_start_blocked", readiness.get("runtime_start_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_start_artifact_runtime_execution_blocked", readiness.get("runtime_execution_ready") is False, checks=checks, failures=failures)
    _require_bool("runtime_start_artifact_executable_goal_blocked", readiness.get("executable_goal_ready") is False, checks=checks, failures=failures)


def _require_start_artifact_boundary(boundary: dict[str, Any], *, checks: dict[str, bool], failures: list[str]) -> None:
    _require_bool("runtime_start_artifact_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in UPSTREAM_BLOCKING_FLAGS:
        _require_bool(f"runtime_start_artifact_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_reviewed_start_packet_shape(packets: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not packets:
        checks["reviewed_runtime_start_packets_optional_or_present"] = True
        return
    _require_bool("reviewed_runtime_start_packet_state_valid", all(packet.get("state") == "runtime_start_artifacts_reviewed_no_runtime" for packet in packets), checks=checks, failures=failures)
    _require_bool("reviewed_runtime_start_packet_origin_known", all(_packet_origin(packet) in {"production", "local_controlled"} for packet in packets), checks=checks, failures=failures)
    _require_bool("reviewed_runtime_start_packet_not_synthetic", all(packet.get("synthetic_runtime_start_fixture") is not True for packet in packets), checks=checks, failures=failures)
    _require_bool("reviewed_runtime_start_packet_execution_disabled", all(_upstream_execution_disabled(_object(packet.get("execution_policy"))) for packet in packets), checks=checks, failures=failures)
    _require_bool("reviewed_runtime_start_packet_runtime_blocked", all(_reviewed_packet_runtime_blocked(packet) for packet in packets), checks=checks, failures=failures)
    _require_bool("reviewed_runtime_start_packet_refs_complete", all(_runtime_start_refs_complete(_object(packet.get("runtime_start_artifact_refs"))) for packet in packets), checks=checks, failures=failures)


def _require_pending_start_packet_shape(packets: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not packets:
        checks["pending_runtime_start_packets_optional_or_present"] = True
        return
    _require_bool("pending_runtime_start_packet_state_valid", all(packet.get("state") == "runtime_start_review_required" for packet in packets), checks=checks, failures=failures)


def _require_blocked_start_shape(candidates: list[dict[str, Any]], *, checks: dict[str, bool], failures: list[str]) -> None:
    if not candidates:
        checks["blocked_runtime_start_candidates_optional_or_present"] = True
        return
    _require_bool("blocked_runtime_start_candidate_state_valid", all(candidate.get("state") == "runtime_start_blocked" for candidate in candidates), checks=checks, failures=failures)


def _require_start_artifact_packet_consistency(
    readiness: dict[str, Any],
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_candidates: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    decision = str(readiness.get("decision") or "")
    production_ready = decision == "production_runtime_start_artifacts_reviewed_no_runtime"
    synthetic_ready = decision == "synthetic_runtime_start_artifacts_reviewed_no_runtime"
    local_ready = decision == "local_controlled_runtime_start_artifacts_reviewed_no_runtime"
    pending = decision == "runtime_start_artifacts_blocked_pending_required_artifacts"
    blocked = decision == "runtime_start_artifacts_blocked_synthetic_or_blocked_start"
    _require_bool(
        "runtime_start_artifact_reviewed_packet_decision_consistent",
        bool(reviewed_packets) == (production_ready or synthetic_ready or local_ready or decision.startswith("partial_")),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_start_artifact_pending_packet_decision_consistent",
        bool(pending_packets) == pending or (decision.startswith("partial_") and bool(pending_packets)),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "runtime_start_artifact_blocked_candidate_decision_consistent",
        bool(blocked_candidates) == blocked,
        checks=checks,
        failures=failures,
    )


def _evaluate_execution_packets(
    reviewed_packets: list[dict[str, Any]],
    pending_packets: list[dict[str, Any]],
    blocked_start_candidates: list[dict[str, Any]],
    ack_runtime_execution: bool,
    allow_local_controlled_execution: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    if pending_packets:
        return [], [], [_blocked_from_pending(packet, "runtime start artifacts incomplete") for packet in pending_packets]
    if blocked_start_candidates:
        return [], [], [_blocked_from_start_candidate(candidate) for candidate in blocked_start_candidates]
    if not reviewed_packets:
        return [], [], []
    if not ack_runtime_execution:
        return [], [_pending_execution_ack(packet) for packet in reviewed_packets], []
    execution_packets = []
    blocked_candidates = []
    for packet in reviewed_packets:
        origin = _packet_origin(packet)
        if origin == "local_controlled" and not allow_local_controlled_execution:
            blocked_candidates.append(_blocked_from_reviewed(packet, "local controlled start artifacts require --allow-local-controlled-execution"))
            continue
        if origin == "invalid":
            blocked_candidates.append(_blocked_from_reviewed(packet, "runtime start artifacts are not production or local controlled execution ready"))
            continue
        execution_packets.append(_execution_packet(packet, origin))
    return execution_packets, [], blocked_candidates


def _execution_packet(packet: dict[str, Any], origin: str) -> dict[str, Any]:
    goal_id = str(packet.get("goal_id") or "unknown")
    return {
        "runtime_execution_packet_id": f"h3-runtime-execution:{goal_id}",
        "runtime_start_artifact_review_id": packet.get("artifact_review_id"),
        "runtime_start_packet_id": packet.get("runtime_start_packet_id"),
        "runtime_activation_artifact_review_id": packet.get("runtime_activation_artifact_review_id"),
        "runtime_activation_packet_id": packet.get("runtime_activation_packet_id"),
        "activation_packet_id": packet.get("activation_packet_id"),
        "preflight_id": packet.get("preflight_id"),
        "approval_id": packet.get("approval_id"),
        "goal_id": goal_id,
        "state": "runtime_execution_packet_ready",
        "execution_origin": origin,
        "production_runtime_execution": origin == "production",
        "local_controlled_runtime_execution": origin == "local_controlled",
        "action": "record_h3_controlled_runtime_execution_receipt",
        "runtime_start_artifact_refs": _object(packet.get("runtime_start_artifact_refs")),
        "execution_scope": {
            "mode": "local_controlled_receipt_execution",
            "allowed_actions": ["write_runtime_execution_receipt"],
            "forbidden_actions": [
                "llm_call",
                "agent_loop_start",
                "iem_value_mutation",
                "normative_local_mutation",
                "external_system_mutation",
            ],
        },
        "execution_policy": {
            "runtime_start_allowed": True,
            "runtime_execution_allowed": True,
            "goal_emission_allowed": True,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "gate_status": {
            "runtime_start_ready": True,
            "runtime_execution_ready": True,
            "runtime_execution_started": False,
            "runtime_execution_completed": False,
            "executable_plan_ready": False,
        },
    }


def _pending_execution_ack(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "runtime_start_artifact_review_id": packet.get("artifact_review_id"),
        "goal_id": packet.get("goal_id"),
        "state": "runtime_execution_ack_required",
        "missing_ack": "ack-runtime-execution",
        "blocked_transition": {
            "transition": "runtime_start_artifacts_reviewed -> runtime_execution_packet_ready",
            "reason": "explicit runtime execution acknowledgement is required",
        },
    }


def _blocked_from_reviewed(packet: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "runtime_start_artifact_review_id": packet.get("artifact_review_id"),
        "goal_id": packet.get("goal_id"),
        "state": "runtime_execution_blocked",
        "blocked_reason": reason,
        "runtime_execution_allowed": False,
    }


def _blocked_from_pending(packet: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "runtime_start_packet_id": packet.get("runtime_start_packet_id"),
        "goal_id": packet.get("goal_id"),
        "state": "runtime_execution_blocked",
        "blocked_reason": reason,
        "runtime_execution_allowed": False,
    }


def _blocked_from_start_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "runtime_start_packet_id": candidate.get("runtime_start_packet_id"),
        "goal_id": candidate.get("goal_id"),
        "state": "runtime_execution_blocked",
        "blocked_reason": candidate.get("blocked_reason") or "runtime start candidate blocked upstream",
        "runtime_execution_allowed": False,
    }


def _execution_decision(
    passed: bool,
    execution_packets: list[dict[str, Any]],
    pending_ack_packets: list[dict[str, Any]],
    pending_start_packets: list[dict[str, Any]],
    blocked_start_candidates: list[dict[str, Any]],
    blocked_execution_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_h3_goal_emission_runtime_execution_gate"
    if execution_packets:
        if _all_packets_origin(execution_packets, "local_controlled"):
            return "local_controlled_runtime_execution_packets_ready"
        return "runtime_execution_packets_ready"
    if pending_ack_packets:
        return "runtime_execution_blocked_pending_operator_ack"
    if pending_start_packets:
        return "runtime_execution_blocked_pending_start_artifacts"
    if blocked_start_candidates or blocked_execution_candidates:
        return "runtime_execution_blocked_synthetic_or_blocked_start"
    return "runtime_execution_blocked_no_reviewed_start_artifacts"


def _allowed_scope(
    passed: bool,
    execution_packets: list[dict[str, Any]],
    pending_ack_packets: list[dict[str, Any]],
    pending_start_packets: list[dict[str, Any]],
    blocked_execution_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not evaluate runtime execution until runtime start artifacts are valid"
    if execution_packets:
        return "controlled runtime execution packets may be executed by the explicit executor only"
    if pending_ack_packets:
        return "runtime execution waits for explicit operator acknowledgement"
    if pending_start_packets:
        return "runtime execution waits for complete runtime start artifacts"
    if blocked_execution_candidates:
        return "runtime execution remains blocked by upstream start candidates"
    return "runtime execution has no reviewed runtime start artifacts to execute"


def _production_start_complete(readiness: dict[str, Any]) -> bool:
    return (
        readiness.get("decision") == "production_runtime_start_artifacts_reviewed_no_runtime"
        and readiness.get("production_runtime_start_artifacts_complete") is True
    )


def _local_start_complete(readiness: dict[str, Any]) -> bool:
    return (
        readiness.get("decision") == "local_controlled_runtime_start_artifacts_reviewed_no_runtime"
        and readiness.get("local_controlled_runtime_start_artifacts_complete") is True
    )


def _packet_origin(packet: dict[str, Any]) -> str:
    if packet.get("production_runtime_start_artifacts_ready") is True and packet.get("synthetic_runtime_start_fixture") is not True and packet.get("local_controlled_runtime_start_fixture") is not True:
        return "production"
    if packet.get("local_controlled_runtime_start_artifacts_ready") is True or packet.get("local_controlled_runtime_start_fixture") is True:
        return "local_controlled"
    return "invalid"


def _all_packets_origin(packets: list[dict[str, Any]], origin: str) -> bool:
    return bool(packets) and all(packet.get("execution_origin") == origin for packet in packets)


def _any_packet_origin(packets: list[dict[str, Any]], origin: str) -> bool:
    return any(packet.get("execution_origin") == origin for packet in packets)


def _upstream_execution_disabled(policy: dict[str, Any]) -> bool:
    return all(policy.get(flag) is False for flag in [
        "runtime_execution_allowed",
        "goal_emission_allowed",
        "executable_plan_allowed",
        "llm_planning_allowed",
        "iem_value_mutation_allowed",
        "normative_local_mutation_allowed",
    ])


def _reviewed_packet_runtime_blocked(packet: dict[str, Any]) -> bool:
    gate_status = _object(packet.get("gate_status"))
    return gate_status.get("runtime_start_ready") is False and gate_status.get("runtime_execution_ready") is False


def _runtime_start_refs_complete(refs: dict[str, Any]) -> bool:
    return all(str(refs.get(kind) or "").strip() for kind in REQUIRED_RUNTIME_START_CONTROL_KINDS)


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
    parser.add_argument("--runtime-start-artifact-gate", required=True)
    parser.add_argument("--ack-runtime-execution", action="store_true")
    parser.add_argument("--allow-local-controlled-execution", action="store_true")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_runtime_execution_gate(
        runtime_start_artifact_gate_path=Path(args.runtime_start_artifact_gate),
        agent_root=agent_root,
        ack_runtime_execution=args.ack_runtime_execution,
        allow_local_controlled_execution=args.allow_local_controlled_execution,
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