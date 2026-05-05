"""H.3 goal emission activation gate skeleton.

This artifact-only gate reads H.3 goal emission preflight artifacts and prepares
activation review packets only when production preflight exists. It does not
activate emission, emit goals, generate executable plans, start runtime
components, call LLMs, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-activation-gate:v1"
EMISSION_GATE_SCHEMA_VERSION = "h3-goal-emission-gate:v1"
EXECUTION_POLICY_FLAGS = [
    "goal_emission_allowed",
    "executable_plan_allowed",
    "runtime_execution_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]
REQUIRED_ACTIVATION_ARTIFACTS = [
    "human_activation_record",
    "governance_activation_record",
    "h1_h2_replay_attestation",
    "rollback_activation_ack",
    "runtime_non_execution_ack",
]


def build_h3_goal_emission_activation_gate(
    *,
    emission_gate_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    emission_gate_path = _resolve_path(emission_gate_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    emission_gate = _read_json(emission_gate_path, failures)

    emission_readiness: dict[str, Any] = {}
    emission_boundary: dict[str, Any] = {}
    preflight_candidates: list[dict[str, Any]] = []
    blocked_candidates: list[dict[str, Any]] = []
    if emission_gate is None:
        _fail(checks, failures, "emission_gate_present", f"missing H3 emission gate: {emission_gate_path}")
    else:
        checks["emission_gate_present"] = True
        _require_equal(
            "emission_gate_schema_version",
            emission_gate.get("schema_version"),
            EMISSION_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("emission_gate_passed", bool(emission_gate.get("passed")), checks=checks, failures=failures)
        emission_readiness = _object(emission_gate.get("readiness"))
        _require_emission_readiness(emission_readiness, checks=checks, failures=failures)
        emission_boundary = _object(emission_gate.get("emission_boundary"))
        _require_emission_boundary(emission_boundary, checks=checks, failures=failures)
        surface = _object(emission_gate.get("emission_surface"))
        _require_equal(
            "emission_surface_mode",
            surface.get("mode"),
            "preflight_only_no_goal_emission",
            checks=checks,
            failures=failures,
        )
        preflight_candidates = _candidate_list(surface.get("emission_preflight_candidates"))
        blocked_candidates = _candidate_list(surface.get("blocked_candidates"))
        _require_preflight_consistency(emission_readiness, preflight_candidates, checks=checks, failures=failures)
        _require_preflight_shape(preflight_candidates, checks=checks, failures=failures)
        _require_blocked_shape(blocked_candidates, checks=checks, failures=failures)

    activation_packets: list[dict[str, Any]] = []
    blocked_activation_candidates: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        activation_packets = [_activation_packet(candidate) for candidate in preflight_candidates]
        if blocked_candidates:
            blocked_activation_candidates = [_blocked_activation(candidate) for candidate in blocked_candidates]

    metrics = {
        "emission_preflight_candidate_count": len(preflight_candidates),
        "activation_packet_count": len(activation_packets),
        "blocked_activation_candidate_count": len(blocked_activation_candidates),
        "activation_ready_count": 0,
        "emitted_goal_count": 0,
        "executable_goal_ready_count": 0,
        "runtime_execution_ready_count": 0,
    }
    _require_bool("activation_blocked_by_default", metrics["activation_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("goal_emission_blocked", metrics["emitted_goal_count"] == 0, checks=checks, failures=failures)
    _require_bool("execution_blocked", metrics["executable_goal_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_blocked", metrics["runtime_execution_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _activation_decision(passed, emission_readiness, activation_packets, blocked_activation_candidates)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "emission_gate_path": str(emission_gate_path),
        "checks": checks,
        "readiness": {
            "activation_gate_evaluated": passed,
            "activation_review_packets_ready": passed and bool(activation_packets),
            "activation_ready": False,
            "emitted_goal_ready": False,
            "executable_goal_ready": False,
            "runtime_execution_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, activation_packets, blocked_activation_candidates),
        },
        "activation_boundary": {
            "artifact_only": True,
            "activation_review_packets_allowed": passed and bool(activation_packets),
            "activation_allowed": False,
            "goal_emission_allowed": False,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "activation_policy": {
            "required_activation_artifacts": REQUIRED_ACTIVATION_ARTIFACTS,
            "requires_production_goal_emission_preflight": True,
            "rejects_synthetic_approval_and_blocked_emission_candidates": True,
            "requires_separate_runtime_activation_gate": True,
            "blocked_after_activation_review": [
                "goal_emission_activation_review_required -> emitted_goal_activated",
                "emitted_goal_activated -> executable_plan_generated",
                "executable_plan_generated -> runtime_execution_started",
            ],
        },
        "activation_surface": {
            "mode": "activation_review_only_no_emission",
            "activation_packet_count": len(activation_packets),
            "activation_packets": activation_packets,
            "blocked_activation_candidate_count": len(blocked_activation_candidates),
            "blocked_activation_candidates": blocked_activation_candidates,
            "emitted_goals": [],
        },
        "metrics": metrics,
        "evidence": {
            "emission_readiness": emission_readiness,
            "emission_boundary": emission_boundary,
        },
        "non_claims": [
            "does_not_activate_goal_emission",
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
        ],
    }


def _require_emission_readiness(
    readiness: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    valid_decisions = {
        "goal_emission_blocked_pending_production_approval",
        "goal_emission_blocked_synthetic_approval_only",
        "goal_emission_preflight_ready_no_emission",
    }
    _require_bool(
        "emission_gate_decision_known",
        str(readiness.get("decision") or "") in valid_decisions,
        checks=checks,
        failures=failures,
    )
    _require_bool("emission_emitted_goal_blocked", readiness.get("emitted_goal_ready") is False, checks=checks, failures=failures)
    _require_bool("emission_executable_goal_blocked", readiness.get("executable_goal_ready") is False, checks=checks, failures=failures)
    _require_bool("emission_runtime_blocked", readiness.get("runtime_execution_ready") is False, checks=checks, failures=failures)


def _require_emission_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("emission_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    _require_bool("emission_boundary_emitted_goal_allowed_false", boundary.get("emitted_goal_allowed") is False, checks=checks, failures=failures)
    for flag in EXECUTION_POLICY_FLAGS:
        _require_bool(f"emission_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_preflight_consistency(
    readiness: dict[str, Any],
    candidates: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    decision = str(readiness.get("decision") or "")
    production_preflight_decision = decision == "goal_emission_preflight_ready_no_emission"
    _require_bool(
        "preflight_candidate_decision_consistent",
        bool(candidates) == production_preflight_decision,
        checks=checks,
        failures=failures,
    )
    if production_preflight_decision:
        _require_bool(
            "preflight_candidate_readiness_consistent",
            readiness.get("production_approval_observed") is True
            and readiness.get("goal_emission_preflight_ready") is True,
            checks=checks,
            failures=failures,
        )


def _require_preflight_shape(
    candidates: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not candidates:
        checks["preflight_candidates_optional_or_present"] = True
        return
    _require_bool(
        "preflight_candidate_state_valid",
        all(candidate.get("state") == "goal_emission_preflight_ready" for candidate in candidates),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "preflight_candidate_execution_disabled",
        all(_execution_policy_disabled(_object(candidate.get("execution_policy"))) for candidate in candidates),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "preflight_candidate_production_ready",
        all(candidate.get("production_approval_ready") is True for candidate in candidates),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "preflight_candidate_not_synthetic",
        all(candidate.get("synthetic_review_fixture") is not True for candidate in candidates),
        checks=checks,
        failures=failures,
    )


def _require_blocked_shape(
    candidates: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not candidates:
        checks["blocked_candidates_optional_or_present"] = True
        return
    _require_bool(
        "blocked_candidate_state_valid",
        all(candidate.get("state") == "goal_emission_blocked" for candidate in candidates),
        checks=checks,
        failures=failures,
    )


def _activation_packet(candidate: dict[str, Any]) -> dict[str, Any]:
    goal_id = str(candidate.get("goal_id") or "unknown")
    return {
        "activation_packet_id": f"h3-goal-emission-activation:{goal_id}",
        "preflight_id": candidate.get("preflight_id"),
        "goal_id": goal_id,
        "approval_id": candidate.get("approval_id"),
        "state": "goal_emission_activation_review_required",
        "identity": candidate.get("identity"),
        "trigger_event_kind": candidate.get("trigger_event_kind"),
        "risk_class": candidate.get("risk_class"),
        "required_activation_artifacts": {
            artifact: "required_before_emission_activation" for artifact in REQUIRED_ACTIVATION_ARTIFACTS
        },
        "external_artifact_refs": _object(candidate.get("external_artifact_refs")),
        "execution_policy": {flag: False for flag in EXECUTION_POLICY_FLAGS},
        "blocked_transitions": [
            {
                "transition": "goal_emission_activation_review_required -> emitted_goal_activated",
                "reason": "activation requires a later explicit activation artifact gate",
            },
            {
                "transition": "emitted_goal_activated -> runtime_execution_started",
                "reason": "runtime execution remains disabled in H3 activation gate",
            },
        ],
    }


def _blocked_activation(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "goal_id": candidate.get("goal_id"),
        "approval_id": candidate.get("approval_id"),
        "state": "goal_emission_activation_blocked",
        "blocked_reason": candidate.get("blocked_reason") or "goal emission preflight is not ready",
        "synthetic_review_fixture": candidate.get("synthetic_review_fixture") is True,
    }


def _activation_decision(
    passed: bool,
    emission_readiness: dict[str, Any],
    activation_packets: list[dict[str, Any]],
    blocked_activation_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_h3_goal_emission_activation_gate"
    if activation_packets:
        return "goal_emission_activation_review_packets_ready_no_activation"
    if blocked_activation_candidates or emission_readiness.get("synthetic_approval_observed") is True:
        return "goal_emission_activation_blocked_synthetic_or_blocked_emission"
    return "goal_emission_activation_blocked_no_preflight"


def _allowed_scope(
    passed: bool,
    activation_packets: list[dict[str, Any]],
    blocked_activation_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not evaluate activation until emission gate artifact is valid"
    if activation_packets:
        return "activation review packets only; no emitted goals, plans, or runtime"
    if blocked_activation_candidates:
        return "blocked activation candidates only; no activation"
    return "emission preflight is not ready; activation remains blocked"


def _execution_policy_disabled(policy: dict[str, Any]) -> bool:
    return all(policy.get(flag) is False for flag in EXECUTION_POLICY_FLAGS)


def _candidate_list(value: object) -> list[dict[str, Any]]:
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
    parser.add_argument("--emission-gate", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_activation_gate(
        emission_gate_path=Path(args.emission_gate),
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