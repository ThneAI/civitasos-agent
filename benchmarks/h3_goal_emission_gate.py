"""H.3 goal emission gate skeleton.

This artifact-only gate reads H.3 approval artifacts and evaluates whether any
approved candidates are eligible for a future goal-emission stage. It does not
emit goals, generate executable plans, start runtime components, call LLMs, or
mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-emission-gate:v1"
APPROVAL_GATE_SCHEMA_VERSION = "h3-goal-approval-gate:v1"
EXECUTION_POLICY_FLAGS = [
    "goal_emission_allowed",
    "executable_plan_allowed",
    "runtime_execution_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]


def build_h3_goal_emission_gate(
    *,
    approval_gate_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    approval_gate_path = _resolve_path(approval_gate_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    approval_gate = _read_json(approval_gate_path, failures)

    approval_boundary: dict[str, Any] = {}
    readiness: dict[str, Any] = {}
    approved_candidates: list[dict[str, Any]] = []
    if approval_gate is None:
        _fail(checks, failures, "approval_gate_present", f"missing H3 approval gate: {approval_gate_path}")
    else:
        checks["approval_gate_present"] = True
        _require_equal(
            "approval_gate_schema_version",
            approval_gate.get("schema_version"),
            APPROVAL_GATE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("approval_gate_passed", bool(approval_gate.get("passed")), checks=checks, failures=failures)
        readiness = _object(approval_gate.get("readiness"))
        _require_approval_readiness(readiness, checks=checks, failures=failures)
        approval_boundary = _object(approval_gate.get("approval_boundary"))
        _require_approval_boundary(approval_boundary, checks=checks, failures=failures)
        surface = _object(approval_gate.get("approval_surface"))
        _require_equal(
            "approval_surface_mode",
            surface.get("mode"),
            "approval_only_no_execution",
            checks=checks,
            failures=failures,
        )
        approved_candidates = _candidate_list(surface.get("approved_candidates"))
        _require_candidate_shape(approved_candidates, checks=checks, failures=failures)

    production_approved = readiness.get("production_approved_candidate_ready") is True
    synthetic_approved = readiness.get("synthetic_approved_candidate_ready") is True
    emission_preflight_candidates: list[dict[str, Any]] = []
    blocked_candidates: list[dict[str, Any]] = []
    if not failures and all(checks.values()) and approved_candidates:
        if production_approved:
            emission_preflight_candidates = [_emission_preflight_candidate(candidate) for candidate in approved_candidates]
        else:
            blocked_candidates = [_blocked_candidate(candidate, synthetic_approved) for candidate in approved_candidates]

    metrics = {
        "approved_candidate_count": len(approved_candidates),
        "production_approved_candidate_count": _count_production_candidates(approved_candidates),
        "synthetic_approved_candidate_count": _count_synthetic_candidates(approved_candidates),
        "emission_preflight_candidate_count": len(emission_preflight_candidates),
        "blocked_candidate_count": len(blocked_candidates),
        "emitted_goal_count": 0,
        "executable_goal_ready_count": 0,
        "runtime_execution_ready_count": 0,
    }
    _require_bool("goal_emission_blocked", metrics["emitted_goal_count"] == 0, checks=checks, failures=failures)
    _require_bool("execution_blocked", metrics["executable_goal_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_blocked", metrics["runtime_execution_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    decision = _emission_decision(passed, production_approved, synthetic_approved, emission_preflight_candidates)
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "approval_gate_path": str(approval_gate_path),
        "checks": checks,
        "readiness": {
            "goal_emission_gate_evaluated": passed,
            "production_approval_observed": passed and production_approved,
            "synthetic_approval_observed": passed and synthetic_approved,
            "goal_emission_preflight_ready": passed and bool(emission_preflight_candidates),
            "emitted_goal_ready": False,
            "executable_goal_ready": False,
            "runtime_execution_ready": False,
            "decision": decision,
            "allowed_scope": _allowed_scope(passed, production_approved, synthetic_approved, emission_preflight_candidates),
        },
        "emission_boundary": {
            "artifact_only": True,
            "goal_emission_preflight_allowed": passed and bool(emission_preflight_candidates),
            "goal_emission_allowed": False,
            "emitted_goal_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "emission_policy": {
            "requires_production_approved_candidate_ready": True,
            "rejects_synthetic_approved_candidate_surface": True,
            "requires_separate_goal_emission_activation_gate": True,
            "blocked_after_preflight": [
                "goal_emission_preflight_ready -> executable_goal_emitted",
                "executable_goal_emitted -> runtime_execution_started",
            ],
        },
        "emission_surface": {
            "mode": "preflight_only_no_goal_emission",
            "emission_preflight_candidate_count": len(emission_preflight_candidates),
            "emission_preflight_candidates": emission_preflight_candidates,
            "blocked_candidate_count": len(blocked_candidates),
            "blocked_candidates": blocked_candidates,
            "emitted_goals": [],
        },
        "metrics": metrics,
        "evidence": {
            "approval_readiness": readiness,
            "approval_boundary": approval_boundary,
        },
        "non_claims": [
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
            "does_not_treat_synthetic_approval_as_emission_ready",
        ],
    }


def _require_approval_readiness(
    readiness: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    valid_decisions = {
        "approval_blocked_pending_external_review_artifacts",
        "approved_candidate_surface_ready",
        "partial_approved_candidate_surface_ready",
        "synthetic_approved_candidate_surface_ready",
        "partial_synthetic_approved_candidate_surface_ready",
    }
    _require_bool(
        "approval_gate_decision_known",
        str(readiness.get("decision") or "") in valid_decisions,
        checks=checks,
        failures=failures,
    )
    _require_bool("approval_executable_goal_blocked", readiness.get("executable_goal_ready") is False, checks=checks, failures=failures)


def _require_approval_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("approval_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    for flag in EXECUTION_POLICY_FLAGS:
        _require_bool(f"approval_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _require_candidate_shape(
    candidates: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    if not candidates:
        checks["approved_candidates_optional_or_present"] = True
        return
    _require_bool(
        "approved_candidate_state_valid",
        all(candidate.get("state") == "approved_candidate" for candidate in candidates),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "approved_candidate_execution_disabled",
        all(_execution_policy_disabled(_object(candidate.get("execution_policy"))) for candidate in candidates),
        checks=checks,
        failures=failures,
    )
    _require_bool(
        "approved_candidate_runtime_blocked",
        all(_object(candidate.get("gate_status")).get("runtime_execution_ready") is False for candidate in candidates),
        checks=checks,
        failures=failures,
    )


def _emission_preflight_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    goal_id = str(candidate.get("goal_id") or "unknown")
    return {
        "preflight_id": f"h3-goal-emission-preflight:{goal_id}",
        "goal_id": goal_id,
        "approval_id": candidate.get("approval_id"),
        "state": "goal_emission_preflight_ready",
        "identity": candidate.get("identity"),
        "trigger_event_kind": candidate.get("trigger_event_kind"),
        "risk_class": candidate.get("risk_class"),
        "production_approval_ready": True,
        "synthetic_review_fixture": False,
        "external_artifact_refs": _object(candidate.get("external_artifact_refs")),
        "execution_policy": {flag: False for flag in EXECUTION_POLICY_FLAGS},
        "blocked_transitions": [
            {
                "transition": "goal_emission_preflight_ready -> executable_goal_emitted",
                "reason": "goal emission requires a separate activation gate after H3 emission preflight",
            },
            {
                "transition": "executable_goal_emitted -> runtime_execution_started",
                "reason": "runtime execution remains disabled in H3 emission gate",
            },
        ],
    }


def _blocked_candidate(candidate: dict[str, Any], synthetic_approved: bool) -> dict[str, Any]:
    return {
        "goal_id": candidate.get("goal_id"),
        "approval_id": candidate.get("approval_id"),
        "state": "goal_emission_blocked",
        "synthetic_review_fixture": candidate.get("synthetic_review_fixture") is True,
        "blocked_reason": (
            "synthetic approval cannot enter goal emission"
            if synthetic_approved or candidate.get("synthetic_review_fixture") is True
            else "production approval is not ready"
        ),
    }


def _emission_decision(
    passed: bool,
    production_approved: bool,
    synthetic_approved: bool,
    preflight_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "blocked_before_h3_goal_emission_gate"
    if production_approved and preflight_candidates:
        return "goal_emission_preflight_ready_no_emission"
    if synthetic_approved:
        return "goal_emission_blocked_synthetic_approval_only"
    return "goal_emission_blocked_pending_production_approval"


def _allowed_scope(
    passed: bool,
    production_approved: bool,
    synthetic_approved: bool,
    preflight_candidates: list[dict[str, Any]],
) -> str:
    if not passed:
        return "do not evaluate goal emission until approval gate artifact is valid"
    if production_approved and preflight_candidates:
        return "preflight records only; emitted goals, executable plans, and runtime remain blocked"
    if synthetic_approved:
        return "synthetic approvals remain blocked before goal emission"
    return "approval is not production-ready; goal emission remains blocked"


def _count_production_candidates(candidates: list[dict[str, Any]]) -> int:
    return sum(1 for candidate in candidates if candidate.get("production_approval_ready") is True)


def _count_synthetic_candidates(candidates: list[dict[str, Any]]) -> int:
    return sum(1 for candidate in candidates if candidate.get("synthetic_review_fixture") is True)


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
    parser.add_argument("--approval-gate", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_emission_gate(
        approval_gate_path=Path(args.approval_gate),
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