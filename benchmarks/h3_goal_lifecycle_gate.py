"""H.3 goal candidate review lifecycle gate.

This artifact-only gate reads an H.3 draft goal candidate report and prepares
review packets for human/governance/challenge/rollback handling. It does not
approve candidates, emit executable goals, generate plans, start runtime
components, call LLMs, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-lifecycle-gate:v1"
DRAFT_REPORT_SCHEMA_VERSION = "h3-goal-candidate-draft-report:v1"
REQUIRED_REVIEW_POLICY_FLAGS = [
    "human_review_required",
    "governance_review_required",
    "challenge_window_required",
    "rollback_plan_required",
    "r2r_accountability_required",
]
EXECUTION_POLICY_FLAGS = [
    "goal_emission_allowed",
    "executable_plan_allowed",
    "runtime_execution_allowed",
    "llm_planning_allowed",
    "iem_value_mutation_allowed",
    "normative_local_mutation_allowed",
]
REQUIRED_REFUSAL_CONDITIONS = [
    "missing_h1_or_h2_gate_evidence",
    "missing_human_or_governance_review",
    "missing_challenge_window",
    "attempts_normative_local_mutation",
    "attempts_runtime_execution_from_draft",
]


def build_h3_goal_lifecycle_gate(
    *,
    draft_report_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    draft_report_path = _resolve_path(draft_report_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    draft_report = _read_json(draft_report_path, failures)

    candidates: list[dict[str, Any]] = []
    draft_boundary: dict[str, Any] = {}
    vmv_stage_gate: dict[str, Any] = {}
    if draft_report is None:
        _fail(checks, failures, "draft_report_present", f"missing H3 draft report: {draft_report_path}")
    else:
        checks["draft_report_present"] = True
        _require_equal(
            "draft_report_schema_version",
            draft_report.get("schema_version"),
            DRAFT_REPORT_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("draft_report_passed", bool(draft_report.get("passed")), checks=checks, failures=failures)
        readiness = _object(draft_report.get("readiness"))
        _require_equal(
            "draft_report_decision",
            readiness.get("decision"),
            "h3_draft_goal_candidates_ready",
            checks=checks,
            failures=failures,
        )
        draft_boundary = _object(draft_report.get("h3_boundary"))
        _require_draft_boundary(draft_boundary, checks=checks, failures=failures)
        vmv_stage_gate = _object(draft_report.get("vmv_stage_gate"))
        _require_bool("vmv_stage_gate_passed", vmv_stage_gate.get("passed") is True, checks=checks, failures=failures)
        surface = _object(draft_report.get("goal_candidate_surface"))
        _require_equal("goal_candidate_surface_mode", surface.get("mode"), "draft_only", checks=checks, failures=failures)
        candidates = _candidate_list(surface.get("candidate_goals"))
        _require_bool("draft_candidates_present", bool(candidates), checks=checks, failures=failures)

    candidate_checks = _candidate_checks(candidates)
    for name, value in candidate_checks.items():
        _require_bool(f"candidate_{name}", value, checks=checks, failures=failures)

    review_packets: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        review_packets = [_review_packet(candidate) for candidate in candidates]
    _require_bool("review_packets_present", bool(review_packets), checks=checks, failures=failures)

    metrics = {
        "draft_candidate_count": len(candidates),
        "review_packet_count": len(review_packets),
        "approval_ready_count": 0,
        "executable_goal_ready_count": 0,
        "runtime_execution_ready_count": 0,
    }
    _require_bool("approval_blocked_by_default", metrics["approval_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("execution_blocked_by_default", metrics["executable_goal_ready_count"] == 0, checks=checks, failures=failures)
    _require_bool("runtime_blocked_by_default", metrics["runtime_execution_ready_count"] == 0, checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "draft_report_path": str(draft_report_path),
        "checks": checks,
        "readiness": {
            "review_lifecycle_ready": passed,
            "approval_ready": False,
            "executable_goal_ready": False,
            "decision": "h3_review_lifecycle_ready" if passed else "blocked_before_h3_review_lifecycle",
            "allowed_scope": (
                "review packets only; approval and execution remain blocked"
                if passed
                else "do not open H3 review lifecycle until draft candidate gate passes"
            ),
        },
        "lifecycle_boundary": {
            "artifact_only": True,
            "review_packets_allowed": passed,
            "approval_allowed": False,
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "lifecycle_policy": {
            "states": [
                "draft_review_required",
                "review_packet_ready",
                "human_review_pending",
                "governance_review_pending",
                "challenge_window_pending",
                "rollback_plan_pending",
            ],
            "terminal_blocked_states": [
                "approved_candidate",
                "executable_goal_emitted",
                "runtime_execution_started",
            ],
            "approval_requires_external_artifacts": [
                "human_review_record",
                "governance_review_record",
                "challenge_window_result",
                "rollback_plan_record",
                "r2r_accountability_record",
            ],
        },
        "review_packet_surface": {
            "mode": "review_only",
            "review_packet_count": len(review_packets),
            "review_packets": review_packets,
        },
        "metrics": metrics,
        "evidence": {
            "draft_boundary": draft_boundary,
            "vmv_stage_gate": vmv_stage_gate,
        },
        "non_claims": [
            "does_not_approve_goal_candidates",
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
        ],
    }


def _require_draft_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("draft_boundary_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    _require_bool("draft_candidates_allowed", boundary.get("draft_goal_candidates_allowed") is True, checks=checks, failures=failures)
    for flag in EXECUTION_POLICY_FLAGS:
        _require_bool(f"draft_boundary_{flag}_false", boundary.get(flag) is False, checks=checks, failures=failures)


def _candidate_checks(candidates: list[dict[str, Any]]) -> dict[str, bool]:
    return {
        "states_are_review_required": bool(candidates)
        and all(candidate.get("state") == "draft_review_required" for candidate in candidates),
        "execution_policy_disabled": bool(candidates) and all(_execution_disabled(candidate) for candidate in candidates),
        "review_policy_complete": bool(candidates) and all(_review_policy_complete(candidate) for candidate in candidates),
        "evidence_backend_sourced": bool(candidates) and all(_candidate_evidence_valid(candidate) for candidate in candidates),
        "refusal_conditions_complete": bool(candidates) and all(_refusal_conditions_complete(candidate) for candidate in candidates),
    }


def _review_packet(candidate: dict[str, Any]) -> dict[str, Any]:
    goal_id = str(candidate.get("goal_id") or "unknown")
    return {
        "packet_id": f"h3-review-packet:{goal_id}",
        "goal_id": goal_id,
        "candidate_state": candidate.get("state"),
        "lifecycle_state": "review_packet_ready",
        "trigger_event_kind": candidate.get("trigger_event_kind"),
        "identity": candidate.get("identity"),
        "risk_class": candidate.get("risk_class"),
        "review_policy": _object(candidate.get("review_policy")),
        "execution_policy": {flag: False for flag in EXECUTION_POLICY_FLAGS},
        "evidence_ref": _object(candidate.get("evidence")),
        "required_external_artifacts": {
            "human_review_record": "required_before_approval",
            "governance_review_record": "required_before_approval",
            "challenge_window_result": "required_before_approval",
            "rollback_plan_record": "required_before_approval",
            "r2r_accountability_record": "required_before_approval",
        },
        "allowed_transitions": [
            "draft_review_required -> review_packet_ready",
            "review_packet_ready -> human_review_pending",
            "review_packet_ready -> governance_review_pending",
            "review_packet_ready -> challenge_window_pending",
            "review_packet_ready -> rollback_plan_pending",
        ],
        "blocked_transitions": [
            {
                "transition": "review_packet_ready -> approved_candidate",
                "reason": "missing required human/governance/challenge/rollback/R2R artifacts",
            },
            {
                "transition": "approved_candidate -> executable_goal_emitted",
                "reason": "goal emission remains disabled in H3 lifecycle gate",
            },
            {
                "transition": "executable_goal_emitted -> runtime_execution_started",
                "reason": "runtime execution remains disabled in H3 lifecycle gate",
            },
        ],
        "gate_status": {
            "review_packet_ready": True,
            "approval_ready": False,
            "executable_goal_ready": False,
            "runtime_execution_ready": False,
        },
    }


def _candidate_evidence_valid(candidate: dict[str, Any]) -> bool:
    evidence = _object(candidate.get("evidence"))
    return (
        evidence.get("backend_sourced") is True
        and bool(_string_list(evidence.get("sources")))
        and bool(_string_list(evidence.get("record_ids")))
        and (_int(evidence.get("max_pattern_count")) or 0) >= 2
    )


def _execution_disabled(candidate: dict[str, Any]) -> bool:
    execution_policy = _object(candidate.get("execution_policy"))
    return all(execution_policy.get(flag) is False for flag in EXECUTION_POLICY_FLAGS)


def _review_policy_complete(candidate: dict[str, Any]) -> bool:
    review_policy = _object(candidate.get("review_policy"))
    return all(review_policy.get(flag) is True for flag in REQUIRED_REVIEW_POLICY_FLAGS)


def _refusal_conditions_complete(candidate: dict[str, Any]) -> bool:
    observed = set(_string_list(candidate.get("refusal_conditions")))
    return all(condition in observed for condition in REQUIRED_REFUSAL_CONDITIONS)


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


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item or "").strip() for item in value if str(item or "").strip()]


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


def _int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft-report", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = build_h3_goal_lifecycle_gate(
        draft_report_path=Path(args.draft_report),
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