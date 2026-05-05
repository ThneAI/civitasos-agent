"""H.3 draft goal candidate report.

This report is artifact-only. It reads an H.3 skeleton report plus the referenced
H.2-E closure report, then derives non-executable draft goal candidates from
backend-sourced repeated outcome patterns. It does not emit executable goals,
start runtime components, call LLMs, or mutate IEM/value state.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-goal-candidate-draft-report:v1"
H3_SKELETON_SCHEMA_VERSION = "h3-goal-generator-skeleton:v1"
H2_CLOSURE_SCHEMA_VERSION = "h2-value-calibration-closure:v1"
BACKEND_REPEATED_PATTERN_SOURCES = {
    "backend_task_pool_read_model",
    "backend_protocol_upgrade_read_model",
    "backend_economic_read_model",
}
STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS = [
    "post_delivery_dispute",
    "post_delivery_failure",
    "relation_repair_relapse",
    "governance_rollback",
    "economic_deviation",
]
_EVENT_KIND_ORDER = {
    event_kind: index for index, event_kind in enumerate(STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS)
}
_EVENT_KIND_POLICIES = {
    "post_delivery_dispute": {
        "goal_kind": "reduce_post_delivery_dispute_risk",
        "risk_class": "high",
        "title": "Draft goal: reduce repeated post-delivery disputes",
        "proposed_goal": "Reduce repeated post-delivery disputes for the affected identity while preserving challenge rights.",
    },
    "post_delivery_failure": {
        "goal_kind": "reduce_post_delivery_failure_risk",
        "risk_class": "high",
        "title": "Draft goal: reduce repeated post-delivery failures",
        "proposed_goal": "Reduce repeated post-delivery failures for the affected identity without bypassing verifier gates.",
    },
    "relation_repair_relapse": {
        "goal_kind": "stabilize_relation_repair_outcomes",
        "risk_class": "high",
        "title": "Draft goal: stabilize relation repair outcomes",
        "proposed_goal": "Reduce relapse after relation repair while preserving failure history and accountability.",
    },
    "governance_rollback": {
        "goal_kind": "stabilize_governance_rollout",
        "risk_class": "critical",
        "title": "Draft goal: review repeated governance rollback",
        "proposed_goal": "Review repeated governance rollback patterns before any future protocol rollout target is proposed.",
    },
    "economic_deviation": {
        "goal_kind": "resolve_economic_deviation_risk",
        "risk_class": "critical",
        "title": "Draft goal: resolve repeated economic deviation",
        "proposed_goal": "Reduce repeated failed-task escrow deviation while preserving settlement and arbitration evidence.",
    },
}


def build_h3_goal_candidate_draft_report(
    *,
    h3_skeleton_report_path: Path,
    agent_root: Path,
    max_candidate_goals: int = 10,
) -> dict[str, Any]:
    h3_skeleton_report_path = _resolve_path(h3_skeleton_report_path, agent_root)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    skeleton = _read_json(h3_skeleton_report_path, failures)

    h3_readiness: dict[str, Any] = {}
    h3_boundary: dict[str, Any] = {}
    h2_closure_report_path: Path | None = None
    if skeleton is None:
        _fail(checks, failures, "h3_skeleton_present", f"missing H3 skeleton report: {h3_skeleton_report_path}")
    else:
        checks["h3_skeleton_present"] = True
        _require_equal(
            "h3_skeleton_schema_version",
            skeleton.get("schema_version"),
            H3_SKELETON_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("h3_skeleton_passed", bool(skeleton.get("passed")), checks=checks, failures=failures)
        h3_readiness = _object(skeleton.get("readiness"))
        h3_boundary = _object(skeleton.get("h3_boundary"))
        _require_bool(
            "h3_minimum_skeleton_ready",
            h3_readiness.get("minimum_skeleton_ready") is True,
            checks=checks,
            failures=failures,
        )
        _require_bool(
            "h3_full_behavior_evidence_ready",
            h3_readiness.get("full_goal_generator_behavior_ready") is True,
            checks=checks,
            failures=failures,
        )
        _require_h3_boundary(h3_boundary, checks=checks, failures=failures)
        h2_closure_report_path = _h2_closure_path_from_skeleton(skeleton, agent_root, failures)
        checks["h2_closure_path_present"] = h2_closure_report_path is not None

    closure: dict[str, Any] | None = None
    if h2_closure_report_path is not None:
        closure = _read_json(h2_closure_report_path, failures)
    if h2_closure_report_path is not None and closure is None:
        _fail(checks, failures, "h2_closure_present", f"missing H2 closure report: {h2_closure_report_path}")
    elif closure is not None:
        checks["h2_closure_present"] = True
        _require_equal(
            "h2_closure_schema_version",
            closure.get("schema_version"),
            H2_CLOSURE_SCHEMA_VERSION,
            checks=checks,
            failures=failures,
        )
        _require_bool("h2_closure_passed", bool(closure.get("passed")), checks=checks, failures=failures)
        _require_h2_boundary(_object(closure.get("closure_boundary")), checks=checks, failures=failures)

    evidence = _object(closure.get("evidence")) if closure else {}
    value_report = _object(evidence.get("value_report"))
    metrics = _object(value_report.get("metrics"))
    repeated_patterns = _backend_sourced_repeated_patterns(metrics.get("repeated_outcome_patterns"))
    repeated_event_kinds = _event_kinds(pattern.get("event_kind") for pattern in repeated_patterns)
    missing_backend_kinds = _missing_event_kinds(STANDARD_REQUIRED_REPEATED_OUTCOME_EVENT_KINDS, repeated_event_kinds)
    _require_bool("h2_value_report_embedded", bool(value_report), checks=checks, failures=failures)
    _require_bool(
        "backend_sourced_repeated_outcome_patterns_present",
        bool(repeated_patterns),
        checks=checks,
        failures=failures,
    )
    _require_missing_event_kinds(
        "standard_backend_sourced_repeated_outcome_event_kinds",
        missing_backend_kinds,
        checks=checks,
        failures=failures,
    )
    _require_bool("max_candidate_goals_positive", max_candidate_goals > 0, checks=checks, failures=failures)

    candidates = []
    if not failures and all(checks.values()):
        candidates = _draft_goal_candidates(repeated_patterns, max_candidate_goals=max_candidate_goals)
    _require_bool("draft_goal_candidates_present", bool(candidates), checks=checks, failures=failures)

    vmv_stage_gate = _vmv_stage_gate(candidates)
    for name, value in vmv_stage_gate["checks"].items():
        _require_bool(f"vmv_gate_{name}", bool(value), checks=checks, failures=failures)

    passed = not failures and all(checks.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "h3_skeleton_report_path": str(h3_skeleton_report_path),
        "h2_closure_report_path": str(h2_closure_report_path) if h2_closure_report_path else None,
        "checks": checks,
        "readiness": {
            "draft_candidate_surface_ready": passed,
            "decision": "h3_draft_goal_candidates_ready" if passed else "blocked_before_h3_draft_goal_candidates",
            "allowed_scope": (
                "draft-only goal candidate surface; no executable goal emission"
                if passed
                else "do not surface draft goal candidates until H3 skeleton and H2-E evidence gates pass"
            ),
        },
        "h3_boundary": {
            "artifact_only": True,
            "draft_goal_candidates_allowed": passed,
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "goal_candidate_surface": {
            "mode": "draft_only",
            "candidate_goal_count": len(candidates),
            "candidate_goals": candidates,
        },
        "vmv_stage_gate": vmv_stage_gate,
        "evidence": {
            "h3_readiness": h3_readiness,
            "h3_boundary": h3_boundary,
            "backend_sourced_repeated_outcome_event_kinds": repeated_event_kinds,
            "missing_backend_sourced_repeated_outcome_event_kinds": missing_backend_kinds,
            "backend_sourced_repeated_outcome_patterns": repeated_patterns,
            "value_metrics": metrics,
        },
        "non_claims": [
            "does_not_emit_executable_goals",
            "does_not_generate_executable_plans",
            "does_not_start_runtime_or_agents",
            "does_not_call_llms_or_train_models",
            "does_not_mutate_iem_or_normative_state",
            "does_not_replace_human_or_governance_review",
        ],
    }


def _require_h3_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("h3_goal_emission_disallowed", boundary.get("goal_emission_allowed") is False, checks=checks, failures=failures)
    _require_bool("h3_runtime_execution_disallowed", boundary.get("runtime_execution_allowed") is False, checks=checks, failures=failures)
    _require_bool("h3_llm_planning_disallowed", boundary.get("llm_planning_allowed") is False, checks=checks, failures=failures)
    _require_bool("h3_iem_mutation_disallowed", boundary.get("iem_value_mutation_allowed") is False, checks=checks, failures=failures)
    _require_bool("h3_normative_mutation_disallowed", boundary.get("normative_local_mutation_allowed") is False, checks=checks, failures=failures)


def _require_h2_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require_bool("h2_closure_artifact_only", boundary.get("artifact_only") is True, checks=checks, failures=failures)
    _require_bool("h2_runtime_mutation_disallowed", boundary.get("runtime_mutation_allowed") is False, checks=checks, failures=failures)
    _require_bool("h2_normative_mutation_disallowed", boundary.get("normative_local_mutation_allowed") is False, checks=checks, failures=failures)
    _require_bool(
        "h2_seed_patterns_not_counted_as_backend_readiness",
        boundary.get("seed_patterns_count_as_h3_backend_readiness") is False,
        checks=checks,
        failures=failures,
    )


def _h2_closure_path_from_skeleton(
    skeleton: dict[str, Any],
    agent_root: Path,
    failures: list[str],
) -> Path | None:
    raw = str(skeleton.get("h2_closure_report_path") or "").strip()
    if not raw:
        failures.append("h3 skeleton missing h2_closure_report_path")
        return None
    return _resolve_path(Path(raw), agent_root)


def _backend_sourced_repeated_patterns(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    patterns: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        sources = _string_list(item.get("sources"))
        if not any(source in BACKEND_REPEATED_PATTERN_SOURCES for source in sources):
            continue
        event_kind = str(item.get("event_kind") or "").strip()
        identity = str(item.get("identity") or "").strip()
        if not event_kind or not identity:
            continue
        patterns.append(
            {
                "identity": identity,
                "event_kind": event_kind,
                "max_pattern_count": _int(item.get("max_pattern_count")) or 0,
                "candidate_count": _int(item.get("candidate_count")) or 0,
                "record_ids": sorted(_string_list(item.get("record_ids"))),
                "sources": sorted(sources),
            }
        )
    return sorted(patterns, key=_pattern_sort_key)


def _draft_goal_candidates(
    patterns: list[dict[str, Any]],
    *,
    max_candidate_goals: int,
) -> list[dict[str, Any]]:
    return [_draft_goal_candidate(pattern) for pattern in patterns[:max_candidate_goals]]


def _draft_goal_candidate(pattern: dict[str, Any]) -> dict[str, Any]:
    event_kind = str(pattern.get("event_kind") or "unknown")
    identity = str(pattern.get("identity") or "unknown")
    policy = _EVENT_KIND_POLICIES.get(
        event_kind,
        {
            "goal_kind": "review_repeated_outcome_pattern",
            "risk_class": "high",
            "title": "Draft goal: review repeated outcome pattern",
            "proposed_goal": "Review repeated backend-sourced outcome evidence before any executable goal is proposed.",
        },
    )
    evidence = {
        "identity": identity,
        "event_kind": event_kind,
        "max_pattern_count": _int(pattern.get("max_pattern_count")) or 0,
        "candidate_count": _int(pattern.get("candidate_count")) or 0,
        "record_ids": sorted(_string_list(pattern.get("record_ids"))),
        "sources": sorted(_string_list(pattern.get("sources"))),
        "backend_sourced": True,
    }
    return {
        "goal_id": f"h3-draft-goal:{event_kind}:{_slug(identity)}",
        "state": "draft_review_required",
        "goal_kind": policy["goal_kind"],
        "title": policy["title"],
        "identity": identity,
        "trigger_event_kind": event_kind,
        "risk_class": policy["risk_class"],
        "proposed_goal": policy["proposed_goal"],
        "evidence": evidence,
        "review_policy": {
            "human_review_required": True,
            "governance_review_required": True,
            "challenge_window_required": True,
            "rollback_plan_required": True,
            "r2r_accountability_required": True,
        },
        "execution_policy": {
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_value_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "vmv_alignment": {
            "human_sovereignty": "requires human and governance review before any executable behavior",
            "rules_before_capability": "draft remains non-executable even when evidence gate is ready",
            "verifiable_truth": "candidate is grounded in backend-sourced repeated outcome evidence",
            "non_disappearing_accountability": "record_ids and challenge requirements are preserved",
            "safety_over_efficiency": "runtime execution and LLM planning are disabled at draft stage",
            "long_termism": "candidate requires repeated outcome patterns, not a single event",
            "incremental_evolution": "candidate surface advances one artifact-only stage",
            "open_collaboration_with_security_boundaries": "review path preserves governance and challenge boundaries",
        },
        "refusal_conditions": [
            "missing_h1_or_h2_gate_evidence",
            "missing_human_or_governance_review",
            "missing_challenge_window",
            "attempts_normative_local_mutation",
            "attempts_runtime_execution_from_draft",
        ],
    }


def _vmv_stage_gate(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    checks = {
        "human_sovereignty": all(_review_policy(candidate).get("human_review_required") is True for candidate in candidates),
        "rules_before_capability": all(candidate.get("state") == "draft_review_required" and _execution_disabled(candidate) for candidate in candidates),
        "verifiable_truth": all(_evidence(candidate).get("backend_sourced") is True and _evidence(candidate).get("sources") for candidate in candidates),
        "non_disappearing_accountability": all(_evidence(candidate).get("record_ids") and _review_policy(candidate).get("challenge_window_required") is True for candidate in candidates),
        "safety_over_efficiency": all(_execution_disabled(candidate) and candidate.get("refusal_conditions") for candidate in candidates),
        "long_termism": all((_int(_evidence(candidate).get("max_pattern_count")) or 0) >= 2 for candidate in candidates),
        "incremental_evolution": all(_review_policy(candidate).get("rollback_plan_required") is True for candidate in candidates),
        "open_collaboration_with_security_boundaries": all(_review_policy(candidate).get("governance_review_required") is True and _review_policy(candidate).get("r2r_accountability_required") is True for candidate in candidates),
    }
    return {
        "checks": checks,
        "passed": bool(candidates) and all(checks.values()),
        "north_star": {
            "vision": "verifiable accountable evolvable human-sovereign AI social operating system",
            "mission": "institutionalize AI execution and governance with long-term safety and rule evolution",
            "values_guarded": sorted(checks),
        },
    }


def _execution_disabled(candidate: dict[str, Any]) -> bool:
    execution_policy = _object(candidate.get("execution_policy"))
    return all(
        execution_policy.get(name) is False
        for name in (
            "goal_emission_allowed",
            "executable_plan_allowed",
            "runtime_execution_allowed",
            "llm_planning_allowed",
            "iem_value_mutation_allowed",
            "normative_local_mutation_allowed",
        )
    )


def _review_policy(candidate: dict[str, Any]) -> dict[str, Any]:
    return _object(candidate.get("review_policy"))


def _evidence(candidate: dict[str, Any]) -> dict[str, Any]:
    return _object(candidate.get("evidence"))


def _pattern_sort_key(pattern: dict[str, Any]) -> tuple[int, str, str]:
    event_kind = str(pattern.get("event_kind") or "")
    identity = str(pattern.get("identity") or "")
    return (_EVENT_KIND_ORDER.get(event_kind, len(_EVENT_KIND_ORDER)), event_kind, identity)


def _event_kinds(values: object) -> list[str]:
    if not isinstance(values, list):
        values = list(values) if values is not None else []
    return sorted({str(item or "").strip() for item in values if str(item or "").strip()})


def _missing_event_kinds(required: list[str], observed: list[str]) -> list[str]:
    observed_set = set(observed)
    return [event_kind for event_kind in required if event_kind not in observed_set]


def _require_missing_event_kinds(
    name: str,
    missing: list[str],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    checks[name] = not missing
    if missing:
        failures.append(f"missing {name}: {', '.join(missing)}")


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


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.:-]+", "-", value.strip()).strip("-")
    return slug[:96] or "unknown"


def _resolve_path(path: Path, agent_root: Path) -> Path:
    return path if path.is_absolute() else agent_root / path


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--h3-skeleton-report", required=True)
    parser.add_argument("--output", default="")
    parser.add_argument("--max-candidate-goals", type=int, default=10)
    args = parser.parse_args()

    report = build_h3_goal_candidate_draft_report(
        h3_skeleton_report_path=Path(args.h3_skeleton_report),
        agent_root=agent_root,
        max_candidate_goals=args.max_candidate_goals,
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