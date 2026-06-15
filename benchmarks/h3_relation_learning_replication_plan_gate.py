"""Build a non-executable H.3 plan draft from relation-learning replication evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_bounded_plan_draft_gate import (
    GATE_BOUNDARY,
    SCHEMA_VERSION,
)
from benchmarks.h3_relation_learning_replication_gate import (
    EXPECTED_OUTCOMES,
    SCHEMA_VERSION as REPLICATION_SCHEMA_VERSION,
)


PROPOSAL_KIND = "validate_relation_learning_replication"
REQUIRED_REPLICATION_CHECKS = {
    "at_least_two_passing_source_reports",
    "at_least_two_distinct_owners",
    "at_least_six_distinct_tasks",
    "at_least_six_distinct_relation_pairs",
    "success_dispute_failure_covered",
    "at_least_three_task_kinds",
    "at_least_three_agent_providers",
    "all_records_have_explainable_provenance",
    "all_deltas_within_caps",
    "all_normative_updates_blocked",
    "different_outcomes_produce_different_post_states",
    "negative_outcome_severity_is_ordered",
    "owner_negative_control_is_neutral",
    "provider_negative_control_is_neutral",
    "provider_owner_negative_control_is_neutral",
    "duplicate_event_replay_is_blocked",
    "different_relation_history_changes_delta",
    "stress_update_respects_all_caps",
}


def build_replication_plan_gate(
    *,
    replication_report_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    report = _read_json(replication_report_path, failures)
    records = _validate_replication_report(report, checks=checks, failures=failures)
    draft = (
        _build_draft(
            report=report or {},
            records=records,
            replication_report_path=replication_report_path,
        )
        if not failures and all(checks.values())
        else None
    )
    _check(checks, failures, "one_replication_draft_created", draft is not None)
    passed = not failures and all(checks.values())
    result = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_replication_report": (
            _artifact_ref(replication_report_path)
            if replication_report_path.is_file()
            else None
        ),
        "draft_surface": {
            "mode": "bounded_non_executable",
            "draft_count": 1 if draft is not None else 0,
            "drafts": [draft] if draft is not None else [],
        },
        "readiness": {
            "bounded_plan_drafts_ready_for_review": passed,
            "decision": (
                "h3_relation_learning_replication_plan_ready_for_review"
                if passed
                else "blocked_h3_relation_learning_replication_plan"
            ),
            "next_action": (
                "open a fresh A4 challenge window; do not reuse prior authorization"
                if passed
                else "repair relation-learning replication evidence"
            ),
        },
        "boundary": dict(GATE_BOUNDARY),
        "non_claims": [
            "replication_plan_is_not_an_emitted_goal",
            "replication_plan_is_not_an_executable_plan",
            "replication_plan_does_not_authorize_agent_dispatch",
            "replication_plan_does_not_mutate_iem_relation_authorization_or_normative_state",
            "replication_plan_does_not_claim_open_world_causality",
            "replication_plan_does_not_reuse_prior_authorization",
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def _validate_replication_report(
    value: dict[str, Any] | None,
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> list[dict[str, Any]]:
    if value is None:
        _check(checks, failures, "replication_report_present", False)
        return []
    checks["replication_report_present"] = True
    _check(
        checks,
        failures,
        "replication_schema_valid",
        value.get("schema_version") == REPLICATION_SCHEMA_VERSION,
    )
    _check(checks, failures, "replication_gate_passed", value.get("passed") is True)
    readiness = _object(value.get("readiness"))
    _check(
        checks,
        failures,
        "replication_ready_for_h3_review",
        readiness.get("replication_evidence_ready_for_h3_review") is True
        and readiness.get("valid_for_qualification") is False
        and readiness.get("automatic_state_change_allowed") is False,
    )
    source_checks = _object(value.get("checks"))
    _check(
        checks,
        failures,
        "required_replication_checks_passed",
        REQUIRED_REPLICATION_CHECKS.issubset(source_checks)
        and all(source_checks.get(name) is True for name in REQUIRED_REPLICATION_CHECKS),
    )
    records = _objects(value.get("records"))
    record_ids = [str(item.get("record_id") or "") for item in records]
    task_ids = [str(item.get("task_id") or "") for item in records]
    _check(
        checks,
        failures,
        "replication_records_unique_and_complete",
        len(records) >= 6
        and all(record_ids)
        and len(record_ids) == len(set(record_ids))
        and all(task_ids)
        and len(task_ids) == len(set(task_ids))
        and all(_valid_record(item) for item in records),
    )
    outcomes = {str(item.get("event_kind") or "") for item in records}
    _check(
        checks,
        failures,
        "replication_outcomes_complete",
        EXPECTED_OUTCOMES.issubset(outcomes),
    )
    return records


def _valid_record(record: dict[str, Any]) -> bool:
    source = _object(record.get("source_report"))
    return (
        bool(str(record.get("owner_id") or ""))
        and bool(str(record.get("relation_key") or ""))
        and bool(str(record.get("task_kind") or ""))
        and bool(str(record.get("provider") or ""))
        and record.get("provenance_valid") is True
        and record.get("within_caps") is True
        and record.get("normative_guard_observed") is True
        and bool(str(source.get("path") or ""))
        and _valid_sha256(source.get("sha256"))
    )


def _build_draft(
    *,
    report: dict[str, Any],
    records: list[dict[str, Any]],
    replication_report_path: Path,
) -> dict[str, Any]:
    evidence_refs = [
        {
            "record_id": str(record["record_id"]),
            "task_id": str(record["task_id"]),
            "source_report_sha256": str(
                _object(record.get("source_report"))["sha256"]
            ),
            "owner_id": str(record["owner_id"]),
            "relation_key": str(record["relation_key"]),
            "event_kind": str(record["event_kind"]),
            "task_kind": str(record["task_kind"]),
            "provider": str(record["provider"]),
        }
        for record in sorted(records, key=lambda item: str(item["record_id"]))
    ]
    seed = {
        "replication_report_sha256": _sha256(replication_report_path),
        "evidence_refs": evidence_refs,
    }
    return {
        "draft_id": f"h3-bounded-plan:{_canonical_sha256(seed)[:20]}",
        "state": "bounded_plan_draft_review_required",
        "proposal_kind": PROPOSAL_KIND,
        "accepted_proposal_id": "h3-relation-learning-replication",
        "merged_proposal_ids": [],
        "source_binding": {
            "replication_gate": _artifact_ref(replication_report_path),
            "owner_ids": sorted(
                {str(record["owner_id"]) for record in records}
            ),
            "subject_agent_ids": sorted(
                {
                    str(record.get("agent_id") or "")
                    for record in records
                    if str(record.get("agent_id") or "")
                }
            ),
            "trigger_event_kinds": sorted(
                {str(record["event_kind"]) for record in records}
            ),
            "evidence_refs": evidence_refs,
            "negative_control_checks": dict(
                _object(report.get("negative_controls")).get("checks", {})
            ),
        },
        "title": "Challenge differentiated relation-learning deltas",
        "objective": (
            "independently review whether relation updates are outcome-specific, "
            "source-bound, capped, replay-safe, and identity-neutral"
        ),
        "non_objectives": [
            "do not mutate relation, IEM, authorization, or normative state",
            "do not infer Agent quality from owner or provider identity",
            "do not treat controlled replication as open-world causality",
        ],
        "hypotheses": [
            "success, dispute, and failure evidence produce distinguishable bounded deltas",
            "delta magnitude is explained by outcome, risk, confidence, and prior precision",
            "owner and provider labels are provenance-only negative controls",
            "duplicate source events do not produce a second update",
        ],
        "draft_phases": [
            {
                "phase": "provenance_audit",
                "purpose": "trace every delta to source event, component, cap, and prior",
                "output": "source-bound delta findings",
            },
            {
                "phase": "counterexample_challenge",
                "purpose": "search for template fallback, identity bias, replay, or cap bypass",
                "output": "counterexamples and unresolved assumptions",
            },
            {
                "phase": "replication_decision",
                "purpose": "decide whether broader qualification evidence is justified",
                "output": "operator-reviewed replication recommendation",
            },
        ],
        "success_metrics": [
            "all six records are hash-bound to their source reports",
            "all applied deltas expose raw, bounded, and applied values",
            "all applied deltas remain within parameter-specific caps",
            "success, dispute, and failure post-states remain distinguishable",
            "provider and owner negative controls remain numerically neutral",
            "duplicate replay remains blocked",
        ],
        "failure_conditions": [
            "any delta lacks a source event or component explanation",
            "owner or provider identity changes an otherwise identical delta",
            "duplicate evidence changes relation state twice",
            "any bounded delta exceeds its declared cap",
            "different outcomes collapse to a shared template post-state",
        ],
        "rollback_plan": [
            "discard the draft without changing runtime state",
            "retain source evidence and challenge findings for repair",
            "restore the prior relation learner before any wider qualification trial",
        ],
        "stop_conditions": [
            "source evidence hash mismatch",
            "unexplained or uncapped relation delta",
            "identity-dependent update detected",
            "duplicate replay changes state",
            "operator, audit owner, or affected relation owner objects",
            "any request to auto-modify trust, authorization, or normative state",
        ],
        "bounded_scope": {
            "environment": "future_controlled_pilot_only",
            "max_tasks_per_trial": 1,
            "max_agents_per_trial": 3,
            "max_trial_duration_seconds": 1800,
            "production_use_allowed": False,
            "automatic_rollout_allowed": False,
        },
        "challenge_window": {
            "required": True,
            "minimum_duration_seconds": 86400,
            "required_roles": [
                "operator",
                "audit_owner",
                "affected_relation_owner",
            ],
            "unresolved_challenge_blocks_progression": True,
        },
        "responsibility": {
            "draft_owner": "operator",
            "evidence_owner": "audit_owner",
            "monitoring_owner": "observability_owner",
            "approval_authority": "human_operator_or_governance",
        },
        "review_policy": {
            "operator_review_required": True,
            "governance_review_required_for_normative_change": True,
            "affected_relation_owner_review_required": True,
            "automatic_approval_allowed": False,
        },
        "execution_policy": {
            "draft_only": True,
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "agent_dispatch_allowed": False,
            "external_side_effect_allowed": False,
            "iem_mutation_allowed": False,
            "relation_mutation_allowed": False,
            "authorization_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "vmv_alignment": {
            "mission": "make previously impossible accountable Agent relationships possible",
            "human_sovereignty_preserved": True,
            "rules_before_capability": True,
            "verifiable_truth_required": True,
            "accountability_must_not_disappear": True,
            "safety_over_efficiency": True,
            "normative_change_requires_governance": True,
        },
    }


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"replication report missing: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"replication report invalid: {exc}")
        return None
    if not isinstance(value, dict):
        failures.append("replication report must be an object")
        return None
    return value


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _check(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    passed: bool,
) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replication-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_replication_plan_gate(
        replication_report_path=args.replication_report.resolve(),
        output_path=args.output.resolve(),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
