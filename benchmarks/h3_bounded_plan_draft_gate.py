"""Build non-executable bounded plan drafts from reconciled H.3 proposals.

This gate turns operator-accepted proposal directions into reviewable planning
artifacts. It does not call an LLM, emit a goal, authorize execution, or mutate
runtime, identity, relation, authorization, or normative state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.h3_operator_review_reconciliation_gate import (
    PROPOSAL_SCHEMA_VERSION,
    RECONCILIATION_SCHEMA_VERSION,
    SOURCE_BOUNDARY,
)


SCHEMA_VERSION = "h3-bounded-plan-draft-gate:v1"
RECONCILIATION_BOUNDARY = {
    "artifact_only": True,
    "operator_review_recording_allowed": True,
    "bounded_plan_draft_input_ready": True,
    "goal_emission_allowed": False,
    "executable_plan_allowed": False,
    "runtime_execution_allowed": False,
    "llm_planning_allowed": False,
    "iem_mutation_allowed": False,
    "relation_mutation_allowed": False,
    "authorization_mutation_allowed": False,
    "normative_local_mutation_allowed": False,
    "production_transition_allowed": False,
}
GATE_BOUNDARY = {
    "artifact_only": True,
    "bounded_plan_draft_generation_allowed": True,
    "bounded_plan_review_allowed": True,
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
}
SUPPORTED_KINDS = {
    "review_conditions_for_preserving_successful_relations",
    "review_relation_risk_and_verification_policy",
}


def build_h3_bounded_plan_draft_gate(
    *,
    proposal_report_path: Path,
    reconciliation_report_path: Path,
    agent_root: Path,
) -> dict[str, Any]:
    proposal_path = _resolve(proposal_report_path, agent_root)
    reconciliation_path = _resolve(reconciliation_report_path, agent_root)
    failures: list[str] = []
    checks: dict[str, bool] = {}

    proposal_report = _read_json(proposal_path, failures, "proposal report")
    reconciliation = _read_json(
        reconciliation_path,
        failures,
        "operator reconciliation",
    )
    proposals = _validate_proposal_report(
        proposal_report,
        failures=failures,
        checks=checks,
    )
    proposal_by_id = {
        str(proposal.get("proposal_id") or ""): proposal for proposal in proposals
    }
    accepted_ids, merged = _validate_reconciliation(
        reconciliation,
        proposal_path=proposal_path,
        proposal_by_id=proposal_by_id,
        failures=failures,
        checks=checks,
    )
    groups = _build_groups(
        accepted_ids=accepted_ids,
        merged=merged,
        proposal_by_id=proposal_by_id,
        failures=failures,
        checks=checks,
    )

    drafts = []
    if not failures and all(checks.values()):
        drafts = [
            _build_plan_draft(
                accepted_id=accepted_id,
                proposals=group,
                reconciliation_sha256=_sha256(reconciliation_path),
            )
            for accepted_id, group in groups
        ]
    _require(
        checks,
        failures,
        "one_draft_per_accepted_proposal",
        len(drafts) == len(accepted_ids) and bool(drafts),
    )

    passed = not failures and all(checks.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_proposal_report": (
            _artifact_ref(proposal_path) if proposal_path.is_file() else None
        ),
        "source_reconciliation_report": (
            _artifact_ref(reconciliation_path)
            if reconciliation_path.is_file()
            else None
        ),
        "draft_surface": {
            "mode": "bounded_non_executable",
            "draft_count": len(drafts),
            "drafts": drafts,
        },
        "readiness": {
            "bounded_plan_drafts_ready_for_review": passed,
            "decision": (
                "h3_bounded_plan_drafts_ready_for_review"
                if passed
                else "blocked_h3_bounded_plan_draft_gate"
            ),
            "next_action": (
                "challenge and review drafts; do not execute or emit goals"
                if passed
                else "repair proposal or reconciliation evidence"
            ),
        },
        "boundary": dict(GATE_BOUNDARY),
        "non_claims": [
            "drafts_are_not_emitted_goals",
            "drafts_are_not_executable_plans",
            "gate_does_not_call_llms",
            "gate_does_not_dispatch_agents",
            "gate_does_not_start_runtime",
            "gate_does_not_mutate_iem_relation_authorization_or_normative_state",
            "gate_does_not_authorize_production_transition",
        ],
    }


def _validate_proposal_report(
    value: dict[str, Any] | None,
    *,
    failures: list[str],
    checks: dict[str, bool],
) -> list[dict[str, Any]]:
    if value is None:
        _require(checks, failures, "proposal_report_present", False)
        return []
    checks["proposal_report_present"] = True
    _require_equal(
        checks,
        failures,
        "proposal_report_schema",
        value.get("schema_version"),
        PROPOSAL_SCHEMA_VERSION,
    )
    _require(checks, failures, "proposal_report_passed", value.get("passed") is True)
    _require_equal(
        checks,
        failures,
        "proposal_report_boundary",
        value.get("h3_boundary"),
        SOURCE_BOUNDARY,
    )
    readiness = _object(value.get("readiness"))
    _require(
        checks,
        failures,
        "proposal_surface_ready",
        readiness.get("read_only_proposal_surface_ready") is True,
    )
    surface = _object(value.get("proposal_surface"))
    proposals = _objects(surface.get("proposals"))
    proposal_ids = [str(item.get("proposal_id") or "") for item in proposals]
    _require(checks, failures, "proposals_present", bool(proposals))
    _require_equal(
        checks,
        failures,
        "proposal_count_consistent",
        surface.get("proposal_count"),
        len(proposals),
    )
    _require(
        checks,
        failures,
        "proposal_ids_unique_and_present",
        all(proposal_ids) and len(proposal_ids) == len(set(proposal_ids)),
    )
    _require(
        checks,
        failures,
        "proposal_kinds_supported",
        all(str(item.get("proposal_kind") or "") in SUPPORTED_KINDS for item in proposals),
    )
    _require(
        checks,
        failures,
        "proposals_remain_non_executable",
        all(
            item.get("state") == "read_only_review_required"
            and not any(_object(item.get("execution_policy")).values())
            and bool(_objects(item.get("evidence_refs")))
            for item in proposals
        ),
    )
    return proposals


def _validate_reconciliation(
    value: dict[str, Any] | None,
    *,
    proposal_path: Path,
    proposal_by_id: dict[str, dict[str, Any]],
    failures: list[str],
    checks: dict[str, bool],
) -> tuple[list[str], list[dict[str, str]]]:
    if value is None:
        _require(checks, failures, "reconciliation_present", False)
        return [], []
    checks["reconciliation_present"] = True
    _require_equal(
        checks,
        failures,
        "reconciliation_schema",
        value.get("schema_version"),
        RECONCILIATION_SCHEMA_VERSION,
    )
    _require(checks, failures, "reconciliation_passed", value.get("passed") is True)
    _require_equal(
        checks,
        failures,
        "reconciliation_source_proposal_binding",
        value.get("source_proposal_report"),
        _artifact_ref(proposal_path) if proposal_path.is_file() else None,
    )
    _require_equal(
        checks,
        failures,
        "reconciliation_boundary",
        value.get("boundary"),
        RECONCILIATION_BOUNDARY,
    )
    readiness = _object(value.get("readiness"))
    _require(
        checks,
        failures,
        "operator_review_complete",
        readiness.get("operator_review_complete") is True,
    )
    _require(
        checks,
        failures,
        "bounded_plan_input_ready",
        readiness.get("bounded_plan_draft_input_ready") is True,
    )
    _require_equal(
        checks,
        failures,
        "reconciliation_decision",
        readiness.get("decision"),
        "h3_operator_review_reconciled",
    )

    review_packet_ref = _object(value.get("source_review_packet"))
    review_packet_path = Path(str(review_packet_ref.get("path") or ""))
    _require(
        checks,
        failures,
        "review_packet_ref_complete",
        review_packet_path.is_file()
        and _valid_sha256(review_packet_ref.get("sha256")),
    )
    if review_packet_path.is_file():
        _require_equal(
            checks,
            failures,
            "review_packet_hash_matches",
            _sha256(review_packet_path),
            review_packet_ref.get("sha256"),
        )

    reconciliation = _object(value.get("reconciliation"))
    accepted = [str(item) for item in reconciliation.get("accepted_proposal_ids", [])]
    merged = _objects(reconciliation.get("merged_proposals"))
    rejected = {
        str(item) for item in reconciliation.get("rejected_proposal_ids", [])
    }
    needs_evidence = {
        str(item)
        for item in reconciliation.get("need_more_evidence_proposal_ids", [])
    }
    merged_ids = [str(item.get("proposal_id") or "") for item in merged]
    merged_targets = [str(item.get("merge_into_proposal_id") or "") for item in merged]
    proposal_ids = set(proposal_by_id)
    _require(
        checks,
        failures,
        "accepted_ids_unique_and_present",
        all(accepted) and len(accepted) == len(set(accepted)),
    )
    _require(
        checks,
        failures,
        "accepted_ids_exist",
        set(accepted).issubset(proposal_ids),
    )
    _require(
        checks,
        failures,
        "merged_ids_unique_and_present",
        all(merged_ids) and len(merged_ids) == len(set(merged_ids)),
    )
    _require(
        checks,
        failures,
        "merged_ids_exist",
        set(merged_ids).issubset(proposal_ids),
    )
    _require(
        checks,
        failures,
        "merged_targets_are_accepted",
        all(target in accepted for target in merged_targets),
    )
    partition = set(accepted) | set(merged_ids) | rejected | needs_evidence
    _require(
        checks,
        failures,
        "reconciliation_partitions_all_proposals",
        partition == proposal_ids,
    )
    _require(
        checks,
        failures,
        "reconciliation_sets_disjoint",
        sum(
            len(items)
            for items in (
                set(accepted),
                set(merged_ids),
                rejected,
                needs_evidence,
            )
        )
        == len(partition),
    )
    reviews = _objects(reconciliation.get("reviews"))
    review_by_id = {
        str(review.get("proposal_id") or ""): review for review in reviews
    }
    _require(
        checks,
        failures,
        "review_ids_match_proposals",
        set(review_by_id) == proposal_ids and len(reviews) == len(review_by_id),
    )
    _require(
        checks,
        failures,
        "review_proposal_hashes_match",
        all(
            review.get("proposal_sha256")
            == _canonical_sha256(proposal_by_id[proposal_id])
            for proposal_id, review in review_by_id.items()
            if proposal_id in proposal_by_id
        )
        and set(review_by_id) == proposal_ids,
    )
    _require(
        checks,
        failures,
        "accepted_reviews_match",
        all(_object(review_by_id.get(item)).get("decision") == "accept" for item in accepted),
    )
    _require(
        checks,
        failures,
        "merged_reviews_match",
        all(
            _object(review_by_id.get(item.get("proposal_id"))).get("decision")
            == "merge"
            and _object(review_by_id.get(item.get("proposal_id"))).get(
                "merge_into_proposal_id"
            )
            == item.get("merge_into_proposal_id")
            for item in merged
        ),
    )
    summary = _object(value.get("review_summary"))
    _require_equal(
        checks,
        failures,
        "accepted_count_consistent",
        summary.get("accepted_count"),
        len(accepted),
    )
    _require_equal(
        checks,
        failures,
        "merged_count_consistent",
        summary.get("merged_count"),
        len(merged),
    )
    return sorted(accepted), [
        {
            "proposal_id": str(item.get("proposal_id") or ""),
            "merge_into_proposal_id": str(item.get("merge_into_proposal_id") or ""),
        }
        for item in merged
    ]


def _build_groups(
    *,
    accepted_ids: list[str],
    merged: list[dict[str, str]],
    proposal_by_id: dict[str, dict[str, Any]],
    failures: list[str],
    checks: dict[str, bool],
) -> list[tuple[str, list[dict[str, Any]]]]:
    groups = []
    kinds_match = True
    for accepted_id in accepted_ids:
        accepted = proposal_by_id.get(accepted_id)
        members = [accepted] if accepted is not None else []
        for edge in merged:
            if edge["merge_into_proposal_id"] == accepted_id:
                child = proposal_by_id.get(edge["proposal_id"])
                if child is not None:
                    members.append(child)
                    if (
                        accepted is not None
                        and child.get("proposal_kind") != accepted.get("proposal_kind")
                    ):
                        kinds_match = False
        groups.append((accepted_id, members))
    _require(
        checks,
        failures,
        "accepted_groups_complete",
        all(members and members[0].get("proposal_id") == accepted_id for accepted_id, members in groups),
    )
    _require(
        checks,
        failures,
        "merged_proposal_kinds_match_targets",
        kinds_match,
    )
    return groups


def _build_plan_draft(
    *,
    accepted_id: str,
    proposals: list[dict[str, Any]],
    reconciliation_sha256: str,
) -> dict[str, Any]:
    primary = proposals[0]
    kind = str(primary["proposal_kind"])
    evidence_refs = _deduplicate_objects(
        [
            {
                **ref,
                "proposal_id": str(proposal["proposal_id"]),
            }
            for proposal in proposals
            for ref in _objects(proposal.get("evidence_refs"))
        ]
    )
    owner_ids = sorted(
        {
            str(owner)
            for proposal in proposals
            for owner in proposal.get("owner_ids", [])
            if str(owner)
        }
    )
    trigger_event_kinds = sorted(
        {
            str(event_kind)
            for proposal in proposals
            for event_kind in proposal.get("trigger_event_kinds", [])
            if str(event_kind)
        }
    )
    subject_agent_ids = sorted(
        {
            str(proposal.get("subject_agent_id") or "")
            for proposal in proposals
            if str(proposal.get("subject_agent_id") or "")
        }
    )
    content = (
        _successful_relation_plan_content()
        if kind == "review_conditions_for_preserving_successful_relations"
        else _risk_verification_plan_content()
    )
    plan_seed = {
        "accepted_proposal_id": accepted_id,
        "member_proposal_ids": sorted(
            str(proposal["proposal_id"]) for proposal in proposals
        ),
        "reconciliation_sha256": reconciliation_sha256,
        "evidence_refs": evidence_refs,
    }
    return {
        "draft_id": f"h3-bounded-plan:{_canonical_sha256(plan_seed)[:20]}",
        "state": "bounded_plan_draft_review_required",
        "proposal_kind": kind,
        "accepted_proposal_id": accepted_id,
        "merged_proposal_ids": sorted(
            str(proposal["proposal_id"])
            for proposal in proposals
            if proposal["proposal_id"] != accepted_id
        ),
        "source_binding": {
            "reconciliation_sha256": reconciliation_sha256,
            "proposal_ids": sorted(
                str(proposal["proposal_id"]) for proposal in proposals
            ),
            "owner_ids": owner_ids,
            "subject_agent_ids": subject_agent_ids,
            "trigger_event_kinds": trigger_event_kinds,
            "evidence_refs": evidence_refs,
        },
        **content,
        "bounded_scope": {
            "environment": "future_controlled_pilot_only",
            "max_tasks_per_trial": 3,
            "max_agents_per_trial": 3,
            "max_trial_duration_seconds": 3600,
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


def _successful_relation_plan_content() -> dict[str, Any]:
    return {
        "title": "Preserve conditions for accountable successful relations",
        "objective": (
            "identify and test which observable conditions consistently support "
            "successful accountable Agent cooperation"
        ),
        "non_objectives": [
            "do not increase trust or authorization automatically",
            "do not generalize one successful relation to unrelated Agents",
            "do not bypass challenge, governance, or operator review",
        ],
        "hypotheses": [
            "successful settlement plus complete receipts predicts safer repeat cooperation",
            "relation-specific evidence is more reliable than global reputation alone",
        ],
        "draft_phases": [
            {
                "phase": "evidence_baseline",
                "purpose": "compare successful relation evidence across owners and tasks",
                "output": "reviewable condition matrix",
            },
            {
                "phase": "counterexample_challenge",
                "purpose": "search for success cases lacking the proposed conditions",
                "output": "challenge findings and unresolved assumptions",
            },
            {
                "phase": "controlled_trial_design",
                "purpose": "design a bounded future pilot without authorizing it",
                "output": "separate execution authorization request",
            },
        ],
        "success_metrics": [
            "all claimed conditions trace to source task and receipt evidence",
            "counterexamples are documented rather than discarded",
            "no relation or authorization state is changed by the draft",
        ],
        "failure_conditions": [
            "evidence cannot distinguish causal conditions from coincidence",
            "conditions require hidden or unverifiable state",
            "proposal would create automatic trust escalation",
        ],
        "rollback_plan": [
            "discard the draft and retain original proposal evidence",
            "restore previous review status without changing runtime state",
            "record challenge reasons for future evidence collection",
        ],
        "stop_conditions": [
            "source evidence hash mismatch",
            "unresolved accountability gap",
            "operator or affected relation owner objects",
            "any request to auto-modify trust, authorization, or normative state",
        ],
    }


def _risk_verification_plan_content() -> dict[str, Any]:
    return {
        "title": "Design tiered relation risk, verification, and stake policy",
        "objective": (
            "define a challengeable mapping from dispute and failure evidence to "
            "bounded verification and stake requirements"
        ),
        "non_objectives": [
            "do not punish Agents automatically",
            "do not make permanent normative or reputation changes",
            "do not deny participation without review and appeal",
        ],
        "hypotheses": [
            "repeated negative relation outcomes justify stronger verification before retry",
            "stake and verification should scale with evidence strength and recency",
            "appeal and repair evidence should permit risk reduction",
        ],
        "draft_phases": [
            {
                "phase": "evidence_classification",
                "purpose": "separate dispute, failure, repair, and false-positive evidence",
                "output": "reviewable evidence severity matrix",
            },
            {
                "phase": "policy_simulation",
                "purpose": "compare baseline, elevated, and strict verification outcomes",
                "output": "simulation-only policy impact report",
            },
            {
                "phase": "challenge_and_appeal_design",
                "purpose": "define challenge, repair, expiry, and operator override paths",
                "output": "separate controlled-pilot authorization request",
            },
        ],
        "success_metrics": [
            "every risk tier traces to relation-specific evidence",
            "verification and stake changes are reversible and time-bounded",
            "challenge, appeal, repair, and expiry paths are explicit",
            "no authorization state is changed by the draft",
        ],
        "failure_conditions": [
            "policy cannot distinguish dispute from confirmed failure",
            "risk escalation lacks proportionality or expiry",
            "repair evidence cannot reduce restrictions",
            "policy creates irreversible exclusion",
        ],
        "rollback_plan": [
            "discard simulated policy parameters",
            "retain existing authorization behavior unchanged",
            "record rejected thresholds and challenge findings",
        ],
        "stop_conditions": [
            "source evidence hash mismatch",
            "false-positive or appeal path is missing",
            "proposed restriction is irreversible",
            "operator, audit owner, or affected relation owner objects",
            "any request to mutate authorization or normative state directly",
        ],
    }


def _deduplicate_objects(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {
        json.dumps(value, ensure_ascii=False, sort_keys=True): value for value in values
    }
    return [unique[key] for key in sorted(unique)]


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _valid_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _read_json(
    path: Path,
    failures: list[str],
    label: str,
) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"{label} missing: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"{label} invalid: {exc}")
        return None
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return None
    return value


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _require(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    condition: bool,
) -> None:
    checks[name] = bool(condition)
    if not condition:
        failures.append(name)


def _require_equal(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    actual: Any,
    expected: Any,
) -> None:
    condition = actual == expected
    checks[name] = condition
    if not condition:
        failures.append(f"{name}: expected {expected!r}, got {actual!r}")


def _resolve(path: Path, root: Path) -> Path:
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal-report", type=Path, required=True)
    parser.add_argument("--reconciliation-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    report = build_h3_bounded_plan_draft_gate(
        proposal_report_path=args.proposal_report,
        reconciliation_report_path=args.reconciliation_report,
        agent_root=agent_root,
    )
    output = _resolve(args.output, agent_root)
    _write_json(output, report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
