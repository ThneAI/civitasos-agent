"""Review and reconcile H.3 read-only goal proposals without executing them.

The gate creates an operator worksheet bound to the exact proposal artifact,
then validates a completed worksheet into a reconciliation receipt. It never
calls an LLM, emits goals, generates executable plans, or mutates runtime state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


PROPOSAL_SCHEMA_VERSION = "h3-read-only-goal-proposal-gate:v1"
REVIEW_PACKET_SCHEMA_VERSION = "h3-read-only-goal-proposal-review-packet:v1"
RECONCILIATION_SCHEMA_VERSION = (
    "h3-read-only-goal-proposal-review-reconciliation:v1"
)
ALLOWED_DECISIONS = {
    "accept",
    "reject",
    "merge",
    "need_more_evidence",
}
SOURCE_BOUNDARY = {
    "artifact_only": True,
    "proposal_review_allowed": True,
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
RECONCILIATION_BOUNDARY = {
    "artifact_only": True,
    "operator_review_recording_allowed": True,
    "bounded_plan_draft_input_ready": False,
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


def create_review_packet(
    *,
    proposal_report_path: Path,
    output_path: Path,
    agent_root: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    proposal_path = _resolve(proposal_report_path, agent_root)
    output = _resolve(output_path, agent_root)
    if output.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite review packet: {output}")

    failures: list[str] = []
    proposal_report = _read_json(proposal_path, failures, "proposal report")
    proposals = _validate_proposal_report(proposal_report, failures)
    if failures:
        raise ValueError(f"cannot create review packet: {failures}")

    reviews = [
        {
            "proposal_id": proposal["proposal_id"],
            "proposal_sha256": _canonical_sha256(proposal),
            "proposal_kind": proposal["proposal_kind"],
            "subject_agent_id": proposal["subject_agent_id"],
            "decision": "pending",
            "reason": "",
            "reviewer_id": "",
            "reviewer_role": "",
            "reviewed_at": "",
            "merge_into_proposal_id": None,
            "evidence_request": None,
        }
        for proposal in proposals
    ]
    packet = {
        "schema_version": REVIEW_PACKET_SCHEMA_VERSION,
        "state": "operator_input_required",
        "source_proposal_report": _artifact_ref(proposal_path),
        "proposal_count": len(proposals),
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "instructions": {
            "accept": "retain as an input candidate for a separate bounded plan draft gate",
            "reject": "close the proposal without execution",
            "merge": "merge into another proposal whose decision is accept",
            "need_more_evidence": "block this proposal pending a concrete evidence request",
        },
        "reviews": reviews,
        "boundary": dict(RECONCILIATION_BOUNDARY),
        "non_claims": _non_claims(),
    }
    _write_json(output, packet)
    return packet


def reconcile_operator_reviews(
    *,
    proposal_report_path: Path,
    review_packet_path: Path,
    output_path: Path,
    agent_root: Path,
    max_future_skew_seconds: float = 300.0,
) -> dict[str, Any]:
    proposal_path = _resolve(proposal_report_path, agent_root)
    review_path = _resolve(review_packet_path, agent_root)
    output = _resolve(output_path, agent_root)
    failures: list[str] = []
    checks: dict[str, bool] = {}

    proposal_report = _read_json(proposal_path, failures, "proposal report")
    review_packet = _read_json(review_path, failures, "review packet")
    proposals = _validate_proposal_report(proposal_report, failures, checks)
    reviews = _validate_review_packet(
        review_packet,
        proposal_path=proposal_path,
        proposals=proposals,
        failures=failures,
        checks=checks,
        max_future_skew_seconds=max_future_skew_seconds,
    )

    review_by_id = {
        str(review.get("proposal_id") or ""): review
        for review in reviews
        if str(review.get("proposal_id") or "")
    }
    _validate_merge_graph(review_by_id, failures=failures, checks=checks)

    accepted = sorted(
        proposal_id
        for proposal_id, review in review_by_id.items()
        if review.get("decision") == "accept"
    )
    rejected = sorted(
        proposal_id
        for proposal_id, review in review_by_id.items()
        if review.get("decision") == "reject"
    )
    needs_evidence = sorted(
        proposal_id
        for proposal_id, review in review_by_id.items()
        if review.get("decision") == "need_more_evidence"
    )
    merged = sorted(
        (
            {
                "proposal_id": proposal_id,
                "merge_into_proposal_id": review.get("merge_into_proposal_id"),
            }
            for proposal_id, review in review_by_id.items()
            if review.get("decision") == "merge"
        ),
        key=lambda item: item["proposal_id"],
    )

    passed = not failures and all(checks.values())
    bounded_input_ready = passed and bool(accepted)
    boundary = dict(RECONCILIATION_BOUNDARY)
    boundary["bounded_plan_draft_input_ready"] = bounded_input_ready
    reconciliation = {
        "schema_version": RECONCILIATION_SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_proposal_report": (
            _artifact_ref(proposal_path) if proposal_path.is_file() else None
        ),
        "source_review_packet": (
            _artifact_ref(review_path) if review_path.is_file() else None
        ),
        "review_summary": {
            "proposal_count": len(proposals),
            "review_count": len(reviews),
            "accepted_count": len(accepted),
            "rejected_count": len(rejected),
            "merged_count": len(merged),
            "need_more_evidence_count": len(needs_evidence),
        },
        "reconciliation": {
            "accepted_proposal_ids": accepted,
            "rejected_proposal_ids": rejected,
            "merged_proposals": merged,
            "need_more_evidence_proposal_ids": needs_evidence,
            "reviews": reviews if passed else [],
        },
        "readiness": {
            "operator_review_complete": passed,
            "bounded_plan_draft_input_ready": bounded_input_ready,
            "decision": (
                "h3_operator_review_reconciled"
                if passed
                else "blocked_h3_operator_review_reconciliation"
            ),
            "next_action": _next_action(
                passed=passed,
                accepted=accepted,
                needs_evidence=needs_evidence,
            ),
        },
        "boundary": boundary,
        "non_claims": _non_claims(),
    }
    _write_json(output, reconciliation)
    return reconciliation


def _validate_proposal_report(
    value: dict[str, Any] | None,
    failures: list[str],
    checks: dict[str, bool] | None = None,
) -> list[dict[str, Any]]:
    checks = checks if checks is not None else {}
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
    readiness = _object(value.get("readiness"))
    _require(
        checks,
        failures,
        "proposal_surface_ready",
        readiness.get("read_only_proposal_surface_ready") is True,
    )
    _require_equal(
        checks,
        failures,
        "proposal_readiness_decision",
        readiness.get("decision"),
        "h3_read_only_goal_proposals_ready_for_review",
    )
    _require_equal(
        checks,
        failures,
        "proposal_report_boundary",
        value.get("h3_boundary"),
        SOURCE_BOUNDARY,
    )
    surface = _object(value.get("proposal_surface"))
    proposals = _objects(surface.get("proposals"))
    _require(checks, failures, "proposals_present", bool(proposals))
    _require_equal(
        checks,
        failures,
        "proposal_count_consistent",
        surface.get("proposal_count"),
        len(proposals),
    )
    proposal_ids = [str(item.get("proposal_id") or "") for item in proposals]
    _require(
        checks,
        failures,
        "proposal_ids_unique_and_present",
        all(proposal_ids) and len(proposal_ids) == len(set(proposal_ids)),
    )
    _require(
        checks,
        failures,
        "proposals_remain_read_only",
        all(
            proposal.get("state") == "read_only_review_required"
            and _object(proposal.get("review_policy")).get("operator_review_required")
            is True
            and _object(proposal.get("review_policy")).get(
                "automatic_approval_allowed"
            )
            is False
            and not any(_object(proposal.get("execution_policy")).values())
            for proposal in proposals
        ),
    )
    return proposals


def _validate_review_packet(
    value: dict[str, Any] | None,
    *,
    proposal_path: Path,
    proposals: list[dict[str, Any]],
    failures: list[str],
    checks: dict[str, bool],
    max_future_skew_seconds: float,
) -> list[dict[str, Any]]:
    if value is None:
        _require(checks, failures, "review_packet_present", False)
        return []
    checks["review_packet_present"] = True
    _require_equal(
        checks,
        failures,
        "review_packet_schema",
        value.get("schema_version"),
        REVIEW_PACKET_SCHEMA_VERSION,
    )
    _require_equal(
        checks,
        failures,
        "review_packet_state",
        value.get("state"),
        "operator_input_required",
    )
    _require_equal(
        checks,
        failures,
        "review_packet_allowed_decisions",
        value.get("allowed_decisions"),
        sorted(ALLOWED_DECISIONS),
    )
    _require_equal(
        checks,
        failures,
        "review_packet_source_binding",
        value.get("source_proposal_report"),
        _artifact_ref(proposal_path) if proposal_path.is_file() else None,
    )
    _require_equal(
        checks,
        failures,
        "review_packet_boundary",
        value.get("boundary"),
        RECONCILIATION_BOUNDARY,
    )
    _require_equal(
        checks,
        failures,
        "review_packet_non_claims",
        value.get("non_claims"),
        _non_claims(),
    )
    _require(
        checks,
        failures,
        "max_future_skew_non_negative",
        max_future_skew_seconds >= 0,
    )
    reviews = _objects(value.get("reviews"))
    proposal_ids = [str(proposal.get("proposal_id") or "") for proposal in proposals]
    review_ids = [str(review.get("proposal_id") or "") for review in reviews]
    _require_equal(
        checks,
        failures,
        "review_count_consistent",
        value.get("proposal_count"),
        len(proposals),
    )
    _require(
        checks,
        failures,
        "review_ids_unique_and_present",
        all(review_ids) and len(review_ids) == len(set(review_ids)),
    )
    _require(
        checks,
        failures,
        "all_proposals_reviewed_exactly_once",
        sorted(review_ids) == sorted(proposal_ids),
    )
    proposal_by_id = {
        str(proposal["proposal_id"]): proposal for proposal in proposals
    }
    now = datetime.now(timezone.utc)
    review_checks = []
    for review in reviews:
        proposal_id = str(review.get("proposal_id") or "")
        proposal = proposal_by_id.get(proposal_id)
        decision = str(review.get("decision") or "")
        reviewed_at = _timestamp(review.get("reviewed_at"))
        expected_hash = _canonical_sha256(proposal) if proposal is not None else None
        valid = {
            "proposal_exists": proposal is not None,
            "proposal_hash_matches": review.get("proposal_sha256") == expected_hash,
            "proposal_kind_matches": (
                proposal is not None
                and review.get("proposal_kind") == proposal.get("proposal_kind")
            ),
            "subject_agent_matches": (
                proposal is not None
                and review.get("subject_agent_id")
                == proposal.get("subject_agent_id")
            ),
            "decision_allowed": decision in ALLOWED_DECISIONS,
            "reason_present": len(str(review.get("reason") or "").strip()) >= 8,
            "reviewer_id_present": bool(str(review.get("reviewer_id") or "").strip()),
            "reviewer_role_present": bool(
                str(review.get("reviewer_role") or "").strip()
            ),
            "reviewed_at_valid": reviewed_at is not None,
            "reviewed_at_not_future": (
                reviewed_at is not None
                and reviewed_at
                <= now + timedelta(seconds=max_future_skew_seconds)
            ),
            "merge_target_shape": (
                bool(str(review.get("merge_into_proposal_id") or "").strip())
                if decision == "merge"
                else review.get("merge_into_proposal_id") in (None, "")
            ),
            "evidence_request_shape": (
                len(str(review.get("evidence_request") or "").strip()) >= 8
                if decision == "need_more_evidence"
                else review.get("evidence_request") in (None, "")
            ),
        }
        review_checks.append(all(valid.values()))
        for name, passed in valid.items():
            if not passed:
                failures.append(f"review {proposal_id or '<missing>'}: {name} failed")
    _require(
        checks,
        failures,
        "review_fields_valid",
        bool(reviews) and all(review_checks),
    )
    return reviews


def _validate_merge_graph(
    review_by_id: dict[str, dict[str, Any]],
    *,
    failures: list[str],
    checks: dict[str, bool],
) -> None:
    valid = True
    for proposal_id, review in review_by_id.items():
        if review.get("decision") != "merge":
            continue
        target_id = str(review.get("merge_into_proposal_id") or "")
        target = review_by_id.get(target_id)
        if target_id == proposal_id:
            failures.append(f"review {proposal_id}: merge target must differ")
            valid = False
        elif target is None:
            failures.append(f"review {proposal_id}: merge target does not exist")
            valid = False
        elif target.get("decision") != "accept":
            failures.append(
                f"review {proposal_id}: merge target {target_id} must be accepted"
            )
            valid = False
    _require(checks, failures, "merge_graph_valid", valid)


def _next_action(
    *,
    passed: bool,
    accepted: list[str],
    needs_evidence: list[str],
) -> str:
    if not passed:
        return "complete or repair every operator review"
    if accepted:
        return (
            "accepted proposals may enter a separate bounded plan draft gate; "
            "do not emit or execute goals"
        )
    if needs_evidence:
        return "collect requested evidence before proposing a bounded plan draft"
    return "no proposals selected for bounded plan drafting"


def _non_claims() -> list[str]:
    return [
        "review_does_not_emit_goals",
        "review_does_not_generate_executable_plans",
        "review_does_not_call_llms",
        "review_does_not_start_agents_or_runtime",
        "review_does_not_mutate_iem_relation_authorization_or_normative_state",
        "review_does_not_authorize_production_transition",
    ]


def _artifact_ref(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": _sha256(path),
    }


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


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip().replace("Z", "+00:00")
    normalized = re.sub(r"(\.\d{6})\d+(?=[+-]\d\d:\d\d$)", r"\1", normalized)
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


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
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create a pending operator worksheet")
    init.add_argument("--proposal-report", type=Path, required=True)
    init.add_argument("--output", type=Path, required=True)
    init.add_argument("--overwrite", action="store_true")

    reconcile = subparsers.add_parser(
        "reconcile",
        help="validate completed reviews and write a reconciliation receipt",
    )
    reconcile.add_argument("--proposal-report", type=Path, required=True)
    reconcile.add_argument("--review-packet", type=Path, required=True)
    reconcile.add_argument("--output", type=Path, required=True)
    reconcile.add_argument("--max-future-skew-seconds", type=float, default=300.0)
    return parser


def main() -> None:
    args = _parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    if args.command == "init":
        report = create_review_packet(
            proposal_report_path=args.proposal_report,
            output_path=args.output,
            agent_root=agent_root,
            overwrite=args.overwrite,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return

    report = reconcile_operator_reviews(
        proposal_report_path=args.proposal_report,
        review_packet_path=args.review_packet,
        output_path=args.output,
        agent_root=agent_root,
        max_future_skew_seconds=args.max_future_skew_seconds,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
