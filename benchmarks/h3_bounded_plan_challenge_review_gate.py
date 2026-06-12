"""Challenge and review H.3 bounded plan drafts without authorizing execution."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from benchmarks.h3_bounded_plan_draft_gate import (
    GATE_BOUNDARY as SOURCE_BOUNDARY,
)
from benchmarks.h3_bounded_plan_draft_gate import (
    SCHEMA_VERSION as SOURCE_SCHEMA_VERSION,
)


REVIEW_PACKET_SCHEMA_VERSION = "h3-bounded-plan-challenge-review-packet:v1"
RECONCILIATION_SCHEMA_VERSION = (
    "h3-bounded-plan-challenge-review-reconciliation:v1"
)
MINIMUM_CHALLENGE_WINDOW_SECONDS = 86400
DEFAULT_DEVELOPMENT_WINDOW_SECONDS = 60
MAXIMUM_DEVELOPMENT_WINDOW_SECONDS = 3600
VALIDATION_PROFILES = {"qualification", "development"}
REQUIRED_REVIEWER_ROLES = {
    "operator",
    "audit_owner",
    "affected_relation_owner",
}
ALLOWED_DECISIONS = {
    "approve_for_authorization_request",
    "reject",
    "request_revision",
    "need_more_evidence",
}
REVIEW_BOUNDARY = {
    "artifact_only": True,
    "challenge_review_recording_allowed": True,
    "controlled_pilot_authorization_request_ready": False,
    "controlled_pilot_execution_allowed": False,
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


def create_challenge_review_packet(
    *,
    bounded_plan_report_path: Path,
    output_path: Path,
    agent_root: Path,
    overwrite: bool = False,
    opened_at: datetime | None = None,
    validation_profile: str = "qualification",
    development_window_seconds: int = DEFAULT_DEVELOPMENT_WINDOW_SECONDS,
) -> dict[str, Any]:
    source_path = _resolve(bounded_plan_report_path, agent_root)
    output = _resolve(output_path, agent_root)
    if output.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite challenge packet: {output}")

    failures: list[str] = []
    source = _read_json(source_path, failures, "bounded plan report")
    drafts = _validate_source_report(source, failures=failures)
    if failures:
        raise ValueError(f"cannot create challenge packet: {failures}")
    if validation_profile not in VALIDATION_PROFILES:
        raise ValueError(f"unsupported validation profile: {validation_profile}")

    opened = _as_utc(opened_at or datetime.now(timezone.utc))
    qualification_minimum_duration = max(
        _integer(
            _object(draft.get("challenge_window")).get(
                "minimum_duration_seconds"
            )
        )
        for draft in drafts
    )
    if validation_profile == "development":
        if not 1 <= development_window_seconds <= MAXIMUM_DEVELOPMENT_WINDOW_SECONDS:
            raise ValueError(
                "development window must be between 1 and "
                f"{MAXIMUM_DEVELOPMENT_WINDOW_SECONDS} seconds"
            )
        minimum_duration = development_window_seconds
    else:
        minimum_duration = qualification_minimum_duration
    closes = opened + timedelta(seconds=minimum_duration)
    reviews = [
        {
            "draft_id": draft["draft_id"],
            "draft_sha256": _canonical_sha256(draft),
            "proposal_kind": draft["proposal_kind"],
            "reviewer_role": role,
            "reviewer_id": "",
            "decision": "pending",
            "reason": "",
            "reviewed_at": "",
            "requested_changes": None,
            "evidence_request": None,
        }
        for draft in drafts
        for role in sorted(
            _object(draft.get("challenge_window")).get("required_roles", [])
        )
    ]
    packet = {
        "schema_version": REVIEW_PACKET_SCHEMA_VERSION,
        "state": "challenge_window_open",
        "validation_profile": validation_profile,
        "development_only": validation_profile == "development",
        "valid_for_qualification": validation_profile == "qualification",
        "source_bounded_plan_report": _artifact_ref(source_path),
        "opened_at": opened.isoformat(),
        "closes_at": closes.isoformat(),
        "minimum_duration_seconds": minimum_duration,
        "qualification_minimum_duration_seconds": qualification_minimum_duration,
        "draft_count": len(drafts),
        "required_review_count": len(reviews),
        "required_reviewer_roles": sorted(REQUIRED_REVIEWER_ROLES),
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "instructions": {
            "approve_for_authorization_request": (
                "accept the draft only as input to a separate controlled-pilot "
                "authorization request gate"
            ),
            "reject": "close the draft without execution",
            "request_revision": "block progression and describe required changes",
            "need_more_evidence": "block progression and request concrete evidence",
        },
        "reviews": reviews,
        "boundary": dict(REVIEW_BOUNDARY),
        "non_claims": _non_claims(),
    }
    _write_json(output, packet)
    return packet


def reconcile_challenge_reviews(
    *,
    bounded_plan_report_path: Path,
    review_packet_path: Path,
    output_path: Path,
    agent_root: Path,
    max_future_skew_seconds: float = 300.0,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    source_path = _resolve(bounded_plan_report_path, agent_root)
    packet_path = _resolve(review_packet_path, agent_root)
    output = _resolve(output_path, agent_root)
    failures: list[str] = []
    checks: dict[str, bool] = {}

    source = _read_json(source_path, failures, "bounded plan report")
    packet = _read_json(packet_path, failures, "challenge review packet")
    drafts = _validate_source_report(source, failures=failures, checks=checks)
    reviews, window_closed = _validate_review_packet(
        packet,
        source_path=source_path,
        drafts=drafts,
        failures=failures,
        checks=checks,
        max_future_skew_seconds=max_future_skew_seconds,
        current_time=_as_utc(current_time or datetime.now(timezone.utc)),
    )
    validation_profile = _validation_profile(packet)

    review_by_draft = _group_reviews(reviews)
    draft_results = [
        _reconcile_draft(draft, review_by_draft.get(str(draft["draft_id"]), []))
        for draft in drafts
    ]
    approved = sorted(
        result["draft_id"]
        for result in draft_results
        if result["decision"] == "approved_for_authorization_request"
    )
    blocked = sorted(
        result["draft_id"]
        for result in draft_results
        if result["decision"] != "approved_for_authorization_request"
    )

    non_window_failures = [
        failure for failure in failures if failure != "challenge_window_closed"
    ]
    structural_integrity_passed = not non_window_failures and all(
        passed
        for name, passed in checks.items()
        if name != "challenge_window_closed"
    )
    passed = structural_integrity_passed and window_closed
    qualification_request_ready = (
        passed and validation_profile == "qualification" and bool(approved)
    )
    development_request_input_ready = (
        passed and validation_profile == "development" and bool(approved)
    )
    boundary = dict(REVIEW_BOUNDARY)
    boundary["controlled_pilot_authorization_request_ready"] = (
        qualification_request_ready
    )
    report = {
        "schema_version": RECONCILIATION_SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "validation_profile": validation_profile,
        "development_only": validation_profile == "development",
        "valid_for_qualification": validation_profile == "qualification",
        "source_bounded_plan_report": (
            _artifact_ref(source_path) if source_path.is_file() else None
        ),
        "source_review_packet": (
            _artifact_ref(packet_path) if packet_path.is_file() else None
        ),
        "review_summary": {
            "draft_count": len(drafts),
            "review_count": len(reviews),
            "approved_draft_count": len(approved),
            "blocked_draft_count": len(blocked),
            "challenge_window_closed": window_closed,
        },
        "reconciliation": {
            "approved_draft_ids": approved,
            "blocked_draft_ids": blocked,
            "draft_results": draft_results if structural_integrity_passed else [],
            "reviews": reviews if structural_integrity_passed else [],
        },
        "readiness": {
            "challenge_review_complete": passed,
            "controlled_pilot_authorization_request_ready": (
                qualification_request_ready
            ),
            "development_authorization_request_input_ready": (
                development_request_input_ready
            ),
            "decision": _decision(
                structural_integrity_passed=structural_integrity_passed,
                window_closed=window_closed,
                approved=approved,
                validation_profile=validation_profile,
            ),
            "next_action": _next_action(
                structural_integrity_passed=structural_integrity_passed,
                window_closed=window_closed,
                approved=approved,
                blocked=blocked,
                validation_profile=validation_profile,
            ),
        },
        "boundary": boundary,
        "non_claims": _non_claims(),
    }
    _write_json(output, report)
    return report


def challenge_review_status(
    *,
    review_packet_path: Path,
    agent_root: Path,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    packet_path = _resolve(review_packet_path, agent_root)
    failures: list[str] = []
    packet = _read_json(packet_path, failures, "challenge review packet")
    now = _as_utc(current_time or datetime.now(timezone.utc))
    packet = packet or {}
    validation_profile = _validation_profile(packet)
    closes_at = _timestamp(packet.get("closes_at"))
    reviews = _objects(packet.get("reviews"))
    pending = [
        {
            "draft_id": str(review.get("draft_id") or ""),
            "reviewer_role": str(review.get("reviewer_role") or ""),
        }
        for review in reviews
        if review.get("decision") == "pending"
    ]
    remaining_seconds = (
        max(0.0, (closes_at - now).total_seconds())
        if closes_at is not None
        else None
    )
    return {
        "schema_version": "h3-bounded-plan-challenge-review-status:v1",
        "checked_at": now.isoformat(),
        "packet_path": str(packet_path),
        "packet_present": packet_path.is_file(),
        "packet_schema_valid": (
            packet.get("schema_version") == REVIEW_PACKET_SCHEMA_VERSION
        ),
        "validation_profile": validation_profile,
        "development_only": validation_profile == "development",
        "valid_for_qualification": validation_profile == "qualification",
        "challenge_closes_at": closes_at.isoformat() if closes_at else None,
        "time_state": (
            "READY" if remaining_seconds == 0.0 else "WAITING"
        )
        if remaining_seconds is not None
        else "INVALID",
        "remaining_seconds": remaining_seconds,
        "review_count": len(reviews),
        "pending_review_count": len(pending),
        "pending_reviews": pending,
        "failures": failures,
    }


def record_challenge_review(
    *,
    review_packet_path: Path,
    agent_root: Path,
    draft_id: str,
    reviewer_role: str,
    reviewer_id: str,
    decision: str,
    reason: str,
    requested_changes: str | None = None,
    evidence_request: str | None = None,
    current_time: datetime | None = None,
) -> dict[str, Any]:
    packet_path = _resolve(review_packet_path, agent_root)
    failures: list[str] = []
    packet = _read_json(packet_path, failures, "challenge review packet")
    if packet is None or failures:
        raise ValueError(f"cannot record challenge review: {failures}")
    if packet.get("schema_version") != REVIEW_PACKET_SCHEMA_VERSION:
        raise ValueError("challenge review packet schema mismatch")
    validation_profile = _validation_profile(packet)
    if reviewer_role not in REQUIRED_REVIEWER_ROLES:
        raise ValueError(f"unsupported reviewer role: {reviewer_role}")
    if decision not in ALLOWED_DECISIONS:
        raise ValueError(f"unsupported review decision: {decision}")
    if not reviewer_id.strip():
        raise ValueError("reviewer id is required")
    if len(reason.strip()) < 8:
        raise ValueError("review reason must contain at least 8 characters")
    if decision == "request_revision":
        if len(str(requested_changes or "").strip()) < 8:
            raise ValueError("requested changes must contain at least 8 characters")
    elif requested_changes not in (None, ""):
        raise ValueError("requested changes are only valid for request_revision")
    if decision == "need_more_evidence":
        if len(str(evidence_request or "").strip()) < 8:
            raise ValueError("evidence request must contain at least 8 characters")
    elif evidence_request not in (None, ""):
        raise ValueError("evidence request is only valid for need_more_evidence")

    now = _as_utc(current_time or datetime.now(timezone.utc))
    opened_at = _timestamp(packet.get("opened_at"))
    closes_at = _timestamp(packet.get("closes_at"))
    if opened_at is None or closes_at is None or not opened_at <= now <= closes_at:
        raise ValueError("review must be recorded during the challenge window")
    matches = [
        review
        for review in _objects(packet.get("reviews"))
        if review.get("draft_id") == draft_id
        and review.get("reviewer_role") == reviewer_role
    ]
    if len(matches) != 1:
        raise ValueError("review slot not found or duplicated")
    review = matches[0]
    if review.get("decision") != "pending":
        raise FileExistsError("review slot is already completed")
    review.update(
        {
            "reviewer_id": reviewer_id.strip(),
            "decision": decision,
            "reason": reason.strip(),
            "reviewed_at": now.isoformat(),
            "requested_changes": (
                requested_changes.strip() if requested_changes else None
            ),
            "evidence_request": (
                evidence_request.strip() if evidence_request else None
            ),
        }
    )
    _write_json_atomic(packet_path, packet)
    return {
        "schema_version": "h3-bounded-plan-challenge-review-record:v1",
        "recorded": True,
        "packet_path": str(packet_path),
        "draft_id": draft_id,
        "reviewer_role": reviewer_role,
        "reviewer_id": reviewer_id.strip(),
        "decision": decision,
        "validation_profile": validation_profile,
        "development_only": validation_profile == "development",
        "valid_for_qualification": validation_profile == "qualification",
        "reviewed_at": now.isoformat(),
        "packet_sha256": _sha256(packet_path),
        "execution_allowed": False,
    }


def _validate_source_report(
    value: dict[str, Any] | None,
    *,
    failures: list[str],
    checks: dict[str, bool] | None = None,
) -> list[dict[str, Any]]:
    checks = checks if checks is not None else {}
    if value is None:
        _require(checks, failures, "bounded_plan_report_present", False)
        return []
    checks["bounded_plan_report_present"] = True
    _require_equal(
        checks,
        failures,
        "bounded_plan_report_schema",
        value.get("schema_version"),
        SOURCE_SCHEMA_VERSION,
    )
    _require(checks, failures, "bounded_plan_report_passed", value.get("passed") is True)
    _require_equal(
        checks,
        failures,
        "bounded_plan_report_boundary",
        value.get("boundary"),
        SOURCE_BOUNDARY,
    )
    readiness = _object(value.get("readiness"))
    _require(
        checks,
        failures,
        "bounded_plan_drafts_ready",
        readiness.get("bounded_plan_drafts_ready_for_review") is True,
    )
    surface = _object(value.get("draft_surface"))
    drafts = _objects(surface.get("drafts"))
    draft_ids = [str(draft.get("draft_id") or "") for draft in drafts]
    _require(checks, failures, "bounded_plan_drafts_present", bool(drafts))
    _require_equal(
        checks,
        failures,
        "bounded_plan_draft_count_consistent",
        surface.get("draft_count"),
        len(drafts),
    )
    _require(
        checks,
        failures,
        "bounded_plan_draft_ids_unique",
        all(draft_ids) and len(draft_ids) == len(set(draft_ids)),
    )
    _require(
        checks,
        failures,
        "bounded_plan_draft_contracts_valid",
        all(_valid_draft_contract(draft) for draft in drafts),
    )
    return drafts


def _valid_draft_contract(draft: dict[str, Any]) -> bool:
    challenge = _object(draft.get("challenge_window"))
    execution = _object(draft.get("execution_policy"))
    return (
        draft.get("state") == "bounded_plan_draft_review_required"
        and bool(_object(draft.get("source_binding")).get("evidence_refs"))
        and challenge.get("required") is True
        and _integer(challenge.get("minimum_duration_seconds"))
        >= MINIMUM_CHALLENGE_WINDOW_SECONDS
        and set(challenge.get("required_roles", [])) == REQUIRED_REVIEWER_ROLES
        and challenge.get("unresolved_challenge_blocks_progression") is True
        and execution.get("draft_only") is True
        and not any(
            value for key, value in execution.items() if key != "draft_only"
        )
        and _object(draft.get("review_policy")).get("automatic_approval_allowed")
        is False
    )


def _validate_review_packet(
    value: dict[str, Any] | None,
    *,
    source_path: Path,
    drafts: list[dict[str, Any]],
    failures: list[str],
    checks: dict[str, bool],
    max_future_skew_seconds: float,
    current_time: datetime,
) -> tuple[list[dict[str, Any]], bool]:
    if value is None:
        _require(checks, failures, "challenge_review_packet_present", False)
        return [], False
    checks["challenge_review_packet_present"] = True
    _require_equal(
        checks,
        failures,
        "challenge_review_packet_schema",
        value.get("schema_version"),
        REVIEW_PACKET_SCHEMA_VERSION,
    )
    _require_equal(
        checks,
        failures,
        "challenge_review_packet_state",
        value.get("state"),
        "challenge_window_open",
    )
    _require_equal(
        checks,
        failures,
        "challenge_review_source_binding",
        value.get("source_bounded_plan_report"),
        _artifact_ref(source_path) if source_path.is_file() else None,
    )
    _require_equal(
        checks,
        failures,
        "challenge_review_packet_boundary",
        value.get("boundary"),
        REVIEW_BOUNDARY,
    )
    _require_equal(
        checks,
        failures,
        "challenge_review_packet_non_claims",
        value.get("non_claims"),
        _non_claims(),
    )
    validation_profile = _validation_profile(value)
    _require(
        checks,
        failures,
        "validation_profile_supported",
        validation_profile in VALIDATION_PROFILES,
    )
    _require_equal(
        checks,
        failures,
        "development_only_flag",
        value.get("development_only", False),
        validation_profile == "development",
    )
    _require_equal(
        checks,
        failures,
        "valid_for_qualification_flag",
        value.get("valid_for_qualification", True),
        validation_profile == "qualification",
    )
    _require_equal(
        checks,
        failures,
        "challenge_review_allowed_decisions",
        value.get("allowed_decisions"),
        sorted(ALLOWED_DECISIONS),
    )
    _require_equal(
        checks,
        failures,
        "challenge_review_required_roles",
        value.get("required_reviewer_roles"),
        sorted(REQUIRED_REVIEWER_ROLES),
    )
    opened_at = _timestamp(value.get("opened_at"))
    closes_at = _timestamp(value.get("closes_at"))
    minimum_duration = _integer(value.get("minimum_duration_seconds"))
    qualification_minimum_duration = _integer(
        value.get(
            "qualification_minimum_duration_seconds",
            MINIMUM_CHALLENGE_WINDOW_SECONDS,
        )
    )
    if validation_profile == "development":
        duration_valid = (
            1 <= minimum_duration <= MAXIMUM_DEVELOPMENT_WINDOW_SECONDS
            and qualification_minimum_duration
            >= MINIMUM_CHALLENGE_WINDOW_SECONDS
        )
    else:
        duration_valid = (
            minimum_duration >= MINIMUM_CHALLENGE_WINDOW_SECONDS
            and qualification_minimum_duration == minimum_duration
        )
    valid_window = (
        opened_at is not None
        and closes_at is not None
        and duration_valid
        and closes_at == opened_at + timedelta(seconds=minimum_duration)
        and opened_at <= current_time + timedelta(seconds=max_future_skew_seconds)
    )
    _require(checks, failures, "challenge_window_valid", valid_window)
    window_closed = bool(closes_at is not None and current_time >= closes_at)
    _require(checks, failures, "challenge_window_closed", window_closed)

    reviews = _objects(value.get("reviews"))
    draft_by_id = {str(draft["draft_id"]): draft for draft in drafts}
    expected_keys = {
        (draft_id, role)
        for draft_id in draft_by_id
        for role in REQUIRED_REVIEWER_ROLES
    }
    review_keys = [
        (
            str(review.get("draft_id") or ""),
            str(review.get("reviewer_role") or ""),
        )
        for review in reviews
    ]
    _require_equal(
        checks,
        failures,
        "challenge_review_draft_count",
        value.get("draft_count"),
        len(drafts),
    )
    _require_equal(
        checks,
        failures,
        "challenge_review_count",
        value.get("required_review_count"),
        len(expected_keys),
    )
    _require(
        checks,
        failures,
        "challenge_review_keys_unique_and_complete",
        len(review_keys) == len(set(review_keys))
        and set(review_keys) == expected_keys,
    )
    _require(
        checks,
        failures,
        "max_future_skew_non_negative",
        max_future_skew_seconds >= 0,
    )

    review_checks = []
    for review in reviews:
        draft_id = str(review.get("draft_id") or "")
        draft = draft_by_id.get(draft_id)
        decision = str(review.get("decision") or "")
        reviewed_at = _timestamp(review.get("reviewed_at"))
        expected_hash = _canonical_sha256(draft) if draft is not None else None
        valid = {
            "draft_exists": draft is not None,
            "draft_hash_matches": review.get("draft_sha256") == expected_hash,
            "proposal_kind_matches": (
                draft is not None
                and review.get("proposal_kind") == draft.get("proposal_kind")
            ),
            "reviewer_role_required": (
                str(review.get("reviewer_role") or "") in REQUIRED_REVIEWER_ROLES
            ),
            "reviewer_id_present": bool(str(review.get("reviewer_id") or "").strip()),
            "decision_allowed": decision in ALLOWED_DECISIONS,
            "reason_present": len(str(review.get("reason") or "").strip()) >= 8,
            "reviewed_at_valid": reviewed_at is not None,
            "reviewed_after_open": (
                reviewed_at is not None
                and opened_at is not None
                and reviewed_at >= opened_at
            ),
            "reviewed_at_not_future": (
                reviewed_at is not None
                and reviewed_at
                <= current_time + timedelta(seconds=max_future_skew_seconds)
            ),
            "requested_changes_shape": (
                len(str(review.get("requested_changes") or "").strip()) >= 8
                if decision == "request_revision"
                else review.get("requested_changes") in (None, "")
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
                failures.append(f"review {draft_id or '<missing>'}: {name} failed")
    _require(
        checks,
        failures,
        "challenge_review_fields_valid",
        bool(reviews) and all(review_checks),
    )
    return reviews, window_closed


def _group_reviews(
    reviews: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for review in reviews:
        grouped.setdefault(str(review.get("draft_id") or ""), []).append(review)
    return grouped


def _reconcile_draft(
    draft: dict[str, Any],
    reviews: list[dict[str, Any]],
) -> dict[str, Any]:
    decisions = sorted(str(review.get("decision") or "") for review in reviews)
    if decisions and all(
        decision == "approve_for_authorization_request" for decision in decisions
    ):
        decision = "approved_for_authorization_request"
    elif "reject" in decisions:
        decision = "rejected"
    elif "request_revision" in decisions:
        decision = "revision_required"
    elif "need_more_evidence" in decisions:
        decision = "more_evidence_required"
    else:
        decision = "review_incomplete"
    return {
        "draft_id": draft["draft_id"],
        "draft_sha256": _canonical_sha256(draft),
        "proposal_kind": draft["proposal_kind"],
        "decision": decision,
        "reviewer_roles": sorted(
            str(review.get("reviewer_role") or "") for review in reviews
        ),
        "reviewer_ids": sorted(
            str(review.get("reviewer_id") or "") for review in reviews
        ),
        "review_decisions": decisions,
        "authorization_request_only": (
            decision == "approved_for_authorization_request"
        ),
        "execution_allowed": False,
    }


def _decision(
    *,
    structural_integrity_passed: bool,
    window_closed: bool,
    approved: list[str],
    validation_profile: str,
) -> str:
    if not structural_integrity_passed:
        return "blocked_h3_bounded_plan_challenge_review"
    if not window_closed:
        return "challenge_window_open"
    if approved:
        if validation_profile == "development":
            return "h3_development_authorization_request_flow_validated"
        return "h3_controlled_pilot_authorization_request_inputs_ready"
    return "h3_bounded_plan_drafts_blocked_by_review"


def _next_action(
    *,
    structural_integrity_passed: bool,
    window_closed: bool,
    approved: list[str],
    blocked: list[str],
    validation_profile: str,
) -> str:
    if not structural_integrity_passed:
        return "complete or repair all required challenge reviews"
    if not window_closed:
        return "wait for the minimum challenge window to close"
    if approved:
        if validation_profile == "development":
            return (
                "create a development-only authorization request artifact; "
                "do not treat it as qualification evidence or execute it"
            )
        return (
            "create a separate controlled-pilot authorization request for approved "
            "drafts; do not execute them"
        )
    if blocked:
        return "revise, close, or collect evidence for blocked drafts"
    return "no bounded plan draft is ready"


def _non_claims() -> list[str]:
    return [
        "review_does_not_emit_goals",
        "review_does_not_create_executable_plans",
        "review_does_not_authorize_controlled_pilot_execution",
        "review_does_not_call_llms_or_dispatch_agents",
        "review_does_not_create_external_side_effects",
        "review_does_not_mutate_iem_relation_authorization_or_normative_state",
        "review_does_not_authorize_production_transition",
    ]


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
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return value.astimezone(timezone.utc)


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _validation_profile(value: dict[str, Any] | None) -> str:
    if not value:
        return "qualification"
    return str(value.get("validation_profile") or "qualification")


def _integer(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


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


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    _write_json(temporary, value)
    temporary.replace(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init")
    init.add_argument("--bounded-plan-report", type=Path, required=True)
    init.add_argument("--output", type=Path, required=True)
    init.add_argument("--overwrite", action="store_true")
    init.add_argument(
        "--profile",
        choices=sorted(VALIDATION_PROFILES),
        default="qualification",
    )
    init.add_argument(
        "--development-window-seconds",
        type=int,
        default=DEFAULT_DEVELOPMENT_WINDOW_SECONDS,
    )
    reconcile = subparsers.add_parser("reconcile")
    reconcile.add_argument("--bounded-plan-report", type=Path, required=True)
    reconcile.add_argument("--review-packet", type=Path, required=True)
    reconcile.add_argument("--output", type=Path, required=True)
    reconcile.add_argument("--max-future-skew-seconds", type=float, default=300.0)
    status = subparsers.add_parser("status")
    status.add_argument("--review-packet", type=Path, required=True)
    record = subparsers.add_parser("record")
    record.add_argument("--review-packet", type=Path, required=True)
    record.add_argument("--draft-id", required=True)
    record.add_argument(
        "--reviewer-role",
        required=True,
        choices=sorted(REQUIRED_REVIEWER_ROLES),
    )
    record.add_argument("--reviewer-id", required=True)
    record.add_argument("--decision", required=True, choices=sorted(ALLOWED_DECISIONS))
    record.add_argument("--reason", required=True)
    record.add_argument("--requested-changes")
    record.add_argument("--evidence-request")
    return parser


def main() -> None:
    args = _parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    if args.command == "init":
        report = create_challenge_review_packet(
            bounded_plan_report_path=args.bounded_plan_report,
            output_path=args.output,
            agent_root=agent_root,
            overwrite=args.overwrite,
            validation_profile=args.profile,
            development_window_seconds=args.development_window_seconds,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return
    if args.command == "status":
        report = challenge_review_status(
            review_packet_path=args.review_packet,
            agent_root=agent_root,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        raise SystemExit(
            0
            if report["packet_present"] and report["packet_schema_valid"]
            else 2
        )
    if args.command == "record":
        report = record_challenge_review(
            review_packet_path=args.review_packet,
            agent_root=agent_root,
            draft_id=args.draft_id,
            reviewer_role=args.reviewer_role,
            reviewer_id=args.reviewer_id,
            decision=args.decision,
            reason=args.reason,
            requested_changes=args.requested_changes,
            evidence_request=args.evidence_request,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return
    report = reconcile_challenge_reviews(
        bounded_plan_report_path=args.bounded_plan_report,
        review_packet_path=args.review_packet,
        output_path=args.output,
        agent_root=agent_root,
        max_future_skew_seconds=args.max_future_skew_seconds,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
