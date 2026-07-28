from __future__ import annotations

import copy
import hashlib
import json

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_roster_assignment_rebind import (
    REQUIRED_REVIEW_CHECKS,
)
from benchmarks.j1.qualification_outcome_sensitive_roster_assignment_rebind_review import (
    APPROVAL_DECISION,
    approval_review_declaration,
    build_review_decision_template,
    build_review_request,
    validate_review_request,
)
from benchmarks.tests.test_j1_qualification_outcome_sensitive_roster_assignment_rebind import (
    _candidates,
)


NOW = "2026-07-29T10:00:00+08:00"
STATEMENT_SHA256 = "a" * 64
IMPLEMENTATION = {"source_revision": "b" * 40, "source_sha256": "c" * 64}
PLAN_PATH = "/private/outcome-rebind-plan.json"
PREFLIGHT_PATH = "/private/outcome-rebind-preflight.json"


def _bundle() -> tuple[dict, bytes, dict, bytes, dict]:
    _, _, plan = _candidates()
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    preflight = {
        "schema_version": (
            "j1-qualification-outcome-sensitive-"
            "roster-assignment-rebind-preflight:v1"
        ),
        "passed": True,
        "state": (
            "outcome_sensitive_roster_assignment_candidates_"
            "independent_review_required"
        ),
        "report_sha256": "d" * 64,
    }
    preflight_raw = json.dumps(preflight, sort_keys=True).encode()
    request = build_review_request(
        request_id="j1d-outcome-rebind-review-r1",
        created_at=NOW,
        plan_path=PLAN_PATH,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight_path=PREFLIGHT_PATH,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        authorization_id="j1d-outcome-rebind-owner-approval-r1",
        authorized_at=NOW,
        authorization_statement_sha256=STATEMENT_SHA256,
        implementation=IMPLEMENTATION,
    )
    return plan, plan_raw, preflight, preflight_raw, request


def _validate(bundle: tuple[dict, bytes, dict, bytes, dict]) -> list[str]:
    plan, plan_raw, preflight, preflight_raw, request = bundle
    return validate_review_request(
        request,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        expected_plan_path=PLAN_PATH,
        expected_candidate_preflight_path=PREFLIGHT_PATH,
        expected_authorization_statement_sha256=STATEMENT_SHA256,
        expected_implementation=IMPLEMENTATION,
    )


def test_request_binds_owner_candidates_scope_and_ten_checks() -> None:
    bundle = _bundle()
    request = bundle[4]

    assert _validate(bundle) == []
    assert request["owner_authorization"]["scope"] == "independent_review_only"
    assert request["required_checklist"] == sorted(REQUIRED_REVIEW_CHECKS)
    assert len(request["required_checklist"]) == 10
    assert request["review_scope"]["inventory"]["total_decision_count"] == 480
    assert request["review_scope"]["inventory"]["mentor_advice_required_count"] == 180
    template = build_review_decision_template(request)
    assert template["review_request_sha256"] == request["request_sha256"]
    assert all(value is False for value in template["checklist"].values())


def test_request_rejects_owner_authorization_drift() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    changed = copy.deepcopy(request)
    changed["owner_authorization"]["statement_sha256"] = "e" * 64
    changed["request_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "request_sha256"}
    )

    failures = _validate(
        (plan, plan_raw, preflight, preflight_raw, changed)
    )

    assert "outcome_rebind_review_owner_authorization_invalid" in failures


def test_request_rejects_candidate_path_or_hash_drift() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    changed = copy.deepcopy(request)
    changed["candidate_artifacts"]["rebind_plan"]["path"] = "/other/plan.json"
    changed["candidate_artifacts"]["rebound_assignment"][
        "canonical_sha256"
    ] = "f" * 64
    changed["request_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "request_sha256"}
    )

    failures = _validate(
        (plan, plan_raw, preflight, preflight_raw, changed)
    )

    assert "outcome_rebind_review_candidate_binding_invalid" in failures


def test_reviewer_declaration_is_exactly_request_bound_and_non_executable() -> None:
    request = _bundle()[4]
    declaration = approval_review_declaration(request)

    assert request["request_sha256"] in declaration
    assert APPROVAL_DECISION in declaration
    assert "all 10 required checklist items" in declaration
    assert "does not reassign or substitute any participant" in declaration
    assert "upgrade SI-13 maturity" in declaration
    assert hashlib.sha256(declaration.encode()).hexdigest()
