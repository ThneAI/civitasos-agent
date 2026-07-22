from __future__ import annotations

import copy
import hashlib
import json

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_roster_assignment_rebind_review import (
    REQUIRED_CHECKS,
    approval_review_declaration,
    build_rebind_review_decision_template,
    build_rebind_review_request,
    validate_rebind_review_request,
)
from benchmarks.tests.test_j1_qualification_roster_assignment_rebind import (
    _candidates,
)


NOW = "2026-07-23T11:00:00+08:00"
STATEMENT_SHA256 = "a" * 64
IMPLEMENTATION = {"source_revision": "b" * 40, "source_sha256": "c" * 64}


def _bundle() -> tuple[dict, bytes, dict, bytes, dict]:
    _, _, plan = _candidates()
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    preflight = {
        "schema_version": "j1-qualification-roster-assignment-rebind-preflight:v1",
        "passed": True,
        "state": "roster_assignment_rebind_candidates_independent_review_required",
        "report_sha256": "d" * 64,
    }
    preflight_raw = json.dumps(preflight, sort_keys=True).encode()
    request = build_rebind_review_request(
        request_id="j1d-rebind-review-r1",
        created_at=NOW,
        plan_path="/private/rebind-plan.json",
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight_path="/private/rebind-preflight.json",
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        authorization_id="j1d-rebind-owner-approval-r1",
        authorized_at=NOW,
        authorization_statement_sha256=STATEMENT_SHA256,
        implementation=IMPLEMENTATION,
    )
    return plan, plan_raw, preflight, preflight_raw, request


def _validate(bundle: tuple[dict, bytes, dict, bytes, dict]) -> list[str]:
    plan, plan_raw, preflight, preflight_raw, request = bundle
    return validate_rebind_review_request(
        request,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        expected_authorization_statement_sha256=STATEMENT_SHA256,
        expected_implementation=IMPLEMENTATION,
    )


def test_review_request_binds_owner_authorization_and_both_candidates() -> None:
    bundle = _bundle()
    request = bundle[4]

    assert _validate(bundle) == []
    assert request["owner_authorization"]["scope"] == "independent_review_only"
    assert request["required_checklist"] == sorted(REQUIRED_CHECKS)
    assert request["candidate_artifacts"]["rebound_roster"]
    assert request["candidate_artifacts"]["rebound_assignment"]
    template = build_rebind_review_decision_template(request)
    assert template["review_request_sha256"] == request["request_sha256"]
    assert all(value is False for value in template["checklist"].values())


def test_review_request_rejects_owner_authorization_drift() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    tampered = copy.deepcopy(request)
    tampered["owner_authorization"]["statement_sha256"] = "e" * 64
    tampered["request_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "request_sha256"}
    )

    failures = _validate((plan, plan_raw, preflight, preflight_raw, tampered))

    assert "rebind_review_owner_authorization_invalid" in failures


def test_review_request_rejects_candidate_drift() -> None:
    plan, plan_raw, preflight, preflight_raw, request = _bundle()
    tampered = copy.deepcopy(request)
    tampered["candidate_artifacts"]["rebound_roster"]["canonical_sha256"] = "f" * 64
    tampered["request_sha256"] = canonical_sha256(
        {key: item for key, item in tampered.items() if key != "request_sha256"}
    )

    failures = _validate((plan, plan_raw, preflight, preflight_raw, tampered))

    assert "rebind_review_candidate_binding_invalid" in failures


def test_review_declaration_is_request_bound_and_non_executable() -> None:
    request = _bundle()[4]
    declaration = approval_review_declaration(request)

    assert request["request_sha256"] in declaration
    assert "approve_roster_assignment_rebind" in declaration
    assert "does not reassign or substitute any participant" in declaration
    assert hashlib.sha256(declaration.encode()).hexdigest()
