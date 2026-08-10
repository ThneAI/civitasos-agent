from __future__ import annotations

import copy
import hashlib
import json

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_infrastructure_rebind import (
    REQUIRED_REVIEW_CHECKS,
)
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_infrastructure_rebind_review import (
    APPROVAL_DECISION,
    EXECUTION_BOUNDARY,
    approval_review_declaration,
    build_review_decision_template,
    build_review_request,
    validate_review_request,
)
from benchmarks.tests.test_j1_qualification_outcome_sensitive_confirmatory_infrastructure_rebind import (
    _build,
    _fixtures,
)


NOW = "2026-08-11T08:00:00+08:00"
PLAN_PATH = "/private/confirmatory-infrastructure-plan.json"
PREFLIGHT_PATH = "/private/confirmatory-infrastructure-preflight.json"
STATEMENT_SHA256 = "a" * 64
IMPLEMENTATION = {"source_revision": "b" * 40, "source_sha256": "c" * 64}


def _bundle() -> tuple[dict, bytes, dict, bytes, dict]:
    plan = _build(_fixtures())
    plan_raw = json.dumps(plan, sort_keys=True).encode()
    preflight = {
        "report_sha256": "d" * 64,
        "docker_census": {
            "historical_j1_container_count": 240,
            "running_count": 0,
            "cleanup_authorized": False,
        },
        "disk_safety": {
            "historical_container_cleanup_authorized": False,
            "implicit_container_prune_authorized": False,
            "implicit_image_prune_authorized": False,
            "source_container_removal_authorized": False,
        },
    }
    preflight_raw = json.dumps(preflight, sort_keys=True).encode()
    request = build_review_request(
        request_id="confirmatory-infrastructure-review-r1",
        created_at=NOW,
        plan_path=PLAN_PATH,
        plan=plan,
        plan_bytes=plan_raw,
        candidate_preflight_path=PREFLIGHT_PATH,
        candidate_preflight=preflight,
        candidate_preflight_bytes=preflight_raw,
        authorization_id="owner-review-approval-r1",
        authorized_at=NOW,
        authorization_statement_sha256=STATEMENT_SHA256,
        implementation=IMPLEMENTATION,
    )
    return plan, plan_raw, preflight, preflight_raw, request


def _validate(request: dict) -> list[str]:
    plan, plan_raw, preflight, preflight_raw, _ = _bundle()
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


def test_request_binds_confirmatory_scope_and_owner_approval() -> None:
    request = _bundle()[4]

    assert _validate(request) == []
    assert request["owner_authorization"]["scope"] == "independent_review_only"
    assert request["review_scope"]["inventory"]["participant_count"] == 40
    assert request["review_scope"]["inventory"]["total_decision_count"] == 480
    assert (
        request["review_scope"]["inventory"][
            "mentor_confirmatory_signed_advice_count"
        ]
        == 180
    )
    assert request["review_scope"]["r4_reanalysis_allowed"] is False
    assert request["review_scope"]["advice_adherence_observed"] is False
    assert request["required_checklist"] == sorted(REQUIRED_REVIEW_CHECKS)
    assert len(request["required_checklist"]) == 14
    assert request["execution_boundary"] == EXECUTION_BOUNDARY


def test_request_rejects_owner_or_scope_tamper() -> None:
    changed = copy.deepcopy(_bundle()[4])
    changed["owner_authorization"]["statement_sha256"] = "0" * 64
    changed["review_scope"]["r4_reanalysis_allowed"] = True
    changed["request_sha256"] = canonical_sha256(
        {key: item for key, item in changed.items() if key != "request_sha256"}
    )

    failures = _validate(changed)

    assert "confirmatory_infrastructure_review_copy_on_write_binding_invalid" in failures


def test_decision_template_is_empty_and_fail_closed() -> None:
    request = _bundle()[4]
    decision = build_review_decision_template(request)

    assert decision["review_request_sha256"] == request["request_sha256"]
    assert decision["decision"] == ""
    assert decision["reviewer"]["did"] == ""
    assert all(value is False for value in decision["independence"].values())
    assert len(decision["checklist"]) == 14
    assert all(value is False for value in decision["checklist"].values())
    assert decision["execution_boundary"] == EXECUTION_BOUNDARY


def test_reviewer_declaration_binds_request_and_nonclaims() -> None:
    request = _bundle()[4]
    raw_sha256 = hashlib.sha256(b"review request").hexdigest()

    statement = approval_review_declaration(request, raw_sha256)

    assert raw_sha256 in statement
    assert request["request_sha256"] in statement
    assert APPROVAL_DECISION in statement
    assert "all 14 required checklist items" in statement
    assert "It does not create, start, rename, or remove any container" in statement
    assert "reanalyze r4" in statement
    assert "infer advice adherence" in statement
