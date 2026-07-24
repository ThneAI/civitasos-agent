from __future__ import annotations

import copy
import hashlib

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_frozen_execution_preflight import (
    PLAN_BOUNDARY,
    SOURCE_NAMES,
    build_execution_plan,
    build_preflight,
    owner_authorization_statement,
    validate_execution_plan,
    validate_preflight,
)


def _sources() -> dict[str, dict[str, str]]:
    return {
        name: {
            "path": f"/private/{name}.json",
            "sha256": hashlib.sha256(f"raw:{name}".encode()).hexdigest(),
            "canonical_sha256": hashlib.sha256(
                f"canonical:{name}".encode()
            ).hexdigest(),
        }
        for name in SOURCE_NAMES
    }


def _scope() -> dict:
    return {
        "provider_id": "openai_compatible",
        "provider_host": "api.deepseek.com",
        "model_id": "deepseek-v4-pro",
        "temperature": 0,
        "participant_count": 40,
        "mentor_participant_count": 20,
        "control_participant_count": 20,
        "matched_pair_count": 20,
        "task_count_per_participant": 8,
        "authorized_task_executions": 320,
        "same_stack_for_both_cohorts": True,
        "cohort_source": "reviewed_rebound_assignment",
        "outcome_evaluator_status": "operator_reviewed_frozen",
        "post_run_contract_status": "operator_reviewed_frozen",
        "operator_closeout_contract_status": "operator_reviewed_frozen",
    }


def _cost() -> dict:
    return {
        "currency": "usd_microunit",
        "authorized_provider_calls": 320,
        "aggregate_reserved_tokens": 800000,
        "aggregate_reserved_cost_microunits": 487360,
        "aggregate_protocol_max_cost_microunits": 4000000,
        "reservation_required_before_each_call": True,
        "actual_usage_reconciliation_required": True,
        "budget_overrun_fail_stop_required": True,
    }


def _controls() -> dict:
    return {
        "single_use": True,
        "atomic_claim_create_exclusive": True,
        "claimed_failure_requires_new_authorization": True,
        "unclaimed_expiry_requires_new_authorization": True,
        "container_state_recheck_before_claim": True,
        "provider_admission_recheck_before_claim": True,
        "post_run_receipt_required": True,
        "operator_closeout_required": True,
        "backend_fact_append_allowed": False,
        "ledger_append_allowed": False,
        "effectiveness_claim_before_closeout_allowed": False,
        "execution_root": "/private/run",
        "authorization_output_root": "/private/authorization",
        "authorization_consumption_path": "/private/claim.json",
        "post_run_output_root": "/private/post-run",
    }


def _plan(*, supersession: dict | None = None) -> dict:
    return build_execution_plan(
        run_id="j1d-run-r1",
        created_at="2026-07-24T08:00:00+08:00",
        ttl_seconds=1800,
        source_artifacts=_sources(),
        execution_scope=_scope(),
        cost_acknowledgement=_cost(),
        controls=_controls(),
        implementation={
            "source_revision": "a" * 40,
            "domain_source_sha256": "b" * 64,
            "operation_source_sha256": "c" * 64,
        },
        superseded_execution_evidence=supersession,
    )


def test_frozen_execution_plan_binds_exact_scope_cost_and_supersession() -> None:
    plan = _plan()

    assert validate_execution_plan(plan) == []
    assert plan["execution_scope"]["authorized_task_executions"] == 320
    assert plan["cost_acknowledgement"]["aggregate_reserved_tokens"] == 800000
    assert plan["superseded_execution_evidence"] == {
        "prior_v2_preflight_reusable": False,
        "prior_v2_authorization_reusable": False,
        "reason": "active_stack_and_frozen_evaluator_binding_changed",
    }
    assert plan["execution_boundary"] == PLAN_BOUNDARY


@pytest.mark.parametrize(
    ("section", "field", "value", "failure"),
    [
        (
            "execution_scope",
            "authorized_task_executions",
            319,
            "frozen_execution_scope_invalid",
        ),
        (
            "cost_acknowledgement",
            "aggregate_reserved_tokens",
            799999,
            "frozen_execution_cost_invalid",
        ),
        (
            "controls",
            "backend_fact_append_allowed",
            True,
            "frozen_execution_controls_invalid",
        ),
        (
            "execution_boundary",
            "provider_api_call_performed",
            True,
            "frozen_execution_boundary_invalid",
        ),
    ],
)
def test_frozen_execution_plan_rejects_scope_cost_or_boundary_tamper(
    section: str, field: str, value: object, failure: str
) -> None:
    plan = _plan()
    plan[section][field] = value

    failures = validate_execution_plan(plan)
    assert failure in failures
    assert "frozen_execution_plan_hash_invalid" in failures


def test_owner_statement_binds_active_stack_scope_and_cost() -> None:
    plan = _plan()
    statement = owner_authorization_statement(
        plan_artifact_sha256="d" * 64,
        plan=plan,
    )

    expected_hashes = (
        "d" * 64,
        plan["plan_sha256"],
        plan["source_artifacts"]["amended_protocol"]["canonical_sha256"],
        plan["source_artifacts"]["amended_design"]["canonical_sha256"],
        plan["source_artifacts"]["rebound_assignment"]["canonical_sha256"],
        plan["source_artifacts"]["infrastructure_activation"]["canonical_sha256"],
        plan["source_artifacts"]["provider_admission_receipt"]["canonical_sha256"],
        plan["source_artifacts"]["frozen_evaluation_closeout_bundle"][
            "canonical_sha256"
        ],
    )
    assert all(digest in statement for digest in expected_hashes)
    assert "exactly 40 participants, 20 pairs, and 320 provider calls" in statement
    assert "800000 tokens and 487360 USD microunits" in statement
    assert "4000000 USD microunits" in statement
    assert "does not itself start a container" in statement


def test_renewal_plan_binds_expired_unclaimed_v3_authorization() -> None:
    supersession = {
        "prior_v2_preflight_reusable": False,
        "prior_v2_authorization_reusable": False,
        "reason": "active_stack_and_frozen_evaluator_binding_changed",
        "prior_v3_authorization": {
            "path": "/private/prior-authorization.json",
            "sha256": "1" * 64,
            "signed_payload_sha256": "2" * 64,
            "authorization_id": "prior-v3-r1",
            "valid_until": "2026-07-24T14:07:35+00:00",
        },
        "prior_v3_gate": {
            "path": "/private/prior-gate.json",
            "sha256": "3" * 64,
            "canonical_sha256": "4" * 64,
        },
        "prior_v3_authorization_expired": True,
        "prior_v3_authorization_consumed": False,
        "prior_v3_authorization_reusable": False,
        "renewal_reason": "expired_unclaimed",
    }
    plan = _plan(supersession=supersession)
    statement = owner_authorization_statement(
        plan_artifact_sha256="5" * 64,
        plan=plan,
    )

    assert validate_execution_plan(plan) == []
    assert "prior-v3-r1" in statement
    assert "expired, unclaimed, non-reusable authorization" in statement
    assert "1" * 64 in statement
    assert "4" * 64 in statement


def test_renewal_plan_rejects_reusable_or_claimed_prior_authorization() -> None:
    supersession = {
        "prior_v2_preflight_reusable": False,
        "prior_v2_authorization_reusable": False,
        "reason": "active_stack_and_frozen_evaluator_binding_changed",
        "prior_v3_authorization": {
            "path": "/private/prior-authorization.json",
            "sha256": "1" * 64,
            "signed_payload_sha256": "2" * 64,
            "authorization_id": "prior-v3-r1",
            "valid_until": "2026-07-24T14:07:35+00:00",
        },
        "prior_v3_gate": {
            "path": "/private/prior-gate.json",
            "sha256": "3" * 64,
            "canonical_sha256": "4" * 64,
        },
        "prior_v3_authorization_expired": True,
        "prior_v3_authorization_consumed": True,
        "prior_v3_authorization_reusable": True,
        "renewal_reason": "expired_unclaimed",
    }
    plan = _plan()
    plan["superseded_execution_evidence"] = supersession

    failures = validate_execution_plan(plan)
    assert "frozen_execution_supersession_invalid" in failures
    assert "frozen_execution_plan_hash_invalid" in failures


def test_preflight_validates_exact_plan_inventory_and_statement() -> None:
    plan = _plan()
    plan_bytes = b'{"frozen":"plan"}\n'
    inventory = {
        "participant_count": 40,
        "container_count": 40,
        "created_count": 40,
        "running_count": 0,
        "container_set_sha256": "e" * 64,
        "container_details_persisted": False,
    }
    preflight = build_preflight(
        plan_path="/private/plan.json",
        plan_bytes=plan_bytes,
        plan=plan,
        created_at="2026-07-24T08:00:00+08:00",
        inventory_snapshot=inventory,
    )

    assert (
        validate_preflight(
            preflight,
            plan_path="/private/plan.json",
            plan_bytes=plan_bytes,
            plan=plan,
            expected_inventory_snapshot=inventory,
        )
        == []
    )
    assert preflight["readiness"]["single_use_authorization_issued"] is False
    assert preflight["readiness"]["controlled_experiment_execution_ready"] is False


def test_preflight_rejects_statement_or_check_tamper() -> None:
    plan = _plan()
    plan_bytes = b'{"frozen":"plan"}\n'
    inventory = {"running_count": 0}
    preflight = build_preflight(
        plan_path="/private/plan.json",
        plan_bytes=plan_bytes,
        plan=plan,
        created_at="2026-07-24T08:00:00+08:00",
        inventory_snapshot=inventory,
    )
    tampered = copy.deepcopy(preflight)
    tampered["checks"]["no_execution_or_external_write_performed"] = False
    tampered["owner_authorization"]["required_exact_statement"] += " tampered"

    failures = validate_preflight(
        tampered,
        plan_path="/private/plan.json",
        plan_bytes=plan_bytes,
        plan=plan,
        expected_inventory_snapshot=inventory,
    )
    assert "frozen_execution_preflight_checks_invalid" in failures
    assert "frozen_execution_preflight_owner_request_invalid" in failures
    assert "frozen_execution_preflight_hash_invalid" in failures


def test_validator_accepts_immutable_legacy_nonrenewal_preflight() -> None:
    plan = _plan()
    plan_bytes = b'{"frozen":"plan"}\n'
    inventory = {"running_count": 0}
    preflight = build_preflight(
        plan_path="/private/plan.json",
        plan_bytes=plan_bytes,
        plan=plan,
        created_at="2026-07-24T08:00:00+08:00",
        inventory_snapshot=inventory,
    )
    del preflight["checks"]["expired_unclaimed_v3_authorization_bound"]
    preflight["preflight_sha256"] = canonical_sha256(
        {key: item for key, item in preflight.items() if key != "preflight_sha256"}
    )

    assert (
        validate_preflight(
            preflight,
            plan_path="/private/plan.json",
            plan_bytes=plan_bytes,
            plan=plan,
            expected_inventory_snapshot=inventory,
        )
        == []
    )
