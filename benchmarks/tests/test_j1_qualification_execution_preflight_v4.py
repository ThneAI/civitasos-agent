from __future__ import annotations

import copy
import hashlib

from benchmarks.j1.qualification_execution_preflight_v4 import (
    BOUNDARY,
    SOURCE_NAMES,
    build_execution_plan,
    build_preflight,
    validate_execution_plan,
)


def _refs() -> dict[str, dict[str, str]]:
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


def _plan() -> dict:
    return build_execution_plan(
        run_id="j1d-r4-run-r1",
        created_at="2026-07-25T12:00:00+08:00",
        source_artifacts=_refs(),
        frozen_stack_sha256="a" * 64,
        contract_sha256="b" * 64,
        provider_receipt_sha256="c" * 64,
        evaluation_bundle_sha256="d" * 64,
        paths={
            "execution_root": "/private/execution",
            "authorization_output_root": "/private/authorization",
            "authorization_claim_path": "/private/claim.json",
            "post_run_output_root": "/private/post-run",
        },
        implementation={
            "source_revision": "e" * 40,
            "domain_source_sha256": "f" * 64,
            "operation_source_sha256": "1" * 64,
        },
    )


def test_r4_execution_plan_binds_scope_budget_and_recovery_controls() -> None:
    plan = _plan()

    assert validate_execution_plan(plan) == []
    assert plan["execution_scope"]["authorized_provider_calls"] == 320
    assert plan["budget"]["aggregate_reserved_tokens"] == 800000
    assert plan["controls"]["unknown_provider_outcome_never_retried"] is True
    assert plan["execution_boundary"] == BOUNDARY


def test_r4_execution_plan_rejects_scope_or_claim_tamper() -> None:
    plan = _plan()
    tampered = copy.deepcopy(plan)
    tampered["execution_scope"]["authorized_provider_calls"] = 321
    tampered["controls"]["atomic_claim_create_exclusive"] = False

    failures = validate_execution_plan(tampered)
    assert "r4_execution_plan_scope_invalid" in failures
    assert "r4_execution_plan_controls_or_boundary_invalid" in failures
    assert "r4_execution_plan_hash_invalid" in failures


def test_r4_execution_preflight_requests_issuance_not_execution() -> None:
    plan = _plan()
    preflight = build_preflight(
        plan_path="/private/plan.json",
        plan_raw_sha256="2" * 64,
        plan=plan,
        created_at="2026-07-25T12:00:00+08:00",
        inventory_snapshot={
            "participant_container_count": 40,
            "created_count": 40,
            "running_count": 0,
        },
    )

    statement = preflight["owner_authorization"]["required_exact_statement"]
    assert "issuance of exactly one 1800-second single-use" in statement
    assert "does not itself claim the authorization" in statement
    assert preflight["readiness"]["single_use_authorization_issued"] is False
