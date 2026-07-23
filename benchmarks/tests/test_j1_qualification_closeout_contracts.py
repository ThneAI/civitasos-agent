from __future__ import annotations

import copy

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_closeout_contracts import (
    build_closeout_contract,
    build_post_run_contract,
    validate_closeout_contract,
    validate_post_run_contract,
)


def _source() -> dict[str, str]:
    return {
        "amended_protocol_sha256": "a" * 64,
        "rebound_assignment_sha256": "b" * 64,
        "provider_admission_receipt_sha256": "c" * 64,
    }


def _implementation() -> dict[str, str]:
    return {"source_revision": "d" * 40, "source_sha256": "e" * 64}


def test_post_run_and_closeout_contracts_are_hash_bound() -> None:
    evaluator_sha256 = "f" * 64
    post_run = build_post_run_contract(
        contract_id="j1q-post-run-r1",
        created_at="2026-07-23T00:00:00+00:00",
        evaluator_manifest_sha256=evaluator_sha256,
        source_binding=_source(),
        implementation=_implementation(),
    )
    closeout = build_closeout_contract(
        contract_id="j1q-closeout-r1",
        created_at="2026-07-23T00:00:00+00:00",
        evaluator_manifest_sha256=evaluator_sha256,
        post_run_contract_sha256=post_run["contract_sha256"],
        source_binding=_source(),
        implementation=_implementation(),
    )

    assert (
        validate_post_run_contract(
            post_run,
            evaluator_manifest_sha256=evaluator_sha256,
            source_binding=_source(),
            implementation=_implementation(),
        )
        == []
    )
    assert (
        validate_closeout_contract(
            closeout,
            evaluator_manifest_sha256=evaluator_sha256,
            post_run_contract_sha256=post_run["contract_sha256"],
            source_binding=_source(),
            implementation=_implementation(),
        )
        == []
    )
    assert closeout["claim_policy"]["automatic_maturity_upgrade_allowed"] is False
    assert (
        post_run["terminal_completeness"]["failed_or_aborted_allows_partial_inventory"]
        is True
    )
    assert (
        post_run["terminal_completeness"][
            "partial_inventory_effectiveness_claim_allowed"
        ]
        is False
    )


def test_closeout_contract_rejects_effectiveness_override() -> None:
    evaluator_sha256 = "f" * 64
    post_run = build_post_run_contract(
        contract_id="j1q-post-run-r1",
        created_at="2026-07-23T00:00:00+00:00",
        evaluator_manifest_sha256=evaluator_sha256,
        source_binding=_source(),
        implementation=_implementation(),
    )
    closeout = build_closeout_contract(
        contract_id="j1q-closeout-r1",
        created_at="2026-07-23T00:00:00+00:00",
        evaluator_manifest_sha256=evaluator_sha256,
        post_run_contract_sha256=post_run["contract_sha256"],
        source_binding=_source(),
        implementation=_implementation(),
    )
    tampered = copy.deepcopy(closeout)
    tampered["operator_decision"]["operator_override_of_metrics_allowed"] = True
    assert canonical_sha256(tampered) != closeout["contract_sha256"]

    failures = validate_closeout_contract(
        tampered,
        evaluator_manifest_sha256=evaluator_sha256,
        post_run_contract_sha256=post_run["contract_sha256"],
        source_binding=_source(),
        implementation=_implementation(),
    )
    assert "closeout_contract_binding_invalid" in failures
    assert "closeout_contract_hash_invalid" in failures
