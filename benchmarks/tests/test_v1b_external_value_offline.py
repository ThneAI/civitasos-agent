from __future__ import annotations

import json
import stat
from copy import deepcopy
from pathlib import Path

from benchmarks.v1a_cost.contracts import write_private_json
from benchmarks.v1b_value.contracts import (
    OFFLINE_BOUNDARY,
    build_external_value_contract,
    build_external_value_receipt,
    finalize_artifact,
    validate_external_value_contract,
    validate_external_value_receipt,
)
from benchmarks.v1b_value.offline import (
    build_external_value_gate,
    build_preflight,
    generate_dry_run_fixture,
    validate_external_value_gate,
)


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _ref(name: str, seed: str = "a") -> dict[str, str]:
    return {"uri": f"evidence:v1b:{name}", "sha256": seed * 64}


def _contract(
    *,
    environment: str = "bank",
    test_funds: bool = False,
    internal_civ: bool = False,
    real: bool = True,
) -> dict:
    return build_external_value_contract(
        contract_id="v1b-contract:real-case-01",
        created_at=1,
        task_id="v1b-task-01",
        requester={
            "identity": "did:civ:external-requester",
            "control_group_id": "external-requester-control",
            "identity_attestation": _ref("requester-identity", "1"),
        },
        provider={
            "identity": "did:civ:provider",
            "control_group_id": "provider-control",
            "identity_attestation": _ref("provider-identity", "2"),
        },
        counterparty={
            "relationship_class": "independent" if real else "affiliate",
            "beneficial_owner_distinct": real,
            "real_external_counterparty": real,
            "independently_reviewed": real,
            "control_review_ref": _ref("control-review", "3"),
        },
        consideration={
            "kind": "monetary",
            "currency": "USD",
            "amount_microunits": 2_000_000,
            "unit": None,
            "quantity": None,
        },
        terms={
            "payment_environment": environment,
            "test_funds": test_funds,
            "internal_civ": internal_civ,
            "acceptance_required": True,
            "dispute_window_seconds": 60,
            "refund_policy": "full_or_partial_by_resolution",
            "requester_consent_ref": _ref("requester-consent", "4"),
            "deliverable_commitment_ref": _ref("deliverable", "5"),
        },
    )


def _receipt(
    contract: dict,
    *,
    outcome_status: str = "paid",
    dispute_status: str = "none_closed",
    environment: str = "bank",
    test_funds: bool = False,
    internal_civ: bool = False,
    attestation_class: str = "bank_statement",
    independently_verified: bool = True,
) -> dict:
    disputed = dispute_status == "open"
    if outcome_status == "paid":
        gross, refunded, net = 2_000_000, 0, 2_000_000
    elif outcome_status == "refunded":
        gross, refunded, net = 2_000_000, 2_000_000, 0
    else:
        gross, refunded, net = 0, 0, 0
    return build_external_value_receipt(
        receipt_id="v1b-receipt:real-case-01",
        observed_at=100,
        contract=contract,
        task_receipt={
            "task_id": contract["task_id"],
            "receipt_hash": "6" * 64,
            "complete": True,
            "consistency_status": "complete",
            "lifecycle": {
                "requester": contract["requester"]["identity"],
                "worker": contract["provider"]["identity"],
                "delivered": True,
                "reviewed": True,
                "settled": not disputed,
                "disputed": disputed,
                "failed": False,
            },
            "evidence": _ref("task-receipt", "7"),
        },
        acceptance={
            "status": "disputed" if disputed else "accepted",
            "accepted_at": 10,
            "evidence": _ref("acceptance", "8"),
        },
        dispute=(
            {
                "status": "open",
                "window_expires_at": 70,
                "opened_at": 20,
                "resolved_at": None,
                "evidence_refs": [_ref("open-dispute", "9")],
            }
            if disputed
            else {
                "status": "none_closed",
                "window_expires_at": 70,
                "opened_at": None,
                "resolved_at": None,
                "evidence_refs": [],
            }
        ),
        outcome={
            "status": outcome_status,
            "payment_environment": environment,
            "currency": "USD",
            "gross_microunits": gross,
            "refunded_microunits": refunded,
            "net_microunits": net,
            "unit": None,
            "quantity": None,
            "test_funds": test_funds,
            "internal_civ": internal_civ,
            "attestation_class": attestation_class,
            "independently_verified": independently_verified,
            "attestation_ref": _ref("outcome-attestation", "b"),
        },
    )


def _gate(root: Path, contract: dict, receipt: dict) -> dict:
    root.mkdir()
    contract_path = root / "contract.json"
    receipt_path = root / "receipt.json"
    preflight_path = root / "preflight.json"
    write_private_json(contract_path, contract)
    write_private_json(receipt_path, receipt)
    preflight = build_preflight(contract_path=contract_path, receipt_path=receipt_path)
    write_private_json(preflight_path, preflight)
    return build_external_value_gate(
        contract_path=contract_path,
        receipt_path=receipt_path,
        preflight_path=preflight_path,
    )


def test_dry_run_is_private_structural_and_non_promotable(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    result = generate_dry_run_fixture(root)
    gate = _read(root / "external-value-gate.json")

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600 for path in root.glob("*.json")
    )
    assert (
        result["decision"]
        == "offline_dry_run_passed_real_counterparty_evidence_required"
    )
    assert gate["offline_structural_passed"] is True
    assert gate["case_terminal_and_dispute_closed"] is True
    assert gate["real_counterparty_verified"] is False
    assert gate["real_counterparty_case_closed"] is False
    assert gate["external_revenue_observed"] is False
    assert gate["external_value_observed"] is False
    assert gate["market_demand_claim_allowed"] is False
    assert gate["unit_economics_claim_allowed"] is False
    assert gate["offline_boundary"] == OFFLINE_BOUNDARY


def test_dry_run_canonical_artifacts_are_deterministic(tmp_path: Path) -> None:
    first = generate_dry_run_fixture(tmp_path / "first")
    second = generate_dry_run_fixture(tmp_path / "second")

    for key in ("contract", "receipt", "preflight", "gate"):
        assert first[key]["canonical_sha256"] == second[key]["canonical_sha256"]


def test_fixture_contract_cannot_be_relabelled_as_real(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    generate_dry_run_fixture(root)
    contract = _read(root / "external-value-contract.json")
    contract["counterparty"].update(
        {
            "relationship_class": "independent",
            "beneficial_owner_distinct": True,
            "real_external_counterparty": True,
            "independently_reviewed": True,
        }
    )
    contract["provider"]["control_group_id"] = "another-control-group"
    contract = finalize_artifact(contract)

    failures = validate_external_value_contract(contract)
    assert "real_counterparty_requester_identity_fixture_evidence_forbidden" in failures
    assert "real_counterparty_control_review_fixture_evidence_forbidden" in failures


def test_real_counterparty_requires_distinct_control_groups() -> None:
    contract = _contract()
    contract["provider"]["control_group_id"] = contract["requester"]["control_group_id"]
    contract = finalize_artifact(contract)

    assert (
        "real_counterparty_control_group_matches"
        in validate_external_value_contract(contract)
    )


def test_verified_bank_payment_closes_one_external_value_case(tmp_path: Path) -> None:
    contract = _contract()
    gate = _gate(tmp_path / "paid", contract, _receipt(contract))

    assert gate["offline_structural_passed"] is True
    assert gate["real_counterparty_verified"] is True
    assert gate["real_counterparty_case_closed"] is True
    assert gate["external_revenue_observed"] is True
    assert gate["external_value_observed"] is True
    assert (
        gate["decision"] == "single_external_value_case_observed_no_market_demand_claim"
    )
    assert gate["market_demand_claim_allowed"] is False
    assert gate["unit_economics_claim_allowed"] is False


def test_verified_nonpayment_closes_case_without_external_value(tmp_path: Path) -> None:
    contract = _contract(environment="none")
    receipt = _receipt(
        contract,
        outcome_status="nonpayment",
        environment="none",
        attestation_class="signed_nonpayment",
    )
    gate = _gate(tmp_path / "nonpayment", contract, receipt)

    assert gate["real_counterparty_case_closed"] is True
    assert gate["gross_microunits"] == 0
    assert gate["net_microunits"] == 0
    assert gate["external_revenue_observed"] is False
    assert gate["external_value_observed"] is False
    assert gate["decision"] == "real_counterparty_case_closed_without_external_value"


def test_test_funds_do_not_become_external_revenue(tmp_path: Path) -> None:
    contract = _contract(environment="testnet_blockchain", test_funds=True)
    receipt = _receipt(
        contract,
        environment="testnet_blockchain",
        test_funds=True,
        attestation_class="test_funds_receipt",
    )
    gate = _gate(tmp_path / "test-funds", contract, receipt)

    assert gate["real_counterparty_case_closed"] is True
    assert gate["external_revenue_observed"] is False
    assert gate["external_value_observed"] is False


def test_refund_closes_case_without_external_revenue(tmp_path: Path) -> None:
    contract = _contract()
    receipt = _receipt(contract, outcome_status="refunded")
    gate = _gate(tmp_path / "refunded", contract, receipt)

    assert gate["real_counterparty_case_closed"] is True
    assert gate["net_microunits"] == 0
    assert gate["external_revenue_observed"] is False


def test_open_dispute_blocks_case_closure(tmp_path: Path) -> None:
    contract = _contract(environment="none")
    receipt = _receipt(
        contract,
        outcome_status="nonpayment",
        dispute_status="open",
        environment="none",
        attestation_class="signed_nonpayment",
    )
    gate = _gate(tmp_path / "open-dispute", contract, receipt)

    assert gate["offline_structural_passed"] is True
    assert gate["case_terminal_and_dispute_closed"] is False
    assert gate["real_counterparty_case_closed"] is False


def test_task_party_mismatch_is_rejected() -> None:
    contract = _contract()
    receipt = _receipt(contract)
    receipt["task_receipt"]["lifecycle"]["worker"] = "did:civ:wrong-provider"
    receipt = finalize_artifact(receipt)

    assert "task_provider_mismatch" in validate_external_value_receipt(
        receipt, contract
    )


def test_payment_arithmetic_is_rejected() -> None:
    contract = _contract()
    receipt = _receipt(contract)
    receipt["outcome"]["net_microunits"] = 1
    receipt = finalize_artifact(receipt)

    failures = validate_external_value_receipt(receipt, contract)
    assert "outcome_net_arithmetic_invalid" in failures
    assert "paid_outcome_amount_invalid" in failures


def test_preflight_fails_closed_on_tampered_contract(tmp_path: Path) -> None:
    root = tmp_path / "tampered"
    root.mkdir()
    contract = _contract()
    receipt = _receipt(contract)
    contract["task_id"] = "tampered-task"
    contract_path = root / "contract.json"
    receipt_path = root / "receipt.json"
    write_private_json(contract_path, contract)
    write_private_json(receipt_path, receipt)

    preflight = build_preflight(contract_path=contract_path, receipt_path=receipt_path)

    assert preflight["structural_passed"] is False
    assert (
        "external_value_contract_self_hash_invalid" in preflight["structural_failures"]
    )
    assert preflight["gate_generation_allowed"] is False


def test_gate_revalidates_preflight_lineage(tmp_path: Path) -> None:
    root = tmp_path / "lineage"
    root.mkdir()
    contract = _contract()
    receipt = _receipt(contract)
    contract_path = root / "contract.json"
    receipt_path = root / "receipt.json"
    preflight_path = root / "preflight.json"
    write_private_json(contract_path, contract)
    write_private_json(receipt_path, receipt)
    preflight = build_preflight(contract_path=contract_path, receipt_path=receipt_path)
    preflight["contract"]["canonical_sha256"] = "0" * 64
    write_private_json(preflight_path, finalize_artifact(preflight))

    gate = build_external_value_gate(
        contract_path=contract_path,
        receipt_path=receipt_path,
        preflight_path=preflight_path,
    )

    assert gate["offline_structural_passed"] is False
    assert "preflight_contract_binding_invalid" in gate["failure_reasons"]


def test_wrong_attestation_class_is_rejected() -> None:
    contract = _contract()
    receipt = deepcopy(_receipt(contract))
    receipt["outcome"]["attestation_class"] = "internal_civ_receipt"
    receipt = finalize_artifact(receipt)

    assert "outcome_attestation_class_mismatch" in validate_external_value_receipt(
        receipt, contract
    )


def test_gate_replay_rejects_forged_revenue_claim(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    generate_dry_run_fixture(root)
    contract = _read(root / "external-value-contract.json")
    receipt = _read(root / "external-value-receipt.json")
    preflight = _read(root / "preflight.json")
    gate = _read(root / "external-value-gate.json")
    gate["external_revenue_observed"] = True
    gate["external_value_observed"] = True
    gate = finalize_artifact(gate)

    failures = validate_external_value_gate(gate, contract, receipt, preflight)
    assert "gate_external_revenue_observed_replay_mismatch" in failures
    assert "gate_external_value_observed_replay_mismatch" in failures
