"""Offline V1-B external-value candidate, preflight, and Gate."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from benchmarks.v1a_cost.contracts import read_private_json, write_private_json

from .contracts import (
    GATE_SCHEMA,
    OFFLINE_BOUNDARY,
    PREFLIGHT_SCHEMA,
    artifact_ref,
    build_external_value_contract,
    build_external_value_receipt,
    finalize_artifact,
    real_counterparty_blockers,
    validate_external_value_contract,
    validate_external_value_receipt,
    validate_self_hash,
)


def build_preflight(*, contract_path: Path, receipt_path: Path) -> dict[str, Any]:
    contract = read_private_json(contract_path, "external value contract")
    receipt = read_private_json(receipt_path, "external value receipt")
    failures = _structural_failures(contract, receipt)
    blockers = real_counterparty_blockers(contract, receipt)
    structural_passed = not failures
    artifact = {
        "schema_version": PREFLIGHT_SCHEMA,
        "contract": artifact_ref(contract_path, contract),
        "receipt": artifact_ref(receipt_path, receipt),
        "structural_passed": structural_passed,
        "real_counterparty_review_ready": structural_passed and not blockers,
        "gate_generation_allowed": structural_passed,
        "structural_failures": failures,
        "real_counterparty_blockers": blockers,
        "decision": (
            "offline_external_value_gate_generation_ready"
            if structural_passed
            else "offline_external_value_preflight_failed"
        ),
        "offline_boundary": deepcopy(OFFLINE_BOUNDARY),
    }
    return finalize_artifact(artifact)


def validate_preflight(
    value: dict[str, Any], contract: dict[str, Any], receipt: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != PREFLIGHT_SCHEMA:
        return ["external_value_preflight_schema_invalid"]
    validate_self_hash(value, failures, "external_value_preflight")
    structural_failures = _structural_failures(contract, receipt)
    blockers = real_counterparty_blockers(contract, receipt)
    structural_passed = not structural_failures
    if _canonical_ref(value.get("contract")) != contract.get("contract_sha256"):
        failures.append("preflight_contract_binding_invalid")
    if _canonical_ref(value.get("receipt")) != receipt.get("receipt_sha256"):
        failures.append("preflight_receipt_binding_invalid")
    if value.get("structural_passed") is not structural_passed:
        failures.append("preflight_structural_decision_invalid")
    if value.get("real_counterparty_review_ready") is not (
        structural_passed and not blockers
    ):
        failures.append("preflight_real_counterparty_decision_invalid")
    if value.get("gate_generation_allowed") is not structural_passed:
        failures.append("preflight_gate_permission_invalid")
    if value.get("structural_failures") != structural_failures:
        failures.append("preflight_structural_failures_invalid")
    if value.get("real_counterparty_blockers") != blockers:
        failures.append("preflight_counterparty_blockers_invalid")
    expected_decision = (
        "offline_external_value_gate_generation_ready"
        if structural_passed
        else "offline_external_value_preflight_failed"
    )
    if value.get("decision") != expected_decision:
        failures.append("preflight_decision_invalid")
    if value.get("offline_boundary") != OFFLINE_BOUNDARY:
        failures.append("preflight_offline_boundary_invalid")
    return sorted(set(failures))


def build_external_value_gate(
    *, contract_path: Path, receipt_path: Path, preflight_path: Path
) -> dict[str, Any]:
    contract = read_private_json(contract_path, "external value contract")
    receipt = read_private_json(receipt_path, "external value receipt")
    preflight = read_private_json(preflight_path, "external value preflight")
    failures = _structural_failures(contract, receipt)
    failures.extend(validate_preflight(preflight, contract, receipt))
    failures = sorted(set(failures))
    structural_passed = not failures
    blockers = real_counterparty_blockers(contract, receipt)
    projection = _project_gate_state(contract, receipt, structural_passed, blockers)
    outcome = _object(receipt.get("outcome"))
    artifact = {
        "schema_version": GATE_SCHEMA,
        "contract": artifact_ref(contract_path, contract),
        "receipt": artifact_ref(receipt_path, receipt),
        "preflight": artifact_ref(preflight_path, preflight),
        **projection,
        "payment_status": outcome.get("status"),
        "currency": outcome.get("currency"),
        "gross_microunits": outcome.get("gross_microunits"),
        "refunded_microunits": outcome.get("refunded_microunits"),
        "net_microunits": outcome.get("net_microunits"),
        "test_funds": outcome.get("test_funds"),
        "internal_civ": outcome.get("internal_civ"),
        "failure_reasons": failures,
        "real_counterparty_blockers": blockers,
        "market_demand_claim_allowed": False,
        "unit_economics_claim_allowed": False,
        "backend_fact_append_allowed": False,
        "ledger_append_allowed": False,
        "separate_real_effect_authorization_required": True,
        "offline_boundary": deepcopy(OFFLINE_BOUNDARY),
    }
    result = finalize_artifact(artifact)
    gate_failures = validate_external_value_gate(result, contract, receipt, preflight)
    if gate_failures:
        raise ValueError(f"external value Gate invalid: {gate_failures}")
    return result


def validate_external_value_gate(
    value: dict[str, Any],
    contract: dict[str, Any] | None = None,
    receipt: dict[str, Any] | None = None,
    preflight: dict[str, Any] | None = None,
) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != GATE_SCHEMA:
        return ["external_value_gate_schema_invalid"]
    validate_self_hash(value, failures, "external_value_gate")
    for field in (
        "market_demand_claim_allowed",
        "unit_economics_claim_allowed",
        "backend_fact_append_allowed",
        "ledger_append_allowed",
    ):
        if value.get(field) is not False:
            failures.append(f"gate_{field}_must_be_false")
    if value.get("separate_real_effect_authorization_required") is not True:
        failures.append("gate_real_effect_authorization_boundary_invalid")
    if value.get("offline_boundary") != OFFLINE_BOUNDARY:
        failures.append("gate_offline_boundary_invalid")
    if value.get("external_revenue_observed") is True and not all(
        value.get(field) is True
        for field in (
            "offline_structural_passed",
            "real_counterparty_case_closed",
            "external_value_observed",
        )
    ):
        failures.append("external_revenue_without_required_gate_conditions")
    supplied = (contract, receipt, preflight)
    if any(item is not None for item in supplied) and not all(
        item is not None for item in supplied
    ):
        failures.append("gate_replay_inputs_incomplete")
    elif all(item is not None for item in supplied):
        assert contract is not None
        assert receipt is not None
        assert preflight is not None
        replay_failures = _structural_failures(contract, receipt)
        replay_failures.extend(validate_preflight(preflight, contract, receipt))
        replay_failures = sorted(set(replay_failures))
        blockers = real_counterparty_blockers(contract, receipt)
        projection = _project_gate_state(
            contract, receipt, not replay_failures, blockers
        )
        for field, expected in projection.items():
            if value.get(field) != expected:
                failures.append(f"gate_{field}_replay_mismatch")
        if value.get("failure_reasons") != replay_failures:
            failures.append("gate_failure_reasons_replay_mismatch")
        if value.get("real_counterparty_blockers") != blockers:
            failures.append("gate_counterparty_blockers_replay_mismatch")
        if _canonical_ref(value.get("contract")) != contract.get("contract_sha256"):
            failures.append("gate_contract_binding_invalid")
        if _canonical_ref(value.get("receipt")) != receipt.get("receipt_sha256"):
            failures.append("gate_receipt_binding_invalid")
        if _canonical_ref(value.get("preflight")) != preflight.get("preflight_sha256"):
            failures.append("gate_preflight_binding_invalid")
    return sorted(set(failures))


def generate_dry_run_fixture(output_root: Path) -> dict[str, Any]:
    root = output_root.expanduser().resolve()
    if root.exists():
        raise ValueError(f"V1-B output root already exists: {root}")
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    requester_identity = "did:civ:v1b-fixture-requester"
    provider_identity = "did:civ:v1b-fixture-provider"
    requester = {
        "identity": requester_identity,
        "control_group_id": "fixture-control-group",
        "identity_attestation": _fixture_ref("requester-identity", "a"),
    }
    provider = {
        "identity": provider_identity,
        "control_group_id": "fixture-control-group",
        "identity_attestation": _fixture_ref("provider-identity", "b"),
    }
    contract = build_external_value_contract(
        contract_id="v1b-contract:dry-run-20260814",
        created_at=10,
        task_id="v1b-dry-task-01",
        requester=requester,
        provider=provider,
        counterparty={
            "relationship_class": "self",
            "beneficial_owner_distinct": False,
            "real_external_counterparty": False,
            "independently_reviewed": False,
            "control_review_ref": _fixture_ref("control-review", "c"),
        },
        consideration={
            "kind": "monetary",
            "currency": "USD",
            "amount_microunits": 1_000_000,
            "unit": None,
            "quantity": None,
        },
        terms={
            "payment_environment": "testnet_blockchain",
            "test_funds": True,
            "internal_civ": False,
            "acceptance_required": True,
            "dispute_window_seconds": 86_400,
            "refund_policy": "full_on_rejection",
            "requester_consent_ref": _fixture_ref("requester-consent", "d"),
            "deliverable_commitment_ref": _fixture_ref("deliverable", "e"),
        },
    )
    contract_path = root / "external-value-contract.json"
    write_private_json(contract_path, contract)
    receipt = build_external_value_receipt(
        receipt_id="v1b-receipt:dry-run-20260814",
        observed_at=86_510,
        contract=contract,
        task_receipt={
            "task_id": "v1b-dry-task-01",
            "receipt_hash": "f" * 64,
            "complete": True,
            "consistency_status": "complete",
            "lifecycle": {
                "requester": requester_identity,
                "worker": provider_identity,
                "delivered": True,
                "reviewed": True,
                "settled": True,
                "disputed": False,
                "failed": False,
            },
            "evidence": _fixture_ref("task-receipt", "1"),
        },
        acceptance={
            "status": "accepted",
            "accepted_at": 100,
            "evidence": _fixture_ref("acceptance", "2"),
        },
        dispute={
            "status": "none_closed",
            "window_expires_at": 86_500,
            "opened_at": None,
            "resolved_at": None,
            "evidence_refs": [],
        },
        outcome={
            "status": "paid",
            "payment_environment": "testnet_blockchain",
            "currency": "USD",
            "gross_microunits": 1_000_000,
            "refunded_microunits": 0,
            "net_microunits": 1_000_000,
            "unit": None,
            "quantity": None,
            "test_funds": True,
            "internal_civ": False,
            "attestation_class": "dry_run_fixture",
            "independently_verified": False,
            "attestation_ref": _fixture_ref("test-payment", "3"),
        },
    )
    receipt_path = root / "external-value-receipt.json"
    write_private_json(receipt_path, receipt)
    preflight = build_preflight(contract_path=contract_path, receipt_path=receipt_path)
    preflight_path = root / "preflight.json"
    write_private_json(preflight_path, preflight)
    gate = build_external_value_gate(
        contract_path=contract_path,
        receipt_path=receipt_path,
        preflight_path=preflight_path,
    )
    gate_path = root / "external-value-gate.json"
    write_private_json(gate_path, gate)
    return {
        "output_root": str(root),
        "contract": artifact_ref(contract_path, contract),
        "receipt": artifact_ref(receipt_path, receipt),
        "preflight": artifact_ref(preflight_path, preflight),
        "gate": artifact_ref(gate_path, gate),
        "decision": gate["decision"],
    }


def _structural_failures(
    contract: dict[str, Any], receipt: dict[str, Any]
) -> list[str]:
    failures = validate_external_value_contract(contract)
    failures.extend(validate_external_value_receipt(receipt, contract))
    return sorted(set(failures))


def _case_closed(receipt: dict[str, Any]) -> bool:
    dispute_status = _object(receipt.get("dispute")).get("status")
    outcome_status = _object(receipt.get("outcome")).get("status")
    return dispute_status != "open" and outcome_status in {
        "paid",
        "nonpayment",
        "refunded",
        "in_kind_fulfilled",
    }


def _project_gate_state(
    contract: dict[str, Any],
    receipt: dict[str, Any],
    structural_passed: bool,
    blockers: list[str],
) -> dict[str, Any]:
    del contract
    case_closed = _case_closed(receipt)
    outcome = _object(receipt.get("outcome"))
    outcome_verified = (
        outcome.get("independently_verified") is True
        and outcome.get("attestation_class") != "dry_run_fixture"
        and not str(_object(outcome.get("attestation_ref")).get("uri", "")).startswith(
            "fixture:"
        )
    )
    real_counterparty_verified = structural_passed and not blockers
    real_case_closed = real_counterparty_verified and case_closed
    external_revenue_observed = (
        real_case_closed
        and outcome_verified
        and outcome.get("status") == "paid"
        and outcome.get("test_funds") is False
        and outcome.get("internal_civ") is False
        and outcome.get("payment_environment")
        in {"bank", "invoice", "mainnet_blockchain"}
        and _positive_int(outcome.get("net_microunits"))
    )
    external_non_monetary_value_observed = (
        real_case_closed
        and outcome_verified
        and outcome.get("status") == "in_kind_fulfilled"
    )
    external_value_observed = (
        external_revenue_observed or external_non_monetary_value_observed
    )
    if not structural_passed:
        decision = "offline_external_value_gate_failed"
    elif real_case_closed and external_value_observed:
        decision = "single_external_value_case_observed_no_market_demand_claim"
    elif real_case_closed:
        decision = "real_counterparty_case_closed_without_external_value"
    else:
        decision = "offline_dry_run_passed_real_counterparty_evidence_required"
    return {
        "offline_structural_passed": structural_passed,
        "case_terminal_and_dispute_closed": case_closed,
        "real_counterparty_verified": real_counterparty_verified,
        "real_counterparty_case_closed": real_case_closed,
        "external_revenue_observed": external_revenue_observed,
        "external_non_monetary_value_observed": external_non_monetary_value_observed,
        "external_value_observed": external_value_observed,
        "decision": decision,
    }


def _fixture_ref(name: str, seed: str) -> dict[str, str]:
    return {"uri": f"fixture:v1b:{name}", "sha256": seed * 64}


def _canonical_ref(value: Any) -> str:
    return str(_object(value).get("canonical_sha256", ""))


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _write_result(path: Path, value: dict[str, Any]) -> None:
    write_private_json(path.expanduser().resolve(), value)


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fixture = commands.add_parser("fixture")
    fixture.add_argument("--output-root", type=Path, required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--contract", type=Path, required=True)
    preflight.add_argument("--receipt", type=Path, required=True)
    preflight.add_argument("--output", type=Path, required=True)
    gate = commands.add_parser("gate")
    gate.add_argument("--contract", type=Path, required=True)
    gate.add_argument("--receipt", type=Path, required=True)
    gate.add_argument("--preflight", type=Path, required=True)
    gate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "fixture":
        result = generate_dry_run_fixture(args.output_root)
    elif args.command == "preflight":
        result = build_preflight(contract_path=args.contract, receipt_path=args.receipt)
        _write_result(args.output, result)
    else:
        result = build_external_value_gate(
            contract_path=args.contract,
            receipt_path=args.receipt,
            preflight_path=args.preflight,
        )
        _write_result(args.output, result)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
