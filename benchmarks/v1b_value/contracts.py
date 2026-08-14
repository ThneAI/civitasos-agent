"""Contracts for append-disabled V1-B external-value Evidence."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from benchmarks.v1a_cost.contracts import canonical_sha256, raw_sha256


CONTRACT_SCHEMA = "civitasos-v1b-external-value-contract:v1"
RECEIPT_SCHEMA = "civitasos-v1b-external-value-receipt:v1"
PREFLIGHT_SCHEMA = "civitasos-v1b-external-value-preflight:v1"
GATE_SCHEMA = "civitasos-v1b-external-value-gate:v1"

HASH_FIELDS = {
    CONTRACT_SCHEMA: "contract_sha256",
    RECEIPT_SCHEMA: "receipt_sha256",
    PREFLIGHT_SCHEMA: "preflight_sha256",
    GATE_SCHEMA: "gate_sha256",
}

RELATIONSHIP_CLASSES = {"independent", "affiliate", "self"}
CONSIDERATION_KINDS = {"monetary", "non_monetary"}
PAYMENT_ENVIRONMENTS = {
    "bank",
    "invoice",
    "mainnet_blockchain",
    "testnet_blockchain",
    "internal_civ",
    "none",
}
ACCEPTANCE_STATUSES = {"accepted", "rejected", "disputed"}
DISPUTE_STATUSES = {
    "none_closed",
    "open",
    "resolved_for_requester",
    "resolved_for_provider",
}
OUTCOME_STATUSES = {"paid", "nonpayment", "refunded", "in_kind_fulfilled"}
ATTESTATION_CLASSES = {
    "bank_statement",
    "invoice_receipt",
    "blockchain_confirmation",
    "signed_nonpayment",
    "signed_in_kind_attestation",
    "test_funds_receipt",
    "internal_civ_receipt",
    "dry_run_fixture",
}

OFFLINE_BOUNDARY = {
    "credential_file_accessed": False,
    "external_network_accessed": False,
    "external_payment_effect_performed": False,
    "participant_or_agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "external_revenue_claim_authorized": False,
    "market_demand_claim_authorized": False,
    "si12_or_si15_maturity_upgrade_authorized": False,
}


def finalize_artifact(value: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(value)
    field = HASH_FIELDS.get(str(result.get("schema_version", "")))
    if field is None:
        raise ValueError("unsupported V1-B artifact schema")
    result.pop(field, None)
    result[field] = canonical_sha256(result)
    return result


def validate_self_hash(value: dict[str, Any], failures: list[str], label: str) -> None:
    field = HASH_FIELDS.get(str(value.get("schema_version", "")))
    if field is None:
        failures.append(f"{label}_schema_invalid")
        return
    body = {key: item for key, item in value.items() if key != field}
    if value.get(field) != canonical_sha256(body):
        failures.append(f"{label}_self_hash_invalid")


def artifact_ref(path: Path, value: dict[str, Any]) -> dict[str, str]:
    field = HASH_FIELDS.get(str(value.get("schema_version", "")))
    if field is None:
        raise ValueError("unsupported V1-B artifact reference")
    return {
        "uri": f"artifact:v1b:{path.name}",
        "sha256": raw_sha256(path),
        "canonical_sha256": str(value.get(field, "")),
    }


def build_external_value_contract(
    *,
    contract_id: str,
    created_at: int,
    task_id: str,
    requester: dict[str, Any],
    provider: dict[str, Any],
    counterparty: dict[str, Any],
    consideration: dict[str, Any],
    terms: dict[str, Any],
) -> dict[str, Any]:
    artifact = {
        "schema_version": CONTRACT_SCHEMA,
        "contract_id": contract_id,
        "created_at": created_at,
        "status": "candidate",
        "task_id": task_id,
        "requester": deepcopy(requester),
        "provider": deepcopy(provider),
        "counterparty": deepcopy(counterparty),
        "consideration": deepcopy(consideration),
        "terms": deepcopy(terms),
        "raw_identity_payment_or_deliverable_payload_recorded": False,
        "offline_boundary": deepcopy(OFFLINE_BOUNDARY),
    }
    result = finalize_artifact(artifact)
    failures = validate_external_value_contract(result)
    if failures:
        raise ValueError(f"external value contract invalid: {failures}")
    return result


def validate_external_value_contract(value: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != CONTRACT_SCHEMA:
        return ["external_value_contract_schema_invalid"]
    validate_self_hash(value, failures, "external_value_contract")
    _require(_text(value.get("contract_id")), "contract_id_missing", failures)
    _require(_nonnegative_int(value.get("created_at")), "created_at_invalid", failures)
    _require(value.get("status") == "candidate", "contract_status_invalid", failures)
    _require(_text(value.get("task_id")), "task_id_missing", failures)
    requester = _object(value.get("requester"))
    provider = _object(value.get("provider"))
    _validate_party(requester, "requester", failures)
    _validate_party(provider, "provider", failures)
    _require(
        requester.get("identity") != provider.get("identity"),
        "requester_provider_identity_must_differ",
        failures,
    )
    counterparty = _object(value.get("counterparty"))
    relationship = counterparty.get("relationship_class")
    distinct = counterparty.get("beneficial_owner_distinct")
    real = counterparty.get("real_external_counterparty")
    reviewed = counterparty.get("independently_reviewed")
    _require(
        relationship in RELATIONSHIP_CLASSES,
        "counterparty_relationship_invalid",
        failures,
    )
    _require(type(distinct) is bool, "beneficial_owner_distinct_invalid", failures)
    _require(type(real) is bool, "real_external_counterparty_invalid", failures)
    _require(type(reviewed) is bool, "counterparty_review_flag_invalid", failures)
    _validate_evidence(
        counterparty.get("control_review_ref"), "control_review", failures
    )
    if relationship == "self":
        _require(distinct is False, "self_payment_cannot_be_owner_distinct", failures)
        _require(real is False, "self_payment_cannot_be_real_counterparty", failures)
    if relationship == "affiliate":
        _require(real is False, "affiliate_cannot_be_real_counterparty", failures)
    if real is True:
        _require(
            relationship == "independent", "real_counterparty_not_independent", failures
        )
        _require(distinct is True, "real_counterparty_owner_not_distinct", failures)
        _require(reviewed is True, "real_counterparty_not_reviewed", failures)
        _require(
            requester.get("control_group_id") != provider.get("control_group_id"),
            "real_counterparty_control_group_matches",
            failures,
        )
        for label, ref in (
            ("requester_identity", requester.get("identity_attestation")),
            ("provider_identity", provider.get("identity_attestation")),
            ("control_review", counterparty.get("control_review_ref")),
            (
                "requester_consent",
                _object(value.get("terms")).get("requester_consent_ref"),
            ),
            (
                "deliverable_commitment",
                _object(value.get("terms")).get("deliverable_commitment_ref"),
            ),
        ):
            _forbid_fixture_evidence(ref, f"real_counterparty_{label}", failures)
    consideration = _object(value.get("consideration"))
    terms = _object(value.get("terms"))
    _validate_consideration(consideration, failures)
    _validate_terms(terms, failures)
    _validate_terms_consideration(terms, consideration, failures)
    _require(
        value.get("raw_identity_payment_or_deliverable_payload_recorded") is False,
        "raw_sensitive_payload_must_not_be_recorded",
        failures,
    )
    _validate_boundary(value.get("offline_boundary"), failures)
    return sorted(set(failures))


def build_external_value_receipt(
    *,
    receipt_id: str,
    observed_at: int,
    contract: dict[str, Any],
    task_receipt: dict[str, Any],
    acceptance: dict[str, Any],
    dispute: dict[str, Any],
    outcome: dict[str, Any],
) -> dict[str, Any]:
    artifact = {
        "schema_version": RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "observed_at": observed_at,
        "contract_canonical_sha256": contract.get("contract_sha256"),
        "task_id": contract.get("task_id"),
        "task_receipt": deepcopy(task_receipt),
        "acceptance": deepcopy(acceptance),
        "dispute": deepcopy(dispute),
        "outcome": deepcopy(outcome),
        "raw_payment_deliverable_or_identity_payload_recorded": False,
        "offline_boundary": deepcopy(OFFLINE_BOUNDARY),
    }
    result = finalize_artifact(artifact)
    failures = validate_external_value_receipt(result, contract)
    if failures:
        raise ValueError(f"external value receipt invalid: {failures}")
    return result


def validate_external_value_receipt(
    value: dict[str, Any], contract: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != RECEIPT_SCHEMA:
        return ["external_value_receipt_schema_invalid"]
    validate_self_hash(value, failures, "external_value_receipt")
    _require(_text(value.get("receipt_id")), "receipt_id_missing", failures)
    observed_at = value.get("observed_at")
    _require(_nonnegative_int(observed_at), "receipt_observed_at_invalid", failures)
    _require(
        value.get("contract_canonical_sha256") == contract.get("contract_sha256"),
        "receipt_contract_binding_invalid",
        failures,
    )
    _require(
        value.get("task_id") == contract.get("task_id"),
        "receipt_task_binding_invalid",
        failures,
    )
    task = _object(value.get("task_receipt"))
    _validate_task_receipt(task, contract, failures)
    acceptance = _object(value.get("acceptance"))
    _validate_acceptance(acceptance, task, failures)
    dispute = _object(value.get("dispute"))
    _validate_dispute(dispute, acceptance, contract, observed_at, failures)
    outcome = _object(value.get("outcome"))
    _validate_outcome(outcome, contract, acceptance, dispute, failures)
    _require(
        value.get("raw_payment_deliverable_or_identity_payload_recorded") is False,
        "receipt_raw_sensitive_payload_must_not_be_recorded",
        failures,
    )
    _validate_boundary(value.get("offline_boundary"), failures)
    return sorted(set(failures))


def _validate_party(value: dict[str, Any], label: str, failures: list[str]) -> None:
    _require(_text(value.get("identity")), f"{label}_identity_missing", failures)
    _require(
        _text(value.get("control_group_id")), f"{label}_control_group_missing", failures
    )
    _validate_evidence(value.get("identity_attestation"), f"{label}_identity", failures)


def _validate_consideration(value: dict[str, Any], failures: list[str]) -> None:
    kind = value.get("kind")
    _require(kind in CONSIDERATION_KINDS, "consideration_kind_invalid", failures)
    if kind == "monetary":
        _require(
            _currency(value.get("currency")), "consideration_currency_invalid", failures
        )
        _require(
            _positive_int(value.get("amount_microunits")),
            "consideration_amount_invalid",
            failures,
        )
        _require(value.get("unit") is None, "monetary_unit_must_be_null", failures)
        _require(
            value.get("quantity") is None, "monetary_quantity_must_be_null", failures
        )
    elif kind == "non_monetary":
        _require(
            value.get("currency") is None,
            "non_monetary_currency_must_be_null",
            failures,
        )
        _require(
            value.get("amount_microunits") is None,
            "non_monetary_amount_must_be_null",
            failures,
        )
        _require(_text(value.get("unit")), "non_monetary_unit_missing", failures)
        _require(
            _positive_int(value.get("quantity")),
            "non_monetary_quantity_invalid",
            failures,
        )


def _validate_terms(value: dict[str, Any], failures: list[str]) -> None:
    environment = value.get("payment_environment")
    _require(
        environment in PAYMENT_ENVIRONMENTS, "payment_environment_invalid", failures
    )
    _require(type(value.get("test_funds")) is bool, "test_funds_flag_invalid", failures)
    _require(
        type(value.get("internal_civ")) is bool, "internal_civ_flag_invalid", failures
    )
    _require(
        value.get("acceptance_required") is True,
        "acceptance_must_be_required",
        failures,
    )
    _require(
        _positive_int(value.get("dispute_window_seconds")),
        "dispute_window_invalid",
        failures,
    )
    _require(
        value.get("refund_policy")
        in {"full_on_rejection", "full_or_partial_by_resolution"},
        "refund_policy_invalid",
        failures,
    )
    _validate_evidence(
        value.get("requester_consent_ref"), "requester_consent", failures
    )
    _validate_evidence(
        value.get("deliverable_commitment_ref"), "deliverable_commitment", failures
    )
    if environment == "testnet_blockchain":
        _require(
            value.get("test_funds") is True, "testnet_must_be_test_funds", failures
        )
    if value.get("test_funds") is True:
        _require(
            environment == "testnet_blockchain",
            "test_funds_environment_mismatch",
            failures,
        )
    if environment == "internal_civ":
        _require(
            value.get("internal_civ") is True,
            "internal_environment_flag_invalid",
            failures,
        )
    if value.get("internal_civ") is True:
        _require(
            environment == "internal_civ", "internal_civ_environment_mismatch", failures
        )


def _validate_terms_consideration(
    terms: dict[str, Any], consideration: dict[str, Any], failures: list[str]
) -> None:
    if consideration.get("kind") == "non_monetary":
        _require(
            terms.get("payment_environment") == "none",
            "non_monetary_payment_environment_must_be_none",
            failures,
        )
        _require(
            terms.get("test_funds") is False,
            "non_monetary_test_funds_invalid",
            failures,
        )
        _require(
            terms.get("internal_civ") is False,
            "non_monetary_internal_civ_invalid",
            failures,
        )


def _validate_task_receipt(
    value: dict[str, Any], contract: dict[str, Any], failures: list[str]
) -> None:
    _validate_evidence(value.get("evidence"), "task_receipt", failures)
    _require(_sha256(value.get("receipt_hash")), "task_receipt_hash_invalid", failures)
    _require(
        value.get("task_id") == contract.get("task_id"),
        "task_receipt_task_mismatch",
        failures,
    )
    _require(value.get("complete") is True, "task_receipt_incomplete", failures)
    _require(
        value.get("consistency_status") == "complete",
        "task_receipt_inconsistent",
        failures,
    )
    lifecycle = _object(value.get("lifecycle"))
    requester = _object(contract.get("requester"))
    provider = _object(contract.get("provider"))
    _require(
        lifecycle.get("requester") == requester.get("identity"),
        "task_requester_mismatch",
        failures,
    )
    _require(
        lifecycle.get("worker") == provider.get("identity"),
        "task_provider_mismatch",
        failures,
    )
    for field in ("delivered", "reviewed", "settled", "disputed", "failed"):
        _require(
            type(lifecycle.get(field)) is bool,
            f"task_lifecycle_{field}_invalid",
            failures,
        )


def _validate_acceptance(
    value: dict[str, Any], task: dict[str, Any], failures: list[str]
) -> None:
    status = value.get("status")
    accepted_at = value.get("accepted_at")
    _require(status in ACCEPTANCE_STATUSES, "acceptance_status_invalid", failures)
    _require(_nonnegative_int(accepted_at), "acceptance_time_invalid", failures)
    _validate_evidence(value.get("evidence"), "acceptance", failures)
    lifecycle = _object(task.get("lifecycle"))
    if status == "accepted":
        _require(
            lifecycle.get("delivered") is True, "accepted_task_not_delivered", failures
        )
        _require(
            lifecycle.get("reviewed") is True, "accepted_task_not_reviewed", failures
        )
        _require(
            lifecycle.get("settled") is True, "accepted_task_not_settled", failures
        )
        _require(
            lifecycle.get("disputed") is False,
            "accepted_task_marked_disputed",
            failures,
        )
        _require(
            lifecycle.get("failed") is False, "accepted_task_marked_failed", failures
        )
    elif status == "disputed":
        _require(
            lifecycle.get("disputed") is True,
            "disputed_acceptance_task_not_disputed",
            failures,
        )
    elif status == "rejected":
        _require(
            lifecycle.get("failed") is True or lifecycle.get("disputed") is True,
            "rejected_acceptance_task_not_terminal_failure",
            failures,
        )


def _validate_dispute(
    value: dict[str, Any],
    acceptance: dict[str, Any],
    contract: dict[str, Any],
    observed_at: Any,
    failures: list[str],
) -> None:
    status = value.get("status")
    _require(status in DISPUTE_STATUSES, "dispute_status_invalid", failures)
    accepted_at = acceptance.get("accepted_at")
    expires_at = value.get("window_expires_at")
    window = _object(contract.get("terms")).get("dispute_window_seconds")
    expected_expiry = (
        accepted_at + window
        if _nonnegative_int(accepted_at) and _positive_int(window)
        else None
    )
    _require(expires_at == expected_expiry, "dispute_window_expiry_invalid", failures)
    refs = value.get("evidence_refs")
    ref_values = refs if isinstance(refs, list) else []
    for index, ref in enumerate(ref_values):
        _validate_evidence(ref, f"dispute_{index}", failures)
    if status == "none_closed":
        window_closed = (
            _nonnegative_int(observed_at)
            and _nonnegative_int(expires_at)
            and observed_at >= expires_at
        )
        _require(window_closed, "dispute_window_not_closed", failures)
        _require(
            value.get("opened_at") is None, "closed_dispute_opened_at_invalid", failures
        )
        _require(
            value.get("resolved_at") is None,
            "closed_dispute_resolved_at_invalid",
            failures,
        )
    elif status == "open":
        _require(
            _nonnegative_int(value.get("opened_at")),
            "dispute_opened_at_invalid",
            failures,
        )
        _require(
            value.get("resolved_at") is None,
            "open_dispute_resolved_at_invalid",
            failures,
        )
        _require(bool(ref_values), "open_dispute_evidence_missing", failures)
    else:
        _require(
            _nonnegative_int(value.get("opened_at")),
            "resolved_dispute_opened_at_invalid",
            failures,
        )
        _require(
            _nonnegative_int(value.get("resolved_at")),
            "resolved_dispute_time_invalid",
            failures,
        )
        opened_at = value.get("opened_at")
        resolved_at = value.get("resolved_at")
        resolution_order_valid = (
            _nonnegative_int(opened_at)
            and _nonnegative_int(resolved_at)
            and resolved_at >= opened_at
        )
        _require(resolution_order_valid, "dispute_resolution_order_invalid", failures)
        _require(bool(ref_values), "resolved_dispute_evidence_missing", failures)


def _validate_outcome(
    value: dict[str, Any],
    contract: dict[str, Any],
    acceptance: dict[str, Any],
    dispute: dict[str, Any],
    failures: list[str],
) -> None:
    status = value.get("status")
    _require(status in OUTCOME_STATUSES, "outcome_status_invalid", failures)
    _require(
        value.get("payment_environment")
        == _object(contract.get("terms")).get("payment_environment"),
        "outcome_payment_environment_mismatch",
        failures,
    )
    _require(
        type(value.get("test_funds")) is bool, "outcome_test_funds_invalid", failures
    )
    _require(
        type(value.get("internal_civ")) is bool,
        "outcome_internal_civ_invalid",
        failures,
    )
    _require(
        type(value.get("independently_verified")) is bool,
        "outcome_review_flag_invalid",
        failures,
    )
    attestation_class = value.get("attestation_class")
    _require(
        attestation_class in ATTESTATION_CLASSES,
        "outcome_attestation_class_invalid",
        failures,
    )
    _validate_evidence(value.get("attestation_ref"), "outcome_attestation", failures)
    terms = _object(contract.get("terms"))
    _require(
        value.get("test_funds") == terms.get("test_funds"),
        "outcome_test_funds_mismatch",
        failures,
    )
    _require(
        value.get("internal_civ") == terms.get("internal_civ"),
        "outcome_internal_civ_mismatch",
        failures,
    )
    consideration = _object(contract.get("consideration"))
    kind = consideration.get("kind")
    gross = value.get("gross_microunits")
    refunded = value.get("refunded_microunits")
    net = value.get("net_microunits")
    if kind == "monetary":
        _require(
            value.get("currency") == consideration.get("currency"),
            "outcome_currency_mismatch",
            failures,
        )
        for field, item in (("gross", gross), ("refunded", refunded), ("net", net)):
            _require(_nonnegative_int(item), f"outcome_{field}_invalid", failures)
        if (
            _nonnegative_int(gross)
            and _nonnegative_int(refunded)
            and _nonnegative_int(net)
        ):
            _require(refunded <= gross, "outcome_refund_exceeds_gross", failures)
            _require(
                net == gross - refunded, "outcome_net_arithmetic_invalid", failures
            )
        if status == "paid":
            _require(
                gross == consideration.get("amount_microunits"),
                "outcome_gross_contract_mismatch",
                failures,
            )
            _require(
                refunded == 0 and net == gross, "paid_outcome_amount_invalid", failures
            )
            _require(
                acceptance.get("status") == "accepted",
                "paid_outcome_not_accepted",
                failures,
            )
        elif status == "nonpayment":
            _require(
                gross == 0 and refunded == 0 and net == 0,
                "nonpayment_outcome_amount_invalid",
                failures,
            )
        elif status == "refunded":
            _require(
                gross == consideration.get("amount_microunits"),
                "outcome_gross_contract_mismatch",
                failures,
            )
            _require(
                refunded == gross and net == 0,
                "refunded_outcome_amount_invalid",
                failures,
            )
        else:
            failures.append("monetary_outcome_cannot_be_in_kind")
    elif kind == "non_monetary":
        _require(
            status == "in_kind_fulfilled",
            "non_monetary_outcome_status_invalid",
            failures,
        )
        _require(
            value.get("currency") is None,
            "non_monetary_outcome_currency_invalid",
            failures,
        )
        _require(
            gross is None and refunded is None and net is None,
            "non_monetary_amounts_must_be_null",
            failures,
        )
        _require(
            value.get("unit") == consideration.get("unit"),
            "non_monetary_unit_mismatch",
            failures,
        )
        _require(
            value.get("quantity") == consideration.get("quantity"),
            "non_monetary_quantity_mismatch",
            failures,
        )
    if dispute.get("status") == "open":
        _require(
            status not in {"paid", "in_kind_fulfilled"},
            "open_dispute_cannot_finalize_value",
            failures,
        )
    expected_attestations = _expected_attestation_classes(
        str(status), str(value.get("payment_environment"))
    )
    _require(
        attestation_class in expected_attestations,
        "outcome_attestation_class_mismatch",
        failures,
    )
    if attestation_class == "dry_run_fixture":
        _require(
            value.get("independently_verified") is False,
            "fixture_outcome_marked_verified",
            failures,
        )
    if value.get("independently_verified") is True:
        _forbid_fixture_evidence(
            value.get("attestation_ref"), "verified_outcome", failures
        )


def real_counterparty_blockers(
    contract: dict[str, Any], receipt: dict[str, Any]
) -> list[str]:
    blockers: list[str] = []
    counterparty = _object(contract.get("counterparty"))
    requester = _object(contract.get("requester"))
    provider = _object(contract.get("provider"))
    if counterparty.get("real_external_counterparty") is not True:
        blockers.append("counterparty_not_declared_real_external")
    if counterparty.get("independently_reviewed") is not True:
        blockers.append("counterparty_not_independently_reviewed")
    if counterparty.get("relationship_class") != "independent":
        blockers.append("counterparty_not_independent")
    if counterparty.get("beneficial_owner_distinct") is not True:
        blockers.append("beneficial_owner_not_distinct")
    if requester.get("control_group_id") == provider.get("control_group_id"):
        blockers.append("requester_provider_control_group_matches")
    for label, ref in (
        ("requester_identity", requester.get("identity_attestation")),
        ("provider_identity", provider.get("identity_attestation")),
        ("control_review", counterparty.get("control_review_ref")),
        (
            "requester_consent",
            _object(contract.get("terms")).get("requester_consent_ref"),
        ),
        (
            "deliverable_commitment",
            _object(contract.get("terms")).get("deliverable_commitment_ref"),
        ),
        ("task_receipt", _object(receipt.get("task_receipt")).get("evidence")),
        ("acceptance", _object(receipt.get("acceptance")).get("evidence")),
        ("outcome_attestation", _object(receipt.get("outcome")).get("attestation_ref")),
    ):
        if _is_fixture_evidence(ref):
            blockers.append(f"{label}_uses_fixture_evidence")
    return sorted(set(blockers))


def _expected_attestation_classes(status: str, environment: str) -> set[str]:
    if status == "nonpayment":
        return {"signed_nonpayment", "dry_run_fixture"}
    if status == "in_kind_fulfilled":
        return {"signed_in_kind_attestation", "dry_run_fixture"}
    by_environment = {
        "bank": {"bank_statement"},
        "invoice": {"invoice_receipt"},
        "mainnet_blockchain": {"blockchain_confirmation"},
        "testnet_blockchain": {"test_funds_receipt", "dry_run_fixture"},
        "internal_civ": {"internal_civ_receipt", "dry_run_fixture"},
    }
    return by_environment.get(environment, set())


def _validate_evidence(value: Any, label: str, failures: list[str]) -> None:
    ref = _object(value)
    _require(_text(ref.get("uri")), f"{label}_evidence_uri_missing", failures)
    _require(_sha256(ref.get("sha256")), f"{label}_evidence_sha256_invalid", failures)


def _forbid_fixture_evidence(value: Any, label: str, failures: list[str]) -> None:
    if _is_fixture_evidence(value):
        failures.append(f"{label}_fixture_evidence_forbidden")


def _is_fixture_evidence(value: Any) -> bool:
    return str(_object(value).get("uri", "")).startswith("fixture:")


def _validate_boundary(value: Any, failures: list[str]) -> None:
    if _object(value) != OFFLINE_BOUNDARY:
        failures.append("offline_boundary_invalid")


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value if isinstance(value, str) and value.strip() else ""


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _currency(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 3 <= len(value) <= 16
        and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for char in value)
    )


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _require(condition: bool, failure: str, failures: list[str]) -> None:
    if not condition:
        failures.append(failure)
