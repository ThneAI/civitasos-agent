"""Independent-review contracts for the J1-D r4 failed-closeout implementation."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256


BUNDLE_SCHEMA = "j1-qualification-r4-failed-closeout-review-bundle:v1"
REQUEST_SCHEMA = "j1-qualification-r4-failed-closeout-review-request:v1"
RECEIPT_SCHEMA = "j1-qualification-r4-failed-closeout-review-receipt:v1"
GATE_SCHEMA = "j1-qualification-r4-failed-closeout-review-gate:v1"
CHECKLIST = [
    "failed_closeout_v1_replay_compatibility_reviewed",
    "failed_closeout_v2_schema_and_signature_boundary_reviewed",
    "known_actual_and_unknown_reservation_accounting_reviewed",
    "conservative_chargeable_upper_bound_reviewed",
    "provider_outcome_unknown_terminal_no_retry_reviewed",
    "provider_broker_unknown_state_transition_reviewed",
    "r8_claim_live_report_and_budget_evidence_binding_reviewed",
    "source_revision_and_source_file_hashes_reviewed",
    "ruff_and_full_pytest_evidence_reviewed",
    "closeout_only_non_execution_boundary_reviewed",
]
BOUNDARY = {
    "failed_closeout_implementation_review_only": True,
    "execution_stack_promoted": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "pkcs11_signature_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_review_bundle(
    *,
    bundle_id: str,
    created_at: str,
    run_evidence: dict[str, Any],
    source_implementation: dict[str, Any],
    verification: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": BUNDLE_SCHEMA,
        "bundle_id": bundle_id,
        "status": "independent_review_required",
        "created_at": created_at,
        "review_scope": "failed_closeout_implementation_only",
        "run_evidence": copy.deepcopy(run_evidence),
        "source_implementation": copy.deepcopy(source_implementation),
        "verification": copy.deepcopy(verification),
        "review_checklist": copy.deepcopy(CHECKLIST),
        "promotion_contract": {
            "copy_on_write_only": True,
            "independent_human_review_required": True,
            "reviewer_signature_required": True,
            "failed_closeout_preflight_allowed_after_promotion": True,
            "execution_preflight_allowed": False,
            "provider_refresh_allowed": False,
            "new_execution_authorization_allowed": False,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["bundle_sha256"] = canonical_sha256(value)
    failures = validate_review_bundle(value)
    if failures:
        raise ValueError(f"failed closeout review bundle invalid: {failures}")
    return value


def validate_review_bundle(value: Any) -> list[str]:
    bundle = value if isinstance(value, dict) else {}
    failures: list[str] = []
    run = bundle.get("run_evidence", {})
    budget = run.get("budget_summary", {})
    source = bundle.get("source_implementation", {})
    files = source.get("source_files", {})
    verification = bundle.get("verification", {})
    if not (
        bundle.get("schema_version") == BUNDLE_SCHEMA
        and bundle.get("status") == "independent_review_required"
        and bundle.get("review_scope") == "failed_closeout_implementation_only"
        and _text(bundle.get("bundle_id"))
        and _rfc3339(bundle.get("created_at"))
    ):
        failures.append("failed_closeout_review_bundle_identity_invalid")
    if not (
        run.get("run_id") == "j1d-qualification-run-20260726-r8"
        and _ref(run.get("claim"))
        and _ref(run.get("live_report"))
        and run.get("failure_state") == "provider_outcome_unknown"
        and run.get("provider_call_count") == 4
        and run.get("committed_task_count") == 3
        and run.get("unattempted_task_count") == 316
        and budget.get("reconciled_provider_call_count") == 3
        and budget.get("provider_outcome_unknown_call_count") == 1
        and budget.get("actual_tokens") == 1256
        and budget.get("actual_cost_microunits") == 966
        and budget.get("unknown_reserved_tokens") == 2500
        and budget.get("unknown_reserved_cost_microunits") == 1523
        and budget.get("chargeable_token_upper_bound") == 3756
        and budget.get("chargeable_cost_upper_bound_microunits") == 2489
    ):
        failures.append("failed_closeout_review_run_evidence_invalid")
    required_sources = {
        "benchmarks/j1/qualification_failed_closeout_review_v4.py",
        "benchmarks/j1/qualification_failed_execution_closeout_v4.py",
        "benchmarks/j1/qualification_provider_broker.py",
        "benchmarks/j1_qualification_failed_closeout_review_v4.py",
        "benchmarks/j1_qualification_failed_execution_closeout_v4.py",
    }
    if not (
        _revision(source.get("source_revision"))
        and set(files) == required_sources
        and all(_sha256(item) for item in files.values())
    ):
        failures.append("failed_closeout_review_source_binding_invalid")
    if not (
        verification.get("ruff_all_passed") is True
        and verification.get("pytest_all_passed") is True
        and verification.get("pytest_passed_count", 0) >= 1490
        and verification.get("remote_revision_verified") is True
        and verification.get("provider_or_model_call_performed") is False
        and verification.get("participant_container_started") is False
    ):
        failures.append("failed_closeout_review_verification_invalid")
    if not (
        bundle.get("review_checklist") == CHECKLIST
        and bundle.get("promotion_contract", {}).get("execution_preflight_allowed")
        is False
        and bundle.get("promotion_contract", {}).get(
            "failed_closeout_preflight_allowed_after_promotion"
        )
        is True
        and bundle.get("execution_boundary") == BOUNDARY
    ):
        failures.append("failed_closeout_review_boundary_invalid")
    body = {key: item for key, item in bundle.items() if key != "bundle_sha256"}
    if bundle.get("bundle_sha256") != canonical_sha256(body):
        failures.append("failed_closeout_review_bundle_hash_invalid")
    return list(dict.fromkeys(failures))


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    bundle_ref: dict[str, str],
    bundle: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": request_id,
        "status": "independent_reviewer_decision_required",
        "created_at": created_at,
        "bundle": copy.deepcopy(bundle_ref),
        "required_checklist": copy.deepcopy(CHECKLIST),
        "allowed_decisions": [
            "approve_failed_closeout_implementation",
            "reject_failed_closeout_implementation",
        ],
        "reviewer_requirements": {
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
            "all_conflicts_disclosed": True,
            "all_checklist_items_confirmed": True,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["request_sha256"] = canonical_sha256(value)
    value["required_exact_approval_statement"] = reviewer_approval_statement(
        request_raw_sha256="{REQUEST_RAW_SHA256}",
        bundle_raw_sha256=bundle_ref["sha256"],
        bundle=bundle,
    )
    value["request_sha256"] = canonical_sha256(
        {key: item for key, item in value.items() if key != "request_sha256"}
    )
    return value


def reviewer_approval_statement(
    *,
    request_raw_sha256: str,
    bundle_raw_sha256: str,
    bundle: dict[str, Any],
) -> str:
    return (
        "I have independently reviewed J1-D r4 failed-closeout implementation review "
        f"request raw SHA-256 {request_raw_sha256} and choose "
        "approve_failed_closeout_implementation. I confirm all "
        f"{len(CHECKLIST)} required checklist items, disclose all conflicts, affirm "
        "that I am independent from candidate authoring and have completed human "
        "review. I approve only copy-on-write promotion of review bundle raw SHA-256 "
        f"{bundle_raw_sha256}, canonical SHA-256 {bundle['bundle_sha256']}, binding "
        f"source revision {bundle['source_implementation']['source_revision']} and "
        "the r8 failed-run conservative unknown-provider-outcome accounting frozen "
        "in that bundle. I acknowledge that this promotion permits only generation "
        "and signing of a failed-run closeout preflight and closeout. It does not "
        "promote an execution stack, start a participant container, read a provider "
        "credential, call a provider or model, execute an Agent or experiment, append "
        "Backend Facts, append the Ledger, issue or consume an execution authorization, "
        "retry any r8 task or provider call, or authorize an effectiveness claim."
    )


def build_signed_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    request_ref: dict[str, str],
    bundle_ref: dict[str, str],
    approval_statement_sha256: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    signer: ReviewSigner,
) -> dict[str, Any]:
    if signer.public_key_hex != reviewer.get("public_key_hex"):
        raise ValueError("failed closeout reviewer signer mismatch")
    value = {
        "schema_version": RECEIPT_SCHEMA,
        "review_id": review_id,
        "decision": "approve_failed_closeout_implementation",
        "reviewed_at": reviewed_at,
        "request": copy.deepcopy(request_ref),
        "bundle": copy.deepcopy(bundle_ref),
        "approval_statement_sha256": approval_statement_sha256,
        "reviewer": {
            **copy.deepcopy(reviewer),
            "identity_profile_sha256": reviewer_profile_sha256,
        },
        "checklist": {name: True for name in CHECKLIST},
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    payload = _payload(value)
    signature = signer.sign(payload)
    value["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    return value


def validate_signed_receipt(
    value: Any,
    *,
    request_ref: dict[str, str],
    bundle_ref: dict[str, str],
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    signature = receipt.get("signature", {})
    unsigned = {key: item for key, item in receipt.items() if key != "signature"}
    payload = _payload(unsigned)
    failures: list[str] = []
    try:
        VerifyKey(bytes.fromhex(expected_reviewer["public_key_hex"])).verify(
            payload, bytes.fromhex(str(signature.get("signature_hex", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append("failed_closeout_review_signature_invalid")
    if not (
        receipt.get("schema_version") == RECEIPT_SCHEMA
        and receipt.get("decision") == "approve_failed_closeout_implementation"
        and receipt.get("request") == request_ref
        and receipt.get("bundle") == bundle_ref
        and receipt.get("reviewer")
        == {
            **expected_reviewer,
            "identity_profile_sha256": expected_reviewer_profile_sha256,
        }
        and receipt.get("checklist") == {name: True for name in CHECKLIST}
        and receipt.get("execution_boundary") == BOUNDARY
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest()
    ):
        failures.append("failed_closeout_review_receipt_invalid")
    return list(dict.fromkeys(failures))


def build_review_gate(
    *,
    bundle_ref: dict[str, str],
    receipt_ref: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "r4_failed_closeout_implementation_frozen",
        "review_bundle": copy.deepcopy(bundle_ref),
        "review_receipt": copy.deepcopy(receipt_ref),
        "signature_valid": True,
        "readiness": {
            "failed_closeout_preflight_allowed": True,
            "failed_closeout_signing_allowed_after_owner_authorization": True,
            "execution_preflight_allowed": False,
            "provider_refresh_allowed": False,
            "execution_authorization_allowed": False,
        },
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    return value


def _payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _ref(value: Any) -> bool:
    item = value if isinstance(value, dict) else {}
    return (
        set(item) == {"path", "sha256", "canonical_sha256"}
        and str(item.get("path", "")).startswith("/")
        and _sha256(item.get("sha256"))
        and _sha256(item.get("canonical_sha256"))
    )


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _revision(value: Any) -> bool:
    if not isinstance(value, str) or len(value) not in {40, 64}:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _rfc3339(value: Any) -> bool:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)
