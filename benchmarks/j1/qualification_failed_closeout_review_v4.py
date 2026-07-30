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


BUNDLE_SCHEMA_V1 = "j1-qualification-r4-failed-closeout-review-bundle:v1"
BUNDLE_SCHEMA = "j1-qualification-r4-failed-closeout-review-bundle:v2"
REQUEST_SCHEMA = "j1-qualification-r4-failed-closeout-review-request:v1"
RECEIPT_SCHEMA = "j1-qualification-r4-failed-closeout-review-receipt:v1"
GATE_SCHEMA = "j1-qualification-r4-failed-closeout-review-gate:v1"
OUTCOME_BUNDLE_SCHEMA = (
    "j1-qualification-outcome-sensitive-failed-closeout-review-bundle:v1"
)
OUTCOME_REQUEST_SCHEMA = (
    "j1-qualification-outcome-sensitive-failed-closeout-review-request:v1"
)
OUTCOME_RECEIPT_SCHEMA = (
    "j1-qualification-outcome-sensitive-failed-closeout-review-receipt:v1"
)
OUTCOME_GATE_SCHEMA = (
    "j1-qualification-outcome-sensitive-failed-closeout-review-gate:v1"
)
LEGACY_CHECKLIST = [
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
CHECKLIST = [
    "failed_closeout_replay_compatibility_reviewed",
    "failed_closeout_schema_and_signature_boundary_reviewed",
    "known_actual_and_unknown_reservation_accounting_reviewed",
    "conservative_chargeable_upper_bound_reviewed",
    "provider_outcome_unknown_terminal_no_retry_reviewed",
    "sanitized_failure_diagnostic_reviewed",
    "claim_live_report_and_budget_evidence_binding_reviewed",
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
    profile: str = "r4",
) -> dict[str, Any]:
    if profile not in {"r4", "outcome_sensitive"}:
        raise ValueError("failed closeout review profile invalid")
    value = {
        "schema_version": (
            OUTCOME_BUNDLE_SCHEMA if profile == "outcome_sensitive" else BUNDLE_SCHEMA
        ),
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
    source = bundle.get("source_implementation", {})
    files = source.get("source_files", {})
    verification = bundle.get("verification", {})
    if not (
        bundle.get("schema_version")
        in {BUNDLE_SCHEMA_V1, BUNDLE_SCHEMA, OUTCOME_BUNDLE_SCHEMA}
        and bundle.get("status") == "independent_review_required"
        and bundle.get("review_scope") == "failed_closeout_implementation_only"
        and _text(bundle.get("bundle_id"))
        and _rfc3339(bundle.get("created_at"))
    ):
        failures.append("failed_closeout_review_bundle_identity_invalid")
    run_valid = (
        _validate_legacy_r8_run(run)
        if bundle.get("schema_version") == BUNDLE_SCHEMA_V1
        else _validate_failed_run(run)
    )
    profile_valid = (
        run.get("execution_profile") == "outcome_sensitive"
        if bundle.get("schema_version") == OUTCOME_BUNDLE_SCHEMA
        else "execution_profile" not in run
    )
    if not (run_valid and profile_valid):
        failures.append("failed_closeout_review_run_evidence_invalid")
    required_sources = _required_sources(bundle)
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
        bundle.get("review_checklist")
        == (
            LEGACY_CHECKLIST
            if bundle.get("schema_version") == BUNDLE_SCHEMA_V1
            else CHECKLIST
        )
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
    outcome_sensitive = bundle.get("schema_version") == OUTCOME_BUNDLE_SCHEMA
    value = {
        "schema_version": (
            OUTCOME_REQUEST_SCHEMA if outcome_sensitive else REQUEST_SCHEMA
        ),
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
    run = bundle["run_evidence"]
    label = (
        "J1-D outcome-sensitive"
        if bundle.get("schema_version") == OUTCOME_BUNDLE_SCHEMA
        else "J1-D r4"
    )
    return (
        f"I have independently reviewed {label} failed-closeout implementation review "
        f"request raw SHA-256 {request_raw_sha256} and choose "
        "approve_failed_closeout_implementation. I confirm all "
        f"{len(CHECKLIST)} required checklist items, disclose all conflicts, affirm "
        "that I am independent from candidate authoring and have completed human "
        "review. I approve only copy-on-write promotion of review bundle raw SHA-256 "
        f"{bundle_raw_sha256}, canonical SHA-256 {bundle['bundle_sha256']}, binding "
        f"source revision {bundle['source_implementation']['source_revision']} and "
        f"failed run {run['run_id']} with {run['committed_task_count']} committed, "
        f"{run.get('failed_task_count', 1)} failed, "
        f"{run['unattempted_task_count']} unattempted tasks and conservative "
        "unknown-provider-outcome accounting frozen in that bundle. I acknowledge "
        "that this promotion permits only generation "
        "and signing of a failed-run closeout preflight and closeout. It does not "
        "promote an execution stack, start a participant container, read a provider "
        "credential, call a provider or model, execute an Agent or experiment, append "
        "Backend Facts, append the Ledger, issue or consume an execution authorization, "
        "retry any task or provider call from the failed run, or authorize an "
        "effectiveness claim."
    )


def _validate_legacy_r8_run(run: dict[str, Any]) -> bool:
    budget = run.get("budget_summary", {})
    return bool(
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
    )


def _validate_failed_run(run: dict[str, Any]) -> bool:
    budget = run.get("budget_summary", {})
    diagnostic = run.get("failure_diagnostic", {})
    committed = run.get("committed_task_count")
    failed = run.get("failed_task_count")
    unattempted = run.get("unattempted_task_count")
    provider_calls = run.get("provider_call_count")
    failure_state = run.get("failure_state")
    counts = (
        budget.get("reconciled_provider_call_count"),
        budget.get("overrun_provider_call_count"),
        budget.get("provider_outcome_unknown_call_count"),
        budget.get("actual_tokens"),
        budget.get("actual_cost_microunits"),
        budget.get("unknown_reserved_tokens"),
        budget.get("unknown_reserved_cost_microunits"),
        budget.get("chargeable_token_upper_bound"),
        budget.get("chargeable_cost_upper_bound_microunits"),
    )
    return bool(
        _text(run.get("run_id"))
        and _ref(run.get("claim"))
        and _ref(run.get("live_report"))
        and failure_state
        in {
            "task_failed_before_dispatch",
            "task_failed_after_response",
            "provider_outcome_unknown",
        }
        and all(_nonnegative_int(item) for item in (committed, failed, unattempted))
        and committed + failed + unattempted
        == (480 if run.get("execution_profile") == "outcome_sensitive" else 320)
        and failed == 1
        and _nonnegative_int(provider_calls)
        and all(_nonnegative_int(item) for item in counts)
        and provider_calls
        == (
            budget["reconciled_provider_call_count"]
            + budget["overrun_provider_call_count"]
            + budget["provider_outcome_unknown_call_count"]
        )
        and budget["chargeable_token_upper_bound"]
        == budget["actual_tokens"] + budget["unknown_reserved_tokens"]
        and budget["chargeable_cost_upper_bound_microunits"]
        == (
            budget["actual_cost_microunits"]
            + budget["unknown_reserved_cost_microunits"]
        )
        and budget["provider_outcome_unknown_call_count"]
        == (1 if failure_state == "provider_outcome_unknown" else 0)
        and (
            failure_state != "provider_outcome_unknown"
            or (
                budget["unknown_reserved_tokens"] > 0
                and budget["unknown_reserved_cost_microunits"] > 0
            )
        )
        and set(diagnostic)
        == {
            "failure_category",
            "failure_stage",
            "reason",
            "source_exception_type",
        }
        and diagnostic.get("failure_category")
        in {"http", "parse", "schema", "usage", "internal"}
        and _text(diagnostic.get("failure_stage"))
        and _text(diagnostic.get("reason"))
        and _text(diagnostic.get("source_exception_type"))
    )


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


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
    profile: str = "r4",
) -> dict[str, Any]:
    if signer.public_key_hex != reviewer.get("public_key_hex"):
        raise ValueError("failed closeout reviewer signer mismatch")
    value = {
        "schema_version": (
            OUTCOME_RECEIPT_SCHEMA if profile == "outcome_sensitive" else RECEIPT_SCHEMA
        ),
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
    profile: str = "r4",
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
        receipt.get("schema_version")
        == (
            OUTCOME_RECEIPT_SCHEMA
            if profile == "outcome_sensitive"
            else RECEIPT_SCHEMA
        )
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
    profile: str = "r4",
) -> dict[str, Any]:
    value = {
        "schema_version": (
            OUTCOME_GATE_SCHEMA if profile == "outcome_sensitive" else GATE_SCHEMA
        ),
        "passed": True,
        "failure_reasons": [],
        "state": (
            "outcome_sensitive_failed_closeout_implementation_frozen"
            if profile == "outcome_sensitive"
            else "r4_failed_closeout_implementation_frozen"
        ),
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


def _required_sources(bundle: dict[str, Any]) -> set[str]:
    if bundle.get("schema_version") == OUTCOME_BUNDLE_SCHEMA:
        return {
            "benchmarks/j1/qualification_failed_closeout_review_v4.py",
            "benchmarks/j1/qualification_failed_execution_closeout_v4.py",
            "benchmarks/j1/qualification_provider_broker.py",
            "benchmarks/j1_qualification_failed_closeout_review_v4.py",
            (
                "benchmarks/"
                "j1_qualification_outcome_sensitive_failed_execution_closeout.py"
            ),
        }
    return {
        "benchmarks/j1/qualification_failed_closeout_review_v4.py",
        "benchmarks/j1/qualification_failed_execution_closeout_v4.py",
        "benchmarks/j1/qualification_provider_broker.py",
        "benchmarks/j1_qualification_failed_closeout_review_v4.py",
        "benchmarks/j1_qualification_failed_execution_closeout_v4.py",
    }


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
        return (
            datetime.fromisoformat(str(value).replace("Z", "+00:00")).tzinfo is not None
        )
    except ValueError:
        return False


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)
