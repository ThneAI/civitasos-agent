"""Independent review contracts for the J1-D r4 descriptive postmortem."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_postmortem import (
    ANALYSIS_BOUNDARY,
    HANDOFF_SCHEMA,
    REVIEW_CHECKLIST,
    REVIEW_REQUEST_SCHEMA,
    POSTMORTEM_SCHEMA,
    owner_review_statement,
    validate_postmortem,
)


OWNER_GATE_SCHEMA = "j1-outcome-sensitive-postmortem-owner-review-gate:v1"
REVIEW_HANDOFF_SCHEMA = "j1-outcome-sensitive-postmortem-review-decision-handoff:v1"
REVIEW_RECEIPT_SCHEMA = "j1-outcome-sensitive-postmortem-review-receipt:v1"
FROZEN_REVIEW_SCHEMA = "j1-outcome-sensitive-postmortem-review-frozen:v1"
PROMOTION_GATE_SCHEMA = "j1-outcome-sensitive-postmortem-review-promotion-gate:v1"
ALLOWED_DECISION = "approve_outcome_sensitive_r4_descriptive_postmortem"
CHECKLIST = tuple(sorted(REVIEW_CHECKLIST))
OWNER_GATE_BOUNDARY = {
    **ANALYSIS_BOUNDARY,
    "owner_review_authorization_recorded": True,
    "independent_review_completed": False,
    "copy_on_write_promotion_performed": False,
}
REVIEW_BOUNDARY = {
    **OWNER_GATE_BOUNDARY,
    "independent_review_decision_required": True,
}
RECEIPT_BOUNDARY = {
    **OWNER_GATE_BOUNDARY,
    "independent_review_completed": True,
    "independent_review_approved": True,
    "copy_on_write_promotion_allowed": True,
}
PROMOTION_BOUNDARY = {
    **RECEIPT_BOUNDARY,
    "copy_on_write_promotion_performed": True,
    "review_promotion_only": True,
}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def validate_source_packet(
    *,
    postmortem: dict[str, Any],
    postmortem_ref: dict[str, str],
    request: dict[str, Any],
    request_ref: dict[str, str],
    handoff: dict[str, Any],
    handoff_ref: dict[str, str],
) -> list[str]:
    failures = validate_postmortem(postmortem)
    _require(
        postmortem.get("schema_version") == POSTMORTEM_SCHEMA
        and _valid_ref(postmortem_ref, postmortem.get("report_sha256")),
        "postmortem_review_source_invalid",
        failures,
    )
    request_body = {
        key: item for key, item in request.items() if key != "request_sha256"
    }
    _require(
        request.get("schema_version") == REVIEW_REQUEST_SCHEMA
        and request.get("postmortem") == postmortem_ref
        and request.get("run_id") == postmortem.get("run_id")
        and request.get("required_decision") == ALLOWED_DECISION
        and request.get("required_checklist") == list(REVIEW_CHECKLIST)
        and request.get("execution_boundary") == ANALYSIS_BOUNDARY
        and request.get("request_sha256") == canonical_sha256(request_body)
        and _valid_ref(request_ref, request.get("request_sha256")),
        "postmortem_review_request_invalid",
        failures,
    )
    expected_owner_statement = owner_review_statement(
        postmortem_raw_sha256=postmortem_ref["sha256"],
        postmortem_canonical_sha256=postmortem_ref["canonical_sha256"],
        request_raw_sha256=request_ref["sha256"],
        request_canonical_sha256=request_ref["canonical_sha256"],
        run_id=str(postmortem.get("run_id")),
    )
    handoff_body = {
        key: item for key, item in handoff.items() if key != "handoff_sha256"
    }
    _require(
        handoff.get("schema_version") == HANDOFF_SCHEMA
        and handoff.get("status") == "owner_review_authorization_required"
        and handoff.get("postmortem") == postmortem_ref
        and handoff.get("review_request") == request_ref
        and handoff.get("required_exact_approval_statement")
        == expected_owner_statement
        and handoff.get("statement_sha256")
        == hashlib.sha256(expected_owner_statement.encode()).hexdigest()
        and handoff.get("execution_boundary") == ANALYSIS_BOUNDARY
        and handoff.get("handoff_sha256") == canonical_sha256(handoff_body)
        and _valid_ref(handoff_ref, handoff.get("handoff_sha256")),
        "postmortem_owner_handoff_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_owner_gate(
    *,
    postmortem: dict[str, Any],
    postmortem_ref: dict[str, str],
    request: dict[str, Any],
    request_ref: dict[str, str],
    handoff: dict[str, Any],
    handoff_ref: dict[str, str],
    owner_statement_sha256: str,
) -> dict[str, Any]:
    failures = validate_source_packet(
        postmortem=postmortem,
        postmortem_ref=postmortem_ref,
        request=request,
        request_ref=request_ref,
        handoff=handoff,
        handoff_ref=handoff_ref,
    )
    statement = str(handoff["required_exact_approval_statement"])
    if not (
        _sha256(owner_statement_sha256)
        and hashlib.sha256(statement.encode()).hexdigest()
        == owner_statement_sha256
    ):
        failures.append("postmortem_owner_statement_not_authorized")
    if failures:
        raise ValueError(f"postmortem owner review Gate invalid: {failures}")
    gate = {
        "schema_version": OWNER_GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "owner_authorized_independent_postmortem_review_only",
        "artifacts": {
            "postmortem": copy.deepcopy(postmortem_ref),
            "review_request": copy.deepcopy(request_ref),
            "owner_handoff": copy.deepcopy(handoff_ref),
        },
        "owner_authorization": {
            "statement": statement,
            "statement_sha256": owner_statement_sha256,
        },
        "execution_boundary": copy.deepcopy(OWNER_GATE_BOUNDARY),
    }
    gate["report_sha256"] = canonical_sha256(gate)
    return gate


def reviewer_approval_statement(
    *,
    request: dict[str, Any],
    request_ref: dict[str, str],
    postmortem_ref: dict[str, str],
    implementation_revision: str,
) -> str:
    return (
        "I have independently reviewed J1-D outcome-sensitive r4 descriptive "
        f"postmortem review request raw SHA-256 {request_ref['sha256']}, canonical "
        f"SHA-256 {request_ref['canonical_sha256']} and choose "
        f"{ALLOWED_DECISION}. I confirm all {len(CHECKLIST)} required checklist "
        "items, disclose all conflicts, affirm that I am independent from "
        "postmortem authoring and have completed human review. I approve only "
        "copy-on-write promotion of postmortem raw SHA-256 "
        f"{postmortem_ref['sha256']}, canonical SHA-256 "
        f"{postmortem_ref['canonical_sha256']}, binding review implementation "
        f"revision {implementation_revision}. I acknowledge that advice adherence "
        "was not directly observed, confirmatory inference remains invalid, no "
        "causal root cause is determined, and r4 remains neither a positive "
        "effectiveness result nor a causal harm or causal null result. Promotion "
        "freezes the reviewed descriptive postmortem only. It does not amend any "
        "protocol, fixture, evaluator, statistical plan, advice, roster, "
        "assignment, consent, or infrastructure; start a container, read a "
        "provider credential, call a provider or model, execute an Agent or task, "
        "append Backend Facts or the Ledger, issue or consume an execution "
        "authorization, authorize an effectiveness or causal claim, or upgrade "
        "SI-13 maturity."
    )


def build_reviewer_handoff(
    *,
    request: dict[str, Any],
    request_ref: dict[str, str],
    postmortem_ref: dict[str, str],
    owner_gate_ref: dict[str, str],
    implementation: dict[str, str],
) -> dict[str, Any]:
    statement = reviewer_approval_statement(
        request=request,
        request_ref=request_ref,
        postmortem_ref=postmortem_ref,
        implementation_revision=implementation["source_revision"],
    )
    handoff = {
        "schema_version": REVIEW_HANDOFF_SCHEMA,
        "status": "independent_reviewer_decision_required",
        "review_request": copy.deepcopy(request_ref),
        "postmortem": copy.deepcopy(postmortem_ref),
        "owner_authorization_gate": copy.deepcopy(owner_gate_ref),
        "decision_template": {
            "decision": None,
            "conflicts": None,
            "independent_from_postmortem_authoring": None,
            "human_review_completed": None,
            "checklist": {item: None for item in CHECKLIST},
        },
        "required_exact_approval_statement": statement,
        "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(REVIEW_BOUNDARY),
    }
    handoff["handoff_sha256"] = canonical_sha256(handoff)
    return handoff


def build_signed_review_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    request_ref: dict[str, str],
    postmortem_ref: dict[str, str],
    owner_gate_ref: dict[str, str],
    approval_statement_sha256: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: ReviewSigner,
) -> dict[str, Any]:
    receipt = {
        "schema_version": REVIEW_RECEIPT_SCHEMA,
        "review_id": review_id,
        "reviewed_at": reviewed_at,
        "decision": ALLOWED_DECISION,
        "review_request": copy.deepcopy(request_ref),
        "reviewed_postmortem": copy.deepcopy(postmortem_ref),
        "owner_authorization_gate": copy.deepcopy(owner_gate_ref),
        "approval_statement_sha256": approval_statement_sha256,
        "reviewer": {
            "did": reviewer["did"],
            "public_key_hex": reviewer["public_key_hex"],
            "credential_version": reviewer["credential_version"],
            "signer_kind": reviewer["signer_kind"],
            "identity_profile_sha256": reviewer_profile_sha256,
        },
        "independence": {
            "conflicts_disclosed": True,
            "independent_from_postmortem_authoring": True,
            "human_review_completed": True,
        },
        "checklist": {item: True for item in CHECKLIST},
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(RECEIPT_BOUNDARY),
    }
    payload = _signature_payload(receipt)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("postmortem review signature must be 64 bytes")
    receipt["signature"] = {
        "algorithm": "ed25519",
        "public_key_hex": signer.public_key_hex,
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    failures = validate_signed_review_receipt(
        receipt,
        expected_request_ref=request_ref,
        expected_postmortem_ref=postmortem_ref,
        expected_owner_gate_ref=owner_gate_ref,
        expected_approval_statement_sha256=approval_statement_sha256,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"postmortem signed review receipt invalid: {failures}")
    return receipt


def validate_signed_review_receipt(
    value: Any,
    *,
    expected_request_ref: dict[str, str],
    expected_postmortem_ref: dict[str, str],
    expected_owner_gate_ref: dict[str, str],
    expected_approval_statement_sha256: str,
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        receipt.get("schema_version") == REVIEW_RECEIPT_SCHEMA
        and _text(receipt.get("review_id"))
        and _text(receipt.get("reviewed_at"))
        and receipt.get("decision") == ALLOWED_DECISION
        and receipt.get("review_request") == expected_request_ref
        and receipt.get("reviewed_postmortem") == expected_postmortem_ref
        and receipt.get("owner_authorization_gate") == expected_owner_gate_ref
        and receipt.get("approval_statement_sha256")
        == expected_approval_statement_sha256,
        "postmortem_review_receipt_binding_invalid",
        failures,
    )
    _require(
        receipt.get("reviewer")
        == {
            "did": expected_reviewer.get("did"),
            "public_key_hex": expected_reviewer.get("public_key_hex"),
            "credential_version": expected_reviewer.get("credential_version"),
            "signer_kind": expected_reviewer.get("signer_kind"),
            "identity_profile_sha256": expected_reviewer_profile_sha256,
        }
        and receipt.get("independence")
        == {
            "conflicts_disclosed": True,
            "independent_from_postmortem_authoring": True,
            "human_review_completed": True,
        }
        and receipt.get("checklist") == {item: True for item in CHECKLIST},
        "postmortem_review_receipt_reviewer_invalid",
        failures,
    )
    _require(
        receipt.get("implementation") == expected_implementation
        and receipt.get("execution_boundary") == RECEIPT_BOUNDARY,
        "postmortem_review_receipt_boundary_invalid",
        failures,
    )
    signature = _object(receipt.get("signature"))
    unsigned = {
        key: item
        for key, item in receipt.items()
        if key not in {"signature", "receipt_sha256"}
    }
    payload = _signature_payload(unsigned)
    _require(
        signature.get("algorithm") == "ed25519"
        and signature.get("public_key_hex") == expected_reviewer.get("public_key_hex")
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest(),
        "postmortem_review_signature_metadata_invalid",
        failures,
    )
    try:
        VerifyKey(bytes.fromhex(str(expected_reviewer.get("public_key_hex")))).verify(
            payload,
            bytes.fromhex(str(signature.get("signature_hex"))),
        )
    except (BadSignatureError, ValueError):
        failures.append("postmortem_review_signature_invalid")
    _require(
        receipt.get("receipt_sha256")
        == canonical_sha256(
            {key: item for key, item in receipt.items() if key != "receipt_sha256"}
        ),
        "postmortem_review_receipt_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_frozen_review(
    *,
    frozen_id: str,
    promoted_at: str,
    source_postmortem_ref: dict[str, str],
    frozen_postmortem_ref: dict[str, str],
    review_receipt_ref: dict[str, str],
    reviewer_did: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    frozen = {
        "schema_version": FROZEN_REVIEW_SCHEMA,
        "frozen_id": frozen_id,
        "promoted_at": promoted_at,
        "source_postmortem": copy.deepcopy(source_postmortem_ref),
        "operator_reviewed_postmortem": copy.deepcopy(frozen_postmortem_ref),
        "review_receipt": copy.deepcopy(review_receipt_ref),
        "reviewer_did": reviewer_did,
        "implementation": copy.deepcopy(implementation),
        "interpretation": {
            "descriptive_postmortem_reviewed": True,
            "advice_adherence_observed": False,
            "confirmatory_inference_valid": False,
            "causal_root_cause_determined": False,
            "effectiveness_claim_authorized": False,
            "si13_maturity_upgrade_authorized": False,
        },
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
        "state": "descriptive_postmortem_independently_reviewed_no_claim_upgrade",
    }
    frozen["frozen_review_sha256"] = canonical_sha256(frozen)
    return frozen


def build_promotion_gate(
    *,
    request_ref: dict[str, str],
    reviewer_handoff_ref: dict[str, str],
    owner_gate_ref: dict[str, str],
    receipt_ref: dict[str, str],
    frozen_review_ref: dict[str, str],
    frozen_review: dict[str, Any],
) -> dict[str, Any]:
    gate = {
        "schema_version": PROMOTION_GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "descriptive_postmortem_review_promoted_no_effectiveness_claim",
        "artifacts": {
            "review_request": copy.deepcopy(request_ref),
            "reviewer_handoff": copy.deepcopy(reviewer_handoff_ref),
            "owner_authorization_gate": copy.deepcopy(owner_gate_ref),
            "signed_review_receipt": copy.deepcopy(receipt_ref),
            "frozen_review": copy.deepcopy(frozen_review_ref),
        },
        "frozen_review_sha256": frozen_review["frozen_review_sha256"],
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
    }
    gate["report_sha256"] = canonical_sha256(gate)
    return gate


def _signature_payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _valid_ref(value: Any, expected_canonical: Any) -> bool:
    ref = value if isinstance(value, dict) else {}
    return (
        _text(ref.get("path"))
        and _sha256(ref.get("sha256"))
        and ref.get("canonical_sha256") == expected_canonical
        and _sha256(expected_canonical)
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition:
        failures.append(reason)
