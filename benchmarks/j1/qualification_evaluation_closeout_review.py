"""Independent-review contracts for J1-D evaluator and closeout promotion."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_closeout_contracts import (
    build_closeout_contract,
    build_post_run_contract,
    validate_closeout_contract,
    validate_post_run_contract,
)
from .qualification_real_evaluator import (
    build_real_evaluator_manifest,
    validate_real_evaluator_manifest,
)


REVIEW_REQUEST_SCHEMA = "j1-qualification-evaluation-closeout-review-request:v1"
REVIEW_DECISION_SCHEMA = "j1-qualification-evaluation-closeout-review-decision:v1"
REVIEW_RECEIPT_SCHEMA = "j1-qualification-evaluation-closeout-review-receipt:v1"
FROZEN_BUNDLE_SCHEMA = "j1-qualification-evaluation-closeout-frozen-bundle:v1"
REQUEST_STATUS = "awaiting_independent_operator_decision"
APPROVAL_DECISION = "approve_evaluation_closeout_materials"
ALLOWED_DECISIONS = {APPROVAL_DECISION, "request_changes", "reject"}
REQUIRED_CHECKS = {
    "active_stack_source_binding_reviewed",
    "assignment_derived_cohort_and_complete_pairing_reviewed",
    "deterministic_paired_bootstrap_reviewed",
    "metric_and_censoring_rules_reviewed",
    "outcome_exclusion_and_early_stop_boundaries_reviewed",
    "post_run_success_inventory_reviewed",
    "failed_and_aborted_inventory_accounting_reviewed",
    "provider_budget_reconciliation_reviewed",
    "operator_closeout_and_claim_boundary_reviewed",
    "execution_boundary_reviewed",
}
SIGNER_CONTRACT = {
    "algorithm": "ed25519",
    "allowed_signer_kinds": [
        "non_exportable_ed25519_callback",
        "pkcs11_ed25519",
    ],
    "reviewer_did_networks": ["mainnet", "testnet"],
    "credential_version_required": True,
    "custody_provenance_required": True,
    "signer_attestation_required": True,
}
INDEPENDENCE_REQUIREMENTS = {
    "conflicts_disclosure_required": True,
    "independent_from_candidate_authoring_required": True,
    "human_review_required": True,
}
REQUEST_BOUNDARY = {
    "review_request_preparation_only": True,
    "evaluation_closeout_frozen": False,
    "execution_preflight_allowed": False,
    "participant_container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
}
RECEIPT_BOUNDARY = {
    "review_approved": True,
    "evaluation_closeout_promotion_allowed": True,
    **{
        key: value
        for key, value in REQUEST_BOUNDARY.items()
        if key != "review_request_preparation_only"
    },
}
PROMOTION_BOUNDARY = {
    "review_promotion_only": True,
    "evaluation_closeout_frozen": True,
    "execution_preflight_allowed": True,
    "participant_container_started": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
}
CONTRACT_SOURCE_FIELDS = {
    "amended_protocol_sha256",
    "amended_design_sha256",
    "reviewed_verifier_sha256",
    "rebound_roster_sha256",
    "rebound_assignment_sha256",
    "provider_admission_gate_sha256",
    "provider_admission_receipt_sha256",
}


class ReviewSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    candidate_paths: dict[str, str],
    bundle: dict[str, Any],
    bundle_bytes: bytes,
    preflight: dict[str, Any],
    preflight_bytes: bytes,
    evaluator: dict[str, Any],
    evaluator_bytes: bytes,
    post_run: dict[str, Any],
    post_run_bytes: bytes,
    closeout: dict[str, Any],
    closeout_bytes: bytes,
    authorization_id: str,
    authorized_at: str,
    authorization_statement_sha256: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    failures = validate_candidate_set(
        bundle=bundle,
        bundle_bytes=bundle_bytes,
        preflight=preflight,
        preflight_bytes=preflight_bytes,
        evaluator=evaluator,
        evaluator_bytes=evaluator_bytes,
        post_run=post_run,
        post_run_bytes=post_run_bytes,
        closeout=closeout,
        closeout_bytes=closeout_bytes,
    )
    if failures:
        raise ValueError(f"evaluation/closeout candidate set invalid: {failures}")
    request = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "status": REQUEST_STATUS,
        "created_at": created_at,
        "candidate_artifacts": {
            "candidate_bundle": _artifact(
                candidate_paths["candidate_bundle"],
                bundle_bytes,
                bundle["bundle_sha256"],
            ),
            "candidate_preflight": _artifact(
                candidate_paths["candidate_preflight"],
                preflight_bytes,
                preflight["preflight_sha256"],
            ),
            "real_evaluator": _artifact(
                candidate_paths["real_evaluator"],
                evaluator_bytes,
                evaluator["manifest_sha256"],
            ),
            "post_run_contract": _artifact(
                candidate_paths["post_run_contract"],
                post_run_bytes,
                post_run["contract_sha256"],
            ),
            "operator_closeout_contract": _artifact(
                candidate_paths["operator_closeout_contract"],
                closeout_bytes,
                closeout["contract_sha256"],
            ),
        },
        "owner_authorization": {
            "authorization_id": authorization_id,
            "authorized_at": authorized_at,
            "statement_sha256": authorization_statement_sha256,
            "scope": "independent_review_only",
        },
        "review_scope": {
            "candidate_id": bundle["candidate_id"],
            "source_binding": copy.deepcopy(bundle["source_binding"]),
            "evaluator_input_contract": copy.deepcopy(evaluator["input_contract"]),
            "evaluator_metrics": copy.deepcopy(evaluator["metrics"]),
            "evaluator_analysis": copy.deepcopy(evaluator["analysis"]),
            "evaluator_safeguards": copy.deepcopy(evaluator["safeguards"]),
            "post_run_terminal_completeness": copy.deepcopy(
                post_run["terminal_completeness"]
            ),
            "post_run_budget_reconciliation": copy.deepcopy(
                post_run["budget_reconciliation"]
            ),
            "closeout_operator_decision": copy.deepcopy(closeout["operator_decision"]),
            "closeout_claim_policy": copy.deepcopy(closeout["claim_policy"]),
            "closeout_failure_policy": copy.deepcopy(closeout["failure_policy"]),
        },
        "required_checklist": sorted(REQUIRED_CHECKS),
        "allowed_decisions": sorted(ALLOWED_DECISIONS),
        "independence_requirements": copy.deepcopy(INDEPENDENCE_REQUIREMENTS),
        "signer_contract": copy.deepcopy(SIGNER_CONTRACT),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(REQUEST_BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
    failures = validate_review_request(
        request,
        candidate_paths=candidate_paths,
        bundle=bundle,
        bundle_bytes=bundle_bytes,
        preflight=preflight,
        preflight_bytes=preflight_bytes,
        evaluator=evaluator,
        evaluator_bytes=evaluator_bytes,
        post_run=post_run,
        post_run_bytes=post_run_bytes,
        closeout=closeout,
        closeout_bytes=closeout_bytes,
        expected_authorization_statement_sha256=authorization_statement_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"evaluation/closeout review request invalid: {failures}")
    return request


def validate_candidate_set(
    *,
    bundle: dict[str, Any],
    bundle_bytes: bytes,
    preflight: dict[str, Any],
    preflight_bytes: bytes,
    evaluator: dict[str, Any],
    evaluator_bytes: bytes,
    post_run: dict[str, Any],
    post_run_bytes: bytes,
    closeout: dict[str, Any],
    closeout_bytes: bytes,
) -> list[str]:
    failures: list[str] = []
    bundle_body = {key: item for key, item in bundle.items() if key != "bundle_sha256"}
    _require(
        bundle.get("schema_version")
        == "j1-qualification-evaluation-closeout-candidate-bundle:v1"
        and bundle.get("status") == "review_required"
        and bundle.get("bundle_sha256") == canonical_sha256(bundle_body),
        "evaluation_closeout_candidate_bundle_invalid",
        failures,
    )
    preflight_body = {
        key: item for key, item in preflight.items() if key != "preflight_sha256"
    }
    _require(
        preflight.get("schema_version")
        == "j1-qualification-evaluation-closeout-preflight:v1"
        and preflight.get("passed") is True
        and preflight.get("state")
        == (
            "evaluation_closeout_candidate_ready_owner_independent_review_"
            "approval_required"
        )
        and preflight.get("preflight_sha256") == canonical_sha256(preflight_body),
        "evaluation_closeout_candidate_preflight_invalid",
        failures,
    )
    expected_bundle_ref = {
        "path": str(
            preflight.get("candidate_bundle", {}).get("path")
            if isinstance(preflight.get("candidate_bundle"), dict)
            else ""
        ),
        "sha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "canonical_sha256": bundle.get("bundle_sha256"),
    }
    _require(
        preflight.get("candidate_bundle") == expected_bundle_ref,
        "evaluation_closeout_preflight_bundle_binding_invalid",
        failures,
    )
    candidates = bundle.get("candidate_artifacts")
    candidates = candidates if isinstance(candidates, dict) else {}
    expected_candidates = {
        "real_evaluator": (
            evaluator_bytes,
            evaluator.get("manifest_sha256"),
        ),
        "post_run_contract": (
            post_run_bytes,
            post_run.get("contract_sha256"),
        ),
        "operator_closeout_contract": (
            closeout_bytes,
            closeout.get("contract_sha256"),
        ),
    }
    for name, (raw, canonical) in expected_candidates.items():
        reference = candidates.get(name)
        _require(
            isinstance(reference, dict)
            and reference.get("sha256") == hashlib.sha256(raw).hexdigest()
            and reference.get("canonical_sha256") == canonical,
            f"evaluation_closeout_{name}_binding_invalid",
            failures,
        )
    source_binding = bundle.get("source_binding")
    source_binding = source_binding if isinstance(source_binding, dict) else {}
    evaluator_implementation = bundle.get("implementation")
    evaluator_implementation = (
        evaluator_implementation if isinstance(evaluator_implementation, dict) else {}
    )
    failures.extend(
        validate_real_evaluator_manifest(
            evaluator,
            expected_source_binding=source_binding,
            expected_implementation=evaluator_implementation,
            expected_status="review_required",
        )
    )
    contract_source = {
        key: source_binding.get(key) for key in sorted(CONTRACT_SOURCE_FIELDS)
    }
    contract_implementation = {
        "source_revision": evaluator_implementation.get("source_revision"),
        "source_sha256": evaluator_implementation.get("closeout_source_sha256"),
    }
    failures.extend(
        validate_post_run_contract(
            post_run,
            evaluator_manifest_sha256=str(evaluator.get("manifest_sha256") or ""),
            source_binding=contract_source,
            implementation=contract_implementation,
            expected_status="review_required",
        )
    )
    failures.extend(
        validate_closeout_contract(
            closeout,
            evaluator_manifest_sha256=str(evaluator.get("manifest_sha256") or ""),
            post_run_contract_sha256=str(post_run.get("contract_sha256") or ""),
            source_binding=contract_source,
            implementation=contract_implementation,
            expected_status="review_required",
        )
    )
    _require(
        preflight.get("readiness")
        == {
            "evaluation_closeout_candidate_complete": True,
            "independent_review_required": True,
            "evaluation_closeout_frozen": False,
            "execution_preflight_allowed": False,
            "controlled_experiment_execution_ready": False,
        },
        "evaluation_closeout_candidate_readiness_invalid",
        failures,
    )
    _require(
        hashlib.sha256(preflight_bytes).hexdigest(),
        "evaluation_closeout_preflight_bytes_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_review_request(
    value: Any,
    *,
    candidate_paths: dict[str, str],
    bundle: dict[str, Any],
    bundle_bytes: bytes,
    preflight: dict[str, Any],
    preflight_bytes: bytes,
    evaluator: dict[str, Any],
    evaluator_bytes: bytes,
    post_run: dict[str, Any],
    post_run_bytes: bytes,
    closeout: dict[str, Any],
    closeout_bytes: bytes,
    expected_authorization_statement_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    request = value if isinstance(value, dict) else {}
    failures = validate_candidate_set(
        bundle=bundle,
        bundle_bytes=bundle_bytes,
        preflight=preflight,
        preflight_bytes=preflight_bytes,
        evaluator=evaluator,
        evaluator_bytes=evaluator_bytes,
        post_run=post_run,
        post_run_bytes=post_run_bytes,
        closeout=closeout,
        closeout_bytes=closeout_bytes,
    )
    _require(
        set(request)
        == {
            "schema_version",
            "request_id",
            "status",
            "created_at",
            "candidate_artifacts",
            "owner_authorization",
            "review_scope",
            "required_checklist",
            "allowed_decisions",
            "independence_requirements",
            "signer_contract",
            "implementation",
            "execution_boundary",
            "request_sha256",
        },
        "evaluation_closeout_review_request_fields_invalid",
        failures,
    )
    _require(
        request.get("schema_version") == REVIEW_REQUEST_SCHEMA
        and request.get("status") == REQUEST_STATUS
        and _text(request.get("request_id"))
        and _rfc3339(request.get("created_at")),
        "evaluation_closeout_review_request_identity_invalid",
        failures,
    )
    expected_artifacts = {
        "candidate_bundle": _artifact(
            candidate_paths["candidate_bundle"],
            bundle_bytes,
            bundle.get("bundle_sha256"),
        ),
        "candidate_preflight": _artifact(
            candidate_paths["candidate_preflight"],
            preflight_bytes,
            preflight.get("preflight_sha256"),
        ),
        "real_evaluator": _artifact(
            candidate_paths["real_evaluator"],
            evaluator_bytes,
            evaluator.get("manifest_sha256"),
        ),
        "post_run_contract": _artifact(
            candidate_paths["post_run_contract"],
            post_run_bytes,
            post_run.get("contract_sha256"),
        ),
        "operator_closeout_contract": _artifact(
            candidate_paths["operator_closeout_contract"],
            closeout_bytes,
            closeout.get("contract_sha256"),
        ),
    }
    _require(
        request.get("candidate_artifacts") == expected_artifacts,
        "evaluation_closeout_review_candidate_binding_invalid",
        failures,
    )
    authorization = request.get("owner_authorization")
    authorization = authorization if isinstance(authorization, dict) else {}
    _require(
        set(authorization)
        == {"authorization_id", "authorized_at", "statement_sha256", "scope"}
        and _text(authorization.get("authorization_id"))
        and _rfc3339(authorization.get("authorized_at"))
        and authorization.get("statement_sha256")
        == expected_authorization_statement_sha256
        and authorization.get("scope") == "independent_review_only",
        "evaluation_closeout_review_owner_authorization_invalid",
        failures,
    )
    expected_scope = {
        "candidate_id": bundle.get("candidate_id"),
        "source_binding": bundle.get("source_binding"),
        "evaluator_input_contract": evaluator.get("input_contract"),
        "evaluator_metrics": evaluator.get("metrics"),
        "evaluator_analysis": evaluator.get("analysis"),
        "evaluator_safeguards": evaluator.get("safeguards"),
        "post_run_terminal_completeness": post_run.get("terminal_completeness"),
        "post_run_budget_reconciliation": post_run.get("budget_reconciliation"),
        "closeout_operator_decision": closeout.get("operator_decision"),
        "closeout_claim_policy": closeout.get("claim_policy"),
        "closeout_failure_policy": closeout.get("failure_policy"),
    }
    _require(
        request.get("review_scope") == expected_scope,
        "evaluation_closeout_review_scope_invalid",
        failures,
    )
    _require(
        request.get("required_checklist") == sorted(REQUIRED_CHECKS)
        and request.get("allowed_decisions") == sorted(ALLOWED_DECISIONS)
        and request.get("independence_requirements") == INDEPENDENCE_REQUIREMENTS
        and request.get("signer_contract") == SIGNER_CONTRACT,
        "evaluation_closeout_review_policy_invalid",
        failures,
    )
    _require(
        request.get("implementation") == expected_implementation,
        "evaluation_closeout_review_implementation_invalid",
        failures,
    )
    _require(
        request.get("execution_boundary") == REQUEST_BOUNDARY,
        "evaluation_closeout_review_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in request.items() if key != "request_sha256"}
    _require(
        request.get("request_sha256") == canonical_sha256(body),
        "evaluation_closeout_review_request_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_review_decision_template(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": REVIEW_DECISION_SCHEMA,
        "review_id": "",
        "review_request_sha256": request["request_sha256"],
        "decision": "",
        "reviewed_at": "",
        "reviewer": {
            "did": "",
            "public_key_hex": "",
            "credential_version": 0,
            "signer_kind": "",
            "custody_provenance_sha256": "",
            "signer_attestation_sha256": "",
        },
        "independence": {
            "conflicts_disclosed": False,
            "independent_from_candidate_authoring": False,
            "human_review_completed": False,
        },
        "checklist": {check: False for check in sorted(REQUIRED_CHECKS)},
    }


def approval_review_declaration(request: dict[str, Any]) -> str:
    return (
        "I have independently reviewed J1-D evaluator/closeout review request "
        f"{request['request_sha256']} and choose {APPROVAL_DECISION}. I confirm all "
        "10 required checklist items, disclose all conflicts, affirm that I am "
        "independent from candidate authoring and have completed human review, and "
        "acknowledge that this approval permits only copy-on-write promotion of the "
        "real evaluator, post-run contract, and operator closeout contract. It does "
        "not start any participant container, authorize provider or model calls, "
        "execute any Agent or experiment, append Backend Facts, append the Ledger, "
        "issue or consume an execution authorization, automatically upgrade "
        "maturity, or authorize an effectiveness claim."
    )


def validate_completed_review_decision(
    value: Any, *, request: dict[str, Any]
) -> list[str]:
    decision = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(decision)
        == {
            "schema_version",
            "review_id",
            "review_request_sha256",
            "decision",
            "reviewed_at",
            "reviewer",
            "independence",
            "checklist",
        },
        "evaluation_closeout_review_decision_fields_invalid",
        failures,
    )
    _require(
        decision.get("schema_version") == REVIEW_DECISION_SCHEMA
        and _text(decision.get("review_id"))
        and decision.get("review_request_sha256") == request.get("request_sha256")
        and decision.get("decision") == APPROVAL_DECISION
        and _rfc3339(decision.get("reviewed_at")),
        "evaluation_closeout_review_decision_invalid",
        failures,
    )
    reviewer = decision.get("reviewer")
    reviewer = reviewer if isinstance(reviewer, dict) else {}
    _require(
        set(reviewer)
        == {
            "did",
            "public_key_hex",
            "credential_version",
            "signer_kind",
            "custody_provenance_sha256",
            "signer_attestation_sha256",
        }
        and _text(reviewer.get("did"))
        and _hex(reviewer.get("public_key_hex"), 64)
        and isinstance(reviewer.get("credential_version"), int)
        and reviewer.get("credential_version", 0) > 0
        and reviewer.get("signer_kind") in SIGNER_CONTRACT["allowed_signer_kinds"]
        and _sha256(reviewer.get("custody_provenance_sha256"))
        and _sha256(reviewer.get("signer_attestation_sha256")),
        "evaluation_closeout_reviewer_invalid",
        failures,
    )
    _require(
        decision.get("independence")
        == {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        },
        "evaluation_closeout_review_independence_invalid",
        failures,
    )
    _require(
        decision.get("checklist") == {check: True for check in sorted(REQUIRED_CHECKS)},
        "evaluation_closeout_review_checklist_incomplete",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_review_receipt(
    *,
    request: dict[str, Any],
    decision: dict[str, Any],
    review_declaration_sha256: str,
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: ReviewSigner,
) -> dict[str, Any]:
    failures = validate_completed_review_decision(decision, request=request)
    if failures:
        raise ValueError(f"evaluation/closeout review decision invalid: {failures}")
    reviewer = decision["reviewer"]
    if not (
        signer.public_key_hex.lower() == reviewer["public_key_hex"].lower()
        and reviewer["custody_provenance_sha256"] == reviewer_profile_sha256
        and reviewer["signer_attestation_sha256"] == reviewer_profile_sha256
    ):
        raise ValueError("evaluation/closeout reviewer signer/profile mismatch")
    receipt = {
        "schema_version": REVIEW_RECEIPT_SCHEMA,
        "review_id": decision["review_id"],
        "review_request_sha256": request["request_sha256"],
        "decision": decision["decision"],
        "reviewed_at": decision["reviewed_at"],
        "review_declaration_sha256": review_declaration_sha256,
        "reviewer": copy.deepcopy(reviewer),
        "independence": copy.deepcopy(decision["independence"]),
        "checklist": copy.deepcopy(decision["checklist"]),
        "review_scope": copy.deepcopy(request["review_scope"]),
        "owner_authorization": copy.deepcopy(request["owner_authorization"]),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(RECEIPT_BOUNDARY),
    }
    payload = review_signature_payload(receipt)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signer.sign(payload).hex(),
    }
    return receipt


def validate_review_receipt(
    value: Any,
    *,
    request: dict[str, Any],
    expected_review_declaration_sha256: str,
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(receipt)
        == {
            "schema_version",
            "review_id",
            "review_request_sha256",
            "decision",
            "reviewed_at",
            "review_declaration_sha256",
            "reviewer",
            "independence",
            "checklist",
            "review_scope",
            "owner_authorization",
            "implementation",
            "execution_boundary",
            "signature",
        },
        "evaluation_closeout_review_receipt_fields_invalid",
        failures,
    )
    decision = {
        "schema_version": REVIEW_DECISION_SCHEMA,
        "review_id": receipt.get("review_id"),
        "review_request_sha256": receipt.get("review_request_sha256"),
        "decision": receipt.get("decision"),
        "reviewed_at": receipt.get("reviewed_at"),
        "reviewer": receipt.get("reviewer"),
        "independence": receipt.get("independence"),
        "checklist": receipt.get("checklist"),
    }
    failures.extend(validate_completed_review_decision(decision, request=request))
    reviewer = receipt.get("reviewer")
    reviewer = reviewer if isinstance(reviewer, dict) else {}
    _require(
        receipt.get("schema_version") == REVIEW_RECEIPT_SCHEMA
        and receipt.get("review_declaration_sha256")
        == expected_review_declaration_sha256,
        "evaluation_closeout_review_receipt_identity_invalid",
        failures,
    )
    _require(
        reviewer.get("custody_provenance_sha256") == expected_reviewer_profile_sha256
        and reviewer.get("signer_attestation_sha256")
        == expected_reviewer_profile_sha256,
        "evaluation_closeout_reviewer_profile_invalid",
        failures,
    )
    _require(
        receipt.get("review_scope") == request.get("review_scope")
        and receipt.get("owner_authorization") == request.get("owner_authorization")
        and receipt.get("implementation") == expected_implementation,
        "evaluation_closeout_review_receipt_binding_invalid",
        failures,
    )
    _require(
        receipt.get("execution_boundary") == RECEIPT_BOUNDARY,
        "evaluation_closeout_review_receipt_boundary_invalid",
        failures,
    )
    signature = receipt.get("signature")
    signature = signature if isinstance(signature, dict) else {}
    payload = review_signature_payload(receipt)
    _require(
        signature.get("algorithm") == "ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest(),
        "evaluation_closeout_review_signature_metadata_invalid",
        failures,
    )
    try:
        VerifyKey(bytes.fromhex(str(reviewer.get("public_key_hex", "")))).verify(
            payload, bytes.fromhex(str(signature.get("signature_hex", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append("evaluation_closeout_review_signature_invalid")
    return list(dict.fromkeys(failures))


def build_frozen_artifacts(
    *,
    evaluator: dict[str, Any],
    post_run: dict[str, Any],
    closeout: dict[str, Any],
    promotion_implementation: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    frozen_evaluator = build_real_evaluator_manifest(
        evaluator_id=evaluator["evaluator_id"],
        created_at=evaluator["created_at"],
        source_binding=evaluator["source_binding"],
        implementation=promotion_implementation,
        status="operator_reviewed_frozen",
    )
    post_source = {
        key: item
        for key, item in post_run["source_binding"].items()
        if key != "evaluator_manifest_sha256"
    }
    frozen_post_run = build_post_run_contract(
        contract_id=post_run["contract_id"],
        created_at=post_run["created_at"],
        evaluator_manifest_sha256=frozen_evaluator["manifest_sha256"],
        source_binding=post_source,
        implementation={
            "source_revision": promotion_implementation["source_revision"],
            "source_sha256": promotion_implementation["closeout_source_sha256"],
        },
        status="operator_reviewed_frozen",
    )
    closeout_source = {
        key: item
        for key, item in closeout["source_binding"].items()
        if key not in {"evaluator_manifest_sha256", "post_run_contract_sha256"}
    }
    frozen_closeout = build_closeout_contract(
        contract_id=closeout["contract_id"],
        created_at=closeout["created_at"],
        evaluator_manifest_sha256=frozen_evaluator["manifest_sha256"],
        post_run_contract_sha256=frozen_post_run["contract_sha256"],
        source_binding=closeout_source,
        implementation={
            "source_revision": promotion_implementation["source_revision"],
            "source_sha256": promotion_implementation["closeout_source_sha256"],
        },
        status="operator_reviewed_frozen",
    )
    return frozen_evaluator, frozen_post_run, frozen_closeout


def build_frozen_bundle(
    *,
    candidate_bundle: dict[str, Any],
    receipt: dict[str, Any],
    receipt_artifact_sha256: str,
    frozen_artifacts: dict[str, dict[str, str]],
) -> dict[str, Any]:
    value = {
        "schema_version": FROZEN_BUNDLE_SCHEMA,
        "candidate_id": candidate_bundle["candidate_id"],
        "status": "operator_reviewed_frozen",
        "source_candidate_bundle_sha256": candidate_bundle["bundle_sha256"],
        "source_binding": copy.deepcopy(candidate_bundle["source_binding"]),
        "frozen_artifacts": copy.deepcopy(frozen_artifacts),
        "operator_review": {
            "review_id": receipt["review_id"],
            "review_request_sha256": receipt["review_request_sha256"],
            "reviewer_did": receipt["reviewer"]["did"],
            "reviewed_at": receipt["reviewed_at"],
            "review_receipt_sha256": receipt_artifact_sha256,
        },
        "readiness": {
            "evaluation_closeout_frozen": True,
            "execution_preflight_allowed": True,
            "execution_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": copy.deepcopy(PROMOTION_BOUNDARY),
    }
    value["frozen_bundle_sha256"] = canonical_sha256(value)
    return value


def validate_frozen_bundle(
    value: Any,
    *,
    candidate_bundle: dict[str, Any],
    receipt: dict[str, Any],
    receipt_artifact_sha256: str,
    frozen_artifacts: dict[str, dict[str, str]],
) -> list[str]:
    frozen = value if isinstance(value, dict) else {}
    expected = build_frozen_bundle(
        candidate_bundle=candidate_bundle,
        receipt=receipt,
        receipt_artifact_sha256=receipt_artifact_sha256,
        frozen_artifacts=frozen_artifacts,
    )
    failures: list[str] = []
    _require(
        frozen == expected,
        "evaluation_closeout_frozen_bundle_copy_on_write_invalid",
        failures,
    )
    body = {key: item for key, item in frozen.items() if key != "frozen_bundle_sha256"}
    _require(
        frozen.get("frozen_bundle_sha256") == canonical_sha256(body),
        "evaluation_closeout_frozen_bundle_hash_invalid",
        failures,
    )
    return failures


def review_signature_payload(receipt: dict[str, Any]) -> bytes:
    body = {key: item for key, item in receipt.items() if key != "signature"}
    return json.dumps(
        body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def _artifact(path: str, raw: bytes, canonical_sha256_value: Any) -> dict[str, str]:
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": str(canonical_sha256_value or ""),
    }


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha256(value: Any) -> bool:
    text = _text(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _hex(value: Any, length: int) -> bool:
    text = _text(value).lower()
    return len(text) == length and all(char in "0123456789abcdef" for char in text)


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _require(condition: Any, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
