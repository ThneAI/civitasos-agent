from __future__ import annotations

import hashlib
import json

from nacl.signing import SigningKey

from benchmarks.j1.controlled_comparison import canonical_sha256
from benchmarks.j1.qualification_closeout_contracts import (
    build_closeout_contract,
    build_post_run_contract,
)
from benchmarks.j1.qualification_evaluation_closeout_review import (
    REQUIRED_CHECKS,
    REVIEW_DECISION_SCHEMA,
    approval_review_declaration,
    build_frozen_artifacts,
    build_frozen_bundle,
    build_review_decision_template,
    build_review_receipt,
    build_review_request,
    validate_frozen_bundle,
    validate_review_receipt,
    validate_review_request,
)
from benchmarks.j1.qualification_real_evaluator import (
    SOURCE_FIELDS,
    build_real_evaluator_manifest,
)


NOW = "2026-07-24T00:00:00+08:00"
STATEMENT_SHA256 = "a" * 64
REQUEST_IMPLEMENTATION = {
    "source_revision": "b" * 40,
    "source_sha256": "c" * 64,
}
REVIEW_IMPLEMENTATION = {
    "source_revision": "d" * 40,
    "source_sha256": "e" * 64,
}
PROMOTION_IMPLEMENTATION = {
    "source_revision": "a" * 40,
    "evaluator_source_sha256": "b" * 64,
    "closeout_source_sha256": "c" * 64,
    "freeze_operation_source_sha256": "d" * 64,
}


def _raw(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _candidate() -> dict:
    source = {
        field: canonical_sha256(["source", field]) for field in sorted(SOURCE_FIELDS)
    }
    candidate_implementation = {
        "source_revision": "1" * 40,
        "evaluator_source_sha256": "2" * 64,
        "closeout_source_sha256": "3" * 64,
        "freeze_operation_source_sha256": "4" * 64,
    }
    evaluator = build_real_evaluator_manifest(
        evaluator_id="j1d-evaluator-r1",
        created_at=NOW,
        source_binding=source,
        implementation=candidate_implementation,
    )
    contract_source = {
        key: source[key] for key in source if "_artifact_sha256" not in key
    }
    contract_implementation = {
        "source_revision": candidate_implementation["source_revision"],
        "source_sha256": candidate_implementation["closeout_source_sha256"],
    }
    post_run = build_post_run_contract(
        contract_id="j1d-post-run-r1",
        created_at=NOW,
        evaluator_manifest_sha256=evaluator["manifest_sha256"],
        source_binding=contract_source,
        implementation=contract_implementation,
    )
    closeout = build_closeout_contract(
        contract_id="j1d-closeout-r1",
        created_at=NOW,
        evaluator_manifest_sha256=evaluator["manifest_sha256"],
        post_run_contract_sha256=post_run["contract_sha256"],
        source_binding=contract_source,
        implementation=contract_implementation,
    )
    evaluator_bytes = _raw(evaluator)
    post_run_bytes = _raw(post_run)
    closeout_bytes = _raw(closeout)
    paths = {
        "candidate_bundle": "/private/candidate-bundle.json",
        "candidate_preflight": "/private/candidate-preflight.json",
        "real_evaluator": "/private/real-evaluator.json",
        "post_run_contract": "/private/post-run.json",
        "operator_closeout_contract": "/private/closeout.json",
    }
    boundary = {
        "candidate_generation_only": True,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "participant_container_started": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
        "execution_authorization_issued_or_consumed": False,
        "effectiveness_claim_authorized": False,
    }
    bundle = {
        "schema_version": "j1-qualification-evaluation-closeout-candidate-bundle:v1",
        "candidate_id": "j1d-evaluation-closeout-r1",
        "status": "review_required",
        "created_at": NOW,
        "source_binding": source,
        "candidate_artifacts": {
            "real_evaluator": {
                "path": paths["real_evaluator"],
                "sha256": hashlib.sha256(evaluator_bytes).hexdigest(),
                "canonical_sha256": evaluator["manifest_sha256"],
            },
            "post_run_contract": {
                "path": paths["post_run_contract"],
                "sha256": hashlib.sha256(post_run_bytes).hexdigest(),
                "canonical_sha256": post_run["contract_sha256"],
            },
            "operator_closeout_contract": {
                "path": paths["operator_closeout_contract"],
                "sha256": hashlib.sha256(closeout_bytes).hexdigest(),
                "canonical_sha256": closeout["contract_sha256"],
            },
        },
        "review_scope": {},
        "readiness": {
            "candidate_complete": True,
            "operator_reviewed": False,
            "execution_preflight_allowed": False,
        },
        "execution_boundary": boundary,
        "implementation": candidate_implementation,
    }
    bundle["bundle_sha256"] = canonical_sha256(bundle)
    bundle_bytes = _raw(bundle)
    preflight = {
        "schema_version": "j1-qualification-evaluation-closeout-preflight:v1",
        "candidate_id": bundle["candidate_id"],
        "passed": True,
        "failure_reasons": [],
        "state": (
            "evaluation_closeout_candidate_ready_owner_independent_review_"
            "approval_required"
        ),
        "source_artifacts": {},
        "candidate_bundle": {
            "path": paths["candidate_bundle"],
            "sha256": hashlib.sha256(bundle_bytes).hexdigest(),
            "canonical_sha256": bundle["bundle_sha256"],
        },
        "checks": {},
        "owner_approval": {
            "required": True,
            "statement": "owner approval",
            "statement_sha256": STATEMENT_SHA256,
        },
        "readiness": {
            "evaluation_closeout_candidate_complete": True,
            "independent_review_required": True,
            "evaluation_closeout_frozen": False,
            "execution_preflight_allowed": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": boundary,
        "implementation": candidate_implementation,
    }
    preflight["preflight_sha256"] = canonical_sha256(preflight)
    return {
        "paths": paths,
        "bundle": bundle,
        "bundle_bytes": bundle_bytes,
        "preflight": preflight,
        "preflight_bytes": _raw(preflight),
        "evaluator": evaluator,
        "evaluator_bytes": evaluator_bytes,
        "post_run": post_run,
        "post_run_bytes": post_run_bytes,
        "closeout": closeout,
        "closeout_bytes": closeout_bytes,
    }


def _request(candidate: dict) -> dict:
    return build_review_request(
        request_id="j1d-evaluation-closeout-review-r1",
        created_at=NOW,
        candidate_paths=candidate["paths"],
        bundle=candidate["bundle"],
        bundle_bytes=candidate["bundle_bytes"],
        preflight=candidate["preflight"],
        preflight_bytes=candidate["preflight_bytes"],
        evaluator=candidate["evaluator"],
        evaluator_bytes=candidate["evaluator_bytes"],
        post_run=candidate["post_run"],
        post_run_bytes=candidate["post_run_bytes"],
        closeout=candidate["closeout"],
        closeout_bytes=candidate["closeout_bytes"],
        authorization_id="owner-approval-r1",
        authorized_at=NOW,
        authorization_statement_sha256=STATEMENT_SHA256,
        implementation=REQUEST_IMPLEMENTATION,
    )


def _validate(request: dict, candidate: dict) -> list[str]:
    return validate_review_request(
        request,
        candidate_paths=candidate["paths"],
        bundle=candidate["bundle"],
        bundle_bytes=candidate["bundle_bytes"],
        preflight=candidate["preflight"],
        preflight_bytes=candidate["preflight_bytes"],
        evaluator=candidate["evaluator"],
        evaluator_bytes=candidate["evaluator_bytes"],
        post_run=candidate["post_run"],
        post_run_bytes=candidate["post_run_bytes"],
        closeout=candidate["closeout"],
        closeout_bytes=candidate["closeout_bytes"],
        expected_authorization_statement_sha256=STATEMENT_SHA256,
        expected_implementation=REQUEST_IMPLEMENTATION,
    )


def test_review_request_binds_candidates_owner_and_checklist() -> None:
    candidate = _candidate()
    request = _request(candidate)
    template = build_review_decision_template(request)

    assert _validate(request, candidate) == []
    assert request["required_checklist"] == sorted(REQUIRED_CHECKS)
    assert request["owner_authorization"]["scope"] == "independent_review_only"
    assert template["review_request_sha256"] == request["request_sha256"]
    assert all(value is False for value in template["checklist"].values())


def test_review_request_rejects_candidate_and_owner_drift() -> None:
    candidate = _candidate()
    request = _request(candidate)
    request["candidate_artifacts"]["real_evaluator"]["sha256"] = "f" * 64
    request["owner_authorization"]["statement_sha256"] = "0" * 64
    request["request_sha256"] = canonical_sha256(
        {key: item for key, item in request.items() if key != "request_sha256"}
    )

    failures = _validate(request, candidate)

    assert "evaluation_closeout_review_candidate_binding_invalid" in failures
    assert "evaluation_closeout_review_owner_authorization_invalid" in failures


def test_declaration_is_request_bound_and_non_executable() -> None:
    request = _request(_candidate())
    declaration = approval_review_declaration(request)

    assert request["request_sha256"] in declaration
    assert "10 required checklist items" in declaration
    assert "does not start any participant container" in declaration
    assert "authorize an effectiveness claim" in declaration


def test_signed_receipt_and_copy_on_write_freeze_pass() -> None:
    candidate = _candidate()
    request = _request(candidate)
    signer = _Signer()
    decision = _decision(request, signer.public_key_hex)
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request).encode()
    ).hexdigest()
    receipt = build_review_receipt(
        request=request,
        decision=decision,
        review_declaration_sha256=declaration_sha256,
        reviewer_profile_sha256="9" * 64,
        implementation=REVIEW_IMPLEMENTATION,
        signer=signer,
    )

    assert (
        validate_review_receipt(
            receipt,
            request=request,
            expected_review_declaration_sha256=declaration_sha256,
            expected_reviewer_profile_sha256="9" * 64,
            expected_implementation=REVIEW_IMPLEMENTATION,
        )
        == []
    )
    evaluator, post_run, closeout = build_frozen_artifacts(
        evaluator=candidate["evaluator"],
        post_run=candidate["post_run"],
        closeout=candidate["closeout"],
        promotion_implementation=PROMOTION_IMPLEMENTATION,
    )
    refs = {
        "real_evaluator": {
            "path": "/private/frozen-evaluator.json",
            "sha256": "5" * 64,
            "canonical_sha256": evaluator["manifest_sha256"],
        },
        "post_run_contract": {
            "path": "/private/frozen-post-run.json",
            "sha256": "6" * 64,
            "canonical_sha256": post_run["contract_sha256"],
        },
        "operator_closeout_contract": {
            "path": "/private/frozen-closeout.json",
            "sha256": "7" * 64,
            "canonical_sha256": closeout["contract_sha256"],
        },
    }
    frozen_bundle = build_frozen_bundle(
        candidate_bundle=candidate["bundle"],
        receipt=receipt,
        receipt_artifact_sha256="8" * 64,
        frozen_artifacts=refs,
    )
    assert (
        validate_frozen_bundle(
            frozen_bundle,
            candidate_bundle=candidate["bundle"],
            receipt=receipt,
            receipt_artifact_sha256="8" * 64,
            frozen_artifacts=refs,
        )
        == []
    )
    assert candidate["evaluator"]["status"] == "review_required"
    assert evaluator["status"] == "operator_reviewed_frozen"
    assert post_run["status"] == "operator_reviewed_frozen"
    assert closeout["status"] == "operator_reviewed_frozen"
    assert frozen_bundle["readiness"]["execution_preflight_allowed"] is True
    assert frozen_bundle["readiness"]["execution_authorization_issued"] is False
    assert (
        frozen_bundle["execution_boundary"]["effectiveness_claim_authorized"] is False
    )


def test_signed_receipt_rejects_signature_tamper() -> None:
    request = _request(_candidate())
    signer = _Signer()
    declaration_sha256 = hashlib.sha256(
        approval_review_declaration(request).encode()
    ).hexdigest()
    receipt = build_review_receipt(
        request=request,
        decision=_decision(request, signer.public_key_hex),
        review_declaration_sha256=declaration_sha256,
        reviewer_profile_sha256="9" * 64,
        implementation=REVIEW_IMPLEMENTATION,
        signer=signer,
    )
    receipt["signature"]["signature_hex"] = "00" * 64

    failures = validate_review_receipt(
        receipt,
        request=request,
        expected_review_declaration_sha256=declaration_sha256,
        expected_reviewer_profile_sha256="9" * 64,
        expected_implementation=REVIEW_IMPLEMENTATION,
    )

    assert "evaluation_closeout_review_signature_invalid" in failures


class _Signer:
    def __init__(self) -> None:
        self._key = SigningKey.generate()
        self.public_key_hex = self._key.verify_key.encode().hex()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message).signature


def _decision(request: dict, public_key_hex: str) -> dict:
    return {
        "schema_version": REVIEW_DECISION_SCHEMA,
        "review_id": "j1d-evaluation-closeout-review-r1",
        "review_request_sha256": request["request_sha256"],
        "decision": "approve_evaluation_closeout_materials",
        "reviewed_at": NOW,
        "reviewer": {
            "did": "did:civ:testnet:z6MkReviewer",
            "public_key_hex": public_key_hex,
            "credential_version": 1,
            "signer_kind": "pkcs11_ed25519",
            "custody_provenance_sha256": "9" * 64,
            "signer_attestation_sha256": "9" * 64,
        },
        "independence": {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        },
        "checklist": {check: True for check in sorted(REQUIRED_CHECKS)},
    }
