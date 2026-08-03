"""Reviewed successful-run evaluation and signed closeout contracts for J1-D."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256


PREFLIGHT_SCHEMA = "j1-qualification-r4-successful-closeout-preflight:v1"
REVIEW_BUNDLE_SCHEMA = "j1-qualification-r4-successful-closeout-review-bundle:v1"
REVIEW_REQUEST_SCHEMA = "j1-qualification-r4-successful-closeout-review-request:v1"
REVIEW_RECEIPT_SCHEMA = "j1-qualification-r4-successful-closeout-review-receipt:v1"
REVIEW_GATE_SCHEMA = "j1-qualification-r4-successful-closeout-review-gate:v1"
OUTCOME_MANIFEST_SCHEMA = "j1-qualification-r4-participant-outcome-manifest:v1"
POST_RUN_SCHEMA = "j1-qualification-r4-successful-post-run-receipt:v1"
CLOSEOUT_SCHEMA = "j1-qualification-r4-successful-closeout-receipt:v1"
CLOSEOUT_GATE_SCHEMA = "j1-qualification-r4-successful-closeout-gate:v1"
CHECKLIST = [
    "complete_320_task_journal_and_artifact_refs_reviewed",
    "provider_receipt_and_budget_reconciliation_reviewed",
    "participant_signature_verification_reviewed",
    "event_trace_and_frozen_verifier_replay_reviewed",
    "complete_40_participant_20_pair_outcome_mapping_reviewed",
    "unobserved_pattern_prediction_not_inferred_reviewed",
    "frozen_real_evaluator_and_threshold_application_reviewed",
    "terminal_40_created_0_running_inventory_reviewed",
    "authorization_claim_and_no_retry_boundary_reviewed",
    "successful_closeout_signature_and_copy_on_write_boundary_reviewed",
    "source_revision_and_source_file_hashes_reviewed",
    "ruff_and_full_pytest_evidence_reviewed",
]
OUTCOME_SENSITIVE_CHECKLIST = [
    "complete_480_task_journal_and_artifact_refs_reviewed",
    "provider_receipt_and_budget_reconciliation_reviewed",
    "participant_signature_verification_reviewed",
    "structured_decision_and_direct_observation_replay_reviewed",
    "hidden_fixture_commitment_and_ground_truth_scoring_reviewed",
    "complete_40_participant_20_pair_outcome_mapping_reviewed",
    "paired_bootstrap_and_confirmatory_inference_limit_reviewed",
    "frozen_outcome_evaluator_and_statistical_plan_reviewed",
    "terminal_40_container_0_running_inventory_reviewed",
    "authorization_claim_and_no_retry_boundary_reviewed",
    "successful_closeout_signature_and_copy_on_write_boundary_reviewed",
    "source_revision_ruff_and_full_pytest_evidence_reviewed",
]
REVIEW_BOUNDARY = {
    "successful_closeout_implementation_review_only": True,
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
CLOSEOUT_BOUNDARY = {
    "successful_closeout_only": True,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
}


class Signer(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_preflight(
    *,
    run_id: str,
    authorization_id: str,
    execution_summary: dict[str, Any],
    budget_summary: dict[str, Any],
    terminal_inventory: dict[str, Any],
    outcome_inventory: dict[str, Any],
    participant_outcomes: list[dict[str, Any]],
    evaluation_report: dict[str, Any],
    source_binding: dict[str, dict[str, str]],
    implementation: dict[str, Any],
    profile: str = "r4",
) -> dict[str, Any]:
    value = {
        "schema_version": PREFLIGHT_SCHEMA,
        "execution_profile": profile,
        "state": "successful_run_evaluated_implementation_review_required",
        "run_id": run_id,
        "authorization_id": authorization_id,
        "execution_summary": copy.deepcopy(execution_summary),
        "budget_summary": copy.deepcopy(budget_summary),
        "terminal_inventory": copy.deepcopy(terminal_inventory),
        "outcome_inventory": copy.deepcopy(outcome_inventory),
        "participant_outcomes": copy.deepcopy(participant_outcomes),
        "evaluation_report": copy.deepcopy(evaluation_report),
        "source_binding": copy.deepcopy(source_binding),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(CLOSEOUT_BOUNDARY),
    }
    value["preflight_sha256"] = canonical_sha256(value)
    failures = validate_preflight(value)
    if failures:
        raise ValueError(f"successful closeout preflight invalid: {failures}")
    return value


def validate_preflight(value: Any) -> list[str]:
    preflight = value if isinstance(value, dict) else {}
    failures: list[str] = []
    summary = preflight.get("execution_summary", {})
    budget = preflight.get("budget_summary", {})
    inventory = preflight.get("terminal_inventory", {})
    outcomes = preflight.get("outcome_inventory", {})
    evaluation = preflight.get("evaluation_report", {})
    scope = _scope(preflight.get("execution_profile"))
    _require(
        preflight.get("schema_version") == PREFLIGHT_SCHEMA
        and preflight.get("state")
        == "successful_run_evaluated_implementation_review_required"
        and _text(preflight.get("run_id"))
        and _text(preflight.get("authorization_id")),
        "successful_closeout_preflight_identity_invalid",
        failures,
    )
    _require(
        summary.get("status") == "complete"
        and summary.get("task_execution_count") == scope["task_count"]
        and summary.get("committed_task_count") == scope["task_count"]
        and summary.get("provider_call_count") == scope["task_count"]
        and summary.get("participant_signature_count") == scope["task_count"]
        and summary.get("journal_event_count") == scope["event_count"]
        and summary.get("validation_failures") == [],
        "successful_closeout_execution_summary_invalid",
        failures,
    )
    _require(
        budget.get("reservation_count") == scope["task_count"]
        and budget.get("reconciled_count") == scope["task_count"]
        and budget.get("non_reconciled_count") == 0
        and _nonnegative_int(budget.get("actual_tokens"))
        and _nonnegative_int(budget.get("actual_cost_microunits"))
        and budget.get("reserved_tokens") == scope["reserved_tokens"]
        and budget.get("reserved_cost_microunits") == scope["reserved_cost_microunits"],
        "successful_closeout_budget_summary_invalid",
        failures,
    )
    _require(
        set(inventory)
        == {
            "participant_container_count",
            "created_count",
            "exited_count",
            "running_count",
            "container_set_sha256",
        }
        and inventory.get("participant_container_count") == 40
        and _nonnegative_int(inventory.get("created_count"))
        and _nonnegative_int(inventory.get("exited_count"))
        and inventory.get("created_count") + inventory.get("exited_count") == 40
        and inventory.get("running_count") == 0
        and _sha256(inventory.get("container_set_sha256")),
        "successful_closeout_terminal_inventory_invalid",
        failures,
    )
    _require(
        outcomes.get("participant_count") == 40
        and outcomes.get("matched_pair_count") == 20
        and outcomes.get("task_evidence_count") == scope["task_count"]
        and outcomes.get("verified_task_count") == scope["task_count"]
        and outcomes.get("participant_outcome_count") == 40
        and _sha256(outcomes.get("task_evidence_set_sha256"))
        and _sha256(outcomes.get("participant_outcome_set_sha256"))
        and outcomes.get("pattern_prediction_observation_policy")
        == scope["pattern_policy"],
        "successful_closeout_outcome_inventory_invalid",
        failures,
    )
    _require(
        evaluation.get("structural_passed") is True
        and evaluation.get("participant_count") == 40
        and evaluation.get("matched_pair_count") == 20
        and evaluation.get("valid_for_qualification") is True
        and evaluation.get("effectiveness_claim_authorized") is False
        and _sha256(evaluation.get("report_sha256")),
        "successful_closeout_evaluation_invalid",
        failures,
    )
    records = preflight.get("participant_outcomes")
    _require(
        isinstance(records, list)
        and len(records) == 40
        and canonical_sha256(records) == outcomes.get("participant_outcome_set_sha256"),
        "successful_closeout_participant_outcomes_invalid",
        failures,
    )
    source = preflight.get("source_binding", {})
    _require(
        isinstance(source, dict)
        and len(source) >= 12
        and all(_artifact_ref(item) for item in source.values()),
        "successful_closeout_source_binding_invalid",
        failures,
    )
    implementation = preflight.get("implementation", {})
    _require(
        _revision(implementation.get("source_revision"))
        and isinstance(implementation.get("source_files"), dict)
        and len(implementation["source_files"]) >= 2
        and all(_sha256(item) for item in implementation["source_files"].values()),
        "successful_closeout_implementation_invalid",
        failures,
    )
    _require(
        preflight.get("execution_boundary") == CLOSEOUT_BOUNDARY,
        "successful_closeout_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in preflight.items() if key != "preflight_sha256"}
    _require(
        preflight.get("preflight_sha256") == canonical_sha256(body),
        "successful_closeout_preflight_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_review_bundle(
    *,
    bundle_id: str,
    created_at: str,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    verification: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": REVIEW_BUNDLE_SCHEMA,
        "execution_profile": preflight.get("execution_profile", "r4"),
        "bundle_id": bundle_id,
        "status": "independent_review_required",
        "created_at": created_at,
        "preflight": copy.deepcopy(preflight_ref),
        "run_summary": {
            "run_id": preflight["run_id"],
            "authorization_id": preflight["authorization_id"],
            "execution_summary": copy.deepcopy(preflight["execution_summary"]),
            "budget_summary": copy.deepcopy(preflight["budget_summary"]),
            "terminal_inventory": copy.deepcopy(preflight["terminal_inventory"]),
            "outcome_inventory": copy.deepcopy(preflight["outcome_inventory"]),
            "evaluation_summary": {
                "structural_passed": preflight["evaluation_report"][
                    "structural_passed"
                ],
                "effectiveness_thresholds_met": preflight["evaluation_report"][
                    "effectiveness_thresholds_met"
                ],
                "report_sha256": preflight["evaluation_report"]["report_sha256"],
            },
        },
        "source_implementation": copy.deepcopy(preflight["implementation"]),
        "verification": copy.deepcopy(verification),
        "review_checklist": copy.deepcopy(
            _checklist(preflight.get("execution_profile"))
        ),
        "promotion_contract": {
            "copy_on_write_only": True,
            "successful_closeout_allowed_after_promotion": True,
            "provider_or_task_execution_allowed": False,
            "backend_or_ledger_append_allowed": False,
        },
        "execution_boundary": copy.deepcopy(REVIEW_BOUNDARY),
    }
    value["bundle_sha256"] = canonical_sha256(value)
    failures = validate_review_bundle(value)
    if failures:
        raise ValueError(f"successful closeout review bundle invalid: {failures}")
    return value


def validate_review_bundle(value: Any) -> list[str]:
    bundle = value if isinstance(value, dict) else {}
    failures: list[str] = []
    summary = bundle.get("run_summary", {})
    source = bundle.get("source_implementation", {})
    verification = bundle.get("verification", {})
    scope = _scope(bundle.get("execution_profile"))
    _require(
        bundle.get("schema_version") == REVIEW_BUNDLE_SCHEMA
        and bundle.get("status") == "independent_review_required"
        and _text(bundle.get("bundle_id"))
        and _artifact_ref(bundle.get("preflight")),
        "successful_closeout_review_bundle_identity_invalid",
        failures,
    )
    _require(
        summary.get("execution_summary", {}).get("committed_task_count")
        == scope["task_count"]
        and summary.get("outcome_inventory", {}).get("participant_count") == 40
        and summary.get("outcome_inventory", {}).get("matched_pair_count") == 20
        and summary.get("evaluation_summary", {}).get("structural_passed") is True
        and _sha256(summary.get("evaluation_summary", {}).get("report_sha256")),
        "successful_closeout_review_run_summary_invalid",
        failures,
    )
    _require(
        _revision(source.get("source_revision"))
        and isinstance(source.get("source_files"), dict)
        and all(_sha256(item) for item in source["source_files"].values()),
        "successful_closeout_review_source_invalid",
        failures,
    )
    _require(
        verification.get("ruff_all_passed") is True
        and verification.get("pytest_all_passed") is True
        and verification.get("pytest_passed_count", 0) >= 1526
        and verification.get("remote_revision_verified") is True
        and verification.get("external_effect_performed") is False,
        "successful_closeout_review_verification_invalid",
        failures,
    )
    _require(
        bundle.get("review_checklist") == _checklist(bundle.get("execution_profile"))
        and bundle.get("execution_boundary") == REVIEW_BOUNDARY
        and bundle.get("promotion_contract")
        == {
            "copy_on_write_only": True,
            "successful_closeout_allowed_after_promotion": True,
            "provider_or_task_execution_allowed": False,
            "backend_or_ledger_append_allowed": False,
        },
        "successful_closeout_review_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in bundle.items() if key != "bundle_sha256"}
    _require(
        bundle.get("bundle_sha256") == canonical_sha256(body),
        "successful_closeout_review_bundle_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    bundle_ref: dict[str, str],
    bundle: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "status": "independent_reviewer_decision_required",
        "created_at": created_at,
        "bundle": copy.deepcopy(bundle_ref),
        "execution_profile": bundle.get("execution_profile", "r4"),
        "required_checklist": copy.deepcopy(
            _checklist(bundle.get("execution_profile"))
        ),
        "allowed_decision": "approve_successful_closeout_implementation",
        "execution_boundary": copy.deepcopy(REVIEW_BOUNDARY),
    }
    value["request_sha256"] = canonical_sha256(value)
    return value


def reviewer_statement(
    *,
    request_raw_sha256: str,
    bundle_raw_sha256: str,
    bundle: dict[str, Any],
) -> str:
    summary = bundle["run_summary"]
    evaluation = summary["evaluation_summary"]
    profile = bundle.get("execution_profile", "r4")
    checklist = _checklist(profile)
    task_count = _scope(profile)["task_count"]
    observation_note = (
        "I acknowledge that all structured decisions and direct behavior observations "
        "were replayed against hidden fixture commitments, while the preregistered "
        "Holm multiplicity rule did not freeze a paired test algorithm before "
        "execution; confirmatory_inference_valid=false and this promotion cannot "
        "authorize an effectiveness claim or maturity upgrade."
        if profile == "outcome_sensitive"
        else "I acknowledge that unobserved pattern prediction metrics are recorded "
        "as zero without inference."
    )
    return (
        "I have independently reviewed J1-D "
        f"{'outcome-sensitive ' if profile == 'outcome_sensitive' else 'r4 '}"
        "successful-closeout implementation "
        f"review request raw SHA-256 {request_raw_sha256} and choose "
        "approve_successful_closeout_implementation. I confirm all "
        f"{len(checklist)} required checklist items, disclose all conflicts, affirm "
        "that I am independent from candidate authoring and have completed human "
        "review. I approve only copy-on-write promotion of review bundle raw SHA-256 "
        f"{bundle_raw_sha256}, canonical SHA-256 {bundle['bundle_sha256']}, binding "
        f"source revision {bundle['source_implementation']['source_revision']} and "
        f"complete run {summary['run_id']} with {task_count} committed tasks, "
        "40 participants, "
        f"20 complete pairs, structural_passed=true, and "
        f"effectiveness_thresholds_met={str(evaluation['effectiveness_thresholds_met']).lower()}. "
        f"{observation_note} Promotion permits only generation and "
        "signing of this successful run's post-run, evaluation, and closeout "
        "Evidence. It does not start a container, read a provider credential, call a "
        "provider or model, execute an Agent or task, append Backend Facts, append "
        "the Ledger, issue or consume an execution authorization, alter the completed "
        "run, or independently authorize an effectiveness claim or maturity upgrade."
    )


def build_review_receipt(
    *,
    review_id: str,
    reviewed_at: str,
    request_ref: dict[str, str],
    bundle_ref: dict[str, str],
    statement_sha256: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    signer: Signer,
    profile: str = "r4",
) -> dict[str, Any]:
    checklist = _checklist(profile)
    payload = {
        "schema_version": REVIEW_RECEIPT_SCHEMA,
        "execution_profile": profile,
        "review_id": review_id,
        "reviewed_at": reviewed_at,
        "decision": "approve_successful_closeout_implementation",
        "request": copy.deepcopy(request_ref),
        "bundle": copy.deepcopy(bundle_ref),
        "review_statement_sha256": statement_sha256,
        "reviewer": {
            "did": reviewer["did"],
            "public_key_hex": reviewer["public_key_hex"],
            "credential_version": reviewer["credential_version"],
            "signer_kind": reviewer["signer_kind"],
            "profile_sha256": reviewer_profile_sha256,
        },
        "independence": {
            "conflicts_disclosed": True,
            "independent_from_candidate_authoring": True,
            "human_review_completed": True,
        },
        "checklist": {item: True for item in checklist},
        "execution_boundary": copy.deepcopy(REVIEW_BOUNDARY),
    }
    encoded = _canonical_bytes(payload)
    return {
        **payload,
        "signature": {
            "algorithm": "ed25519",
            "public_key_hex": signer.public_key_hex,
            "signed_payload_sha256": hashlib.sha256(encoded).hexdigest(),
            "signature_hex": signer.sign(encoded).hex(),
        },
    }


def validate_review_receipt(
    value: Any,
    *,
    request_ref: dict[str, str],
    bundle_ref: dict[str, str],
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    statement_sha256: str,
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    signature = receipt.get("signature", {})
    payload = {key: item for key, item in receipt.items() if key != "signature"}
    encoded = _canonical_bytes(payload)
    checklist = _checklist(receipt.get("execution_profile"))
    _require(
        receipt.get("schema_version") == REVIEW_RECEIPT_SCHEMA
        and receipt.get("decision") == "approve_successful_closeout_implementation"
        and receipt.get("request") == request_ref
        and receipt.get("bundle") == bundle_ref
        and receipt.get("review_statement_sha256") == statement_sha256
        and receipt.get("reviewer", {}).get("profile_sha256") == reviewer_profile_sha256
        and receipt.get("reviewer", {}).get("did") == reviewer.get("did")
        and receipt.get("checklist") == {item: True for item in checklist}
        and receipt.get("execution_boundary") == REVIEW_BOUNDARY,
        "successful_closeout_review_receipt_binding_invalid",
        failures,
    )
    _validate_signature(signature, encoded, reviewer.get("public_key_hex"), failures)
    return list(dict.fromkeys(failures))


def build_review_gate(
    *,
    bundle_ref: dict[str, str],
    receipt_ref: dict[str, str],
    source_revision: str,
) -> dict[str, Any]:
    value = {
        "schema_version": REVIEW_GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "successful_closeout_implementation_frozen",
        "bundle": copy.deepcopy(bundle_ref),
        "review_receipt": copy.deepcopy(receipt_ref),
        "source_revision": source_revision,
        "execution_boundary": copy.deepcopy(REVIEW_BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    return value


def closeout_authorization_statement(
    *,
    preflight_raw_sha256: str,
    preflight: dict[str, Any],
    review_gate_raw_sha256: str,
    review_gate_canonical_sha256: str,
) -> str:
    evaluation = preflight["evaluation_report"]
    budget = preflight["budget_summary"]
    profile = preflight.get("execution_profile", "r4")
    task_count = _scope(profile)["task_count"]
    thresholds = str(evaluation["effectiveness_thresholds_met"]).lower()
    effect = (
        "authorizes the bounded qualification effectiveness result and an explicit "
        "SI-13 maturity review"
        if evaluation["effectiveness_thresholds_met"]
        else "does not authorize an effectiveness claim or SI-13 maturity upgrade"
    )
    return (
        "I authorize exactly one signed J1-D "
        f"{'outcome-sensitive ' if profile == 'outcome_sensitive' else 'r4 '}"
        "successful-run closeout for run "
        f"{preflight['run_id']} and consumed authorization "
        f"{preflight['authorization_id']} from preflight raw SHA-256 "
        f"{preflight_raw_sha256}, canonical SHA-256 "
        f"{preflight['preflight_sha256']}, under successful-closeout implementation "
        f"Gate raw SHA-256 {review_gate_raw_sha256}, canonical SHA-256 "
        f"{review_gate_canonical_sha256}. I authorize accept_qualification_result "
        f"for exactly {task_count} committed task executions, {task_count} provider "
        f"calls, {task_count} "
        "participant signatures, 40 participants, and 20 complete pairs, with "
        f"{budget['actual_tokens']} actual tokens and "
        f"{budget['actual_cost_microunits']} actual USD microunits. The frozen real "
        "evaluator reports structural_passed=true and "
        f"effectiveness_thresholds_met={thresholds}; this closeout {effect}. I "
        "acknowledge that the claim and authorization remain "
        "immutable and consumed, the run may not be replayed, and a single run does "
        "not prove long-term sustainability. This authorization permits only signed "
        "post-run, evaluation, closeout, and Gate Evidence. It does not start a "
        "container, read a provider credential, call a provider or model, execute an "
        "Agent or task, append Backend Facts, or append the Ledger."
    )


def build_closeout_artifacts(
    *,
    closed_at: str,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    owner_authorization_id: str,
    owner_statement_sha256: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    signer: Signer,
) -> dict[str, Any]:
    outcome_manifest = {
        "schema_version": OUTCOME_MANIFEST_SCHEMA,
        "execution_profile": preflight.get("execution_profile", "r4"),
        "run_id": preflight["run_id"],
        "records": copy.deepcopy(preflight["participant_outcomes"]),
        "record_count": 40,
        "records_sha256": preflight["outcome_inventory"][
            "participant_outcome_set_sha256"
        ],
    }
    outcome_manifest["manifest_sha256"] = canonical_sha256(outcome_manifest)
    evaluation = copy.deepcopy(preflight["evaluation_report"])
    post_run = {
        "schema_version": POST_RUN_SCHEMA,
        "execution_profile": preflight.get("execution_profile", "r4"),
        "run_id": preflight["run_id"],
        "authorization_id": preflight["authorization_id"],
        "status": "complete",
        "closed_at": closed_at,
        "preflight": copy.deepcopy(preflight_ref),
        "source_binding": copy.deepcopy(preflight["source_binding"]),
        "execution_summary": copy.deepcopy(preflight["execution_summary"]),
        "budget_summary": copy.deepcopy(preflight["budget_summary"]),
        "terminal_inventory": copy.deepcopy(preflight["terminal_inventory"]),
        "outcome_manifest_sha256": outcome_manifest["manifest_sha256"],
        "evaluation_report_sha256": evaluation["report_sha256"],
        "partial_results_promotable": False,
        "authorization_reusable": False,
        "provider_retry_performed": False,
        "execution_boundary": copy.deepcopy(CLOSEOUT_BOUNDARY),
    }
    post_run["receipt_sha256"] = canonical_sha256(post_run)
    thresholds = evaluation["effectiveness_thresholds_met"]
    closeout_payload = {
        "schema_version": CLOSEOUT_SCHEMA,
        "execution_profile": preflight.get("execution_profile", "r4"),
        "run_id": preflight["run_id"],
        "authorization_id": preflight["authorization_id"],
        "closed_at": closed_at,
        "decision": "accept_qualification_result",
        "post_run_receipt_sha256": post_run["receipt_sha256"],
        "evaluation_report_sha256": evaluation["report_sha256"],
        "outcome_manifest_sha256": outcome_manifest["manifest_sha256"],
        "structural_passed": True,
        "effectiveness_thresholds_met": thresholds,
        "effectiveness_claim_authorized": thresholds,
        "si13_maturity_review_authorized": thresholds,
        "automatic_maturity_upgrade_performed": False,
        "single_run_long_term_sustainability_proven": False,
        "owner_authorization": {
            "authorization_id": owner_authorization_id,
            "statement_sha256": owner_statement_sha256,
        },
        "reviewer": {
            "did": reviewer["did"],
            "public_key_hex": reviewer["public_key_hex"],
            "credential_version": reviewer["credential_version"],
            "signer_kind": reviewer["signer_kind"],
            "profile_sha256": reviewer_profile_sha256,
        },
        "execution_boundary": {
            **CLOSEOUT_BOUNDARY,
            "effectiveness_claim_authorized": thresholds,
        },
    }
    encoded = _canonical_bytes(closeout_payload)
    closeout = {
        **closeout_payload,
        "signature": {
            "algorithm": "ed25519",
            "public_key_hex": signer.public_key_hex,
            "signed_payload_sha256": hashlib.sha256(encoded).hexdigest(),
            "signature_hex": signer.sign(encoded).hex(),
        },
    }
    return {
        "outcome_manifest": outcome_manifest,
        "post_run_receipt": post_run,
        "evaluation_report": evaluation,
        "closeout_receipt": closeout,
    }


def validate_closeout_artifacts(
    artifacts: dict[str, Any],
    *,
    preflight: dict[str, Any],
    preflight_ref: dict[str, str],
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    owner_statement_sha256: str,
) -> list[str]:
    failures: list[str] = []
    outcome = artifacts.get("outcome_manifest", {})
    post_run = artifacts.get("post_run_receipt", {})
    evaluation = artifacts.get("evaluation_report", {})
    closeout = artifacts.get("closeout_receipt", {})
    _require(
        outcome.get("schema_version") == OUTCOME_MANIFEST_SCHEMA
        and outcome.get("run_id") == preflight["run_id"]
        and outcome.get("records") == preflight["participant_outcomes"]
        and outcome.get("record_count") == 40
        and outcome.get("records_sha256")
        == preflight["outcome_inventory"]["participant_outcome_set_sha256"]
        and outcome.get("manifest_sha256")
        == canonical_sha256(
            {key: item for key, item in outcome.items() if key != "manifest_sha256"}
        ),
        "successful_closeout_outcome_manifest_invalid",
        failures,
    )
    _require(
        post_run.get("schema_version") == POST_RUN_SCHEMA
        and post_run.get("status") == "complete"
        and post_run.get("preflight") == preflight_ref
        and post_run.get("outcome_manifest_sha256") == outcome.get("manifest_sha256")
        and post_run.get("evaluation_report_sha256") == evaluation.get("report_sha256")
        and post_run.get("authorization_reusable") is False
        and post_run.get("provider_retry_performed") is False
        and post_run.get("receipt_sha256")
        == canonical_sha256(
            {key: item for key, item in post_run.items() if key != "receipt_sha256"}
        ),
        "successful_closeout_post_run_invalid",
        failures,
    )
    _require(
        evaluation == preflight["evaluation_report"],
        "successful_closeout_evaluation_drifted",
        failures,
    )
    signature = closeout.get("signature", {})
    payload = {key: item for key, item in closeout.items() if key != "signature"}
    encoded = _canonical_bytes(payload)
    thresholds = evaluation.get("effectiveness_thresholds_met")
    _require(
        closeout.get("schema_version") == CLOSEOUT_SCHEMA
        and closeout.get("run_id") == preflight["run_id"]
        and closeout.get("authorization_id") == preflight["authorization_id"]
        and closeout.get("decision") == "accept_qualification_result"
        and closeout.get("structural_passed") is True
        and closeout.get("effectiveness_thresholds_met") is thresholds
        and closeout.get("effectiveness_claim_authorized") is thresholds
        and closeout.get("si13_maturity_review_authorized") is thresholds
        and closeout.get("automatic_maturity_upgrade_performed") is False
        and closeout.get("single_run_long_term_sustainability_proven") is False
        and closeout.get("owner_authorization", {}).get("statement_sha256")
        == owner_statement_sha256
        and closeout.get("reviewer", {}).get("profile_sha256")
        == reviewer_profile_sha256,
        "successful_closeout_receipt_binding_invalid",
        failures,
    )
    _validate_signature(signature, encoded, reviewer.get("public_key_hex"), failures)
    return list(dict.fromkeys(failures))


def build_closeout_gate(
    *,
    artifact_refs: dict[str, dict[str, str]],
    artifacts: dict[str, Any],
) -> dict[str, Any]:
    evaluation = artifacts["evaluation_report"]
    thresholds = evaluation["effectiveness_thresholds_met"]
    profile = artifacts["closeout_receipt"].get("execution_profile", "r4")
    value = {
        "schema_version": CLOSEOUT_GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": (
            "successful_run_closed_effectiveness_thresholds_met_maturity_review_allowed"
            if thresholds
            else "successful_run_closed_structural_pass_thresholds_not_met_no_maturity_upgrade"
        ),
        "artifacts": copy.deepcopy(artifact_refs),
        "terminal_summary": {
            "task_execution_count": _scope(profile)["task_count"],
            "participant_count": 40,
            "matched_pair_count": 20,
            "structural_passed": True,
            "effectiveness_thresholds_met": thresholds,
            "effectiveness_claim_authorized": thresholds,
            "si13_maturity_review_authorized": thresholds,
            "automatic_maturity_upgrade_performed": False,
        },
        "execution_boundary": copy.deepcopy(
            artifacts["closeout_receipt"]["execution_boundary"]
        ),
    }
    value["report_sha256"] = canonical_sha256(value)
    return value


def _scope(profile: Any) -> dict[str, Any]:
    if profile == "outcome_sensitive":
        return {
            "task_count": 480,
            "event_count": 5760,
            "reserved_tokens": 1_200_000,
            "reserved_cost_microunits": 731_040,
            "pattern_policy": "direct_signed_observation_exact_set_scoring",
        }
    return {
        "task_count": 320,
        "event_count": 3840,
        "reserved_tokens": 800_000,
        "reserved_cost_microunits": 487_360,
        "pattern_policy": "no_direct_observation_count_as_zero_no_inference",
    }


def _checklist(profile: Any) -> list[str]:
    return OUTCOME_SENSITIVE_CHECKLIST if profile == "outcome_sensitive" else CHECKLIST


def _validate_signature(
    signature: dict[str, Any],
    encoded: bytes,
    public_key_hex: Any,
    failures: list[str],
) -> None:
    valid_metadata = (
        signature.get("algorithm") == "ed25519"
        and signature.get("public_key_hex") == public_key_hex
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(encoded).hexdigest()
    )
    _require(valid_metadata, "successful_closeout_signature_metadata_invalid", failures)
    try:
        VerifyKey(bytes.fromhex(str(public_key_hex))).verify(
            encoded, bytes.fromhex(str(signature.get("signature_hex", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append("successful_closeout_signature_invalid")


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _artifact_ref(value: Any) -> bool:
    ref = value if isinstance(value, dict) else {}
    return (
        set(ref) == {"path", "sha256", "canonical_sha256"}
        and _text(ref.get("path"))
        and _sha256(ref.get("sha256"))
        and _sha256(ref.get("canonical_sha256"))
    )


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _revision(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 40 and all(char in "0123456789abcdef" for char in text)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition and reason not in failures:
        failures.append(reason)
