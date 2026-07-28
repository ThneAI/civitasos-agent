"""Independent-review contracts for the J1-D r11 null-result materials."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from .controlled_comparison import canonical_sha256
from .qualification_null_result_postmortem import (
    GATE_SCHEMA,
    validate_amendment_candidate,
    validate_postmortem,
)


REVIEW_REQUEST_SCHEMA = "j1-qualification-null-result-postmortem-review-request:v1"
REVIEW_HANDOFF_SCHEMA = "j1-qualification-null-result-postmortem-review-handoff:v1"
ALLOWED_DECISION = "approve_null_result_postmortem_and_amendment_candidate"
EXPECTED_GATE_STATE = (
    "null_result_root_cause_replayed_amendment_candidate_review_required_"
    "execution_blocked"
)
CHECKLIST = {
    "all_320_task_evidence_bound_to_signed_outcome_manifest",
    "decision_hash_binding_distinguished_from_semantic_scoring",
    "direct_observation_contract_content_free_and_signed",
    "outcome_sensitive_task_and_endpoint_contract_reviewed",
    "protocol_evaluator_consent_and_execution_remain_blocked",
    "r11_not_reclassified_as_positive_or_causal_null",
    "r11_terminal_evidence_and_signed_closeout_replayed",
    "script_supplied_maturity_endpoint_confirmed",
    "unobserved_pattern_prediction_zero_fill_confirmed",
    "event_and_host_default_repeated_error_endpoint_confirmed",
}
BOUNDARY = {
    "independent_review_materials_only": True,
    "postmortem_promoted": False,
    "amendment_candidate_promoted": False,
    "protocol_amended": False,
    "evaluator_amended": False,
    "participant_consent_migrated": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "participant_task_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
    "maturity_upgrade_authorized": False,
}


def build_review_request(
    *,
    request_id: str,
    created_at: str,
    postmortem_ref: dict[str, str],
    postmortem: dict[str, Any],
    candidate_ref: dict[str, str],
    candidate: dict[str, Any],
    gate_ref: dict[str, str],
    gate: dict[str, Any],
    owner_statement_sha256: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    """Build a review request after validating every immutable source binding."""
    source_failures = validate_review_sources(
        postmortem_ref=postmortem_ref,
        postmortem=postmortem,
        candidate_ref=candidate_ref,
        candidate=candidate,
        gate_ref=gate_ref,
        gate=gate,
        owner_statement_sha256=owner_statement_sha256,
    )
    if source_failures:
        raise ValueError(f"null-result review sources invalid: {source_failures}")
    request = {
        "schema_version": REVIEW_REQUEST_SCHEMA,
        "request_id": request_id,
        "created_at": created_at,
        "status": "independent_reviewer_decision_required",
        "reviewed_materials": {
            "postmortem": copy.deepcopy(postmortem_ref),
            "amendment_candidate": copy.deepcopy(candidate_ref),
            "owner_approval_gate": copy.deepcopy(gate_ref),
        },
        "source_summary": {
            "r11_task_evidence_replayed": 320,
            "participant_decision_hash_bindings": 320,
            "participant_decision_semantic_assertions": 0,
            "behaviorally_decoupled_acceptances": 320,
            "direct_pattern_prediction_observations": 0,
            "registered_effectiveness_estimand_observable": False,
            "r11_positive_effectiveness_claim_allowed": False,
            "r11_causal_null_claim_allowed": False,
            "si13_maturity_upgrade_allowed": False,
        },
        "owner_statement_sha256": owner_statement_sha256,
        "required_checklist": sorted(CHECKLIST),
        "allowed_decision": ALLOWED_DECISION,
        "decision_template": _empty_decision_template(),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    request["request_sha256"] = canonical_sha256(request)
    failures = validate_review_request(
        request,
        expected_postmortem_ref=postmortem_ref,
        expected_candidate_ref=candidate_ref,
        expected_gate_ref=gate_ref,
        expected_owner_statement_sha256=owner_statement_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"null-result review request invalid: {failures}")
    return request


def validate_review_sources(
    *,
    postmortem_ref: dict[str, str],
    postmortem: dict[str, Any],
    candidate_ref: dict[str, str],
    candidate: dict[str, Any],
    gate_ref: dict[str, str],
    gate: dict[str, Any],
    owner_statement_sha256: str,
) -> list[str]:
    """Validate source artifacts and their owner-approved Gate."""
    failures: list[str] = []
    failures.extend(validate_postmortem(postmortem))
    failures.extend(validate_amendment_candidate(candidate))
    _require(
        _valid_ref(
            postmortem_ref,
            expected_canonical=postmortem.get("report_sha256"),
        ),
        "review_postmortem_ref_invalid",
        failures,
    )
    _require(
        _valid_ref(
            candidate_ref,
            expected_canonical=candidate.get("candidate_sha256"),
        ),
        "review_candidate_ref_invalid",
        failures,
    )
    _require(
        _valid_ref(gate_ref, expected_canonical=gate.get("report_sha256")),
        "review_gate_ref_invalid",
        failures,
    )
    _require(
        candidate.get("parent_postmortem") == postmortem_ref,
        "review_candidate_parent_binding_invalid",
        failures,
    )
    gate_body = {key: item for key, item in gate.items() if key != "report_sha256"}
    _require(
        gate.get("schema_version") == GATE_SCHEMA
        and gate.get("passed") is True
        and gate.get("failure_reasons") == []
        and gate.get("state") == EXPECTED_GATE_STATE
        and gate.get("report_sha256") == canonical_sha256(gate_body),
        "review_owner_gate_identity_invalid",
        failures,
    )
    _require(
        gate.get("artifacts")
        == {
            "postmortem": postmortem_ref,
            "amendment_candidate": candidate_ref,
        },
        "review_owner_gate_artifact_binding_invalid",
        failures,
    )
    owner_approval = _object(gate.get("owner_approval"))
    owner_statement = owner_approval.get("statement")
    _require(
        owner_approval.get("required") is True
        and isinstance(owner_statement, str)
        and hashlib.sha256(owner_statement.encode()).hexdigest()
        == owner_statement_sha256
        == owner_approval.get("statement_sha256"),
        "review_owner_statement_binding_invalid",
        failures,
    )
    _require(
        gate.get("source_summary")
        == {
            "postmortem_sha256": postmortem.get("report_sha256"),
            "candidate_sha256": candidate.get("candidate_sha256"),
        },
        "review_owner_gate_source_summary_invalid",
        failures,
    )
    readiness = _object(candidate.get("readiness"))
    _require(
        gate.get("readiness") == readiness
        and readiness.get("operator_reviewed") is False
        and readiness.get("protocol_amended") is False
        and readiness.get("participant_consent_migrated") is False
        and readiness.get("execution_preflight_allowed") is False
        and readiness.get("provider_or_model_execution_allowed") is False
        and readiness.get("si13_maturity_upgrade_allowed") is False,
        "review_execution_must_remain_blocked",
        failures,
    )
    return list(dict.fromkeys(failures))


def validate_review_request(
    value: Any,
    *,
    expected_postmortem_ref: dict[str, str],
    expected_candidate_ref: dict[str, str],
    expected_gate_ref: dict[str, str],
    expected_owner_statement_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    """Validate an unsigned request without inferring reviewer intent."""
    request = value if isinstance(value, dict) else {}
    failures: list[str] = []
    body = {key: item for key, item in request.items() if key != "request_sha256"}
    _require(
        request.get("schema_version") == REVIEW_REQUEST_SCHEMA
        and _text(request.get("request_id"))
        and _text(request.get("created_at"))
        and request.get("status") == "independent_reviewer_decision_required"
        and request.get("request_sha256") == canonical_sha256(body),
        "null_result_review_request_identity_invalid",
        failures,
    )
    _require(
        request.get("reviewed_materials")
        == {
            "postmortem": expected_postmortem_ref,
            "amendment_candidate": expected_candidate_ref,
            "owner_approval_gate": expected_gate_ref,
        },
        "null_result_review_material_binding_invalid",
        failures,
    )
    summary = _object(request.get("source_summary"))
    _require(
        summary.get("r11_task_evidence_replayed") == 320
        and summary.get("participant_decision_hash_bindings") == 320
        and summary.get("participant_decision_semantic_assertions") == 0
        and summary.get("behaviorally_decoupled_acceptances") == 320
        and summary.get("direct_pattern_prediction_observations") == 0
        and summary.get("registered_effectiveness_estimand_observable") is False
        and summary.get("r11_positive_effectiveness_claim_allowed") is False
        and summary.get("r11_causal_null_claim_allowed") is False
        and summary.get("si13_maturity_upgrade_allowed") is False,
        "null_result_review_source_summary_invalid",
        failures,
    )
    _require(
        request.get("owner_statement_sha256") == expected_owner_statement_sha256,
        "null_result_review_owner_statement_invalid",
        failures,
    )
    _require(
        request.get("required_checklist") == sorted(CHECKLIST)
        and request.get("allowed_decision") == ALLOWED_DECISION
        and request.get("decision_template") == _empty_decision_template(),
        "null_result_review_decision_contract_invalid",
        failures,
    )
    _require(
        request.get("implementation") == expected_implementation,
        "null_result_review_implementation_binding_invalid",
        failures,
    )
    _require(
        request.get("execution_boundary") == BOUNDARY,
        "null_result_review_boundary_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def reviewer_approval_statement(
    *,
    request: dict[str, Any],
    request_raw_sha256: str,
) -> str:
    """Return the exact statement required from an independent human reviewer."""
    materials = request["reviewed_materials"]
    postmortem = materials["postmortem"]
    candidate = materials["amendment_candidate"]
    return (
        "I have independently reviewed J1-D r11 null-result postmortem review "
        f"request raw SHA-256 {request_raw_sha256}, canonical SHA-256 "
        f"{request['request_sha256']} and choose {ALLOWED_DECISION}. I confirm all "
        f"{len(CHECKLIST)} required checklist items, disclose all conflicts, affirm "
        "that I am independent from candidate authoring and have completed human "
        "review. I approve only copy-on-write promotion of postmortem raw SHA-256 "
        f"{postmortem['sha256']}, canonical SHA-256 "
        f"{postmortem['canonical_sha256']}, and amendment candidate raw SHA-256 "
        f"{candidate['sha256']}, canonical SHA-256 "
        f"{candidate['canonical_sha256']}, binding review implementation revision "
        f"{request['implementation']['source_revision']}. I acknowledge that r11 "
        "remains immutable and is neither reclassified as positive nor as a causal "
        "null, and that promotion freezes reviewed postmortem and amendment "
        "materials only. It does not amend the protocol or evaluator, migrate "
        "participant consent, start a container, read a provider credential, call "
        "a provider or model, execute an Agent or task, append Backend Facts, append "
        "the Ledger, issue or consume an execution authorization, authorize an "
        "effectiveness claim, or upgrade SI-13 maturity."
    )


def build_review_handoff(
    *,
    request_ref: dict[str, str],
    request: dict[str, Any],
    request_raw_sha256: str,
) -> dict[str, Any]:
    """Build an unsigned handoff that leaves the reviewer decision empty."""
    statement = reviewer_approval_statement(
        request=request,
        request_raw_sha256=request_raw_sha256,
    )
    handoff = {
        "schema_version": REVIEW_HANDOFF_SCHEMA,
        "status": "independent_reviewer_decision_required",
        "request": copy.deepcopy(request_ref),
        "decision_template": copy.deepcopy(request["decision_template"]),
        "required_exact_approval_statement": statement,
        "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        "execution_boundary": copy.deepcopy(BOUNDARY),
    }
    handoff["handoff_sha256"] = canonical_sha256(handoff)
    return handoff


def _empty_decision_template() -> dict[str, Any]:
    return {
        "decision": None,
        "reviewer_did": None,
        "reviewed_at": None,
        "conflicts_disclosed": None,
        "independent_from_candidate_authoring": None,
        "human_review_completed": None,
        "checklist": {key: None for key in sorted(CHECKLIST)},
    }


def _valid_ref(value: Any, *, expected_canonical: Any) -> bool:
    reference = value if isinstance(value, dict) else {}
    return (
        _text(reference.get("path"))
        and _sha256(reference.get("sha256"))
        and reference.get("canonical_sha256") == expected_canonical
        and _sha256(expected_canonical)
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)
