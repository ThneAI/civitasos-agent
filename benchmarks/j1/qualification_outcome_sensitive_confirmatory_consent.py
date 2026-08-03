"""Contracts for prospective confirmatory-method participant consent extensions."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


PLAN_SCHEMA = "j1-outcome-sensitive-confirmatory-consent-plan:v1"
PLAN_STATUS = "exact_owner_signing_authorization_required"
EXTENSION_SCHEMA = "j1-outcome-sensitive-confirmatory-consent-extension:v1"
MATERIAL_NAMES = {
    "confirmatory_method",
    "consent_impact",
    "evaluator_addendum",
    "protocol_addendum",
    "verification",
}
CONSENT_SCOPE = {
    "participant_count": 40,
    "matched_pair_count": 20,
    "tasks_per_participant": 12,
    "total_task_count": 480,
    "task_treatment_fixture_assignment_decision_schema_changed": False,
    "prospective_confirmatory_method_changed": True,
    "one_sided_exact_20_pair_sign_flip": True,
    "all_2_power_20_assignments": True,
    "exact_rational_p_values": True,
    "zero_effects_and_tail_ties_retained": True,
    "holm_familywise_alpha": "0.05",
    "holm_equal_p_order": ["primary", "secondary"],
    "advice_adherence_observed": False,
    "completed_r4_reanalysis_allowed": False,
    "decline_without_penalty": True,
}
CONSENT_STATEMENT = (
    "I consent this execution identity to the independently reviewed J1-D "
    "prospective confirmatory-method amendment. I acknowledge the one-sided exact "
    "20-pair sign-flip tests, all 2^20 assignments, exact rational p-values, "
    "zero-effect and tail-tie retention, and primary-before-secondary Holm order at "
    "familywise alpha 0.05. I acknowledge that tasks, treatment, fixture, assignment, "
    "decision fields, provider, and model are unchanged; advice adherence remains "
    "unobserved; completed r4 Evidence is immutable and cannot support a new "
    "confirmatory claim. I may decline without penalty. My prior outcome-sensitive "
    "consent remains immutable parent Evidence but is not inherited. This extension "
    "does not authorize roster, assignment, advice, infrastructure, provider, model, "
    "Agent, container, Backend Fact, Ledger, experiment, effectiveness, causal, or "
    "SI-13 maturity action."
)
AUTHORIZED_OPERATION = {
    "open_exactly_one_pkcs11_session": True,
    "sign_exactly_40_confirmatory_consent_extensions": True,
    "write_private_consent_evidence": True,
    "participant_substitution": False,
    "roster_or_assignment_rebind": False,
    "mentor_advice_signing": False,
    "infrastructure_change": False,
    "provider_or_model_call": False,
    "agent_or_container_execution": False,
    "backend_fact_or_ledger_append": False,
    "execution_authorization_issue_or_consume": False,
    "effectiveness_or_causal_claim": False,
    "si13_maturity_upgrade": False,
}
PREFLIGHT_BOUNDARY = {
    "preflight_only": True,
    "pin_read": False,
    "token_login_attempted": False,
    "participant_signature_performed": False,
    "participant_consent_extension_count": 0,
    "participant_consent_extensions_complete": False,
    "downstream_binding_refreshed": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_or_container_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


def build_plan(
    *,
    plan_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    participant_identity_set: list[dict[str, Any]],
    consent_targets: list[dict[str, Any]],
    implementation: dict[str, str],
) -> dict[str, Any]:
    """Build an unsigned, no-token 40-participant consent plan."""
    value = {
        "schema_version": PLAN_SCHEMA,
        "plan_id": plan_id,
        "status": PLAN_STATUS,
        "created_at": created_at,
        "source_binding": copy.deepcopy(source_binding),
        "participant_identity_set": copy.deepcopy(participant_identity_set),
        "participant_identity_set_sha256": canonical_sha256(participant_identity_set),
        "consent_targets": copy.deepcopy(consent_targets),
        "consent_scope": copy.deepcopy(CONSENT_SCOPE),
        "consent_statement": CONSENT_STATEMENT,
        "consent_statement_sha256": hashlib.sha256(
            CONSENT_STATEMENT.encode()
        ).hexdigest(),
        "extension_contract": {
            "schema_version": EXTENSION_SCHEMA,
            "exactly_one_extension_per_participant": True,
            "required_participant_count": 40,
            "required_signature_count": 40,
            "prior_consent_inherited": False,
            "prior_consent_is_immutable_parent_evidence": True,
            "bind_confirmatory_promotion_gate": True,
            "bind_all_five_frozen_materials": True,
            "bind_reviewed_assignment_and_cohort": True,
            "participant_substitution_allowed": False,
            "decline_without_penalty": True,
            "execution_authorized": False,
        },
        "inventory": {
            "participant_count": len(consent_targets),
            "mentor_participant_count": sum(
                item.get("cohort") == "mentor" for item in consent_targets
            ),
            "control_participant_count": sum(
                item.get("cohort") == "control" for item in consent_targets
            ),
            "prior_outcome_consent_count": len(
                {item.get("prior_outcome_consent_sha256") for item in consent_targets}
            ),
            "planned_signature_count": len(consent_targets),
        },
        "authorized_operation_if_approved": copy.deepcopy(AUTHORIZED_OPERATION),
        "current_execution_boundary": copy.deepcopy(PREFLIGHT_BOUNDARY),
        "implementation": copy.deepcopy(implementation),
    }
    value["plan_sha256"] = canonical_sha256(value)
    failures = validate_plan(value)
    if failures:
        raise ValueError(f"confirmatory consent plan invalid: {failures}")
    return value


def validate_plan(value: Any) -> list[str]:
    """Validate scope, source shape, participant inventory, and self-hash."""
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    identities = plan.get("participant_identity_set", [])
    targets = plan.get("consent_targets", [])
    identity_ids = [
        item.get("participant_id") for item in identities if isinstance(item, dict)
    ]
    target_ids = [
        item.get("participant_id") for item in targets if isinstance(item, dict)
    ]
    if not (
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == PLAN_STATUS
        and _text(plan.get("plan_id"))
        and _rfc3339(plan.get("created_at"))
        and plan.get("consent_scope") == CONSENT_SCOPE
        and plan.get("consent_statement") == CONSENT_STATEMENT
        and plan.get("consent_statement_sha256")
        == hashlib.sha256(CONSENT_STATEMENT.encode()).hexdigest()
        and plan.get("authorized_operation_if_approved") == AUTHORIZED_OPERATION
        and plan.get("current_execution_boundary") == PREFLIGHT_BOUNDARY
    ):
        failures.append("confirmatory_consent_plan_contract_invalid")
    if not (
        isinstance(identities, list)
        and len(identities) == 40
        and len(identity_ids) == len(set(identity_ids)) == 40
        and all(_identity_valid(item) for item in identities)
        and plan.get("participant_identity_set_sha256") == canonical_sha256(identities)
    ):
        failures.append("confirmatory_consent_identity_set_invalid")
    if not (
        isinstance(targets, list)
        and len(targets) == 40
        and len(target_ids) == len(set(target_ids)) == 40
        and set(target_ids) == set(identity_ids)
        and sum(item.get("cohort") == "mentor" for item in targets) == 20
        and sum(item.get("cohort") == "control" for item in targets) == 20
        and all(_target_valid(item) for item in targets)
    ):
        failures.append("confirmatory_consent_targets_invalid")
    if plan.get("inventory") != {
        "participant_count": 40,
        "mentor_participant_count": 20,
        "control_participant_count": 20,
        "prior_outcome_consent_count": 40,
        "planned_signature_count": 40,
    }:
        failures.append("confirmatory_consent_inventory_invalid")
    source = plan.get("source_binding", {})
    if not _source_valid(source):
        failures.append("confirmatory_consent_source_binding_invalid")
    expected_extension_contract = {
        "schema_version": EXTENSION_SCHEMA,
        "exactly_one_extension_per_participant": True,
        "required_participant_count": 40,
        "required_signature_count": 40,
        "prior_consent_inherited": False,
        "prior_consent_is_immutable_parent_evidence": True,
        "bind_confirmatory_promotion_gate": True,
        "bind_all_five_frozen_materials": True,
        "bind_reviewed_assignment_and_cohort": True,
        "participant_substitution_allowed": False,
        "decline_without_penalty": True,
        "execution_authorized": False,
    }
    if plan.get("extension_contract") != expected_extension_contract:
        failures.append("confirmatory_consent_extension_contract_invalid")
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    if plan.get("plan_sha256") != canonical_sha256(body):
        failures.append("confirmatory_consent_plan_hash_invalid")
    return list(dict.fromkeys(failures))


def authorization_statement(plan: dict[str, Any], raw_sha256: str) -> str:
    """Return the exact owner authorization accepted by the future signer."""
    source = plan["source_binding"]
    materials = source["frozen_materials"]
    return (
        "I authorize exactly 40 controlled-beta J1-D participant identities from "
        f"identity set {plan['participant_identity_set_sha256']} to each sign exactly "
        "one prospective confirmatory-method consent extension from plan artifact "
        f"raw SHA-256 {raw_sha256}, canonical SHA-256 {plan['plan_sha256']}, binding "
        f"signed confirmatory promotion Gate {source['promotion_gate']['canonical_sha256']}, "
        f"frozen amendment {source['frozen_review']['canonical_sha256']}, exact paired "
        f"method {materials['confirmatory_method']['canonical_sha256']}, protocol "
        f"addendum {materials['protocol_addendum']['canonical_sha256']}, evaluator "
        f"addendum {materials['evaluator_addendum']['canonical_sha256']}, consent "
        f"impact {materials['consent_impact']['canonical_sha256']}, verification "
        f"{materials['verification']['canonical_sha256']}, reviewed assignment "
        f"{source['reviewed_assignment']['canonical_sha256']}, and prior outcome-sensitive "
        f"consent Gate {source['prior_outcome_consent_gate']['canonical_sha256']}. I "
        "acknowledge the prospective one-sided exact 20-pair sign-flip tests, all "
        "2^20 assignments, exact rational p-values, zero-effect and tail-tie retention, "
        "and primary-before-secondary Holm order at familywise alpha 0.05. I "
        "acknowledge that tasks, treatment, fixture, assignment, decision fields, "
        "provider, and model are unchanged; advice adherence remains unobserved; r4 "
        "remains immutable and may not be reanalyzed for a confirmatory claim. Each "
        "participant may decline without penalty; prior consent is not inherited and "
        "remains immutable parent Evidence. This authorization permits one PKCS#11 "
        f"session on token {source['token_label']} and exactly 40 participant Ed25519 "
        "signatures for confirmatory consent-extension Evidence only. It does not "
        "authorize participant substitution, roster or assignment rebind, advice "
        "signing, infrastructure changes, provider or model calls, Agent or container "
        "execution, Backend Fact or Ledger append, execution authorization issuance "
        "or consumption, an effectiveness or causal claim, or an SI-13 maturity upgrade."
    )


def _source_valid(value: Any) -> bool:
    source = value if isinstance(value, dict) else {}
    expected = {
        "promotion_gate",
        "frozen_review",
        "review_receipt",
        "frozen_materials",
        "reviewed_assignment",
        "assignment_gate",
        "participant_provisioning_report",
        "prior_outcome_consent_manifest",
        "prior_outcome_consent_gate",
        "token_label",
    }
    return (
        set(source) == expected
        and all(
            _ref_valid(source.get(name), canonical=True)
            for name in (
                "promotion_gate",
                "frozen_review",
                "review_receipt",
                "reviewed_assignment",
                "assignment_gate",
                "prior_outcome_consent_manifest",
                "prior_outcome_consent_gate",
            )
        )
        and _ref_valid(source.get("participant_provisioning_report"), canonical=False)
        and isinstance(source.get("frozen_materials"), dict)
        and set(source["frozen_materials"]) == MATERIAL_NAMES
        and all(
            _ref_valid(ref, canonical=True)
            for ref in source["frozen_materials"].values()
        )
        and _text(source.get("token_label"))
    )


def _identity_valid(value: Any) -> bool:
    item = value if isinstance(value, dict) else {}
    return (
        set(item)
        == {
            "participant_id",
            "execution_did",
            "public_key_sha256",
            "key_label",
            "key_id_hex",
            "profile_artifact_sha256",
            "profile_sha256",
        }
        and _text(item.get("participant_id"))
        and _text(item.get("execution_did"))
        and _sha256(item.get("public_key_sha256"))
        and _text(item.get("key_label"))
        and _hex(item.get("key_id_hex"))
        and _sha256(item.get("profile_artifact_sha256"))
        and _sha256(item.get("profile_sha256"))
    )


def _target_valid(value: Any) -> bool:
    item = value if isinstance(value, dict) else {}
    return (
        set(item)
        == {
            "participant_id",
            "execution_did",
            "pair_id",
            "cohort",
            "assignment_commitment_sha256",
            "participant_profile_artifact_sha256",
            "participant_profile_sha256",
            "prior_outcome_consent_artifact_sha256",
            "prior_outcome_consent_sha256",
        }
        and _text(item.get("participant_id"))
        and _text(item.get("execution_did"))
        and _text(item.get("pair_id"))
        and item.get("cohort") in {"mentor", "control"}
        and all(
            _sha256(item.get(field))
            for field in (
                "assignment_commitment_sha256",
                "participant_profile_artifact_sha256",
                "participant_profile_sha256",
                "prior_outcome_consent_artifact_sha256",
                "prior_outcome_consent_sha256",
            )
        )
    )


def _ref_valid(value: Any, *, canonical: bool) -> bool:
    ref = value if isinstance(value, dict) else {}
    fields = (
        {"path", "sha256", "canonical_sha256"}
        if canonical
        else {
            "path",
            "sha256",
        }
    )
    return (
        set(ref) == fields
        and _text(ref.get("path"))
        and _sha256(ref.get("sha256"))
        and (not canonical or _sha256(ref.get("canonical_sha256")))
    )


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rfc3339(value: Any) -> bool:
    try:
        return (
            datetime.fromisoformat(str(value).replace("Z", "+00:00")).tzinfo is not None
        )
    except ValueError:
        return False


def _sha256(value: Any) -> bool:
    return _hex(value, expected_bytes=32)


def _hex(value: Any, expected_bytes: int | None = None) -> bool:
    if not isinstance(value, str):
        return False
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return False
    return bool(decoded) and (expected_bytes is None or len(decoded) == expected_bytes)
