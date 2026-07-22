"""Contracts for the J1-D participant consent-extension authorization plan."""

from __future__ import annotations

from typing import Any

from .controlled_comparison import canonical_sha256


PLAN_SCHEMA = "j1-qualification-consent-extension-plan:v1"
PLAN_STATUS = "explicit_owner_signing_authorization_required"
EXTENSION_SCHEMA = "j1-qualification-consent-extension:v1"
AUTHORIZED_OPERATION = {
    "open_exactly_one_pkcs11_session": True,
    "sign_exactly_40_consent_extensions": True,
    "write_private_consent_extension_evidence": True,
    "participant_substitution": False,
    "roster_rebind": False,
    "assignment_rebind": False,
    "infrastructure_rebind": False,
    "provider_api_call": False,
    "model_invocation": False,
    "agent_execution": False,
    "container_execution": False,
    "backend_fact_append": False,
    "ledger_append": False,
    "execution_authorization_issue_or_consume": False,
}
CURRENT_BOUNDARY = {
    "preflight_only": True,
    "pin_read": False,
    "token_login_attempted": False,
    "signature_performed": False,
    "participant_consent_extended": False,
    "roster_rebound": False,
    "assignment_rebound": False,
    "infrastructure_rebound": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "container_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
}


def build_consent_extension_plan(
    *,
    plan_id: str,
    created_at: str,
    source_binding: dict[str, Any],
    participant_identity_set: list[dict[str, Any]],
    consent_targets: list[dict[str, Any]],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": PLAN_SCHEMA,
        "plan_id": plan_id,
        "status": PLAN_STATUS,
        "created_at": created_at,
        "source_binding": source_binding,
        "participant_identity_set": participant_identity_set,
        "participant_identity_set_sha256": canonical_sha256(participant_identity_set),
        "consent_extension_contract": {
            "schema_version": EXTENSION_SCHEMA,
            "required_participant_count": 40,
            "required_signature_count": 40,
            "exactly_one_extension_per_participant": True,
            "prior_consent_inherited": False,
            "prior_consent_is_immutable_parent_evidence": True,
            "bind_amendment_bundle": True,
            "bind_amended_protocol": True,
            "bind_amended_design": True,
            "bind_reviewed_assignment_and_cohort": True,
            "bind_participant_identity_and_credential": True,
            "model_execution_authorized": False,
        },
        "consent_targets": consent_targets,
        "inventory": {
            "participant_count": len(consent_targets),
            "mentor_participant_count": sum(
                target["cohort"] == "mentor" for target in consent_targets
            ),
            "control_participant_count": sum(
                target["cohort"] == "control" for target in consent_targets
            ),
            "prior_consent_count": len(
                {target["prior_consent_artifact_sha256"] for target in consent_targets}
            ),
            "planned_signature_count": len(consent_targets),
        },
        "authorized_operation_if_approved": AUTHORIZED_OPERATION,
        "current_execution_boundary": CURRENT_BOUNDARY,
        "implementation": implementation,
    }
    value["plan_sha256"] = canonical_sha256(value)
    return value


def validate_consent_extension_plan(value: Any) -> list[str]:
    plan = value if isinstance(value, dict) else {}
    failures: list[str] = []
    expected_fields = {
        "schema_version",
        "plan_id",
        "status",
        "created_at",
        "source_binding",
        "participant_identity_set",
        "participant_identity_set_sha256",
        "consent_extension_contract",
        "consent_targets",
        "inventory",
        "authorized_operation_if_approved",
        "current_execution_boundary",
        "implementation",
        "plan_sha256",
    }
    _require(
        set(plan) == expected_fields, "consent_extension_plan_fields_invalid", failures
    )
    _require(
        plan.get("schema_version") == PLAN_SCHEMA,
        "consent_extension_plan_schema_invalid",
        failures,
    )
    _require(_text(plan.get("plan_id")), "consent_extension_plan_id_invalid", failures)
    _require(
        plan.get("status") == PLAN_STATUS,
        "consent_extension_plan_status_invalid",
        failures,
    )
    identities = plan.get("participant_identity_set")
    identity_values = identities if isinstance(identities, list) else []
    targets = plan.get("consent_targets")
    target_values = targets if isinstance(targets, list) else []
    identity_ids = [item.get("participant_id") for item in identity_values]
    target_ids = [item.get("participant_id") for item in target_values]
    _require(
        len(identity_values) == 40
        and len(set(identity_ids)) == 40
        and None not in identity_ids
        and plan.get("participant_identity_set_sha256")
        == canonical_sha256(identity_values),
        "consent_extension_identity_set_invalid",
        failures,
    )
    _require(
        len(target_values) == 40
        and len(set(target_ids)) == 40
        and set(target_ids) == set(identity_ids)
        and {item.get("cohort") for item in target_values} == {"mentor", "control"}
        and sum(item.get("cohort") == "mentor" for item in target_values) == 20
        and sum(item.get("cohort") == "control" for item in target_values) == 20
        and all(_target_valid(item) for item in target_values),
        "consent_extension_targets_invalid",
        failures,
    )
    contract = plan.get("consent_extension_contract")
    _require(
        contract
        == {
            "schema_version": EXTENSION_SCHEMA,
            "required_participant_count": 40,
            "required_signature_count": 40,
            "exactly_one_extension_per_participant": True,
            "prior_consent_inherited": False,
            "prior_consent_is_immutable_parent_evidence": True,
            "bind_amendment_bundle": True,
            "bind_amended_protocol": True,
            "bind_amended_design": True,
            "bind_reviewed_assignment_and_cohort": True,
            "bind_participant_identity_and_credential": True,
            "model_execution_authorized": False,
        },
        "consent_extension_contract_invalid",
        failures,
    )
    inventory = plan.get("inventory")
    _require(
        inventory
        == {
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "prior_consent_count": 40,
            "planned_signature_count": 40,
        },
        "consent_extension_inventory_invalid",
        failures,
    )
    _require(
        plan.get("authorized_operation_if_approved") == AUTHORIZED_OPERATION,
        "consent_extension_authorized_operation_invalid",
        failures,
    )
    _require(
        plan.get("current_execution_boundary") == CURRENT_BOUNDARY,
        "consent_extension_current_boundary_invalid",
        failures,
    )
    source = plan.get("source_binding")
    source_values = source if isinstance(source, dict) else {}
    required_hashes = {
        "amendment_bundle_artifact_sha256",
        "amendment_bundle_sha256",
        "protocol_amendment_artifact_sha256",
        "protocol_amendment_sha256",
        "design_amendment_artifact_sha256",
        "design_amendment_sha256",
        "reviewed_assignment_artifact_sha256",
        "reviewed_assignment_sha256",
        "assignment_gate_artifact_sha256",
        "participant_provisioning_report_artifact_sha256",
        "prior_consent_manifest_artifact_sha256",
        "prior_consent_manifest_sha256",
    }
    _require(
        required_hashes.issubset(source_values)
        and all(_sha256(source_values.get(field)) for field in required_hashes)
        and _text(source_values.get("token_label")),
        "consent_extension_source_binding_invalid",
        failures,
    )
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("plan_sha256") == canonical_sha256(body),
        "consent_extension_plan_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def authorization_statement(plan: dict[str, Any], raw_sha256: str) -> str:
    source = plan["source_binding"]
    return (
        "I authorize exactly 40 controlled-beta J1-D participant identities from identity "
        f"set {plan['participant_identity_set_sha256']} to each sign exactly one consent "
        f"extension from plan artifact {raw_sha256}, canonical plan {plan['plan_sha256']}, "
        f"binding amendment bundle {source['amendment_bundle_sha256']}, amended protocol "
        f"{source['protocol_amendment_sha256']}, amended design "
        f"{source['design_amendment_sha256']}, and reviewed assignment "
        f"{source['reviewed_assignment_sha256']}. I acknowledge that prior consent is not "
        "inherited and each prior consent remains immutable parent Evidence. This authorization "
        f"permits one PKCS#11 session on token {source['token_label']} and exactly 40 participant "
        "Ed25519 signatures for consent-extension Evidence only. It does not authorize "
        "participant substitution, roster, assignment, or infrastructure rebind, provider or "
        "model calls, Agent or container execution, Backend Fact append, Ledger append, or "
        "execution authorization issuance or consumption."
    )


def _target_valid(value: Any) -> bool:
    target = value if isinstance(value, dict) else {}
    return (
        set(target)
        == {
            "participant_id",
            "execution_did",
            "pair_id",
            "cohort",
            "assignment_commitment_sha256",
            "participant_profile_sha256",
            "prior_consent_artifact_sha256",
            "prior_consent_sha256",
        }
        and _text(target.get("participant_id"))
        and _text(target.get("execution_did"))
        and _text(target.get("pair_id"))
        and target.get("cohort") in {"mentor", "control"}
        and all(
            _sha256(target.get(field))
            for field in (
                "assignment_commitment_sha256",
                "participant_profile_sha256",
                "prior_consent_artifact_sha256",
                "prior_consent_sha256",
            )
        )
    )


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return (
        len(text) == 64
        and text == text.lower()
        and all(character in "0123456789abcdef" for character in text)
    )


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
