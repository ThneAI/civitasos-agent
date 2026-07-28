"""Contracts for outcome-sensitive J1-D participant consent extensions."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_participant_provisioning import participant_did, participant_id


PLAN_SCHEMA = "j1-qualification-outcome-sensitive-consent-extension-plan:v1"
PLAN_STATUS = "explicit_owner_signing_authorization_required"
EXTENSION_SCHEMA = "j1-qualification-outcome-sensitive-consent-extension:v1"
REQUIRED_MATERIALS = {
    "consent_impact",
    "evaluator",
    "plan",
    "protocol",
    "statistical_plan",
    "task_fixture",
}
CONSENT_SCOPE = {
    "participant_count": 40,
    "matched_pair_count": 20,
    "tasks_per_participant": 12,
    "total_task_count": 480,
    "baseline_ordinals": [1, 2, 3],
    "treatment_ordinals": list(range(4, 13)),
    "structured_action_and_pattern_observation": True,
    "hidden_deterministic_fixture_scoring": True,
    "new_endpoint_and_censoring_rules": True,
    "decline_without_penalty": True,
}
CONSENT_STATEMENT = (
    "I consent this execution identity to the independently reviewed J1-D "
    "outcome-sensitive amendment covering 12 tasks, strict structured action and "
    "pattern observations, participant-hidden deterministic fixture scoring, a "
    "treatment-free baseline at ordinals 1 through 3, treatment or empty-control "
    "advice at ordinals 4 through 12, and the reviewed endpoint, missingness, "
    "censoring, and multiplicity rules. I may decline without penalty. I acknowledge "
    "that prior consent is immutable but is not inherited. This extension does not "
    "authorize provider, model, Agent, container, Backend Fact, Ledger, or experiment "
    "execution."
)
AUTHORIZED_OPERATION = {
    "open_exactly_one_pkcs11_session": True,
    "sign_exactly_40_consent_extensions": True,
    "write_private_consent_extension_evidence": True,
    "participant_substitution": False,
    "roster_rebind": False,
    "assignment_rebind": False,
    "mentor_advice_signing": False,
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
    "participant_consent_extension_count": 0,
    "participant_consent_extensions_complete": False,
    "roster_rebound": False,
    "assignment_rebound": False,
    "mentor_advice_signed": False,
    "infrastructure_rebound": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "container_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
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
    """Build a fail-closed plan that performs no participant signature."""
    value = {
        "schema_version": PLAN_SCHEMA,
        "plan_id": plan_id,
        "status": PLAN_STATUS,
        "created_at": created_at,
        "source_binding": copy.deepcopy(source_binding),
        "participant_identity_set": copy.deepcopy(participant_identity_set),
        "participant_identity_set_sha256": canonical_sha256(
            participant_identity_set
        ),
        "consent_scope": copy.deepcopy(CONSENT_SCOPE),
        "consent_statement": CONSENT_STATEMENT,
        "consent_statement_sha256": hashlib.sha256(
            CONSENT_STATEMENT.encode()
        ).hexdigest(),
        "consent_extension_contract": {
            "schema_version": EXTENSION_SCHEMA,
            "required_participant_count": 40,
            "required_signature_count": 40,
            "exactly_one_extension_per_participant": True,
            "prior_consent_inherited": False,
            "prior_consent_is_immutable_parent_evidence": True,
            "bind_signed_material_promotion_gate": True,
            "bind_all_six_frozen_materials": True,
            "bind_reviewed_assignment_and_cohort": True,
            "bind_participant_identity_and_credential": True,
            "participant_substitution_allowed": False,
            "decline_without_penalty": True,
            "model_or_experiment_execution_authorized": False,
        },
        "consent_targets": copy.deepcopy(consent_targets),
        "inventory": {
            "participant_count": len(consent_targets),
            "mentor_participant_count": sum(
                target.get("cohort") == "mentor" for target in consent_targets
            ),
            "control_participant_count": sum(
                target.get("cohort") == "control" for target in consent_targets
            ),
            "prior_consent_count": len(
                {
                    target.get("prior_consent_artifact_sha256")
                    for target in consent_targets
                }
            ),
            "planned_signature_count": len(consent_targets),
        },
        "authorized_operation_if_approved": copy.deepcopy(AUTHORIZED_OPERATION),
        "current_execution_boundary": copy.deepcopy(CURRENT_BOUNDARY),
        "implementation": copy.deepcopy(implementation),
    }
    value["plan_sha256"] = canonical_sha256(value)
    failures = validate_consent_extension_plan(value)
    if failures:
        raise ValueError(f"outcome-sensitive consent plan invalid: {failures}")
    return value


def validate_consent_extension_plan(value: Any) -> list[str]:
    """Validate the exact 40-participant plan and its no-execution boundary."""
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
        "consent_scope",
        "consent_statement",
        "consent_statement_sha256",
        "consent_extension_contract",
        "consent_targets",
        "inventory",
        "authorized_operation_if_approved",
        "current_execution_boundary",
        "implementation",
        "plan_sha256",
    }
    _require(
        set(plan) == expected_fields,
        "outcome_consent_plan_fields_invalid",
        failures,
    )
    _require(
        plan.get("schema_version") == PLAN_SCHEMA
        and plan.get("status") == PLAN_STATUS
        and _text(plan.get("plan_id"))
        and _text(plan.get("created_at")),
        "outcome_consent_plan_identity_invalid",
        failures,
    )
    identities = _list(plan.get("participant_identity_set"))
    targets = _list(plan.get("consent_targets"))
    identity_ids = [item.get("participant_id") for item in identities]
    target_ids = [item.get("participant_id") for item in targets]
    _require(
        len(identities) == 40
        and len(set(identity_ids)) == 40
        and None not in identity_ids
        and all(_identity_valid(item) for item in identities)
        and plan.get("participant_identity_set_sha256")
        == canonical_sha256(identities),
        "outcome_consent_identity_set_invalid",
        failures,
    )
    _require(
        len(targets) == 40
        and len(set(target_ids)) == 40
        and set(target_ids) == set(identity_ids)
        and sum(item.get("cohort") == "mentor" for item in targets) == 20
        and sum(item.get("cohort") == "control" for item in targets) == 20
        and all(_target_valid(item) for item in targets),
        "outcome_consent_targets_invalid",
        failures,
    )
    _require(
        plan.get("consent_scope") == CONSENT_SCOPE,
        "outcome_consent_scope_invalid",
        failures,
    )
    _require(
        plan.get("consent_statement") == CONSENT_STATEMENT
        and plan.get("consent_statement_sha256")
        == hashlib.sha256(CONSENT_STATEMENT.encode()).hexdigest(),
        "outcome_consent_statement_invalid",
        failures,
    )
    _require(
        plan.get("consent_extension_contract")
        == {
            "schema_version": EXTENSION_SCHEMA,
            "required_participant_count": 40,
            "required_signature_count": 40,
            "exactly_one_extension_per_participant": True,
            "prior_consent_inherited": False,
            "prior_consent_is_immutable_parent_evidence": True,
            "bind_signed_material_promotion_gate": True,
            "bind_all_six_frozen_materials": True,
            "bind_reviewed_assignment_and_cohort": True,
            "bind_participant_identity_and_credential": True,
            "participant_substitution_allowed": False,
            "decline_without_penalty": True,
            "model_or_experiment_execution_authorized": False,
        },
        "outcome_consent_contract_invalid",
        failures,
    )
    _require(
        plan.get("inventory")
        == {
            "participant_count": 40,
            "mentor_participant_count": 20,
            "control_participant_count": 20,
            "prior_consent_count": 40,
            "planned_signature_count": 40,
        },
        "outcome_consent_inventory_invalid",
        failures,
    )
    _require(
        plan.get("authorized_operation_if_approved") == AUTHORIZED_OPERATION
        and plan.get("current_execution_boundary") == CURRENT_BOUNDARY,
        "outcome_consent_boundary_invalid",
        failures,
    )
    _require(
        _source_binding_valid(plan.get("source_binding")),
        "outcome_consent_source_binding_invalid",
        failures,
    )
    body = {key: item for key, item in plan.items() if key != "plan_sha256"}
    _require(
        plan.get("plan_sha256") == canonical_sha256(body),
        "outcome_consent_plan_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def authorization_statement(plan: dict[str, Any], raw_sha256: str) -> str:
    """Return the only owner statement accepted by the future signing operation."""
    source = plan["source_binding"]
    materials = source["frozen_materials"]
    return (
        "I authorize exactly 40 controlled-beta J1-D participant identities from "
        f"identity set {plan['participant_identity_set_sha256']} to each sign exactly "
        f"one outcome-sensitive consent extension from plan artifact raw SHA-256 "
        f"{raw_sha256}, canonical SHA-256 {plan['plan_sha256']}, binding signed "
        f"material-promotion Gate {source['promotion_gate']['canonical_sha256']}, "
        f"frozen review {source['frozen_review']['canonical_sha256']}, protocol "
        f"{materials['protocol']['canonical_sha256']}, evaluator "
        f"{materials['evaluator']['canonical_sha256']}, task fixture "
        f"{materials['task_fixture']['canonical_sha256']}, statistical plan "
        f"{materials['statistical_plan']['canonical_sha256']}, consent-impact "
        f"{materials['consent_impact']['canonical_sha256']}, and reviewed assignment "
        f"{source['reviewed_assignment']['canonical_sha256']}. I acknowledge the "
        "material scope change to 12 tasks per participant, strict structured action "
        "and pattern observation, participant-hidden deterministic fixture scoring, "
        "a treatment-free baseline at ordinals 1 through 3, treatment or empty-control "
        "advice at ordinals 4 through 12, and reviewed endpoint, missingness, "
        "censoring, and multiplicity rules. I acknowledge that each participant may "
        "decline without penalty, prior consent is not inherited, and each prior "
        "consent remains immutable parent Evidence. This authorization permits one "
        f"PKCS#11 session on token {source['token_label']} and exactly 40 participant "
        "Ed25519 signatures for outcome-sensitive consent-extension Evidence only. "
        "It does not authorize participant substitution, roster or assignment rebind, "
        "mentor-advice signing, infrastructure changes, provider or model calls, Agent "
        "or container execution, Backend Fact append, Ledger append, execution "
        "authorization issuance or consumption, an effectiveness claim, or an SI-13 "
        "maturity upgrade."
    )


class ExtensionSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def signature_payload(value: dict[str, Any]) -> bytes:
    """Return the canonical participant-signed payload."""
    body = {
        key: item
        for key, item in value.items()
        if key not in {"signature", "extension_sha256"}
    }
    return json.dumps(
        body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def build_consent_extension(
    *,
    extension_id: str,
    signed_at: str,
    target: dict[str, Any],
    identity: dict[str, Any],
    public_key_hex: str,
    plan: dict[str, Any],
    plan_artifact_sha256: str,
    preflight_artifact_sha256: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    nonce: bytes,
    signer: ExtensionSigner,
) -> dict[str, Any]:
    """Build one participant-scoped outcome-sensitive consent extension."""
    if signer.public_key_hex.lower() != public_key_hex.lower():
        raise ValueError("outcome consent signer does not match participant identity")
    source = plan["source_binding"]
    materials = source["frozen_materials"]
    value = {
        "schema_version": EXTENSION_SCHEMA,
        "extension_id": extension_id,
        "signed_at": signed_at,
        "public_only": True,
        "secret_material_included": False,
        "participant": {
            "participant_id": target["participant_id"],
            "execution_did": target["execution_did"],
            "credential_version": 1,
            "participant_profile_artifact_sha256": target[
                "participant_profile_artifact_sha256"
            ],
            "participant_profile_sha256": target["participant_profile_sha256"],
            "public_key_hex": public_key_hex,
            "public_key_sha256": identity["public_key_sha256"],
        },
        "cohort_binding": {
            "pair_id": target["pair_id"],
            "cohort": target["cohort"],
            "reviewed_assignment_artifact_sha256": source["reviewed_assignment"][
                "sha256"
            ],
            "reviewed_assignment_sha256": source["reviewed_assignment"][
                "canonical_sha256"
            ],
            "assignment_commitment_sha256": target[
                "assignment_commitment_sha256"
            ],
        },
        "material_binding": {
            "promotion_gate_artifact_sha256": source["promotion_gate"]["sha256"],
            "promotion_gate_sha256": source["promotion_gate"]["canonical_sha256"],
            "frozen_review_artifact_sha256": source["frozen_review"]["sha256"],
            "frozen_review_sha256": source["frozen_review"]["canonical_sha256"],
            "frozen_materials": {
                name: {
                    "artifact_sha256": materials[name]["sha256"],
                    "canonical_sha256": materials[name]["canonical_sha256"],
                }
                for name in sorted(materials)
            },
        },
        "scope_binding": {
            "consent_scope": copy.deepcopy(CONSENT_SCOPE),
            "consent_scope_sha256": canonical_sha256(CONSENT_SCOPE),
            "consent_statement_sha256": hashlib.sha256(
                CONSENT_STATEMENT.encode()
            ).hexdigest(),
        },
        "prior_consent": {
            "artifact_sha256": target["prior_consent_artifact_sha256"],
            "canonical_sha256": target["prior_consent_sha256"],
            "inherited": False,
            "immutable_parent_evidence": True,
        },
        "authorization": {
            "authorization_id": authorization_id,
            "statement_sha256": authorization_statement_sha256,
            "plan_artifact_sha256": plan_artifact_sha256,
            "plan_sha256": plan["plan_sha256"],
            "preflight_artifact_sha256": preflight_artifact_sha256,
        },
        "consent_nonce_hex": nonce.hex(),
        "consent_statement": CONSENT_STATEMENT,
        "participant_consent_extended": True,
        "model_execution_authorized": False,
        "downstream_rebind_authorized": False,
        "effectiveness_claim_authorized": False,
        "si13_maturity_upgrade_authorized": False,
    }
    payload = signature_payload(value)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("Ed25519 signature must be 64 bytes")
    value["signature"] = {
        "algorithm": "Ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    value["extension_sha256"] = canonical_sha256(value)
    failures = validate_consent_extension(value)
    if failures:
        raise ValueError(f"outcome consent extension invalid: {failures}")
    return value


def validate_consent_extension(value: Any) -> list[str]:
    """Validate one participant signature and every outcome-sensitive binding."""
    extension = value if isinstance(value, dict) else {}
    failures: list[str] = []
    expected_fields = {
        "schema_version",
        "extension_id",
        "signed_at",
        "public_only",
        "secret_material_included",
        "participant",
        "cohort_binding",
        "material_binding",
        "scope_binding",
        "prior_consent",
        "authorization",
        "consent_nonce_hex",
        "consent_statement",
        "participant_consent_extended",
        "model_execution_authorized",
        "downstream_rebind_authorized",
        "effectiveness_claim_authorized",
        "si13_maturity_upgrade_authorized",
        "signature",
        "extension_sha256",
    }
    _require(
        set(extension) == expected_fields,
        "outcome_consent_extension_fields_invalid",
        failures,
    )
    _require(
        extension.get("schema_version") == EXTENSION_SCHEMA
        and _text(extension.get("extension_id"))
        and _rfc3339(extension.get("signed_at")),
        "outcome_consent_extension_identity_invalid",
        failures,
    )
    _require(
        extension.get("public_only") is True
        and extension.get("secret_material_included") is False,
        "outcome_consent_extension_public_boundary_invalid",
        failures,
    )
    participant = _object(extension.get("participant"))
    public_key_hex = str(participant.get("public_key_hex", ""))
    _require(
        set(participant)
        == {
            "participant_id",
            "execution_did",
            "credential_version",
            "participant_profile_artifact_sha256",
            "participant_profile_sha256",
            "public_key_hex",
            "public_key_sha256",
        }
        and participant.get("credential_version") == 1
        and _hex(public_key_hex, expected_bytes=32)
        and participant.get("participant_id") == participant_id(public_key_hex)
        and participant.get("execution_did") == participant_did(public_key_hex)
        and participant.get("public_key_sha256")
        == hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()
        and _sha256(participant.get("participant_profile_artifact_sha256"))
        and _sha256(participant.get("participant_profile_sha256")),
        "outcome_consent_extension_participant_invalid",
        failures,
    )
    cohort = _object(extension.get("cohort_binding"))
    _require(
        set(cohort)
        == {
            "pair_id",
            "cohort",
            "reviewed_assignment_artifact_sha256",
            "reviewed_assignment_sha256",
            "assignment_commitment_sha256",
        }
        and _text(cohort.get("pair_id"))
        and cohort.get("cohort") in {"mentor", "control"}
        and all(
            _sha256(cohort.get(field))
            for field in (
                "reviewed_assignment_artifact_sha256",
                "reviewed_assignment_sha256",
                "assignment_commitment_sha256",
            )
        ),
        "outcome_consent_extension_cohort_invalid",
        failures,
    )
    material = _object(extension.get("material_binding"))
    frozen_materials = _object(material.get("frozen_materials"))
    _require(
        set(material)
        == {
            "promotion_gate_artifact_sha256",
            "promotion_gate_sha256",
            "frozen_review_artifact_sha256",
            "frozen_review_sha256",
            "frozen_materials",
        }
        and all(
            _sha256(material.get(field))
            for field in (
                "promotion_gate_artifact_sha256",
                "promotion_gate_sha256",
                "frozen_review_artifact_sha256",
                "frozen_review_sha256",
            )
        )
        and set(frozen_materials) == REQUIRED_MATERIALS
        and all(
            set(item) == {"artifact_sha256", "canonical_sha256"}
            and _sha256(item.get("artifact_sha256"))
            and _sha256(item.get("canonical_sha256"))
            for item in frozen_materials.values()
            if isinstance(item, dict)
        )
        and len(frozen_materials) == len(REQUIRED_MATERIALS),
        "outcome_consent_extension_material_invalid",
        failures,
    )
    scope = _object(extension.get("scope_binding"))
    _require(
        scope
        == {
            "consent_scope": CONSENT_SCOPE,
            "consent_scope_sha256": canonical_sha256(CONSENT_SCOPE),
            "consent_statement_sha256": hashlib.sha256(
                CONSENT_STATEMENT.encode()
            ).hexdigest(),
        },
        "outcome_consent_extension_scope_invalid",
        failures,
    )
    prior = _object(extension.get("prior_consent"))
    _require(
        set(prior)
        == {
            "artifact_sha256",
            "canonical_sha256",
            "inherited",
            "immutable_parent_evidence",
        }
        and _sha256(prior.get("artifact_sha256"))
        and _sha256(prior.get("canonical_sha256"))
        and prior.get("inherited") is False
        and prior.get("immutable_parent_evidence") is True,
        "outcome_consent_extension_prior_invalid",
        failures,
    )
    authorization = _object(extension.get("authorization"))
    _require(
        set(authorization)
        == {
            "authorization_id",
            "statement_sha256",
            "plan_artifact_sha256",
            "plan_sha256",
            "preflight_artifact_sha256",
        }
        and _text(authorization.get("authorization_id"))
        and all(
            _sha256(authorization.get(field))
            for field in (
                "statement_sha256",
                "plan_artifact_sha256",
                "plan_sha256",
                "preflight_artifact_sha256",
            )
        ),
        "outcome_consent_extension_authorization_invalid",
        failures,
    )
    _require(
        _hex(extension.get("consent_nonce_hex"), expected_bytes=32),
        "outcome_consent_extension_nonce_invalid",
        failures,
    )
    _require(
        extension.get("consent_statement") == CONSENT_STATEMENT,
        "outcome_consent_extension_statement_invalid",
        failures,
    )
    _require(
        extension.get("participant_consent_extended") is True
        and extension.get("model_execution_authorized") is False
        and extension.get("downstream_rebind_authorized") is False
        and extension.get("effectiveness_claim_authorized") is False
        and extension.get("si13_maturity_upgrade_authorized") is False,
        "outcome_consent_extension_execution_boundary_invalid",
        failures,
    )
    signature = _object(extension.get("signature"))
    payload = signature_payload(extension)
    _require(
        set(signature) == {"algorithm", "signed_payload_sha256", "signature_hex"}
        and signature.get("algorithm") == "Ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest()
        and _hex(signature.get("signature_hex"), expected_bytes=64),
        "outcome_consent_extension_signature_metadata_invalid",
        failures,
    )
    try:
        VerifyKey(bytes.fromhex(public_key_hex)).verify(
            payload, bytes.fromhex(str(signature.get("signature_hex", "")))
        )
    except (BadSignatureError, ValueError, TypeError):
        _require(
            False,
            "outcome_consent_extension_signature_invalid",
            failures,
        )
    body = {key: item for key, item in extension.items() if key != "extension_sha256"}
    _require(
        extension.get("extension_sha256") == canonical_sha256(body),
        "outcome_consent_extension_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def _source_binding_valid(value: Any) -> bool:
    source = value if isinstance(value, dict) else {}
    expected = {
        "promotion_gate",
        "frozen_review",
        "review_receipt",
        "frozen_materials",
        "reviewed_assignment",
        "assignment_gate",
        "participant_provisioning_report",
        "prior_consent_manifest",
        "prior_consent_gate",
        "token_label",
    }
    return (
        set(source) == expected
        and all(
            _ref_valid(source.get(name), canonical_required=True)
            for name in (
                "promotion_gate",
                "frozen_review",
                "review_receipt",
                "reviewed_assignment",
                "assignment_gate",
                "prior_consent_manifest",
                "prior_consent_gate",
            )
        )
        and _ref_valid(
            source.get("participant_provisioning_report"),
            canonical_required=False,
        )
        and isinstance(source.get("frozen_materials"), dict)
        and set(source["frozen_materials"]) == REQUIRED_MATERIALS
        and all(
            _ref_valid(item, canonical_required=True)
            for item in source["frozen_materials"].values()
        )
        and _text(source.get("token_label"))
    )


def _identity_valid(value: Any) -> bool:
    identity = value if isinstance(value, dict) else {}
    return (
        set(identity)
        == {
            "participant_id",
            "execution_did",
            "public_key_sha256",
            "key_label",
            "key_id_hex",
            "profile_artifact_sha256",
            "profile_sha256",
        }
        and _text(identity.get("participant_id"))
        and _text(identity.get("execution_did"))
        and _sha256(identity.get("public_key_sha256"))
        and _text(identity.get("key_label"))
        and _hex(identity.get("key_id_hex"))
        and _sha256(identity.get("profile_artifact_sha256"))
        and _sha256(identity.get("profile_sha256"))
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
            "participant_profile_artifact_sha256",
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
                "participant_profile_artifact_sha256",
                "participant_profile_sha256",
                "prior_consent_artifact_sha256",
                "prior_consent_sha256",
            )
        )
    )


def _ref_valid(value: Any, *, canonical_required: bool) -> bool:
    ref = value if isinstance(value, dict) else {}
    expected = {"path", "sha256", "canonical_sha256"} if canonical_required else {
        "path",
        "sha256",
    }
    return (
        set(ref) == expected
        and _text(ref.get("path"))
        and _sha256(ref.get("sha256"))
        and (
            not canonical_required
            or _sha256(ref.get("canonical_sha256"))
        )
    )


def _list(value: Any) -> list[dict[str, Any]]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rfc3339(value: Any) -> bool:
    try:
        return (
            datetime.fromisoformat(str(value).replace("Z", "+00:00")).tzinfo
            is not None
        )
    except ValueError:
        return False


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sha256(value: Any) -> bool:
    return _hex(value, expected_bytes=32)


def _hex(value: Any, expected_bytes: int | None = None) -> bool:
    if not isinstance(value, str):
        return False
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return False
    return bool(decoded) and (
        expected_bytes is None or len(decoded) == expected_bytes
    )


def _require(condition: bool, label: str, failures: list[str]) -> None:
    if not condition:
        failures.append(label)
