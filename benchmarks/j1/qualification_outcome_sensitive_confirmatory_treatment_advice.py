"""Prospective confirmatory participant/task-scoped treatment advice contracts."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256
from .qualification_outcome_sensitive_treatment_advice import (
    ADVICE_TEMPLATES,
)


ADVICE_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-treatment-advice-candidate:v1"
)
MANIFEST_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-treatment-advice-manifest:v1"
)
SIGNED_ADVICE_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-treatment-advice-signed:v1"
)
SIGNED_MANIFEST_SCHEMA = (
    "j1-qualification-outcome-sensitive-confirmatory-"
    "treatment-advice-signed-manifest:v1"
)
CANDIDATE_BOUNDARY = {
    "candidate_only": True,
    "mentor_signature_performed": False,
    "prior_advice_reused": False,
    "advice_adherence_observed": False,
    "runtime_projection_allowed": False,
    "provider_api_call_allowed": False,
    "model_invocation_allowed": False,
    "agent_execution_allowed": False,
    "backend_fact_append_allowed": False,
    "ledger_append_allowed": False,
    "execution_authorization_issued_or_consumed": False,
}
MANIFEST_BOUNDARY = {
    "offline_candidate_preparation_only": True,
    "mentor_signature_performed": False,
    "pkcs11_session_opened": False,
    "prior_advice_reused": False,
    "r4_reanalysis_performed": False,
    "runtime_projection_allowed": False,
    "provider_credential_read": False,
    "provider_api_call_allowed": False,
    "model_invocation_allowed": False,
    "agent_execution_allowed": False,
    "infrastructure_change_allowed": False,
    "backend_fact_append_allowed": False,
    "ledger_append_allowed": False,
    "execution_authorization_issued_or_consumed": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}
SIGNED_ADVICE_BOUNDARY = {
    "confirmatory_advice_signature_only": True,
    "prior_advice_reused": False,
    "advice_adherence_observed": False,
    "runtime_projection_allowed": False,
    "provider_credential_read_allowed": False,
    "provider_api_call_allowed": False,
    "model_invocation_allowed": False,
    "agent_execution_allowed": False,
    "infrastructure_change_allowed": False,
    "backend_fact_append_allowed": False,
    "ledger_append_allowed": False,
    "execution_authorization_issued_or_consumed": False,
    "r4_reanalysis_allowed": False,
    "effectiveness_or_causal_claim_authorized": False,
    "si13_maturity_upgrade_authorized": False,
}


class TreatmentAdviceSigner(Protocol):
    public_key_hex: str

    def sign(self, payload: bytes) -> bytes: ...


def build_advice_candidate(
    *,
    created_at: str,
    protocol: dict[str, Any],
    task_fixture: dict[str, Any],
    confirmatory_method: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    assignment_gate: dict[str, Any],
    mentor_identity: dict[str, Any],
    assignment: dict[str, Any],
    task: dict[str, Any],
) -> dict[str, Any]:
    expected = build_advice_expected(
        protocol=protocol,
        task_fixture=task_fixture,
        confirmatory_method=confirmatory_method,
        reviewed_assignment=reviewed_assignment,
        assignment_gate=assignment_gate,
        mentor_identity=mentor_identity,
        assignment=assignment,
        task=task,
    )
    candidate = {
        "schema_version": ADVICE_SCHEMA,
        **expected,
        "status": "review_required_unsigned",
        "created_at": created_at,
        "signature": {
            "required": True,
            "performed": False,
            "algorithm": "ed25519",
            "signed_payload_sha256": None,
            "signature_hex": None,
        },
        "execution_boundary": copy.deepcopy(CANDIDATE_BOUNDARY),
    }
    candidate["candidate_sha256"] = canonical_sha256(candidate)
    failures = validate_advice_candidate(
        candidate,
        protocol=protocol,
        task_fixture=task_fixture,
        confirmatory_method=confirmatory_method,
        reviewed_assignment=reviewed_assignment,
        assignment_gate=assignment_gate,
        mentor_identity=mentor_identity,
        assignment=assignment,
        task=task,
    )
    if failures:
        raise ValueError(f"confirmatory advice candidate invalid: {failures}")
    return candidate


def build_advice_expected(
    *,
    protocol: dict[str, Any],
    task_fixture: dict[str, Any],
    confirmatory_method: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    assignment_gate: dict[str, Any],
    mentor_identity: dict[str, Any],
    assignment: dict[str, Any],
    task: dict[str, Any],
) -> dict[str, Any]:
    template = ADVICE_TEMPLATES[task["phase"]]
    recipient = assignment["mentor"]
    source_binding = {
        "protocol_sha256": protocol["protocol_sha256"],
        "task_fixture_sha256": task_fixture["fixture_sha256"],
        "confirmatory_method_sha256": confirmatory_method["method_sha256"],
        "reviewed_confirmatory_assignment_sha256": reviewed_assignment[
            "reviewed_rebound_assignment_sha256"
        ],
        "assignment_promotion_gate_sha256": assignment_gate["report_sha256"],
        "mentor_identity_sha256": mentor_identity["profile_sha256"],
        "assignment_rebind_commitment_sha256": assignment["rebind_commitment_sha256"],
        "confirmatory_consent_sha256": recipient["confirmatory_consent_sha256"],
        "task_prompt_sha256": task["prompt_sha256"],
    }
    commitment = canonical_sha256(
        {
            "source_binding": source_binding,
            "pair_id": assignment["pair_id"],
            "participant_id": recipient["participant_id"],
            "task_id": task["task_id"],
            "task_ordinal": task["task_ordinal"],
            "template": template,
        }
    )
    return {
        "advice_id": f"j1q-confirmatory-advice-{commitment[:24]}",
        "source_binding": source_binding,
        "mentor": {
            "mentor_id": mentor_identity["mentor"]["mentor_id"],
            "mentor_did": mentor_identity["mentor"]["did"],
            "credential_version": mentor_identity["mentor"]["credential_version"],
            "public_key_sha256": mentor_identity["mentor"]["public_key_sha256"],
        },
        "recipient": {
            "cohort": "mentor",
            "pair_id": assignment["pair_id"],
            "participant_id": recipient["participant_id"],
            "execution_did": recipient["execution_did"],
            "confirmatory_consent_sha256": recipient["confirmatory_consent_sha256"],
        },
        "task": {
            "task_id": task["task_id"],
            "task_ordinal": task["task_ordinal"],
            "phase": task["phase"],
            "prompt_sha256": task["prompt_sha256"],
        },
        "advice": {
            **copy.deepcopy(template),
            "visibility": "mentor_participant_only_at_bound_task",
            "authority": "advisory_only",
            "participant_decision_remains_independent": True,
            "may_override_constitution": False,
            "may_execute_for_participant": False,
        },
        "leakage_guard": {
            "prompt_copied": False,
            "ground_truth_copied": False,
            "action_or_pattern_identifier_count": 0,
        },
        "measurement_boundary": {
            "advice_exposure_observable": True,
            "advice_adherence_observed": False,
            "advice_adherence_inference_allowed": False,
        },
    }


def validate_advice_candidate(
    value: Any,
    *,
    protocol: dict[str, Any],
    task_fixture: dict[str, Any],
    confirmatory_method: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    assignment_gate: dict[str, Any],
    mentor_identity: dict[str, Any],
    assignment: dict[str, Any],
    task: dict[str, Any],
) -> list[str]:
    candidate = value if isinstance(value, dict) else {}
    failures: list[str] = []
    expected = build_advice_expected(
        protocol=protocol,
        task_fixture=task_fixture,
        confirmatory_method=confirmatory_method,
        reviewed_assignment=reviewed_assignment,
        assignment_gate=assignment_gate,
        mentor_identity=mentor_identity,
        assignment=assignment,
        task=task,
    )
    required = {
        "schema_version",
        *expected,
        "status",
        "created_at",
        "signature",
        "execution_boundary",
        "candidate_sha256",
    }
    _require(
        set(candidate) == required,
        "confirmatory_advice_fields_invalid",
        failures,
    )
    _require(
        candidate.get("schema_version") == ADVICE_SCHEMA
        and candidate.get("status") == "review_required_unsigned"
        and _rfc3339(candidate.get("created_at")),
        "confirmatory_advice_identity_invalid",
        failures,
    )
    for field, expected_value in expected.items():
        _require(
            candidate.get(field) == expected_value,
            f"confirmatory_advice_{field}_invalid",
            failures,
        )
    _require(
        candidate.get("signature")
        == {
            "required": True,
            "performed": False,
            "algorithm": "ed25519",
            "signed_payload_sha256": None,
            "signature_hex": None,
        },
        "confirmatory_advice_signature_boundary_invalid",
        failures,
    )
    _require(
        candidate.get("execution_boundary") == CANDIDATE_BOUNDARY,
        "confirmatory_advice_execution_boundary_invalid",
        failures,
    )
    forbidden = set(task.get("allowed_action_ids", [])) | set(
        task.get("allowed_pattern_ids", [])
    )
    advice_text = str(candidate.get("advice", {}).get("text", ""))
    _require(
        all(identifier not in advice_text for identifier in forbidden),
        "confirmatory_advice_ground_truth_identifier_leak",
        failures,
    )
    body = {key: item for key, item in candidate.items() if key != "candidate_sha256"}
    _require(
        candidate.get("candidate_sha256") == canonical_sha256(body),
        "confirmatory_advice_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_signed_advice(
    *,
    candidate: dict[str, Any],
    candidate_artifact_sha256: str,
    source_manifest_artifact_sha256: str,
    source_manifest_sha256: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    signed_at: str,
    mentor_identity: dict[str, Any],
    signer: TreatmentAdviceSigner,
) -> dict[str, Any]:
    candidate_body = {
        key: item for key, item in candidate.items() if key != "candidate_sha256"
    }
    if candidate.get("candidate_sha256") != canonical_sha256(candidate_body):
        raise ValueError("confirmatory advice candidate hash mismatch")
    if (
        signer.public_key_hex.lower()
        != mentor_identity["mentor"]["public_key_hex"].lower()
    ):
        raise ValueError("confirmatory advice signer public key mismatch")
    value = {
        "schema_version": SIGNED_ADVICE_SCHEMA,
        "advice_id": candidate["advice_id"],
        "status": "signed_non_executable",
        "signed_at": signed_at,
        "source_candidate": {
            "artifact_sha256": candidate_artifact_sha256,
            "canonical_sha256": candidate["candidate_sha256"],
        },
        "source_manifest": {
            "artifact_sha256": source_manifest_artifact_sha256,
            "canonical_sha256": source_manifest_sha256,
        },
        "authorization": {
            "authorization_id": authorization_id,
            "statement_sha256": authorization_statement_sha256,
        },
        "source_binding": copy.deepcopy(candidate["source_binding"]),
        "mentor": copy.deepcopy(candidate["mentor"]),
        "recipient": copy.deepcopy(candidate["recipient"]),
        "task": copy.deepcopy(candidate["task"]),
        "advice": copy.deepcopy(candidate["advice"]),
        "leakage_guard": copy.deepcopy(candidate["leakage_guard"]),
        "measurement_boundary": copy.deepcopy(candidate["measurement_boundary"]),
        "execution_boundary": copy.deepcopy(SIGNED_ADVICE_BOUNDARY),
    }
    payload = _signature_payload(value)
    value["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signer.sign(payload).hex(),
    }
    value["signed_advice_sha256"] = canonical_sha256(value)
    failures = validate_signed_advice(
        value,
        candidate=candidate,
        candidate_artifact_sha256=candidate_artifact_sha256,
        source_manifest_artifact_sha256=source_manifest_artifact_sha256,
        source_manifest_sha256=source_manifest_sha256,
        authorization_id=authorization_id,
        authorization_statement_sha256=authorization_statement_sha256,
        mentor_identity=mentor_identity,
    )
    if failures:
        raise ValueError(f"signed confirmatory advice invalid: {failures}")
    return value


def validate_signed_advice(
    value: Any,
    *,
    candidate: dict[str, Any],
    candidate_artifact_sha256: str,
    source_manifest_artifact_sha256: str,
    source_manifest_sha256: str,
    authorization_id: str,
    authorization_statement_sha256: str,
    mentor_identity: dict[str, Any],
) -> list[str]:
    signed = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(signed)
        == {
            "schema_version",
            "advice_id",
            "status",
            "signed_at",
            "source_candidate",
            "source_manifest",
            "authorization",
            "source_binding",
            "mentor",
            "recipient",
            "task",
            "advice",
            "leakage_guard",
            "measurement_boundary",
            "execution_boundary",
            "signature",
            "signed_advice_sha256",
        },
        "signed_confirmatory_advice_fields_invalid",
        failures,
    )
    _require(
        signed.get("schema_version") == SIGNED_ADVICE_SCHEMA
        and signed.get("status") == "signed_non_executable"
        and _rfc3339(signed.get("signed_at")),
        "signed_confirmatory_advice_identity_invalid",
        failures,
    )
    candidate_body = {
        key: item for key, item in candidate.items() if key != "candidate_sha256"
    }
    _require(
        candidate.get("candidate_sha256") == canonical_sha256(candidate_body),
        "signed_confirmatory_advice_candidate_hash_invalid",
        failures,
    )
    _require(
        signed.get("source_candidate")
        == {
            "artifact_sha256": candidate_artifact_sha256,
            "canonical_sha256": candidate.get("candidate_sha256"),
        },
        "signed_confirmatory_advice_candidate_binding_invalid",
        failures,
    )
    _require(
        signed.get("source_manifest")
        == {
            "artifact_sha256": source_manifest_artifact_sha256,
            "canonical_sha256": source_manifest_sha256,
        },
        "signed_confirmatory_advice_manifest_binding_invalid",
        failures,
    )
    _require(
        signed.get("authorization")
        == {
            "authorization_id": authorization_id,
            "statement_sha256": authorization_statement_sha256,
        },
        "signed_confirmatory_advice_authorization_invalid",
        failures,
    )
    for field in (
        "advice_id",
        "source_binding",
        "mentor",
        "recipient",
        "task",
        "advice",
        "leakage_guard",
        "measurement_boundary",
    ):
        _require(
            signed.get(field) == candidate.get(field),
            f"signed_confirmatory_advice_{field}_invalid",
            failures,
        )
    _require(
        signed.get("mentor", {}).get("mentor_did")
        == mentor_identity.get("mentor", {}).get("did")
        and signed.get("mentor", {}).get("public_key_sha256")
        == mentor_identity.get("mentor", {}).get("public_key_sha256"),
        "signed_confirmatory_advice_mentor_identity_invalid",
        failures,
    )
    _require(
        signed.get("execution_boundary") == SIGNED_ADVICE_BOUNDARY,
        "signed_confirmatory_advice_execution_boundary_invalid",
        failures,
    )
    signature = (
        signed.get("signature") if isinstance(signed.get("signature"), dict) else {}
    )
    payload = _signature_payload(signed)
    signature_hex = str(signature.get("signature_hex") or "")
    _require(
        set(signature) == {"algorithm", "signed_payload_sha256", "signature_hex"}
        and signature.get("algorithm") == "ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest()
        and _hex_bytes(signature_hex, 64),
        "signed_confirmatory_advice_signature_invalid",
        failures,
    )
    try:
        VerifyKey(
            bytes.fromhex(str(mentor_identity.get("mentor", {}).get("public_key_hex")))
        ).verify(payload, bytes.fromhex(signature_hex))
    except (BadSignatureError, ValueError, TypeError, AttributeError):
        _require(
            False,
            "signed_confirmatory_advice_signature_unverified",
            failures,
        )
    body = {key: item for key, item in signed.items() if key != "signed_advice_sha256"}
    _require(
        signed.get("signed_advice_sha256") == canonical_sha256(body),
        "signed_confirmatory_advice_hash_invalid",
        failures,
    )
    return list(dict.fromkeys(failures))


def authorization_statement(manifest: dict[str, Any], manifest_raw_sha256: str) -> str:
    source = manifest["source_binding"]
    mentor = manifest["mentor"]
    return (
        "I authorize the J1-D mentor identity "
        f"{mentor['mentor_did']} to sign exactly 180 prospective confirmatory "
        "treatment advice candidates from manifest raw SHA-256 "
        f"{manifest_raw_sha256}, canonical SHA-256 "
        f"{manifest['manifest_sha256']}, binding reviewed confirmatory assignment "
        f"{source['reviewed_assignment']['canonical_sha256']}, assignment "
        f"promotion Gate {source['assignment_gate']['canonical_sha256']}, "
        f"confirmatory method {source['confirmatory_method']['canonical_sha256']}, "
        f"protocol {source['protocol']['canonical_sha256']}, task fixture "
        f"{source['task_fixture']['canonical_sha256']}, and mentor identity "
        f"{source['mentor_identity']['canonical_sha256']}. I acknowledge that "
        "the 180 new signatures cover exactly 20 mentor participants and treatment "
        "ordinals 4 through 12, baseline ordinals 1 through 3 have no advice, "
        "control advice remains empty, prior advice and signatures are not reused, "
        "and advice adherence remains unobserved and may not be inferred. The "
        "three phase-scoped templates do not copy task prompts, hidden ground "
        "truth, action identifiers, or pattern identifiers. Signed advice remains "
        "non-executable advisory data and each participant retains independent "
        "decision authority. This authorization permits one PKCS#11 session on "
        "token dev-token and exactly 180 mentor Ed25519 signatures for these "
        "candidates only. It does not authorize infrastructure changes, provider "
        "or model calls, Agent or task execution, Backend Fact append, Ledger "
        "append, execution authorization issuance or consumption, r4 reanalysis, "
        "an effectiveness or causal claim, or an SI-13 maturity upgrade."
    )


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _require(condition: bool, failure: str, failures: list[str]) -> None:
    if not condition:
        failures.append(failure)


def _signature_payload(value: dict[str, Any]) -> bytes:
    unsigned = {
        key: item
        for key, item in value.items()
        if key not in {"signature", "signed_advice_sha256"}
    }
    return json.dumps(
        unsigned,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _hex_bytes(value: str, size: int) -> bool:
    try:
        return len(bytes.fromhex(value)) == size
    except ValueError:
        return False
