"""Unsigned participant-bound J1-D treatment advice contracts."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256


ADVICE_SCHEMA = "j1-qualification-treatment-advice-candidate:v1"
MANIFEST_SCHEMA = "j1-qualification-treatment-advice-manifest:v1"
SIGNED_ADVICE_SCHEMA = "j1-qualification-treatment-advice-signed:v1"
SIGNED_MANIFEST_SCHEMA = "j1-qualification-treatment-advice-signed-manifest:v1"


class TreatmentAdviceSigner(Protocol):
    public_key_hex: str

    def sign(self, payload: bytes) -> bytes: ...


def build_advice_candidate(
    *,
    created_at: str,
    reviewed_design: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    mentor_identity: dict[str, Any],
    assignment: dict[str, Any],
    task: dict[str, Any],
) -> dict[str, Any]:
    participant = assignment["mentor"]
    commitment = canonical_sha256(
        {
            "reviewed_design_sha256": reviewed_design["reviewed_design_sha256"],
            "reviewed_assignment_sha256": reviewed_assignment[
                "reviewed_assignment_sha256"
            ],
            "mentor_identity_sha256": mentor_identity["profile_sha256"],
            "pair_id": assignment["pair_id"],
            "participant_id": participant["participant_id"],
            "task_id": task["task_id"],
            "advice_template": task["mentor_condition"]["advice_template"],
        }
    )
    value = {
        "schema_version": ADVICE_SCHEMA,
        "advice_id": f"j1q-advice-{commitment[:24]}",
        "status": "review_required_unsigned",
        "created_at": created_at,
        "source_binding": {
            "reviewed_design_sha256": reviewed_design["reviewed_design_sha256"],
            "reviewed_assignment_sha256": reviewed_assignment[
                "reviewed_assignment_sha256"
            ],
            "mentor_identity_sha256": mentor_identity["profile_sha256"],
            "assignment_commitment_sha256": assignment["assignment_commitment_sha256"],
            "task_input_sha256": task["task_input_sha256"],
        },
        "mentor": {
            "mentor_id": mentor_identity["mentor"]["mentor_id"],
            "mentor_did": mentor_identity["mentor"]["did"],
            "credential_version": mentor_identity["mentor"]["credential_version"],
            "public_key_sha256": mentor_identity["mentor"]["public_key_sha256"],
        },
        "recipient": {
            "cohort": "mentor",
            "pair_id": assignment["pair_id"],
            "participant_id": participant["participant_id"],
            "execution_did": participant["execution_did"],
        },
        "task": {
            "task_id": task["task_id"],
            "verifier_case": task["verifier_case"],
            "event_script": task["event_script"],
        },
        "advice": {
            "template": task["mentor_condition"]["advice_template"],
            "visibility": task["mentor_condition"]["visibility"],
            "authority": "advisory_only",
            "may_override_constitution": False,
            "may_execute_for_participant": False,
        },
        "signature": {
            "required": True,
            "performed": False,
            "algorithm": "ed25519",
            "signed_payload_sha256": None,
            "signature_hex": None,
        },
        "execution_boundary": {
            "candidate_only": True,
            "runtime_projection_allowed": False,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    value["candidate_sha256"] = canonical_sha256(value)
    failures = validate_advice_candidate(
        value,
        reviewed_design=reviewed_design,
        reviewed_assignment=reviewed_assignment,
        mentor_identity=mentor_identity,
        assignment=assignment,
        task=task,
    )
    if failures:
        raise ValueError(f"treatment advice candidate invalid: {failures}")
    return value


def validate_advice_candidate(
    value: Any,
    *,
    reviewed_design: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    mentor_identity: dict[str, Any],
    assignment: dict[str, Any],
    task: dict[str, Any],
) -> list[str]:
    candidate = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(
        set(candidate)
        == {
            "schema_version",
            "advice_id",
            "status",
            "created_at",
            "source_binding",
            "mentor",
            "recipient",
            "task",
            "advice",
            "signature",
            "execution_boundary",
            "candidate_sha256",
        },
        "treatment_advice_fields_invalid",
        failures,
    )
    _require(
        candidate.get("schema_version") == ADVICE_SCHEMA,
        "treatment_advice_schema_invalid",
        failures,
    )
    _require(
        candidate.get("status") == "review_required_unsigned",
        "treatment_advice_status_invalid",
        failures,
    )
    _require(
        _rfc3339(candidate.get("created_at")), "treatment_advice_time_invalid", failures
    )
    expected = build_advice_expected(
        reviewed_design=reviewed_design,
        reviewed_assignment=reviewed_assignment,
        mentor_identity=mentor_identity,
        assignment=assignment,
        task=task,
    )
    for field in (
        "advice_id",
        "source_binding",
        "mentor",
        "recipient",
        "task",
        "advice",
    ):
        _require(
            candidate.get(field) == expected[field],
            f"treatment_advice_{field}_invalid",
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
        "treatment_advice_signature_boundary_invalid",
        failures,
    )
    boundary = (
        candidate.get("execution_boundary")
        if isinstance(candidate.get("execution_boundary"), dict)
        else {}
    )
    _require(
        len(boundary) == 7
        and boundary.get("candidate_only") is True
        and all(
            item is False for key, item in boundary.items() if key != "candidate_only"
        ),
        "treatment_advice_execution_boundary_invalid",
        failures,
    )
    body = {key: item for key, item in candidate.items() if key != "candidate_sha256"}
    _require(
        candidate.get("candidate_sha256") == canonical_sha256(body),
        "treatment_advice_hash_mismatch",
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
    if candidate.get("candidate_sha256") != canonical_sha256(
        {key: item for key, item in candidate.items() if key != "candidate_sha256"}
    ):
        raise ValueError("treatment advice candidate hash mismatch")
    if (
        signer.public_key_hex.lower()
        != mentor_identity["mentor"]["public_key_hex"].lower()
    ):
        raise ValueError("treatment advice signer public key mismatch")
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
        "execution_boundary": {
            "advice_signature_only": True,
            "runtime_projection_allowed": False,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
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
        raise ValueError(f"signed treatment advice invalid: {failures}")
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
            "execution_boundary",
            "signature",
            "signed_advice_sha256",
        },
        "signed_treatment_advice_fields_invalid",
        failures,
    )
    _require(
        signed.get("schema_version") == SIGNED_ADVICE_SCHEMA,
        "signed_treatment_advice_schema_invalid",
        failures,
    )
    _require(
        signed.get("status") == "signed_non_executable",
        "signed_treatment_advice_status_invalid",
        failures,
    )
    _require(
        _rfc3339(signed.get("signed_at")),
        "signed_treatment_advice_time_invalid",
        failures,
    )
    _require(
        candidate.get("candidate_sha256")
        == canonical_sha256(
            {key: item for key, item in candidate.items() if key != "candidate_sha256"}
        ),
        "signed_treatment_advice_candidate_hash_invalid",
        failures,
    )
    _require(
        signed.get("source_candidate")
        == {
            "artifact_sha256": candidate_artifact_sha256,
            "canonical_sha256": candidate.get("candidate_sha256"),
        },
        "signed_treatment_advice_candidate_binding_invalid",
        failures,
    )
    _require(
        signed.get("source_manifest")
        == {
            "artifact_sha256": source_manifest_artifact_sha256,
            "canonical_sha256": source_manifest_sha256,
        },
        "signed_treatment_advice_manifest_binding_invalid",
        failures,
    )
    _require(
        signed.get("authorization")
        == {
            "authorization_id": authorization_id,
            "statement_sha256": authorization_statement_sha256,
        },
        "signed_treatment_advice_authorization_invalid",
        failures,
    )
    for field in (
        "advice_id",
        "source_binding",
        "mentor",
        "recipient",
        "task",
        "advice",
    ):
        _require(
            signed.get(field) == candidate.get(field),
            f"signed_treatment_advice_{field}_invalid",
            failures,
        )
    _require(
        signed.get("mentor", {}).get("mentor_did")
        == mentor_identity.get("mentor", {}).get("did")
        and signed.get("mentor", {}).get("public_key_sha256")
        == mentor_identity.get("mentor", {}).get("public_key_sha256"),
        "signed_treatment_advice_mentor_identity_invalid",
        failures,
    )
    boundary = (
        signed.get("execution_boundary")
        if isinstance(signed.get("execution_boundary"), dict)
        else {}
    )
    _require(
        len(boundary) == 7
        and boundary.get("advice_signature_only") is True
        and all(
            item is False
            for key, item in boundary.items()
            if key != "advice_signature_only"
        ),
        "signed_treatment_advice_execution_boundary_invalid",
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
        "signed_treatment_advice_signature_invalid",
        failures,
    )
    try:
        VerifyKey(
            bytes.fromhex(str(mentor_identity.get("mentor", {}).get("public_key_hex")))
        ).verify(payload, bytes.fromhex(signature_hex))
    except (BadSignatureError, ValueError, TypeError, AttributeError):
        _require(False, "signed_treatment_advice_signature_unverified", failures)
    body = {key: item for key, item in signed.items() if key != "signed_advice_sha256"}
    _require(
        signed.get("signed_advice_sha256") == canonical_sha256(body),
        "signed_treatment_advice_hash_mismatch",
        failures,
    )
    return list(dict.fromkeys(failures))


def build_advice_expected(
    *,
    reviewed_design: dict[str, Any],
    reviewed_assignment: dict[str, Any],
    mentor_identity: dict[str, Any],
    assignment: dict[str, Any],
    task: dict[str, Any],
) -> dict[str, Any]:
    participant = assignment["mentor"]
    commitment = canonical_sha256(
        {
            "reviewed_design_sha256": reviewed_design["reviewed_design_sha256"],
            "reviewed_assignment_sha256": reviewed_assignment[
                "reviewed_assignment_sha256"
            ],
            "mentor_identity_sha256": mentor_identity["profile_sha256"],
            "pair_id": assignment["pair_id"],
            "participant_id": participant["participant_id"],
            "task_id": task["task_id"],
            "advice_template": task["mentor_condition"]["advice_template"],
        }
    )
    return {
        "advice_id": f"j1q-advice-{commitment[:24]}",
        "source_binding": {
            "reviewed_design_sha256": reviewed_design["reviewed_design_sha256"],
            "reviewed_assignment_sha256": reviewed_assignment[
                "reviewed_assignment_sha256"
            ],
            "mentor_identity_sha256": mentor_identity["profile_sha256"],
            "assignment_commitment_sha256": assignment["assignment_commitment_sha256"],
            "task_input_sha256": task["task_input_sha256"],
        },
        "mentor": {
            "mentor_id": mentor_identity["mentor"]["mentor_id"],
            "mentor_did": mentor_identity["mentor"]["did"],
            "credential_version": mentor_identity["mentor"]["credential_version"],
            "public_key_sha256": mentor_identity["mentor"]["public_key_sha256"],
        },
        "recipient": {
            "cohort": "mentor",
            "pair_id": assignment["pair_id"],
            "participant_id": participant["participant_id"],
            "execution_did": participant["execution_did"],
        },
        "task": {
            "task_id": task["task_id"],
            "verifier_case": task["verifier_case"],
            "event_script": task["event_script"],
        },
        "advice": {
            "template": task["mentor_condition"]["advice_template"],
            "visibility": task["mentor_condition"]["visibility"],
            "authority": "advisory_only",
            "may_override_constitution": False,
            "may_execute_for_participant": False,
        },
    }


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


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
    ).encode("utf-8")


def _hex_bytes(value: str, size: int) -> bool:
    try:
        return len(bytes.fromhex(value)) == size
    except ValueError:
        return False


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
