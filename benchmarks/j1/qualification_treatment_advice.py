"""Unsigned participant-bound J1-D treatment advice contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .controlled_comparison import canonical_sha256


ADVICE_SCHEMA = "j1-qualification-treatment-advice-candidate:v1"
MANIFEST_SCHEMA = "j1-qualification-treatment-advice-manifest:v1"


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


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
