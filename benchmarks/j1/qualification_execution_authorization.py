"""Signed single-use execution authorization for J1-D qualification."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .qualification_reviewer_identity import validate_reviewer_identity_profile


RECEIPT_SCHEMA = "j1-qualification-execution-authorization:v1"
CONSUMPTION_SCHEMA = "j1-qualification-authorization-consumption:v1"
DECISION = "authorize_once"
MAX_TTL_SECONDS = 1800
RECEIPT_FIELDS = {
    "schema_version",
    "authorization_id",
    "decision",
    "issued_at",
    "valid_from",
    "valid_until",
    "owner_authorization",
    "source_binding",
    "execution_scope",
    "cost_acknowledgement",
    "controls",
    "reviewer",
    "implementation",
    "execution_boundary",
    "signature",
}
SIGNATURE_FIELDS = {"algorithm", "signed_payload_sha256", "signature_hex"}


class ExecutionAuthorizationSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def build_authorization_context(
    *,
    run_id: str,
    protocol: dict[str, Any],
    protocol_artifact_sha256: str,
    roster: dict[str, Any],
    roster_artifact_sha256: str,
    roster_gate_artifact_sha256: str,
    admission_request: dict[str, Any],
    admission_request_artifact_sha256: str,
    provider_admission_report: dict[str, Any],
    provider_admission_artifact_sha256: str,
    execution_root: Path,
    consumption_path: Path,
) -> dict[str, dict[str, Any]]:
    stack = _object(protocol.get("frozen_stack"))
    budget = _object(stack.get("budget"))
    corpus = _object(protocol.get("task_corpus"))
    provider = _object(admission_request.get("provider"))
    participant_count = len(roster.get("participants", []))
    pair_count = len(
        {
            item.get("pair_id")
            for item in roster.get("participants", [])
            if isinstance(item, dict)
        }
    )
    task_count = int(corpus.get("task_count", 0))
    per_participant = {
        "max_tasks": int(budget.get("max_tasks", 0)),
        "max_tokens": int(budget.get("max_tokens", 0)),
        "max_cost_microunits": int(budget.get("max_cost_microunits", 0)),
    }
    aggregate = {
        "authorized_task_executions": participant_count * task_count,
        "max_tokens": participant_count * per_participant["max_tokens"],
        "max_cost_microunits": participant_count
        * per_participant["max_cost_microunits"],
    }
    return {
        "source_binding": {
            "qualification_protocol_sha256": protocol.get("protocol_sha256"),
            "qualification_protocol_artifact_sha256": protocol_artifact_sha256,
            "reviewed_roster_sha256": roster.get("roster_sha256"),
            "reviewed_roster_artifact_sha256": roster_artifact_sha256,
            "roster_gate_artifact_sha256": roster_gate_artifact_sha256,
            "admission_request_sha256": provider_admission_report.get(
                "admission", {}
            ).get("request_sha256"),
            "admission_request_artifact_sha256": admission_request_artifact_sha256,
            "provider_admission_artifact_sha256": provider_admission_artifact_sha256,
        },
        "execution_scope": {
            "run_id": run_id,
            "provider_id": stack.get("provider_id"),
            "provider_host": provider_admission_report.get("admission", {})
            .get("provider_admission", {})
            .get("host"),
            "model_id": stack.get("model_id"),
            "temperature": stack.get("temperature"),
            "corpus_id": corpus.get("corpus_id"),
            "corpus_tasks_sha256": corpus.get("tasks_sha256"),
            "task_count_per_participant": task_count,
            "participant_count": participant_count,
            "pair_count": pair_count,
            "minimum_completed_pairs": protocol.get("minimum_completed_pairs"),
            "same_stack_for_both_cohorts": stack.get("same_stack_for_both_cohorts"),
            "provider_base_url_sha256": hashlib.sha256(
                str(provider.get("base_url", "")).encode("utf-8")
            ).hexdigest(),
        },
        "cost_acknowledgement": {
            "currency": "microunits",
            "per_participant_ceiling": per_participant,
            "aggregate_ceiling": aggregate,
            "billable_provider_calls_acknowledged": True,
            "actual_tokens_and_cost_recording_required": True,
            "budget_overrun_fail_stop_required": True,
            "explicit_owner_acknowledgement": True,
        },
        "controls": {
            "execution_root": str(execution_root.resolve()),
            "authorization_consumption_path": str(consumption_path.resolve()),
            "single_use": True,
            "claim_must_use_create_exclusive": True,
            "claimed_failure_requires_new_authorization": True,
            "unclaimed_expiry_requires_new_authorization": True,
            "post_run_receipt_required": True,
            "operator_closeout_required": True,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }


def build_execution_authorization(
    *,
    authorization_id: str,
    issued_at: str,
    ttl_seconds: int,
    owner_authorization_id: str,
    owner_statement_sha256: str,
    context: dict[str, dict[str, Any]],
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: ExecutionAuthorizationSigner,
) -> dict[str, Any]:
    issued = _timestamp(issued_at)
    if issued is None:
        raise ValueError("authorization issued_at must be RFC3339")
    if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError("authorization TTL must be between 1 and 1800 seconds")
    profile_failures = validate_reviewer_identity_profile(reviewer_profile)
    if profile_failures:
        raise ValueError(f"reviewer identity profile invalid: {profile_failures}")
    reviewer = reviewer_profile["reviewer"]
    if signer.public_key_hex.lower() != reviewer["public_key_hex"].lower():
        raise ValueError("authorization signer does not match reviewer identity")
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "authorization_id": authorization_id,
        "decision": DECISION,
        "issued_at": issued.isoformat(),
        "valid_from": issued.isoformat(),
        "valid_until": (issued + timedelta(seconds=ttl_seconds)).isoformat(),
        "owner_authorization": {
            "authorization_id": owner_authorization_id,
            "authorization_statement_sha256": owner_statement_sha256,
            "source": "interactive_owner_operator_approval",
            "exact_cost_acknowledgement_confirmed": True,
            "single_use_and_failure_boundary_confirmed": True,
        },
        "source_binding": context["source_binding"],
        "execution_scope": context["execution_scope"],
        "cost_acknowledgement": context["cost_acknowledgement"],
        "controls": context["controls"],
        "reviewer": {**reviewer, "identity_profile_sha256": reviewer_profile_sha256},
        "implementation": implementation,
        "execution_boundary": {
            "single_use_authorization_issued": True,
            "provider_api_call_allowed_within_scope": True,
            "model_invocation_allowed_within_scope": True,
            "agent_execution_allowed_within_scope": True,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
            "production_use_allowed": False,
            "automatic_rollout_allowed": False,
            "effectiveness_claim_allowed_before_closeout": False,
            "controlled_experiment_execution_ready": False,
        },
    }
    payload = signature_payload(receipt)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("execution authorization signature must be 64 bytes")
    receipt["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    failures = validate_execution_authorization(
        receipt,
        expected_context=context,
        reviewer_profile=reviewer_profile,
        reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"execution authorization invalid: {failures}")
    return receipt


def validate_execution_authorization(
    value: Any,
    *,
    expected_context: dict[str, dict[str, Any]],
    reviewer_profile: dict[str, Any],
    reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
    current_time: datetime | None = None,
    require_current: bool = False,
) -> list[str]:
    receipt = value if isinstance(value, dict) else {}
    failures: list[str] = []
    _require(set(receipt) == RECEIPT_FIELDS, "authorization_fields_invalid", failures)
    _require(
        receipt.get("schema_version") == RECEIPT_SCHEMA,
        "authorization_schema_invalid",
        failures,
    )
    _require(
        _real_text(receipt.get("authorization_id")),
        "authorization_id_invalid",
        failures,
    )
    _require(
        receipt.get("decision") == DECISION, "authorization_decision_invalid", failures
    )
    issued = _timestamp(receipt.get("issued_at"))
    valid_from = _timestamp(receipt.get("valid_from"))
    valid_until = _timestamp(receipt.get("valid_until"))
    _require(
        issued is not None and valid_from == issued,
        "authorization_start_invalid",
        failures,
    )
    ttl = (
        (valid_until - valid_from).total_seconds() if valid_from and valid_until else 0
    )
    _require(1 <= ttl <= MAX_TTL_SECONDS, "authorization_ttl_invalid", failures)
    if require_current:
        now = (current_time or datetime.now(timezone.utc)).astimezone(timezone.utc)
        _require(
            bool(valid_from and valid_until and valid_from <= now < valid_until),
            "authorization_not_current",
            failures,
        )
    _validate_owner_authorization(_object(receipt.get("owner_authorization")), failures)
    for field in (
        "source_binding",
        "execution_scope",
        "cost_acknowledgement",
        "controls",
    ):
        _require(
            receipt.get(field) == expected_context.get(field),
            f"authorization_{field}_binding_invalid",
            failures,
        )
    _validate_context(receipt, failures)
    expected_reviewer = {
        **_object(reviewer_profile.get("reviewer")),
        "identity_profile_sha256": reviewer_profile_sha256,
    }
    _require(
        receipt.get("reviewer") == expected_reviewer,
        "authorization_reviewer_binding_invalid",
        failures,
    )
    _require(
        not validate_reviewer_identity_profile(reviewer_profile),
        "authorization_reviewer_profile_invalid",
        failures,
    )
    _require(
        receipt.get("implementation") == expected_implementation,
        "authorization_implementation_binding_invalid",
        failures,
    )
    _validate_implementation(_object(receipt.get("implementation")), failures)
    expected_boundary = {
        "single_use_authorization_issued": True,
        "provider_api_call_allowed_within_scope": True,
        "model_invocation_allowed_within_scope": True,
        "agent_execution_allowed_within_scope": True,
        "backend_fact_append_allowed": False,
        "ledger_append_allowed": False,
        "production_use_allowed": False,
        "automatic_rollout_allowed": False,
        "effectiveness_claim_allowed_before_closeout": False,
        "controlled_experiment_execution_ready": False,
    }
    _require(
        receipt.get("execution_boundary") == expected_boundary,
        "authorization_execution_boundary_invalid",
        failures,
    )
    _validate_signature(receipt, failures)
    return list(dict.fromkeys(failures))


def claim_execution_authorization(
    *,
    path: Path,
    receipt: dict[str, Any],
    receipt_artifact_sha256: str,
    gate_artifact_sha256: str,
    claimed_at: str,
) -> dict[str, Any]:
    claimed = _timestamp(claimed_at)
    valid_from = _timestamp(receipt.get("valid_from"))
    valid_until = _timestamp(receipt.get("valid_until"))
    if (
        not claimed
        or not valid_from
        or not valid_until
        or not valid_from <= claimed < valid_until
    ):
        raise ValueError("authorization cannot be claimed outside its validity window")
    expected = Path(
        str(_object(receipt.get("controls")).get("authorization_consumption_path", ""))
    ).resolve()
    if path.resolve() != expected:
        raise ValueError("authorization consumption path does not match signed receipt")
    value = {
        "schema_version": CONSUMPTION_SCHEMA,
        "state": "authorization_claimed_execution_must_close_out",
        "authorization_id": receipt["authorization_id"],
        "authorization_receipt_artifact_sha256": receipt_artifact_sha256,
        "authorization_gate_artifact_sha256": gate_artifact_sha256,
        "run_id": receipt["execution_scope"]["run_id"],
        "claimed_at": claimed.isoformat(),
        "single_use": True,
        "immutable": True,
        "claim_must_survive_execution_failure": True,
    }
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return value


def signature_payload(receipt: dict[str, Any]) -> bytes:
    body = {key: item for key, item in receipt.items() if key != "signature"}
    return json.dumps(
        body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _validate_context(receipt: dict[str, Any], failures: list[str]) -> None:
    source = _object(receipt.get("source_binding"))
    _require(
        len(source) == 8 and all(_sha256(value) for value in source.values()),
        "authorization_source_binding_invalid",
        failures,
    )
    scope = _object(receipt.get("execution_scope"))
    _require(_real_text(scope.get("run_id")), "authorization_run_id_invalid", failures)
    _require(
        scope.get("provider_id") == "openai_compatible",
        "authorization_provider_invalid",
        failures,
    )
    _require(
        _real_text(scope.get("provider_host")),
        "authorization_provider_host_invalid",
        failures,
    )
    _require(_real_text(scope.get("model_id")), "authorization_model_invalid", failures)
    _require(
        scope.get("temperature") == 0, "authorization_temperature_invalid", failures
    )
    _require(
        scope.get("participant_count") == 40 and scope.get("pair_count") == 20,
        "authorization_roster_count_invalid",
        failures,
    )
    _require(
        scope.get("minimum_completed_pairs") == 20,
        "authorization_minimum_pairs_invalid",
        failures,
    )
    _require(
        scope.get("same_stack_for_both_cohorts") is True,
        "authorization_stack_mismatch",
        failures,
    )
    _require(
        _sha256(scope.get("corpus_tasks_sha256"))
        and _sha256(scope.get("provider_base_url_sha256")),
        "authorization_scope_hash_invalid",
        failures,
    )
    cost = _object(receipt.get("cost_acknowledgement"))
    per = _object(cost.get("per_participant_ceiling"))
    aggregate = _object(cost.get("aggregate_ceiling"))
    _require(
        cost.get("currency") == "microunits", "authorization_currency_invalid", failures
    )
    _require(
        per == {"max_tasks": 12, "max_tokens": 20000, "max_cost_microunits": 100000},
        "authorization_per_participant_budget_invalid",
        failures,
    )
    _require(
        aggregate
        == {
            "authorized_task_executions": 320,
            "max_tokens": 800000,
            "max_cost_microunits": 4000000,
        },
        "authorization_aggregate_budget_invalid",
        failures,
    )
    for field in (
        "billable_provider_calls_acknowledged",
        "actual_tokens_and_cost_recording_required",
        "budget_overrun_fail_stop_required",
        "explicit_owner_acknowledgement",
    ):
        _require(cost.get(field) is True, f"authorization_{field}_required", failures)
    controls = _object(receipt.get("controls"))
    for field in (
        "single_use",
        "claim_must_use_create_exclusive",
        "claimed_failure_requires_new_authorization",
        "unclaimed_expiry_requires_new_authorization",
        "post_run_receipt_required",
        "operator_closeout_required",
    ):
        _require(
            controls.get(field) is True, f"authorization_{field}_required", failures
        )
    _require(
        controls.get("backend_fact_append_allowed") is False
        and controls.get("ledger_append_allowed") is False,
        "authorization_side_effect_boundary_invalid",
        failures,
    )
    for field in ("execution_root", "authorization_consumption_path"):
        _require(
            Path(str(controls.get(field, ""))).is_absolute(),
            f"authorization_{field}_invalid",
            failures,
        )


def _validate_owner_authorization(value: dict[str, Any], failures: list[str]) -> None:
    _require(
        set(value)
        == {
            "authorization_id",
            "authorization_statement_sha256",
            "source",
            "exact_cost_acknowledgement_confirmed",
            "single_use_and_failure_boundary_confirmed",
        },
        "authorization_owner_fields_invalid",
        failures,
    )
    _require(
        _real_text(value.get("authorization_id")),
        "authorization_owner_id_invalid",
        failures,
    )
    _require(
        _sha256(value.get("authorization_statement_sha256")),
        "authorization_owner_statement_hash_invalid",
        failures,
    )
    _require(
        value.get("source") == "interactive_owner_operator_approval",
        "authorization_owner_source_invalid",
        failures,
    )
    _require(
        value.get("exact_cost_acknowledgement_confirmed") is True
        and value.get("single_use_and_failure_boundary_confirmed") is True,
        "authorization_owner_acknowledgement_incomplete",
        failures,
    )


def _validate_implementation(value: dict[str, Any], failures: list[str]) -> None:
    _require(
        set(value)
        == {
            "agent_revision",
            "contract_source_sha256",
            "operation_source_sha256",
            "gate_source_sha256",
        },
        "authorization_implementation_fields_invalid",
        failures,
    )
    revision = str(value.get("agent_revision", "")).lower()
    _require(
        7 <= len(revision) <= 64
        and all(char in "0123456789abcdef" for char in revision),
        "authorization_agent_revision_invalid",
        failures,
    )
    for field in (
        "contract_source_sha256",
        "operation_source_sha256",
        "gate_source_sha256",
    ):
        _require(_sha256(value.get(field)), f"authorization_{field}_invalid", failures)


def _validate_signature(receipt: dict[str, Any], failures: list[str]) -> None:
    signature = _object(receipt.get("signature"))
    _require(
        set(signature) == SIGNATURE_FIELDS,
        "authorization_signature_fields_invalid",
        failures,
    )
    payload = signature_payload(receipt)
    _require(
        signature.get("algorithm") == "ed25519",
        "authorization_signature_algorithm_invalid",
        failures,
    )
    _require(
        signature.get("signed_payload_sha256") == hashlib.sha256(payload).hexdigest(),
        "authorization_signature_payload_hash_mismatch",
        failures,
    )
    try:
        VerifyKey(
            bytes.fromhex(
                str(_object(receipt.get("reviewer")).get("public_key_hex", ""))
            )
        ).verify(payload, bytes.fromhex(str(signature.get("signature_hex", ""))))
    except (BadSignatureError, ValueError):
        failures.append("authorization_signature_invalid")


def _timestamp(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _real_text(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and not any(
        token in text for token in ("synthetic", "fixture", "demo")
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require(condition: bool, code: str, failures: list[str]) -> None:
    if not condition and code not in failures:
        failures.append(code)
