"""Contracts for closing a claimed J1-D run that never started execution."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256


PREFLIGHT_SCHEMA = "j1-qualification-claimed-abort-closeout-preflight:v1"
JOURNAL_SCHEMA = "j1-qualification-claimed-abort-execution-journal:v1"
POST_RUN_SCHEMA = "j1-qualification-claimed-abort-post-run-receipt:v1"
EVALUATION_SCHEMA = "j1-qualification-claimed-abort-evaluation-report:v1"
CLOSEOUT_SCHEMA = "j1-qualification-claimed-abort-operator-closeout:v1"
GATE_SCHEMA = "j1-qualification-claimed-abort-closeout-gate:v1"
ABORT_REASON = "controlled_execution_orchestrator_not_present_in_claimed_revision"

PREFLIGHT_BOUNDARY = {
    "abort_closeout_preparation_only": True,
    "signed_closeout_created": False,
    "execution_root_created": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
}
CLOSEOUT_BOUNDARY = {
    "abort_closeout_only": True,
    "signed_closeout_created": True,
    "execution_root_created": False,
    "participant_container_started": False,
    "provider_credential_read": False,
    "provider_api_call_performed": False,
    "model_invocation_performed": False,
    "agent_execution_performed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
}


class CloseoutSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def owner_closeout_statement(
    *,
    claim_artifact_sha256: str,
    claim: dict[str, Any],
    entry_gate: dict[str, Any],
    frozen_bundle: dict[str, Any],
) -> str:
    scope = claim["execution_scope"]
    return (
        "I authorize exactly one signed claimed-before-execution abort closeout "
        f"for run {claim['run_id']}, consumed authorization "
        f"{claim['authorization_id']}, claim raw SHA-256 "
        f"{claim_artifact_sha256}, claim canonical SHA-256 "
        f"{claim['claim_sha256']}, execution-entry Gate canonical SHA-256 "
        f"{entry_gate['report_sha256']}, and frozen evaluation/closeout bundle "
        f"{frozen_bundle['frozen_bundle_sha256']}. I confirm that no participant "
        "container, provider credential, provider or model call, Agent execution, "
        "Backend Fact append, or Ledger append occurred after the claim. I authorize "
        f"record_aborted_run with 0 attempted and {scope['authorized_task_executions']} "
        "unattempted task executions, 0 tokens, and 0 USD microunits, using reason "
        f"{ABORT_REASON}. I acknowledge that the claim remains immutable and consumed, "
        "the run and partial results are not promotable, no effectiveness claim or "
        "maturity upgrade is authorized, and any future run requires a newly reviewed "
        "execution implementation, preflight, and single-use authorization."
    )


def build_closeout_preflight(
    *,
    checked_at: str,
    claim_ref: dict[str, str],
    claim: dict[str, Any],
    entry_gate_ref: dict[str, str],
    entry_gate: dict[str, Any],
    frozen_bundle_ref: dict[str, str],
    frozen_bundle: dict[str, Any],
    post_run_contract_ref: dict[str, str],
    post_run_contract: dict[str, Any],
    closeout_contract_ref: dict[str, str],
    closeout_contract: dict[str, Any],
    inventory_snapshot: dict[str, Any],
    execution_manifest: dict[str, Any],
    output_root: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    _validate_terminal_sources(
        claim=claim,
        entry_gate=entry_gate,
        frozen_bundle=frozen_bundle,
        post_run_contract=post_run_contract,
        closeout_contract=closeout_contract,
        inventory_snapshot=inventory_snapshot,
        execution_manifest=execution_manifest,
    )
    value = _closeout_preflight_value(
        checked_at=checked_at,
        claim_ref=claim_ref,
        claim=claim,
        entry_gate_ref=entry_gate_ref,
        entry_gate=entry_gate,
        frozen_bundle_ref=frozen_bundle_ref,
        frozen_bundle=frozen_bundle,
        post_run_contract_ref=post_run_contract_ref,
        closeout_contract_ref=closeout_contract_ref,
        inventory_snapshot=inventory_snapshot,
        execution_manifest=execution_manifest,
        output_root=output_root,
        implementation=implementation,
    )
    failures = validate_closeout_preflight(
        value,
        claim_ref=claim_ref,
        claim=claim,
        entry_gate_ref=entry_gate_ref,
        entry_gate=entry_gate,
        frozen_bundle_ref=frozen_bundle_ref,
        frozen_bundle=frozen_bundle,
        post_run_contract_ref=post_run_contract_ref,
        post_run_contract=post_run_contract,
        closeout_contract_ref=closeout_contract_ref,
        closeout_contract=closeout_contract,
        inventory_snapshot=inventory_snapshot,
        execution_manifest=execution_manifest,
        output_root=output_root,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"abort closeout preflight invalid: {failures}")
    return value


def validate_closeout_preflight(
    value: Any,
    *,
    claim_ref: dict[str, str],
    claim: dict[str, Any],
    entry_gate_ref: dict[str, str],
    entry_gate: dict[str, Any],
    frozen_bundle_ref: dict[str, str],
    frozen_bundle: dict[str, Any],
    post_run_contract_ref: dict[str, str],
    post_run_contract: dict[str, Any],
    closeout_contract_ref: dict[str, str],
    closeout_contract: dict[str, Any],
    inventory_snapshot: dict[str, Any],
    execution_manifest: dict[str, Any],
    output_root: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    preflight = value if isinstance(value, dict) else {}
    failures: list[str] = []
    try:
        _validate_terminal_sources(
            claim=claim,
            entry_gate=entry_gate,
            frozen_bundle=frozen_bundle,
            post_run_contract=post_run_contract,
            closeout_contract=closeout_contract,
            inventory_snapshot=inventory_snapshot,
            execution_manifest=execution_manifest,
        )
    except ValueError as error:
        failures.append(str(error))
    expected = _closeout_preflight_value(
        checked_at=preflight.get("checked_at", ""),
        claim_ref=claim_ref,
        claim=claim,
        entry_gate_ref=entry_gate_ref,
        entry_gate=entry_gate,
        frozen_bundle_ref=frozen_bundle_ref,
        frozen_bundle=frozen_bundle,
        post_run_contract_ref=post_run_contract_ref,
        closeout_contract_ref=closeout_contract_ref,
        inventory_snapshot=inventory_snapshot,
        execution_manifest=execution_manifest,
        output_root=output_root,
        implementation=expected_implementation,
    )
    failures.extend(_exact(value, expected, "abort_closeout_preflight"))
    _require(
        _rfc3339(preflight.get("checked_at")), "preflight_checked_at_invalid", failures
    )
    return list(dict.fromkeys(failures))


def build_abort_artifacts(
    *,
    closed_at: str,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    owner_authorization_id: str,
    owner_statement: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
    signer: CloseoutSigner,
) -> dict[str, dict[str, Any]]:
    expected_statement = preflight["owner_authorization"]["required_exact_statement"]
    if owner_statement != expected_statement:
        raise ValueError("abort closeout owner statement mismatch")
    if (
        hashlib.sha256(owner_statement.encode()).hexdigest()
        != preflight["owner_authorization"]["statement_sha256"]
    ):
        raise ValueError("abort closeout owner statement hash mismatch")
    if signer.public_key_hex != reviewer.get("public_key_hex"):
        raise ValueError("abort closeout signer/profile mismatch")
    journal = _execution_journal(
        closed_at=closed_at,
        preflight_ref=preflight_ref,
        preflight=preflight,
        implementation=implementation,
    )
    post_run = _post_run_receipt(
        closed_at=closed_at,
        preflight_ref=preflight_ref,
        preflight=preflight,
        journal=journal,
        implementation=implementation,
    )
    evaluation = _evaluation_report(
        closed_at=closed_at,
        preflight_ref=preflight_ref,
        preflight=preflight,
        post_run=post_run,
        implementation=implementation,
    )
    closeout = _closeout_receipt(
        closed_at=closed_at,
        preflight_ref=preflight_ref,
        preflight=preflight,
        journal=journal,
        post_run=post_run,
        evaluation=evaluation,
        owner_authorization_id=owner_authorization_id,
        reviewer=reviewer,
        reviewer_profile_sha256=reviewer_profile_sha256,
        implementation=implementation,
    )
    payload = _signature_payload(closeout)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("abort closeout signature must be 64 bytes")
    closeout["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    failures = validate_abort_artifacts(
        execution_journal=journal,
        post_run_receipt=post_run,
        evaluation_report=evaluation,
        operator_closeout_receipt=closeout,
        preflight_ref=preflight_ref,
        preflight=preflight,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"abort closeout artifacts invalid: {failures}")
    return {
        "execution_journal": journal,
        "post_run_receipt": post_run,
        "evaluation_report": evaluation,
        "operator_closeout_receipt": closeout,
    }


def validate_abort_artifacts(
    *,
    execution_journal: Any,
    post_run_receipt: Any,
    evaluation_report: Any,
    operator_closeout_receipt: Any,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    actual_closeout = (
        operator_closeout_receipt if isinstance(operator_closeout_receipt, dict) else {}
    )
    closed_at = actual_closeout.get("closed_at", "")
    expected_journal = _execution_journal(
        closed_at=closed_at,
        preflight_ref=preflight_ref,
        preflight=preflight,
        implementation=expected_implementation,
    )
    expected_post_run = _post_run_receipt(
        closed_at=closed_at,
        preflight_ref=preflight_ref,
        preflight=preflight,
        journal=expected_journal,
        implementation=expected_implementation,
    )
    expected_evaluation = _evaluation_report(
        closed_at=closed_at,
        preflight_ref=preflight_ref,
        preflight=preflight,
        post_run=expected_post_run,
        implementation=expected_implementation,
    )
    owner = actual_closeout.get("owner_authorization", {})
    expected_closeout = _closeout_receipt(
        closed_at=closed_at,
        preflight_ref=preflight_ref,
        preflight=preflight,
        journal=expected_journal,
        post_run=expected_post_run,
        evaluation=expected_evaluation,
        owner_authorization_id=owner.get("authorization_id", ""),
        reviewer=expected_reviewer,
        reviewer_profile_sha256=expected_reviewer_profile_sha256,
        implementation=expected_implementation,
    )
    failures = _exact(execution_journal, expected_journal, "execution_journal")
    failures.extend(_exact(post_run_receipt, expected_post_run, "post_run_receipt"))
    failures.extend(_exact(evaluation_report, expected_evaluation, "evaluation_report"))
    unsigned = {
        key: item for key, item in actual_closeout.items() if key != "signature"
    }
    failures.extend(_exact(unsigned, expected_closeout, "operator_closeout"))
    _require(_rfc3339(closed_at), "closeout_timestamp_invalid", failures)
    _require(
        owner.get("statement_sha256")
        == preflight.get("owner_authorization", {}).get("statement_sha256")
        and owner.get("scope") == "claimed_before_execution_abort_closeout",
        "closeout_owner_authorization_invalid",
        failures,
    )
    _validate_signature(actual_closeout, expected_reviewer, failures)
    return list(dict.fromkeys(failures))


def build_closeout_gate(
    *,
    checked_at: str,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    artifact_refs: dict[str, dict[str, str]],
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    value = _closeout_gate_value(
        checked_at=checked_at,
        preflight_ref=preflight_ref,
        preflight=preflight,
        artifact_refs=artifact_refs,
        artifacts=artifacts,
    )
    failures = validate_closeout_gate(
        value,
        preflight_ref=preflight_ref,
        preflight=preflight,
        artifact_refs=artifact_refs,
        artifacts=artifacts,
    )
    if failures:
        raise ValueError(f"abort closeout Gate invalid: {failures}")
    return value


def validate_closeout_gate(
    value: Any,
    *,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    artifact_refs: dict[str, dict[str, str]],
    artifacts: dict[str, dict[str, Any]],
) -> list[str]:
    gate = value if isinstance(value, dict) else {}
    expected = _closeout_gate_value(
        checked_at=gate.get("checked_at", ""),
        preflight_ref=preflight_ref,
        preflight=preflight,
        artifact_refs=artifact_refs,
        artifacts=artifacts,
    )
    failures = _exact(value, expected, "abort_closeout_gate")
    _require(
        _rfc3339(gate.get("checked_at")), "closeout_gate_timestamp_invalid", failures
    )
    return list(dict.fromkeys(failures))


def _terminal_observation(
    *,
    claim: dict[str, Any],
    inventory_snapshot: dict[str, Any],
    execution_manifest: dict[str, Any],
) -> dict[str, Any]:
    total = claim["execution_scope"]["authorized_task_executions"]
    return {
        "claim_state": claim["state"],
        "single_use_authorization_consumed": True,
        "execution_started": False,
        "execution_root_exists": False,
        "post_run_root_exists": False,
        "participant_count": claim["execution_scope"]["participant_count"],
        "matched_pair_count": claim["execution_scope"]["matched_pair_count"],
        "planned_task_executions": total,
        "attempted_task_executions": 0,
        "completed_task_executions": 0,
        "failed_task_executions": 0,
        "aborted_task_executions": 0,
        "unattempted_task_executions": total,
        "missing_task_reason": ABORT_REASON,
        "provider_reservation_count": 0,
        "provider_call_count": 0,
        "actual_tokens": 0,
        "actual_cost_microunits": 0,
        "container_count": inventory_snapshot["container_count"],
        "running_container_count": inventory_snapshot["running_count"],
        "container_set_sha256": inventory_snapshot["container_set_sha256"],
        "workspace_set_sha256": execution_manifest["workspace_set_sha256"],
        "input_file_count": execution_manifest["input_file_count"],
        "output_file_count": execution_manifest["output_file_count"],
        "workspace_symlink_count": execution_manifest["symlink_count"],
    }


def _execution_journal(
    *,
    closed_at: str,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": JOURNAL_SCHEMA,
        "run_id": preflight["run_id"],
        "terminal_state": "aborted_before_execution",
        "closed_at": closed_at,
        "source_preflight": copy.deepcopy(preflight_ref),
        "execution_events": [],
        "summary": copy.deepcopy(preflight["terminal_observation"]),
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(CLOSEOUT_BOUNDARY),
    }
    value["journal_sha256"] = canonical_sha256(value)
    return value


def _post_run_receipt(
    *,
    closed_at: str,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    journal: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    observation = preflight["terminal_observation"]
    value = {
        "schema_version": POST_RUN_SCHEMA,
        "run_id": preflight["run_id"],
        "terminal_state": "aborted_before_execution",
        "closed_at": closed_at,
        "source_binding": {
            "preflight": copy.deepcopy(preflight_ref),
            "execution_journal_sha256": journal["journal_sha256"],
            "frozen_post_run_contract": copy.deepcopy(
                preflight["source_binding"]["frozen_post_run_contract"]
            ),
        },
        "inventory_accounting": {
            "planned": observation["planned_task_executions"],
            "attempted": 0,
            "completed": 0,
            "failed": 0,
            "aborted_after_attempt": 0,
            "unattempted": observation["unattempted_task_executions"],
            "unattempted_reason": ABORT_REASON,
            "balanced": True,
        },
        "budget_reconciliation": {
            "reservation_count": 0,
            "terminal_reservation_count": 0,
            "provider_call_count": 0,
            "actual_tokens": 0,
            "actual_cost_microunits": 0,
            "overrun_detected": False,
            "reconciled": True,
        },
        "evidence_inventory": {
            "task_evidence_count": 0,
            "provider_receipt_count": 0,
            "participant_decision_receipt_count": 0,
            "event_trace_count": 0,
            "participant_outcome_count": 0,
            "partial_inventory_promotable": False,
        },
        "container_terminal_inventory": {
            "container_count": observation["container_count"],
            "running_count": observation["running_container_count"],
            "container_set_sha256": observation["container_set_sha256"],
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(CLOSEOUT_BOUNDARY),
    }
    value["receipt_sha256"] = canonical_sha256(value)
    return value


def _evaluation_report(
    *,
    closed_at: str,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    post_run: dict[str, Any],
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": EVALUATION_SCHEMA,
        "run_id": preflight["run_id"],
        "status": "not_evaluated_no_execution_data",
        "closed_at": closed_at,
        "source_binding": {
            "preflight": copy.deepcopy(preflight_ref),
            "post_run_receipt_sha256": post_run["receipt_sha256"],
            "frozen_evaluator": copy.deepcopy(
                preflight["source_binding"]["frozen_evaluation_closeout_bundle"]
            ),
        },
        "structural_pass": False,
        "effectiveness_evaluated": False,
        "effectiveness_verified": False,
        "valid_for_qualification": False,
        "all_20_pairs_present": False,
        "metrics": None,
        "confidence_interval": None,
        "reason": ABORT_REASON,
        "automatic_maturity_upgrade_allowed": False,
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(CLOSEOUT_BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    return value


def _closeout_receipt(
    *,
    closed_at: str,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    journal: dict[str, Any],
    post_run: dict[str, Any],
    evaluation: dict[str, Any],
    owner_authorization_id: str,
    reviewer: dict[str, Any],
    reviewer_profile_sha256: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    return {
        "schema_version": CLOSEOUT_SCHEMA,
        "run_id": preflight["run_id"],
        "authorization_id": preflight["authorization_id"],
        "decision": "record_aborted_run",
        "terminal_state": "aborted_before_execution",
        "closed_at": closed_at,
        "source_binding": {
            "preflight": copy.deepcopy(preflight_ref),
            "execution_journal_sha256": journal["journal_sha256"],
            "post_run_receipt_sha256": post_run["receipt_sha256"],
            "evaluation_report_sha256": evaluation["report_sha256"],
            "frozen_operator_closeout_contract": copy.deepcopy(
                preflight["source_binding"]["frozen_operator_closeout_contract"]
            ),
        },
        "owner_authorization": {
            "authorization_id": owner_authorization_id,
            "statement_sha256": preflight["owner_authorization"]["statement_sha256"],
            "source": "interactive_owner_operator_approval",
            "scope": "claimed_before_execution_abort_closeout",
        },
        "reviewer": {
            **copy.deepcopy(reviewer),
            "identity_profile_sha256": reviewer_profile_sha256,
        },
        "independence": {
            "conflicts_disclosed": True,
            "independent_from_execution": True,
            "human_review_completed": True,
            "operator_override_of_metrics_performed": False,
        },
        "claim_policy": {
            "authorization_reusable": False,
            "partial_result_promotable": False,
            "effectiveness_claim_authorized": False,
            "automatic_maturity_upgrade_allowed": False,
            "future_run_requires_new_authorization": True,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(CLOSEOUT_BOUNDARY),
    }


def _validate_terminal_sources(
    *,
    claim: dict[str, Any],
    entry_gate: dict[str, Any],
    frozen_bundle: dict[str, Any],
    post_run_contract: dict[str, Any],
    closeout_contract: dict[str, Any],
    inventory_snapshot: dict[str, Any],
    execution_manifest: dict[str, Any],
) -> None:
    observation = _terminal_observation(
        claim=claim,
        inventory_snapshot=inventory_snapshot,
        execution_manifest=execution_manifest,
    )
    checks = [
        claim.get("state") == "authorization_claimed_execution_must_close_out",
        claim.get("single_use") is True,
        entry_gate.get("passed") is True,
        entry_gate.get("state")
        == "atomic_claim_validated_bounded_execution_entry_allowed",
        entry_gate.get("claim", {}).get("canonical_sha256")
        == claim.get("claim_sha256"),
        frozen_bundle.get("status") == "operator_reviewed_frozen",
        frozen_bundle.get("frozen_bundle_sha256"),
        post_run_contract.get("status") == "operator_reviewed_frozen",
        post_run_contract.get("terminal_states", {}).get("aborted")
        == "post_run_aborted_operator_closeout_required",
        closeout_contract.get("status") == "operator_reviewed_frozen",
        "record_aborted_run"
        in closeout_contract.get("operator_decision", {}).get("allowed", []),
        closeout_contract.get("failure_policy", {}).get(
            "claimed_authorization_reusable"
        )
        is False,
        observation["container_count"] == 40,
        observation["running_container_count"] == 0,
        observation["input_file_count"] == 0,
        observation["output_file_count"] == 0,
        observation["workspace_symlink_count"] == 0,
        observation["planned_task_executions"] == 320,
    ]
    if not all(checks):
        raise ValueError("claimed-before-execution terminal source invalid")


def _signature_payload(value: dict[str, Any]) -> bytes:
    body = {key: item for key, item in value.items() if key != "signature"}
    return json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _validate_signature(
    value: dict[str, Any], reviewer: dict[str, Any], failures: list[str]
) -> None:
    signature = value.get("signature", {})
    payload = _signature_payload(value)
    try:
        raw = bytes.fromhex(signature.get("signature_hex", ""))
        VerifyKey(bytes.fromhex(reviewer.get("public_key_hex", ""))).verify(
            payload, raw
        )
    except (BadSignatureError, ValueError):
        failures.append("abort_closeout_signature_invalid")
        return
    _require(
        signature.get("algorithm") == "ed25519"
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest(),
        "abort_closeout_signature_metadata_invalid",
        failures,
    )


def _artifact_ref_valid(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"path", "sha256", "canonical_sha256"}
        and isinstance(value.get("path"), str)
        and _sha256(value.get("sha256"))
        and _sha256(value.get("canonical_sha256"))
    )


def _implementation_valid(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and _sha256(value.get("domain_source_sha256"))
        and _sha256(value.get("operation_source_sha256"))
        and isinstance(value.get("source_revision"), str)
        and len(value["source_revision"]) == 40
    )


def _exact(value: Any, expected: Any, prefix: str) -> list[str]:
    return [] if value == expected else [f"{prefix}_invalid"]


def _require(condition: bool, reason: str, failures: list[str]) -> None:
    if not condition:
        failures.append(reason)


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _rfc3339(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _closeout_preflight_value(
    *,
    checked_at: str,
    claim_ref: dict[str, str],
    claim: dict[str, Any],
    entry_gate_ref: dict[str, str],
    entry_gate: dict[str, Any],
    frozen_bundle_ref: dict[str, str],
    frozen_bundle: dict[str, Any],
    post_run_contract_ref: dict[str, str],
    closeout_contract_ref: dict[str, str],
    inventory_snapshot: dict[str, Any],
    execution_manifest: dict[str, Any],
    output_root: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    statement = owner_closeout_statement(
        claim_artifact_sha256=claim_ref["sha256"],
        claim=claim,
        entry_gate=entry_gate,
        frozen_bundle=frozen_bundle,
    )
    value = {
        "schema_version": PREFLIGHT_SCHEMA,
        "state": "claimed_before_execution_abort_closeout_owner_authorization_required",
        "checked_at": checked_at,
        "run_id": claim["run_id"],
        "authorization_id": claim["authorization_id"],
        "source_binding": {
            "claim": copy.deepcopy(claim_ref),
            "execution_entry_gate": copy.deepcopy(entry_gate_ref),
            "frozen_evaluation_closeout_bundle": copy.deepcopy(frozen_bundle_ref),
            "frozen_post_run_contract": copy.deepcopy(post_run_contract_ref),
            "frozen_operator_closeout_contract": copy.deepcopy(closeout_contract_ref),
        },
        "terminal_observation": _terminal_observation(
            claim=claim,
            inventory_snapshot=inventory_snapshot,
            execution_manifest=execution_manifest,
        ),
        "closeout_target": {
            "output_root": output_root,
            "operator_decision": "record_aborted_run",
            "terminal_state": "aborted_before_execution",
            "abort_reason": ABORT_REASON,
        },
        "owner_authorization": {
            "required": True,
            "scope": "claimed_before_execution_abort_closeout",
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        },
        "checks": {
            "atomic_claim_valid_and_consumed": True,
            "execution_entry_gate_valid": True,
            "frozen_closeout_contracts_bound": True,
            "forty_containers_stopped": True,
            "execution_workspace_empty": True,
            "execution_root_absent": True,
            "post_run_root_absent": True,
            "zero_provider_usage_observed": True,
            "no_effectiveness_evidence_present": True,
            "no_closeout_side_effect_performed": True,
        },
        "readiness": {
            "owner_closeout_authorization_required": True,
            "signed_abort_closeout_allowed_by_this_preflight": False,
            "future_authorization_allowed_after_signed_closeout": False,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(PREFLIGHT_BOUNDARY),
    }
    value["preflight_sha256"] = canonical_sha256(value)
    return value


def _closeout_gate_value(
    *,
    checked_at: str,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    artifact_refs: dict[str, dict[str, str]],
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    closeout = artifacts["operator_closeout_receipt"]
    value = {
        "schema_version": GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "claimed_before_execution_run_aborted_and_signed_closed_out",
        "checked_at": checked_at,
        "run_id": preflight["run_id"],
        "authorization_id": preflight["authorization_id"],
        "source_preflight": copy.deepcopy(preflight_ref),
        "artifacts": copy.deepcopy(artifact_refs),
        "terminal_summary": {
            "operator_decision": "record_aborted_run",
            "terminal_state": "aborted_before_execution",
            "attempted_task_executions": 0,
            "unattempted_task_executions": preflight["terminal_observation"][
                "unattempted_task_executions"
            ],
            "provider_calls": 0,
            "actual_tokens": 0,
            "actual_cost_microunits": 0,
            "containers_running": 0,
            "effectiveness_evaluated": False,
        },
        "checks": {
            "atomic_claim_remains_consumed": True,
            "signed_operator_closeout_valid": True,
            "all_terminal_artifacts_content_addressed": True,
            "zero_execution_and_provider_usage_accounted": True,
            "forty_containers_stopped": True,
            "future_run_requires_new_authorization": True,
            "no_effectiveness_claim_authorized": True,
        },
        "readiness": {
            "run_terminally_closed_out": True,
            "authorization_reusable": False,
            "future_execution_preflight_may_be_prepared": True,
        },
        "signature_binding": {
            "signed_payload_sha256": closeout["signature"]["signed_payload_sha256"],
            "reviewer_did": closeout["reviewer"]["did"],
        },
        "execution_boundary": copy.deepcopy(CLOSEOUT_BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    return value
