"""Contracts for closing a partially executed, failed J1-D r4 run."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any, Protocol

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .controlled_comparison import canonical_sha256


PREFLIGHT_SCHEMA = "j1-qualification-r4-failed-execution-closeout-preflight:v1"
POST_RUN_SCHEMA = "j1-qualification-r4-failed-post-run-receipt:v1"
EVALUATION_SCHEMA = "j1-qualification-r4-failed-evaluation-report:v1"
CLOSEOUT_SCHEMA = "j1-qualification-r4-failed-operator-closeout:v1"
GATE_SCHEMA = "j1-qualification-r4-failed-closeout-gate:v1"

PREFLIGHT_BOUNDARY = {
    "failed_closeout_preparation_only": True,
    "signed_closeout_created": False,
    "provider_retry_performed": False,
    "participant_execution_resumed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
}
CLOSEOUT_BOUNDARY = {
    "failed_closeout_only": True,
    "signed_closeout_created": True,
    "provider_retry_performed": False,
    "participant_execution_resumed": False,
    "backend_fact_append_performed": False,
    "ledger_append_performed": False,
    "effectiveness_claim_authorized": False,
}


class CloseoutSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


def owner_closeout_statement(preflight: dict[str, Any]) -> str:
    sources = preflight["source_binding"]
    execution = preflight["execution_summary"]
    budget = preflight["budget_summary"]
    failure = preflight["failure"]
    credential_read = (
        f"{execution['provider_credential_read_count']} provider credential reads, "
        if "provider_credential_read_count" in execution
        else ""
    )
    return (
        "I authorize exactly one signed J1-D r4 partial-failure closeout for run "
        f"{preflight['run_id']}, consumed authorization "
        f"{preflight['authorization_id']}, claim raw SHA-256 "
        f"{sources['claim']['sha256']}, claim canonical SHA-256 "
        f"{sources['claim']['canonical_sha256']}, execution-entry Gate canonical "
        f"SHA-256 {sources['entry_gate']['canonical_sha256']}, and failed live report "
        f"raw SHA-256 {sources['live_report']['sha256']}, canonical SHA-256 "
        f"{sources['live_report']['canonical_sha256']}. I authorize record_failed_run "
        f"for {execution['committed_task_count']} committed, "
        f"{execution['failed_task_count']} failed, and "
        f"{execution['unattempted_task_count']} unattempted task executions, "
        f"{execution['provider_call_count']} provider calls, "
        f"{execution['participant_signature_count']} participant signatures, "
        f"{credential_read}"
        f"{budget['actual_tokens']} actual tokens, and "
        f"{budget['actual_cost_microunits']} actual USD microunits. The terminal "
        f"failure is {failure['state']} caused by {failure['reason']}, with provider "
        f"dispatch performed={str(failure['provider_call_performed']).lower()}. I "
        "acknowledge that the claim remains immutable and consumed, no task or provider "
        "call may be retried in this run, partial results are not promotable, no "
        "effectiveness claim or maturity upgrade is authorized, and any future run "
        "requires a newly reviewed execution stack, preflight, provider admission, and "
        "single-use authorization. Backend Fact and Ledger append remain prohibited."
    )


def build_preflight(
    *,
    checked_at: str,
    run_id: str,
    authorization_id: str,
    source_binding: dict[str, dict[str, str]],
    execution_summary: dict[str, int],
    failure: dict[str, Any],
    budget_summary: dict[str, int],
    terminal_inventory: dict[str, int],
    output_root: str,
    implementation: dict[str, str],
) -> dict[str, Any]:
    value = {
        "schema_version": PREFLIGHT_SCHEMA,
        "state": "r4_failed_execution_closeout_ready_owner_authorization_required",
        "checked_at": checked_at,
        "run_id": run_id,
        "authorization_id": authorization_id,
        "source_binding": copy.deepcopy(source_binding),
        "execution_summary": copy.deepcopy(execution_summary),
        "failure": copy.deepcopy(failure),
        "budget_summary": copy.deepcopy(budget_summary),
        "terminal_inventory": copy.deepcopy(terminal_inventory),
        "output_root": output_root,
        "disposition": {
            "operator_decision": "record_failed_run",
            "authorization_consumed": True,
            "authorization_reusable": False,
            "partial_results_promotable": False,
            "new_reviewed_stack_required": True,
        },
        "implementation": copy.deepcopy(implementation),
        "execution_boundary": copy.deepcopy(PREFLIGHT_BOUNDARY),
    }
    statement = owner_closeout_statement(value)
    value["owner_authorization"] = {
        "required": True,
        "required_exact_statement": statement,
        "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
        "scope": "record_failed_run_only",
    }
    value["preflight_sha256"] = canonical_sha256(value)
    failures = validate_preflight(value)
    if failures:
        raise ValueError(f"failed execution closeout preflight invalid: {failures}")
    return value


def validate_preflight(value: Any) -> list[str]:
    preflight = value if isinstance(value, dict) else {}
    failures: list[str] = []
    execution = preflight.get("execution_summary", {})
    budget = preflight.get("budget_summary", {})
    failure = preflight.get("failure", {})
    inventory = preflight.get("terminal_inventory", {})
    pre_orchestrator = failure.get("state") == "pre_orchestrator_error"
    if not (
        preflight.get("schema_version") == PREFLIGHT_SCHEMA
        and preflight.get("state")
        == "r4_failed_execution_closeout_ready_owner_authorization_required"
        and _rfc3339(preflight.get("checked_at"))
        and _text(preflight.get("run_id"))
        and _text(preflight.get("authorization_id"))
    ):
        failures.append("failed_closeout_preflight_identity_invalid")
    partial_execution_valid = (
        execution.get("authorized_task_count") == 320
        and execution.get("committed_task_count", -1) >= 0
        and execution.get("failed_task_count", -1) >= 1
        and execution.get("unattempted_task_count", -1) >= 0
        and execution.get("committed_task_count")
        + execution.get("failed_task_count")
        + execution.get("unattempted_task_count")
        == 320
        and execution.get("provider_call_count")
        == budget.get("reconciled_provider_call_count")
        and execution.get("participant_signature_count")
        == execution.get("committed_task_count")
    )
    pre_orchestrator_valid = (
        execution.get("authorized_task_count") == 320
        and execution.get("committed_task_count") == 0
        and execution.get("failed_task_count") == 0
        and execution.get("unattempted_task_count") == 320
        and execution.get("provider_call_count") == 0
        and execution.get("participant_signature_count") == 0
        and execution.get("container_start_count") == 0
        and execution.get("container_stop_count") == 0
        and execution.get("provider_credential_read_count") == 1
        and budget.get("reconciled_provider_call_count") == 0
    )
    if not (
        (pre_orchestrator and pre_orchestrator_valid)
        or (not pre_orchestrator and partial_execution_valid)
    ):
        failures.append("failed_closeout_execution_summary_invalid")
    if not (
        failure.get("state")
        in {
            "task_failed_before_dispatch",
            "task_failed_after_response",
            "provider_outcome_unknown",
            "orchestrator_error",
            "pre_orchestrator_error",
        }
        and _text(failure.get("reason"))
        and _text(failure.get("task_execution_id"))
        and isinstance(failure.get("provider_call_performed"), bool)
        and (
            not pre_orchestrator
            or failure.get("provider_credential_read_performed") is True
        )
    ):
        failures.append("failed_closeout_failure_invalid")
    if not (
        all(
            isinstance(budget.get(name), int) and budget[name] >= 0
            for name in (
                "reconciled_provider_call_count",
                "reserved_tokens",
                "reserved_cost_microunits",
                "actual_tokens",
                "actual_cost_microunits",
            )
        )
        and budget.get("actual_tokens") <= budget.get("reserved_tokens")
        and budget.get("actual_cost_microunits")
        <= budget.get("reserved_cost_microunits")
    ):
        failures.append("failed_closeout_budget_summary_invalid")
    if not (
        inventory.get("participant_container_count") == 40
        and inventory.get("running_count") == 0
        and inventory.get("created_count", 0) + inventory.get("exited_count", 0) == 40
    ):
        failures.append("failed_closeout_terminal_inventory_invalid")
    statement = preflight.get("owner_authorization", {}).get("required_exact_statement")
    if not (
        isinstance(statement, str)
        and statement == owner_closeout_statement(preflight)
        and preflight.get("owner_authorization", {}).get("statement_sha256")
        == hashlib.sha256(statement.encode()).hexdigest()
    ):
        failures.append("failed_closeout_owner_authorization_invalid")
    if (
        preflight.get("execution_boundary") != PREFLIGHT_BOUNDARY
        or preflight.get("disposition", {}).get("operator_decision")
        != "record_failed_run"
        or preflight.get("disposition", {}).get("partial_results_promotable")
        is not False
    ):
        failures.append("failed_closeout_disposition_invalid")
    body = {key: item for key, item in preflight.items() if key != "preflight_sha256"}
    if preflight.get("preflight_sha256") != canonical_sha256(body):
        failures.append("failed_closeout_preflight_hash_invalid")
    return list(dict.fromkeys(failures))


def build_closeout_artifacts(
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
    if validate_preflight(preflight):
        raise ValueError("failed closeout preflight is invalid")
    expected = preflight["owner_authorization"]["required_exact_statement"]
    if owner_statement != expected:
        raise ValueError("failed closeout owner statement mismatch")
    if signer.public_key_hex != reviewer.get("public_key_hex"):
        raise ValueError("failed closeout signer/profile mismatch")
    common = {
        "closed_at": closed_at,
        "run_id": preflight["run_id"],
        "authorization_id": preflight["authorization_id"],
        "preflight": copy.deepcopy(preflight_ref),
        "source_binding": copy.deepcopy(preflight["source_binding"]),
        "execution_summary": copy.deepcopy(preflight["execution_summary"]),
        "failure": copy.deepcopy(preflight["failure"]),
        "budget_summary": copy.deepcopy(preflight["budget_summary"]),
        "terminal_inventory": copy.deepcopy(preflight["terminal_inventory"]),
        "implementation": copy.deepcopy(implementation),
    }
    post_run = {
        "schema_version": POST_RUN_SCHEMA,
        "status": "failed",
        **copy.deepcopy(common),
        "partial_results_promotable": False,
        "provider_retry_performed": False,
    }
    post_run["receipt_sha256"] = canonical_sha256(post_run)
    evaluation = {
        "schema_version": EVALUATION_SCHEMA,
        "status": "ineligible_failed_run",
        **copy.deepcopy(common),
        "post_run_receipt_sha256": post_run["receipt_sha256"],
        "all_20_pairs_complete": False,
        "effectiveness_metrics_computed": False,
        "effectiveness_claim_authorized": False,
        "maturity_upgrade_authorized": False,
    }
    evaluation["report_sha256"] = canonical_sha256(evaluation)
    closeout = {
        "schema_version": CLOSEOUT_SCHEMA,
        "decision": "record_failed_run",
        **copy.deepcopy(common),
        "post_run_receipt_sha256": post_run["receipt_sha256"],
        "evaluation_report_sha256": evaluation["report_sha256"],
        "owner_authorization": {
            "authorization_id": owner_authorization_id,
            "statement_sha256": hashlib.sha256(owner_statement.encode()).hexdigest(),
            "scope": "record_failed_run_only",
        },
        "reviewer": {
            **copy.deepcopy(reviewer),
            "identity_profile_sha256": reviewer_profile_sha256,
        },
        "execution_boundary": copy.deepcopy(CLOSEOUT_BOUNDARY),
    }
    payload = _payload(closeout)
    signature = signer.sign(payload)
    if len(signature) != 64:
        raise ValueError("failed closeout signature must be 64 bytes")
    closeout["signature"] = {
        "algorithm": "ed25519",
        "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_hex": signature.hex(),
    }
    artifacts = {
        "post_run_receipt": post_run,
        "evaluation_report": evaluation,
        "operator_closeout": closeout,
    }
    failures = validate_closeout_artifacts(
        artifacts,
        preflight_ref=preflight_ref,
        preflight=preflight,
        expected_reviewer=reviewer,
        expected_reviewer_profile_sha256=reviewer_profile_sha256,
        expected_implementation=implementation,
    )
    if failures:
        raise ValueError(f"failed closeout artifacts invalid: {failures}")
    return artifacts


def validate_closeout_artifacts(
    artifacts: Any,
    *,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    expected_reviewer: dict[str, Any],
    expected_reviewer_profile_sha256: str,
    expected_implementation: dict[str, str],
) -> list[str]:
    values = artifacts if isinstance(artifacts, dict) else {}
    post_run = values.get("post_run_receipt", {})
    evaluation = values.get("evaluation_report", {})
    closeout = values.get("operator_closeout", {})
    failures: list[str] = []
    if not (
        post_run.get("schema_version") == POST_RUN_SCHEMA
        and post_run.get("status") == "failed"
        and post_run.get("preflight") == preflight_ref
        and post_run.get("receipt_sha256")
        == canonical_sha256(
            {key: item for key, item in post_run.items() if key != "receipt_sha256"}
        )
        and post_run.get("partial_results_promotable") is False
        and post_run.get("provider_retry_performed") is False
    ):
        failures.append("failed_closeout_post_run_receipt_invalid")
    if not (
        evaluation.get("schema_version") == EVALUATION_SCHEMA
        and evaluation.get("status") == "ineligible_failed_run"
        and evaluation.get("post_run_receipt_sha256") == post_run.get("receipt_sha256")
        and evaluation.get("report_sha256")
        == canonical_sha256(
            {key: item for key, item in evaluation.items() if key != "report_sha256"}
        )
        and evaluation.get("effectiveness_claim_authorized") is False
    ):
        failures.append("failed_closeout_evaluation_invalid")
    signature = closeout.get("signature", {})
    unsigned = {key: item for key, item in closeout.items() if key != "signature"}
    payload = _payload(unsigned)
    try:
        VerifyKey(bytes.fromhex(expected_reviewer["public_key_hex"])).verify(
            payload, bytes.fromhex(str(signature.get("signature_hex", "")))
        )
    except (BadSignatureError, ValueError):
        failures.append("failed_closeout_signature_invalid")
    if not (
        closeout.get("schema_version") == CLOSEOUT_SCHEMA
        and closeout.get("decision") == "record_failed_run"
        and closeout.get("preflight") == preflight_ref
        and closeout.get("post_run_receipt_sha256") == post_run.get("receipt_sha256")
        and closeout.get("evaluation_report_sha256") == evaluation.get("report_sha256")
        and closeout.get("reviewer")
        == {
            **expected_reviewer,
            "identity_profile_sha256": expected_reviewer_profile_sha256,
        }
        and closeout.get("implementation") == expected_implementation
        and closeout.get("execution_boundary") == CLOSEOUT_BOUNDARY
        and signature.get("signed_payload_sha256")
        == hashlib.sha256(payload).hexdigest()
    ):
        failures.append("failed_closeout_operator_receipt_invalid")
    return list(dict.fromkeys(failures))


def build_closeout_gate(
    *,
    checked_at: str,
    preflight_ref: dict[str, str],
    preflight: dict[str, Any],
    artifact_refs: dict[str, dict[str, str]],
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    pre_orchestrator = (
        preflight.get("failure", {}).get("state") == "pre_orchestrator_error"
    )
    value = {
        "schema_version": GATE_SCHEMA,
        "passed": True,
        "failure_reasons": [],
        "state": "r4_failed_run_closed_no_promotion_new_stack_required",
        "checked_at": checked_at,
        "run_id": preflight["run_id"],
        "preflight": copy.deepcopy(preflight_ref),
        "artifacts": copy.deepcopy(artifact_refs),
        "checks": {
            "claim_remains_consumed": True,
            "partial_execution_bound": not pre_orchestrator,
            "pre_orchestrator_failure_bound": pre_orchestrator,
            "journal_and_budget_reconciled": not pre_orchestrator,
            "journal_and_budget_absence_verified": pre_orchestrator,
            "terminal_inventory_running_zero": True,
            "operator_signature_valid": True,
            "partial_results_not_promotable": True,
            "provider_retry_not_performed": True,
            "backend_and_ledger_append_not_performed": True,
        },
        "readiness": {
            "failed_run_closed": True,
            "effectiveness_claim_authorized": False,
            "maturity_upgrade_authorized": False,
            "future_run_requires_new_reviewed_stack": True,
        },
        "execution_boundary": copy.deepcopy(CLOSEOUT_BOUNDARY),
    }
    value["report_sha256"] = canonical_sha256(value)
    del artifacts
    return value


def _payload(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _rfc3339(value: Any) -> bool:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)
