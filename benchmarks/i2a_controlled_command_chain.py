"""Run I.2-A controlled external Agent command protocol smoke.

The chain consumes an I.2 gate request and writes bounded, hash-bound evidence
for operator review, external Agent registration, scoped command authorization,
isolation preflight, acceptance, read-only execution, rollback/abort, and final
operator reconciliation. It intentionally does not authorize real external task
commanding, source writes, Git operations, deployment, runtime mutation, or
production transition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CHAIN_SCHEMA = "i2a-controlled-command-chain:v1"
OPERATOR_REVIEW_SCHEMA = "i2-operator-review:v1"
REGISTRATION_SCHEMA = "i2a-external-agent-registration-receipt:v1"
AUTHORIZATION_SCHEMA = "i2a-scoped-command-authorization:v1"
ACCEPTANCE_SCHEMA = "i2a-external-agent-acceptance-receipt:v1"
PREFLIGHT_SCHEMA = "i2a-isolation-preflight:v1"
EXECUTION_SCHEMA = "i2a-command-execution-receipt:v1"
ROLLBACK_SCHEMA = "i2a-rollback-or-abort-receipt:v1"
RECONCILIATION_SCHEMA = "i2a-operator-reconciliation:v1"

DEFAULT_OBJECTIVE = (
    "Read the scoped command envelope and return a boundary attestation. "
    "Do not modify source, Git, runtime state, network services, or production."
)
FORBIDDEN_ACTIONS = [
    "network_access",
    "source_tree_write",
    "git_write",
    "git_push",
    "external_system_write",
    "runtime_state_mutation",
    "credential_exfiltration",
    "deploy",
    "production_transition",
]
ALLOWED_ACTIONS = [
    "read_source_artifact_refs",
    "read_command_envelope",
    "write_receipt_under_isolation_workspace",
]


def run_chain(
    *,
    i2_request_path: Path,
    output_root: Path,
    operator_id: str = "operator-cc",
    executor_alias: str = "i2a-controlled-external-agent",
    objective: str = DEFAULT_OBJECTIVE,
    expiry_minutes: int = 30,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "operator_review": output_root / "i2_operator_review.json",
        "registration": output_root / "i2a_external_agent_registration_receipt.json",
        "authorization": output_root / "i2a_scoped_command_authorization.json",
        "acceptance": output_root / "i2a_external_agent_acceptance_receipt.json",
        "preflight": output_root / "i2a_isolation_preflight.json",
        "execution": output_root / "i2a_command_execution_receipt.json",
        "rollback_or_abort": output_root / "i2a_rollback_or_abort_receipt.json",
        "reconciliation": output_root / "i2a_operator_reconciliation.json",
        "summary": output_root / "i2a_chain_summary.json",
    }

    review = write_operator_review(
        i2_request_path=i2_request_path,
        output=artifacts["operator_review"],
        operator_id=operator_id,
    )
    registration = write_registration_receipt(
        operator_review_path=artifacts["operator_review"],
        output=artifacts["registration"],
        executor_alias=executor_alias,
    )
    authorization = write_scoped_authorization(
        operator_review_path=artifacts["operator_review"],
        registration_path=artifacts["registration"],
        output=artifacts["authorization"],
        objective=objective,
        expiry_minutes=expiry_minutes,
    )
    acceptance = write_acceptance_receipt(
        registration_path=artifacts["registration"],
        authorization_path=artifacts["authorization"],
        output=artifacts["acceptance"],
    )
    preflight = write_isolation_preflight(
        authorization_path=artifacts["authorization"],
        acceptance_path=artifacts["acceptance"],
        output=artifacts["preflight"],
        workspace=output_root / "isolation_workspace",
    )
    execution = write_execution_receipt(
        authorization_path=artifacts["authorization"],
        acceptance_path=artifacts["acceptance"],
        preflight_path=artifacts["preflight"],
        output=artifacts["execution"],
    )
    rollback = write_rollback_or_abort_receipt(
        execution_path=artifacts["execution"],
        preflight_path=artifacts["preflight"],
        output=artifacts["rollback_or_abort"],
    )
    reconciliation = write_reconciliation(
        operator_review_path=artifacts["operator_review"],
        registration_path=artifacts["registration"],
        authorization_path=artifacts["authorization"],
        acceptance_path=artifacts["acceptance"],
        preflight_path=artifacts["preflight"],
        execution_path=artifacts["execution"],
        rollback_or_abort_path=artifacts["rollback_or_abort"],
        output=artifacts["reconciliation"],
    )

    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": all(item.get("passed") is True for item in (review, registration, authorization, acceptance, preflight, execution, rollback, reconciliation)),
        "failure_reasons": _collect_failures(review, registration, authorization, acceptance, preflight, execution, rollback, reconciliation),
        "request_id": _object(review.get("operator_review")).get("request_id"),
        "command_id": _object(authorization.get("command")).get("command_id"),
        "executor_alias": executor_alias,
        "artifacts": {name: _artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "readiness": {
            "state": "i2a_protocol_smoke_passed" if reconciliation.get("passed") is True else "blocked_i2a_protocol_smoke",
            "i2a_protocol_smoke_complete": reconciliation.get("passed") is True,
            "real_external_agent_command_allowed": False,
            "real_task_command_allowed": False,
            "operator_discussion_required_for_i2b": reconciliation.get("passed") is True,
        },
        "boundary": _hard_boundary(command_request_recording_allowed=True),
        "non_claims": [
            "i2a_protocol_smoke_is_not_real_external_task_commanding",
            "i2a_execution_receipt_is_controlled_read_only_adapter_output",
            "i2a_does_not_authorize_i2b_or_production",
        ],
    }
    _write_json(artifacts["summary"], summary)
    return summary


def write_operator_review(*, i2_request_path: Path, output: Path, operator_id: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    request = _read_json(i2_request_path)
    request_body = _object(request.get("request"))
    readiness = _object(request.get("readiness"))
    boundary = _object(request.get("boundary"))

    _check(checks, failures, "i2_request_passed", request.get("schema_version") == "i2-external-command-gate-request:v1" and request.get("passed") is True)
    _check(checks, failures, "request_ready_for_operator_review", readiness.get("i2_gate_requested") is True and readiness.get("operator_authorization_required") is True)
    _check(checks, failures, "request_does_not_already_allow_execution", readiness.get("i2_execution_allowed") is False and boundary.get("external_agent_command_allowed") is False)
    _check(checks, failures, "future_evidence_requirements_present", set(request_body.get("required_future_evidence", [])) >= {
        "external_agent_registration_receipt",
        "scoped_command_authorization_request",
        "external_agent_acceptance_receipt",
        "isolation_policy_preflight",
        "command_execution_receipt",
        "rollback_or_abort_receipt",
        "operator_reconciliation",
    })

    passed = _passed(checks, failures)
    report = {
        "schema_version": OPERATOR_REVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"i2_request": _artifact_ref(i2_request_path)},
        "operator_review": {
            "operator_id": operator_id,
            "decision": "approve_i2a_read_only_protocol_smoke" if passed else "blocked_i2a_operator_review",
            "request_id": request_body.get("request_id"),
            "approved_scope": "i2a_read_only_single_use_isolated_command_protocol_smoke" if passed else None,
            "reason": "I.1 passed; approve one low-risk, read-only, one-time I.2-A protocol smoke without external side effects." if passed else "I.2 request did not satisfy operator review prerequisites.",
        },
        "readiness": {
            "state": "i2a_registration_and_authorization_ready" if passed else "blocked_i2a_operator_review",
            "i2a_operator_review_complete": passed,
            "i2a_registration_ready": passed,
            "i2_execution_allowed": False,
        },
        "boundary": _hard_boundary(operator_review_recording_allowed=True),
        "non_claims": ["operator_review_does_not_dispatch_external_agent", "operator_review_does_not_unlock_real_task_commanding"],
    }
    _write_json(output, report)
    return report


def write_registration_receipt(*, operator_review_path: Path, output: Path, executor_alias: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    review = _read_json(operator_review_path)
    review_body = _object(review.get("operator_review"))
    did = "did:civ:i2a:" + _sha256_text(executor_alias)[:32]

    _check(checks, failures, "operator_review_passed", review.get("schema_version") == OPERATOR_REVIEW_SCHEMA and review.get("passed") is True)
    _check(checks, failures, "approved_scope_is_i2a_read_only", review_body.get("approved_scope") == "i2a_read_only_single_use_isolated_command_protocol_smoke")
    _check(checks, failures, "executor_alias_present", bool(executor_alias))

    passed = _passed(checks, failures)
    report = {
        "schema_version": REGISTRATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"operator_review": _artifact_ref(operator_review_path)},
        "external_agent": {
            "agent_alias": executor_alias,
            "agent_did": did,
            "agent_kind": "controlled_external_agent_adapter",
            "provider_family": "local-controlled",
            "runtime_family": "receipt-adapter",
            "capabilities": ["accept_scoped_read_only_command", "write_execution_receipt", "attest_isolation_boundary"],
            "registration_scope": "i2a_read_only_controlled_command_only",
        },
        "readiness": {
            "state": "i2a_external_agent_registered" if passed else "blocked_i2a_registration",
            "external_agent_registration_receipt_present": passed,
            "direct_runtime_mutation_allowed": False,
            "real_task_command_allowed": False,
        },
        "boundary": _hard_boundary(registration_recording_allowed=True),
    }
    _write_json(output, report)
    return report


def write_scoped_authorization(
    *,
    operator_review_path: Path,
    registration_path: Path,
    output: Path,
    objective: str,
    expiry_minutes: int,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    review = _read_json(operator_review_path)
    registration = _read_json(registration_path)
    agent = _object(registration.get("external_agent"))

    _check(checks, failures, "operator_review_passed", review.get("passed") is True)
    _check(checks, failures, "registration_passed", registration.get("schema_version") == REGISTRATION_SCHEMA and registration.get("passed") is True)
    _check(checks, failures, "objective_is_nonempty", bool(objective.strip()))
    _check(checks, failures, "expiry_within_limit", 1 <= expiry_minutes <= 60)

    now = datetime.now(timezone.utc)
    nonce_seed = json.dumps({"review": _artifact_ref(operator_review_path), "registration": _artifact_ref(registration_path), "objective": objective}, sort_keys=True)
    nonce = _sha256_text(nonce_seed)[:24]
    command_id = "i2a-command:" + _sha256_text(nonce_seed)[:20]
    passed = _passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "operator_review": _artifact_ref(operator_review_path),
            "registration": _artifact_ref(registration_path),
        },
        "command": {
            "command_id": command_id,
            "command_class": "read_only_boundary_attestation",
            "objective": objective,
            "executor_alias": agent.get("agent_alias"),
            "executor_did": agent.get("agent_did"),
            "single_use_nonce": nonce,
            "single_use": True,
            "created_at": _iso(now),
            "expires_at": _iso(now + timedelta(minutes=expiry_minutes)),
            "allowed_actions": ALLOWED_ACTIONS,
            "forbidden_actions": FORBIDDEN_ACTIONS,
            "max_duration_seconds": 300,
            "max_output_bytes": 65536,
            "receipt_sink": "run_root_only",
            "rollback_plan": "read_only_command_no_state_change_delete_run_root_if_needed",
        },
        "readiness": {
            "state": "i2a_scoped_command_authorized_for_preflight" if passed else "blocked_i2a_authorization",
            "scoped_command_authorization_request_present": passed,
            "single_use_command_ready_for_preflight": passed,
            "command_execution_allowed_before_preflight": False,
        },
        "boundary": _hard_boundary(scoped_command_authorization_recording_allowed=True),
    }
    _write_json(output, report)
    return report


def write_acceptance_receipt(*, registration_path: Path, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    registration = _read_json(registration_path)
    authorization = _read_json(authorization_path)
    agent = _object(registration.get("external_agent"))
    command = _object(authorization.get("command"))

    _check(checks, failures, "registration_passed", registration.get("passed") is True)
    _check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    _check(checks, failures, "executor_matches_registration", command.get("executor_alias") == agent.get("agent_alias") and command.get("executor_did") == agent.get("agent_did"))
    _check(checks, failures, "forbidden_actions_present", set(command.get("forbidden_actions", [])) == set(FORBIDDEN_ACTIONS))

    passed = _passed(checks, failures)
    report = {
        "schema_version": ACCEPTANCE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"registration": _artifact_ref(registration_path), "authorization": _artifact_ref(authorization_path)},
        "acceptance": {
            "accepted": passed,
            "accepted_command_id": command.get("command_id"),
            "executor_alias": agent.get("agent_alias"),
            "scope_hash": _sha256_json(command),
            "attestations": {
                "will_not_use_network": True,
                "will_not_write_source_tree": True,
                "will_not_use_git": True,
                "will_not_mutate_runtime_state": True,
                "will_write_only_receipts_under_isolation_workspace": True,
            },
        },
        "readiness": {"state": "i2a_external_agent_accepted_scope" if passed else "blocked_i2a_acceptance", "external_agent_acceptance_receipt_present": passed},
        "boundary": _hard_boundary(acceptance_recording_allowed=True),
    }
    _write_json(output, report)
    return report


def write_isolation_preflight(*, authorization_path: Path, acceptance_path: Path, output: Path, workspace: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = _read_json(authorization_path)
    acceptance = _read_json(acceptance_path)
    command = _object(authorization.get("command"))
    accepted = _object(acceptance.get("acceptance"))

    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "README.txt").write_text("I.2-A isolated read-only receipt workspace.\n", encoding="utf-8")

    _check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    _check(checks, failures, "acceptance_passed", acceptance.get("schema_version") == ACCEPTANCE_SCHEMA and acceptance.get("passed") is True)
    _check(checks, failures, "command_id_matches_acceptance", command.get("command_id") == accepted.get("accepted_command_id"))
    _check(checks, failures, "single_use_nonce_present", bool(command.get("single_use_nonce")) and command.get("single_use") is True)
    _check(checks, failures, "network_forbidden", "network_access" in command.get("forbidden_actions", []))
    _check(checks, failures, "git_write_forbidden", "git_write" in command.get("forbidden_actions", []) and "git_push" in command.get("forbidden_actions", []))
    _check(checks, failures, "source_write_forbidden", "source_tree_write" in command.get("forbidden_actions", []))
    _check(checks, failures, "production_forbidden", "production_transition" in command.get("forbidden_actions", []))
    _check(checks, failures, "workspace_created", workspace.is_dir())

    passed = _passed(checks, failures)
    report = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": _artifact_ref(authorization_path), "acceptance": _artifact_ref(acceptance_path)},
        "isolation": {
            "profile": "i2a_read_only_receipt_workspace",
            "workspace": str(workspace.resolve()),
            "allowed_write_roots": [str(workspace.resolve())],
            "network_allowed": False,
            "git_allowed": False,
            "source_tree_write_allowed": False,
            "runtime_state_mutation_allowed": False,
            "production_credential_allowed": False,
            "kill_switch": "delete_workspace_and_mark_command_aborted",
        },
        "readiness": {"state": "i2a_isolation_preflight_passed" if passed else "blocked_i2a_isolation_preflight", "command_execution_allowed_in_isolation": passed},
        "boundary": _hard_boundary(isolation_preflight_recording_allowed=True, isolated_command_execution_allowed=passed),
    }
    _write_json(output, report)
    return report


def write_execution_receipt(*, authorization_path: Path, acceptance_path: Path, preflight_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = _read_json(authorization_path)
    acceptance = _read_json(acceptance_path)
    preflight = _read_json(preflight_path)
    command = _object(authorization.get("command"))
    workspace = Path(str(_object(preflight.get("isolation")).get("workspace") or ""))
    response_path = workspace / "external_agent_response.json"

    _check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    _check(checks, failures, "acceptance_passed", acceptance.get("passed") is True)
    _check(checks, failures, "preflight_passed", preflight.get("schema_version") == PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    _check(checks, failures, "workspace_exists", workspace.is_dir())
    _check(checks, failures, "command_is_read_only", command.get("command_class") == "read_only_boundary_attestation")

    if _passed(checks, failures):
        response = {
            "schema_version": "i2a-controlled-external-agent-response:v1",
            "command_id": command.get("command_id"),
            "executor_alias": command.get("executor_alias"),
            "verdict": "accepted_scope_executed_read_only",
            "summary": "Controlled adapter inspected the command envelope and wrote this read-only attestation under the isolation workspace.",
            "boundary_attestation": {
                "network_used": False,
                "source_tree_modified": False,
                "git_used": False,
                "runtime_state_mutated": False,
                "production_touched": False,
            },
        }
        _write_json(response_path, response)
    _check(checks, failures, "response_written_under_workspace", response_path.is_file() and response_path.parent.resolve() == workspace.resolve())

    passed = _passed(checks, failures)
    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": _artifact_ref(authorization_path), "acceptance": _artifact_ref(acceptance_path), "preflight": _artifact_ref(preflight_path)},
        "execution": {
            "execution_kind": "controlled_read_only_receipt_write",
            "command_id": command.get("command_id"),
            "command_consumed": passed,
            "single_use_nonce": command.get("single_use_nonce"),
            "output_artifact": _artifact_ref(response_path) if response_path.is_file() else None,
            "external_side_effect_observed": False,
        },
        "readiness": {"state": "i2a_command_execution_receipt_present" if passed else "blocked_i2a_execution", "command_execution_receipt_present": passed},
        "boundary": _hard_boundary(execution_receipt_recording_allowed=True),
    }
    _write_json(output, report)
    return report


def write_rollback_or_abort_receipt(*, execution_path: Path, preflight_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    execution = _read_json(execution_path)
    preflight = _read_json(preflight_path)
    isolation = _object(preflight.get("isolation"))

    _check(checks, failures, "execution_passed", execution.get("schema_version") == EXECUTION_SCHEMA and execution.get("passed") is True)
    _check(checks, failures, "preflight_passed", preflight.get("passed") is True)
    _check(checks, failures, "read_only_no_rollback_required", _object(execution.get("execution")).get("external_side_effect_observed") is False)
    _check(checks, failures, "workspace_is_deletable_boundary", bool(isolation.get("workspace")))

    passed = _passed(checks, failures)
    report = {
        "schema_version": ROLLBACK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"execution": _artifact_ref(execution_path), "preflight": _artifact_ref(preflight_path)},
        "rollback_or_abort": {
            "rollback_required": False,
            "abort_required": False,
            "reason": "read_only_command_with_no_external_side_effects",
            "recovery_action": "delete_run_root_if_operator_wants_to_discard_receipts",
            "workspace": isolation.get("workspace"),
        },
        "readiness": {"state": "i2a_rollback_or_abort_receipt_present" if passed else "blocked_i2a_rollback_or_abort", "rollback_or_abort_receipt_present": passed},
        "boundary": _hard_boundary(rollback_or_abort_recording_allowed=True),
    }
    _write_json(output, report)
    return report


def write_reconciliation(
    *,
    operator_review_path: Path,
    registration_path: Path,
    authorization_path: Path,
    acceptance_path: Path,
    preflight_path: Path,
    execution_path: Path,
    rollback_or_abort_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    review = _read_json(operator_review_path)
    registration = _read_json(registration_path)
    authorization = _read_json(authorization_path)
    acceptance = _read_json(acceptance_path)
    preflight = _read_json(preflight_path)
    execution = _read_json(execution_path)
    rollback = _read_json(rollback_or_abort_path)

    for label, report, schema in (
        ("operator_review", review, OPERATOR_REVIEW_SCHEMA),
        ("registration", registration, REGISTRATION_SCHEMA),
        ("authorization", authorization, AUTHORIZATION_SCHEMA),
        ("acceptance", acceptance, ACCEPTANCE_SCHEMA),
        ("preflight", preflight, PREFLIGHT_SCHEMA),
        ("execution", execution, EXECUTION_SCHEMA),
        ("rollback_or_abort", rollback, ROLLBACK_SCHEMA),
    ):
        _check(checks, failures, f"{label}_passed", report.get("schema_version") == schema and report.get("passed") is True)
    command = _object(authorization.get("command"))
    exec_body = _object(execution.get("execution"))
    _check(checks, failures, "command_consumed_once", exec_body.get("command_consumed") is True and exec_body.get("single_use_nonce") == command.get("single_use_nonce"))
    _check(checks, failures, "no_external_side_effects", exec_body.get("external_side_effect_observed") is False)
    _check(checks, failures, "preflight_kept_isolation", _object(preflight.get("isolation")).get("network_allowed") is False and _object(preflight.get("isolation")).get("source_tree_write_allowed") is False)
    _check(checks, failures, "rollback_or_abort_closed", _object(rollback.get("rollback_or_abort")).get("rollback_required") is False and _object(rollback.get("rollback_or_abort")).get("abort_required") is False)

    passed = _passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "operator_review": _artifact_ref(operator_review_path),
            "registration": _artifact_ref(registration_path),
            "authorization": _artifact_ref(authorization_path),
            "acceptance": _artifact_ref(acceptance_path),
            "preflight": _artifact_ref(preflight_path),
            "execution": _artifact_ref(execution_path),
            "rollback_or_abort": _artifact_ref(rollback_or_abort_path),
        },
        "operator_reconciliation": {
            "decision": "i2a_controlled_protocol_smoke_passed" if passed else "blocked_i2a_reconciliation",
            "reason": "I.2-A completed registration, scoped authorization, acceptance, isolation preflight, controlled read-only execution, and rollback/abort receipts without side effects." if passed else "I.2-A evidence chain failed one or more hard controls.",
            "command_id": command.get("command_id"),
        },
        "readiness": {
            "state": "i2a_protocol_smoke_passed" if passed else "blocked_i2a_reconciliation",
            "acceptance_execution_reconciliation_complete": passed,
            "i2b_real_external_command_discussion_ready": passed,
            "real_external_agent_command_allowed": False,
            "real_task_command_allowed": False,
            "production_transition_allowed": False,
        },
        "boundary": _hard_boundary(operator_reconciliation_recording_allowed=True),
        "non_claims": [
            "i2a_reconciliation_does_not_authorize_real_external_agent_commanding",
            "i2a_reconciliation_does_not_authorize_source_changes_or_git",
            "i2a_reconciliation_does_not_unlock_production",
        ],
    }
    _write_json(output, report)
    return report


def _hard_boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "external_agent_command_allowed": False,
        "real_task_command_allowed": False,
        "external_side_effect_allowed": False,
        "source_tree_write_allowed": False,
        "git_write_allowed": False,
        "network_allowed": False,
        "runtime_state_mutation_allowed": False,
        "production_transition_allowed": False,
    }
    base.update(overrides)
    return base


def _collect_failures(*reports: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []))
    return failures


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _check(checks: dict[str, bool], failures: list[str], name: str, passed: bool) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--i2-request", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--operator-id", default="operator-cc")
    parser.add_argument("--executor-alias", default="i2a-controlled-external-agent")
    parser.add_argument("--objective", default=DEFAULT_OBJECTIVE)
    parser.add_argument("--expiry-minutes", type=int, default=30)
    args = parser.parse_args()
    summary = run_chain(
        i2_request_path=Path(args.i2_request).resolve(),
        output_root=Path(args.output_root).resolve(),
        operator_id=args.operator_id,
        executor_alias=args.executor_alias,
        objective=args.objective,
        expiry_minutes=args.expiry_minutes,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if summary["passed"] else 2)


if __name__ == "__main__":
    main()
