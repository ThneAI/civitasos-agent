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
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import (
    all_checks_passed,
    artifact_ref,
    check,
    object_value,
    read_json_object,
    sha256_json,
    sha256_text,
    write_json_object,
)
from benchmarks.i2a_controlled_runner import execute_controlled_read_only_command

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
    "read_sourceartifact_refs",
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
        "request_id": object_value(review.get("operator_review")).get("request_id"),
        "command_id": object_value(authorization.get("command")).get("command_id"),
        "executor_alias": executor_alias,
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
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
    write_json_object(artifacts["summary"], summary)
    return summary


def write_operator_review(*, i2_request_path: Path, output: Path, operator_id: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    request = read_json_object(i2_request_path)
    request_body = object_value(request.get("request"))
    readiness = object_value(request.get("readiness"))
    boundary = object_value(request.get("boundary"))

    check(checks, failures, "i2_request_passed", request.get("schema_version") == "i2-external-command-gate-request:v1" and request.get("passed") is True)
    check(checks, failures, "request_ready_for_operator_review", readiness.get("i2_gate_requested") is True and readiness.get("operator_authorization_required") is True)
    check(checks, failures, "request_does_not_already_allow_execution", readiness.get("i2_execution_allowed") is False and boundary.get("external_agent_command_allowed") is False)
    check(checks, failures, "future_evidence_requirements_present", set(request_body.get("required_future_evidence", [])) >= {
        "external_agent_registration_receipt",
        "scoped_command_authorization_request",
        "external_agent_acceptance_receipt",
        "isolation_policy_preflight",
        "command_execution_receipt",
        "rollback_or_abort_receipt",
        "operator_reconciliation",
    })

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": OPERATOR_REVIEW_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"i2_request": artifact_ref(i2_request_path)},
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
    write_json_object(output, report)
    return report


def write_registration_receipt(*, operator_review_path: Path, output: Path, executor_alias: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    review = read_json_object(operator_review_path)
    review_body = object_value(review.get("operator_review"))
    did = "did:civ:i2a:" + sha256_text(executor_alias)[:32]

    check(checks, failures, "operator_review_passed", review.get("schema_version") == OPERATOR_REVIEW_SCHEMA and review.get("passed") is True)
    check(checks, failures, "approved_scope_is_i2a_read_only", review_body.get("approved_scope") == "i2a_read_only_single_use_isolated_command_protocol_smoke")
    check(checks, failures, "executor_alias_present", bool(executor_alias))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": REGISTRATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"operator_review": artifact_ref(operator_review_path)},
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
    write_json_object(output, report)
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
    review = read_json_object(operator_review_path)
    registration = read_json_object(registration_path)
    agent = object_value(registration.get("external_agent"))

    check(checks, failures, "operator_review_passed", review.get("passed") is True)
    check(checks, failures, "registration_passed", registration.get("schema_version") == REGISTRATION_SCHEMA and registration.get("passed") is True)
    check(checks, failures, "objective_is_nonempty", bool(objective.strip()))
    check(checks, failures, "expiry_within_limit", 1 <= expiry_minutes <= 60)

    now = datetime.now(timezone.utc)
    nonce_seed = json.dumps({"review": artifact_ref(operator_review_path), "registration": artifact_ref(registration_path), "objective": objective}, sort_keys=True)
    nonce = sha256_text(nonce_seed)[:24]
    command_id = "i2a-command:" + sha256_text(nonce_seed)[:20]
    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": AUTHORIZATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "operator_review": artifact_ref(operator_review_path),
            "registration": artifact_ref(registration_path),
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
    write_json_object(output, report)
    return report


def write_acceptance_receipt(*, registration_path: Path, authorization_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    registration = read_json_object(registration_path)
    authorization = read_json_object(authorization_path)
    agent = object_value(registration.get("external_agent"))
    command = object_value(authorization.get("command"))

    check(checks, failures, "registration_passed", registration.get("passed") is True)
    check(checks, failures, "authorization_passed", authorization.get("schema_version") == AUTHORIZATION_SCHEMA and authorization.get("passed") is True)
    check(checks, failures, "executor_matches_registration", command.get("executor_alias") == agent.get("agent_alias") and command.get("executor_did") == agent.get("agent_did"))
    check(checks, failures, "forbidden_actions_present", set(command.get("forbidden_actions", [])) == set(FORBIDDEN_ACTIONS))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": ACCEPTANCE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"registration": artifact_ref(registration_path), "authorization": artifact_ref(authorization_path)},
        "acceptance": {
            "accepted": passed,
            "accepted_command_id": command.get("command_id"),
            "executor_alias": agent.get("agent_alias"),
            "scope_hash": sha256_json(command),
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
    write_json_object(output, report)
    return report


def write_isolation_preflight(*, authorization_path: Path, acceptance_path: Path, output: Path, workspace: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    acceptance = read_json_object(acceptance_path)
    command = object_value(authorization.get("command"))
    accepted = object_value(acceptance.get("acceptance"))

    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "README.txt").write_text("I.2-A isolated read-only receipt workspace.\n", encoding="utf-8")

    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "acceptance_passed", acceptance.get("schema_version") == ACCEPTANCE_SCHEMA and acceptance.get("passed") is True)
    check(checks, failures, "command_id_matches_acceptance", command.get("command_id") == accepted.get("accepted_command_id"))
    check(checks, failures, "single_use_nonce_present", bool(command.get("single_use_nonce")) and command.get("single_use") is True)
    check(checks, failures, "network_forbidden", "network_access" in command.get("forbidden_actions", []))
    check(checks, failures, "git_write_forbidden", "git_write" in command.get("forbidden_actions", []) and "git_push" in command.get("forbidden_actions", []))
    check(checks, failures, "source_write_forbidden", "source_tree_write" in command.get("forbidden_actions", []))
    check(checks, failures, "production_forbidden", "production_transition" in command.get("forbidden_actions", []))
    check(checks, failures, "workspace_created", workspace.is_dir())

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": PREFLIGHT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path), "acceptance": artifact_ref(acceptance_path)},
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
    write_json_object(output, report)
    return report


def write_execution_receipt(*, authorization_path: Path, acceptance_path: Path, preflight_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    authorization = read_json_object(authorization_path)
    acceptance = read_json_object(acceptance_path)
    preflight = read_json_object(preflight_path)
    command = object_value(authorization.get("command"))
    workspace = Path(str(object_value(preflight.get("isolation")).get("workspace") or ""))
    response_path = workspace / "external_agent_response.json"

    check(checks, failures, "authorization_passed", authorization.get("passed") is True)
    check(checks, failures, "acceptance_passed", acceptance.get("passed") is True)
    check(checks, failures, "preflight_passed", preflight.get("schema_version") == PREFLIGHT_SCHEMA and preflight.get("passed") is True)
    check(checks, failures, "workspace_exists", workspace.is_dir())
    check(checks, failures, "command_is_read_only", command.get("command_class") == "read_only_boundary_attestation")

    if all_checks_passed(checks, failures):
        execute_controlled_read_only_command(command=command, workspace=workspace)
    check(checks, failures, "response_written_under_workspace", response_path.is_file() and response_path.parent.resolve() == workspace.resolve())

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": EXECUTION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"authorization": artifact_ref(authorization_path), "acceptance": artifact_ref(acceptance_path), "preflight": artifact_ref(preflight_path)},
        "execution": {
            "execution_kind": "controlled_read_only_receipt_write",
            "command_id": command.get("command_id"),
            "command_consumed": passed,
            "single_use_nonce": command.get("single_use_nonce"),
            "output_artifact": artifact_ref(response_path) if response_path.is_file() else None,
            "external_side_effect_observed": False,
        },
        "readiness": {"state": "i2a_command_execution_receipt_present" if passed else "blocked_i2a_execution", "command_execution_receipt_present": passed},
        "boundary": _hard_boundary(execution_receipt_recording_allowed=True),
    }
    write_json_object(output, report)
    return report


def write_rollback_or_abort_receipt(*, execution_path: Path, preflight_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    execution = read_json_object(execution_path)
    preflight = read_json_object(preflight_path)
    isolation = object_value(preflight.get("isolation"))

    check(checks, failures, "execution_passed", execution.get("schema_version") == EXECUTION_SCHEMA and execution.get("passed") is True)
    check(checks, failures, "preflight_passed", preflight.get("passed") is True)
    check(checks, failures, "read_only_no_rollback_required", object_value(execution.get("execution")).get("external_side_effect_observed") is False)
    check(checks, failures, "workspace_is_deletable_boundary", bool(isolation.get("workspace")))

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": ROLLBACK_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {"execution": artifact_ref(execution_path), "preflight": artifact_ref(preflight_path)},
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
    write_json_object(output, report)
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
    review = read_json_object(operator_review_path)
    registration = read_json_object(registration_path)
    authorization = read_json_object(authorization_path)
    acceptance = read_json_object(acceptance_path)
    preflight = read_json_object(preflight_path)
    execution = read_json_object(execution_path)
    rollback = read_json_object(rollback_or_abort_path)

    for label, report, schema in (
        ("operator_review", review, OPERATOR_REVIEW_SCHEMA),
        ("registration", registration, REGISTRATION_SCHEMA),
        ("authorization", authorization, AUTHORIZATION_SCHEMA),
        ("acceptance", acceptance, ACCEPTANCE_SCHEMA),
        ("preflight", preflight, PREFLIGHT_SCHEMA),
        ("execution", execution, EXECUTION_SCHEMA),
        ("rollback_or_abort", rollback, ROLLBACK_SCHEMA),
    ):
        check(checks, failures, f"{label}_passed", report.get("schema_version") == schema and report.get("passed") is True)
    command = object_value(authorization.get("command"))
    exec_body = object_value(execution.get("execution"))
    check(checks, failures, "command_consumed_once", exec_body.get("command_consumed") is True and exec_body.get("single_use_nonce") == command.get("single_use_nonce"))
    check(checks, failures, "no_external_side_effects", exec_body.get("external_side_effect_observed") is False)
    check(checks, failures, "preflight_kept_isolation", object_value(preflight.get("isolation")).get("network_allowed") is False and object_value(preflight.get("isolation")).get("source_tree_write_allowed") is False)
    check(checks, failures, "rollback_or_abort_closed", object_value(rollback.get("rollback_or_abort")).get("rollback_required") is False and object_value(rollback.get("rollback_or_abort")).get("abort_required") is False)

    passed = all_checks_passed(checks, failures)
    report = {
        "schema_version": RECONCILIATION_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "operator_review": artifact_ref(operator_review_path),
            "registration": artifact_ref(registration_path),
            "authorization": artifact_ref(authorization_path),
            "acceptance": artifact_ref(acceptance_path),
            "preflight": artifact_ref(preflight_path),
            "execution": artifact_ref(execution_path),
            "rollback_or_abort": artifact_ref(rollback_or_abort_path),
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
    write_json_object(output, report)
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
