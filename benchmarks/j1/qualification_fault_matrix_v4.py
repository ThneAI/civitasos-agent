"""Deterministic fault matrix for the J1-D r4 offline orchestrator."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Callable

from .controlled_comparison import canonical_sha256
from .qualification_orchestrator_v4 import (
    ExecutionJournal,
    InjectedCrash,
    OfflineAdapter,
    run_offline_orchestrator,
)


REPORT_SCHEMA = "j1-qualification-r4-fault-matrix-report:v1"
EXPECTED_SCENARIOS = {
    "crash_before_budget_reservation",
    "crash_after_budget_reservation_before_dispatch_intent",
    "crash_after_dispatch_intent_before_response_commit",
    "crash_after_response_commit_before_reconciliation",
    "crash_after_signature_before_task_commit",
    "duplicate_or_reordered_journal_event",
    "container_or_workspace_drift",
    "budget_or_protocol_ceiling_exceeded",
}


class _OverrunAdapter(OfflineAdapter):
    def provider_call(
        self, task: dict[str, Any], request: dict[str, Any]
    ) -> dict[str, Any]:
        response = super().provider_call(task, request)
        response["usage"] = {
            "input_cache_hit": 0,
            "input_cache_miss": 2501,
            "output": 0,
            "cost_microunits": 1524,
        }
        return response


def run_fault_matrix(
    *,
    contract: dict[str, Any],
    root: Path,
    adapter_factory: Callable[[], OfflineAdapter] = OfflineAdapter,
    overrun_adapter_factory: Callable[[], OfflineAdapter] = _OverrunAdapter,
    report_schema: str = REPORT_SCHEMA,
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    root.chmod(0o700)
    results = [
        _crash_resume(
            contract,
            root,
            scenario="crash_before_budget_reservation",
            checkpoint_name="after_request_prepared",
            expected_status="complete",
            expected_provider_calls=1,
            expected_budget_state="reconciled",
            adapter_factory=adapter_factory,
        ),
        _crash_resume(
            contract,
            root,
            scenario="crash_after_budget_reservation_before_dispatch_intent",
            checkpoint_name="after_budget_reserved",
            expected_status="complete",
            expected_provider_calls=1,
            expected_budget_state="reconciled",
            adapter_factory=adapter_factory,
        ),
        _crash_resume(
            contract,
            root,
            scenario="crash_after_dispatch_intent_before_response_commit",
            checkpoint_name="after_provider_return_before_commit",
            expected_status="failed",
            expected_provider_calls=1,
            expected_budget_state="provider_outcome_unknown",
            adapter_factory=adapter_factory,
        ),
        _crash_resume(
            contract,
            root,
            scenario="crash_after_response_commit_before_reconciliation",
            checkpoint_name="after_provider_response_committed",
            expected_status="complete",
            expected_provider_calls=1,
            expected_budget_state="reconciled",
            adapter_factory=adapter_factory,
        ),
        _crash_resume(
            contract,
            root,
            scenario="crash_after_signature_before_task_commit",
            checkpoint_name="after_decision_signed",
            expected_status="complete",
            expected_provider_calls=1,
            expected_budget_state="reconciled",
            adapter_factory=adapter_factory,
        ),
        _journal_tamper(contract, root),
        _workspace_drift(contract, root, adapter_factory=adapter_factory),
        _budget_overrun(
            contract,
            root,
            overrun_adapter_factory=overrun_adapter_factory,
        ),
    ]
    report = {
        "schema_version": report_schema,
        "contract_sha256": contract["contract_sha256"],
        "passed": all(item["passed"] for item in results),
        "scenario_count": len(results),
        "results": results,
        "execution_boundary": {
            "offline_fault_injection_only": True,
            "real_container_started": False,
            "provider_credential_read": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
            "pkcs11_signature_performed": False,
            "backend_fact_append_performed": False,
            "ledger_append_performed": False,
        },
    }
    report["report_sha256"] = canonical_sha256(report)
    failures = validate_fault_matrix(report, expected_schema=report_schema)
    if failures:
        raise ValueError(f"r4 fault matrix invalid: {failures}")
    return report


def validate_fault_matrix(
    value: Any, *, expected_schema: str = REPORT_SCHEMA
) -> list[str]:
    report = value if isinstance(value, dict) else {}
    failures: list[str] = []
    results = report.get("results")
    results = results if isinstance(results, list) else []
    names = {
        item.get("scenario")
        for item in results
        if isinstance(item, dict) and isinstance(item.get("scenario"), str)
    }
    if (
        report.get("schema_version") != expected_schema
        or report.get("passed") is not True
        or report.get("scenario_count") != 8
        or len(results) != 8
        or names != EXPECTED_SCENARIOS
        or not all(item.get("passed") is True for item in results)
    ):
        failures.append("r4_fault_matrix_scenarios_invalid")
    boundary = report.get("execution_boundary")
    if boundary != {
        "offline_fault_injection_only": True,
        "real_container_started": False,
        "provider_credential_read": False,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "pkcs11_signature_performed": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
    }:
        failures.append("r4_fault_matrix_boundary_invalid")
    body = {key: item for key, item in report.items() if key != "report_sha256"}
    if report.get("report_sha256") != canonical_sha256(body):
        failures.append("r4_fault_matrix_hash_invalid")
    return failures


def _crash_resume(
    contract: dict[str, Any],
    root: Path,
    *,
    scenario: str,
    checkpoint_name: str,
    expected_status: str,
    expected_provider_calls: int,
    expected_budget_state: str,
    adapter_factory: Callable[[], OfflineAdapter],
) -> dict[str, Any]:
    scenario_root = root / scenario
    adapter = adapter_factory()
    injected = False

    def checkpoint(name: str, _: dict[str, Any]) -> None:
        nonlocal injected
        if name == checkpoint_name and not injected:
            injected = True
            raise InjectedCrash(name)

    try:
        run_offline_orchestrator(
            contract=contract,
            run_id=f"r4-fault-{scenario}",
            root=scenario_root,
            adapter=adapter,
            checkpoint=checkpoint,
            task_limit=1,
        )
    except InjectedCrash:
        pass
    report = run_offline_orchestrator(
        contract=contract,
        run_id=f"r4-fault-{scenario}",
        root=scenario_root,
        adapter=adapter,
        task_limit=1,
    )
    budget_states = report["journal"]["budget_states"]
    passed = (
        injected
        and report["status"] == expected_status
        and adapter.provider_calls == expected_provider_calls
        and budget_states == {expected_budget_state: 1}
        and report["validation_failures"] == []
    )
    return {
        "scenario": scenario,
        "passed": passed,
        "checkpoint": checkpoint_name,
        "observed_status": report["status"],
        "observed_provider_calls": adapter.provider_calls,
        "observed_budget_states": budget_states,
        "journal_sha256": report["journal"]["journal_sha256"],
    }


def _journal_tamper(contract: dict[str, Any], root: Path) -> dict[str, Any]:
    scenario = "duplicate_or_reordered_journal_event"
    scenario_root = root / scenario
    report = run_offline_orchestrator(
        contract=contract,
        run_id=f"r4-fault-{scenario}",
        root=scenario_root,
        task_limit=1,
    )
    journal_path = scenario_root / "execution-journal.sqlite3"
    connection = sqlite3.connect(journal_path)
    connection.execute(
        "UPDATE events SET payload_json = '{}' WHERE sequence = 1"
    )
    connection.commit()
    connection.close()
    journal = ExecutionJournal(journal_path, contract["contract_sha256"])
    failures = journal.validate()
    journal.close()
    return {
        "scenario": scenario,
        "passed": failures == ["r4_journal_hash_chain_or_transition_invalid"],
        "baseline_status": report["status"],
        "detected_failures": failures,
        "provider_calls_before_tamper": report["offline_scope"]["provider_call_count"],
        "provider_calls_after_tamper": 0,
    }


def _workspace_drift(
    contract: dict[str, Any],
    root: Path,
    *,
    adapter_factory: Callable[[], OfflineAdapter],
) -> dict[str, Any]:
    scenario = "container_or_workspace_drift"
    scenario_root = root / scenario
    adapter = adapter_factory()

    def checkpoint(name: str, _: dict[str, Any]) -> None:
        if name == "after_request_prepared":
            raise InjectedCrash(name)

    try:
        run_offline_orchestrator(
            contract=contract,
            run_id=f"r4-fault-{scenario}",
            root=scenario_root,
            adapter=adapter,
            checkpoint=checkpoint,
            task_limit=1,
        )
    except InjectedCrash:
        pass
    task_id = contract["task_executions"][0]["task_execution_id"]
    request_path = scenario_root / "workspace" / task_id / "request.json"
    request_path.write_bytes(request_path.read_bytes() + b"\n")
    request_path.chmod(0o600)
    report = run_offline_orchestrator(
        contract=contract,
        run_id=f"r4-fault-{scenario}",
        root=scenario_root,
        adapter=adapter,
        task_limit=1,
    )
    return {
        "scenario": scenario,
        "passed": (
            report["status"] == "failed"
            and report["failure_reason"] == "task_failed_before_dispatch"
            and adapter.provider_calls == 0
        ),
        "observed_status": report["status"],
        "observed_failure": report["failure_reason"],
        "observed_provider_calls": adapter.provider_calls,
    }


def _budget_overrun(
    contract: dict[str, Any],
    root: Path,
    *,
    overrun_adapter_factory: Callable[[], OfflineAdapter],
) -> dict[str, Any]:
    scenario = "budget_or_protocol_ceiling_exceeded"
    adapter = overrun_adapter_factory()
    report = run_offline_orchestrator(
        contract=contract,
        run_id=f"r4-fault-{scenario}",
        root=root / scenario,
        adapter=adapter,
        task_limit=1,
    )
    return {
        "scenario": scenario,
        "passed": (
            report["status"] == "failed"
            and report["failure_reason"] == "task_failed_after_response"
            and report["journal"]["budget_states"] == {"overrun": 1}
            and adapter.provider_calls == 1
        ),
        "observed_status": report["status"],
        "observed_failure": report["failure_reason"],
        "observed_budget_states": report["journal"]["budget_states"],
        "observed_provider_calls": adapter.provider_calls,
    }
