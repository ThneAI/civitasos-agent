from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.j1.qualification_orchestrator_v4 import (
    InjectedCrash,
    OfflineAdapter,
    run_offline_orchestrator,
)
from benchmarks.tests.test_j1_qualification_execution_contract_v4 import _contract


def test_offline_orchestrator_completes_without_external_effects(
    tmp_path: Path,
) -> None:
    contract, _ = _contract()
    adapter = OfflineAdapter()

    report = run_offline_orchestrator(
        contract=contract,
        run_id="offline-r4",
        root=tmp_path / "run",
        adapter=adapter,
        task_limit=2,
    )

    assert report["status"] == "complete"
    assert report["offline_scope"] == {
        "task_execution_count": 2,
        "provider_call_count": 2,
        "participant_signature_count": 2,
        "container_start_count": 2,
        "container_stop_count": 2,
    }
    assert report["journal"]["task_states"] == {"task_committed": 2}
    assert report["journal"]["budget_states"] == {"reconciled": 2}
    assert report["execution_boundary"]["provider_api_call_performed"] is False


def test_resume_before_dispatch_reuses_ids_and_reservation(tmp_path: Path) -> None:
    contract, _ = _contract()
    root = tmp_path / "run"
    adapter = OfflineAdapter()
    crashed = False

    def crash_once(name: str, _: dict) -> None:
        nonlocal crashed
        if name == "after_budget_reserved" and not crashed:
            crashed = True
            raise InjectedCrash(name)

    with pytest.raises(InjectedCrash):
        run_offline_orchestrator(
            contract=contract,
            run_id="offline-r4",
            root=root,
            adapter=adapter,
            checkpoint=crash_once,
            task_limit=1,
        )

    report = run_offline_orchestrator(
        contract=contract,
        run_id="offline-r4",
        root=root,
        adapter=adapter,
        task_limit=1,
    )
    assert report["status"] == "complete"
    assert adapter.provider_calls == 1
    assert report["journal"]["budget_states"] == {"reconciled": 1}


def test_resume_after_dispatch_intent_never_retries_provider(tmp_path: Path) -> None:
    contract, _ = _contract()
    root = tmp_path / "run"
    adapter = OfflineAdapter()

    def crash(name: str, _: dict) -> None:
        if name == "after_dispatch_intent_committed":
            raise InjectedCrash(name)

    with pytest.raises(InjectedCrash):
        run_offline_orchestrator(
            contract=contract,
            run_id="offline-r4",
            root=root,
            adapter=adapter,
            checkpoint=crash,
            task_limit=1,
        )

    report = run_offline_orchestrator(
        contract=contract,
        run_id="offline-r4",
        root=root,
        adapter=adapter,
        task_limit=1,
    )
    assert report["status"] == "failed"
    assert report["failure_reason"] == "provider_outcome_unknown"
    assert adapter.provider_calls == 0
    assert report["journal"]["budget_states"] == {"provider_outcome_unknown": 1}


def test_resume_after_response_commit_does_not_call_provider_twice(
    tmp_path: Path,
) -> None:
    contract, _ = _contract()
    root = tmp_path / "run"
    adapter = OfflineAdapter()
    crashed = False

    def crash_once(name: str, _: dict) -> None:
        nonlocal crashed
        if name == "after_provider_response_committed" and not crashed:
            crashed = True
            raise InjectedCrash(name)

    with pytest.raises(InjectedCrash):
        run_offline_orchestrator(
            contract=contract,
            run_id="offline-r4",
            root=root,
            adapter=adapter,
            checkpoint=crash_once,
            task_limit=1,
        )

    report = run_offline_orchestrator(
        contract=contract,
        run_id="offline-r4",
        root=root,
        adapter=adapter,
        task_limit=1,
    )
    assert report["status"] == "complete"
    assert adapter.provider_calls == 1
    assert adapter.participant_signatures == 1
