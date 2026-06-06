"""H.2 multi-Agent restart continuity over real backend outcome events.

Three workers claim tasks and persist identity/relation state in independent
processes. Only after every worker has exited does the orchestrator create
completed, disputed, and failed task outcomes on a real isolated backend.
Fresh worker processes then restore local state, consume the backend read model,
and update directed relation expectations.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from benchmarks.h2_backend_continuity_infra import (
    authenticated_agent,
    provision_agent,
    start_backend_sandbox,
)
from benchmarks.h2_backend_outcome_export import export_backend_outcome_events
from benchmarks.h2_restart_continuity_gate import (
    _NoopLLM,
    _OfflineAgent,
    _check,
    _float,
    _jsonable,
    _now,
    _read_json,
    _read_json_optional,
    _resolve,
    _sha256,
    _timestamp,
    _write_json,
)


SCHEMA_VERSION = "h2-multi-agent-backend-continuity-gate:v1"
PHASE_SCHEMA_VERSION = "h2-multi-agent-backend-continuity-phase:v1"
WORKER_CASES = {
    "alpha": "settlement_confirmed",
    "beta": "post_delivery_dispute",
    "gamma": "post_delivery_failure",
}
PRIOR_EXPECTATION = {
    "expected_trust": 0.72,
    "expected_delivery_quality": 0.72,
    "expected_cooperation": 0.70,
    "expected_betrayal_risk": 0.12,
    "expected_repair_probability": 0.55,
    "precision": 0.35,
}


def run_gate(
    *,
    run_root: Path,
    output: Path | None = None,
    backend_binary: Path | None = None,
    overwrite: bool = False,
    min_delay_seconds: float = 0.02,
) -> dict[str, Any]:
    agent_root = Path(__file__).resolve().parents[1]
    workspace = agent_root.parent
    run_root = _resolve(run_root, agent_root)
    output = (
        run_root / "h2_multi_agent_backend_continuity_gate.json"
        if output is None
        else _resolve(output, agent_root)
    )
    backend_binary = backend_binary or (
        workspace / "civitasos-backend" / "target" / "debug" / "api_only"
    )
    backend_binary = _resolve(backend_binary, workspace)
    _prepare_run_root(run_root, overwrite=overwrite)

    sandbox = start_backend_sandbox(
        backend_binary=backend_binary,
        data_dir=run_root / "backend",
    )
    try:
        identities = _provision_identities(run_root, sandbox.base_url)
        tasks = _post_tasks(sandbox.base_url, identities)
        _write_json(run_root / "tasks.json", tasks)
        phase1_processes = {
            worker: _run_phase(
                "seed",
                worker=worker,
                run_root=run_root,
                base_url=sandbox.base_url,
                task_id=tasks[worker],
                requester_id=identities["requester"]["agent_id"],
                agent_root=agent_root,
            )
            for worker in WORKER_CASES
        }
        if all(item["returncode"] == 0 for item in phase1_processes.values()):
            time.sleep(max(float(min_delay_seconds), 0.0))
            outcome_receipts = _create_post_shutdown_outcomes(
                run_root=run_root,
                base_url=sandbox.base_url,
                identities=identities,
                tasks=tasks,
            )
            outcome_exports = _export_outcomes(
                run_root=run_root,
                base_url=sandbox.base_url,
                identities=identities,
                phase1_processes=phase1_processes,
            )
            phase2_processes = {
                worker: _run_phase(
                    "recover",
                    worker=worker,
                    run_root=run_root,
                    base_url=sandbox.base_url,
                    task_id=tasks[worker],
                    requester_id=identities["requester"]["agent_id"],
                    agent_root=agent_root,
                )
                for worker in WORKER_CASES
            }
        else:
            outcome_receipts = {}
            outcome_exports = {}
            phase2_processes = {}
        report = _evaluate_gate(
            run_root=run_root,
            backend_url=sandbox.base_url,
            identities=identities,
            tasks=tasks,
            phase1_processes=phase1_processes,
            phase2_processes=phase2_processes,
            outcome_receipts=outcome_receipts,
            outcome_exports=outcome_exports,
        )
    finally:
        sandbox.stop()

    output.parent.mkdir(parents=True, exist_ok=True)
    _write_json(output, report)
    return report


def _prepare_run_root(run_root: Path, *, overwrite: bool) -> None:
    if run_root.exists() and any(run_root.iterdir()):
        if not overwrite:
            raise FileExistsError(f"refusing to overwrite non-empty run root: {run_root}")
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True, exist_ok=True)


def _provision_identities(run_root: Path, base_url: str) -> dict[str, dict[str, Any]]:
    identities = {
        "requester": provision_agent(
            base_url=base_url,
            alias="h2_continuity_requester",
            name="H2 Continuity Requester",
            identity_path=run_root / "identity" / "requester.identity.json",
        )
    }
    for worker in WORKER_CASES:
        identities[worker] = provision_agent(
            base_url=base_url,
            alias=f"h2_continuity_{worker}",
            name=f"H2 Continuity Worker {worker.title()}",
            identity_path=run_root / "identity" / f"{worker}.identity.json",
        )
    _write_json(run_root / "identities.json", identities)
    return identities


def _post_tasks(
    base_url: str,
    identities: dict[str, dict[str, Any]],
) -> dict[str, str]:
    requester = authenticated_agent(
        base_url=base_url,
        login_agent_id=identities["requester"]["agent_id"],
        identity_path=Path(identities["requester"]["identity_path"]),
    )
    tasks: dict[str, str] = {}
    for worker, event_kind in WORKER_CASES.items():
        response = requester.pool_post(
            required_capability="general",
            input_data={
                "kind": "h2_restart_continuity_probe",
                "worker": worker,
                "expected_post_shutdown_event_kind": event_kind,
            },
            reward=1,
            allowed_agents=[identities[worker]["agent_id"]],
            required_stake=0,
            deadline_secs=3600,
        )
        task_id = str(response.get("task_id") or "")
        if not task_id:
            raise RuntimeError(f"pool_post response missing task_id for {worker}: {response}")
        tasks[worker] = task_id
    return tasks


def _run_phase(
    phase: str,
    *,
    worker: str,
    run_root: Path,
    base_url: str,
    task_id: str,
    requester_id: str,
    agent_root: Path,
) -> dict[str, Any]:
    phase_number = "1" if phase == "seed" else "2"
    stdout_path = run_root / worker / f"phase{phase_number}.stdout.log"
    stderr_path = run_root / worker / f"phase{phase_number}.stderr.log"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    workspace = agent_root.parent
    python_paths = [
        str(agent_root),
        str(workspace / "civitasos-runtime"),
        str(workspace / "civitasos-sdk" / "python"),
    ]
    if env.get("PYTHONPATH"):
        python_paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(python_paths)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.h2_multi_agent_backend_continuity_gate",
            "--run-root",
            str(run_root),
            "--phase",
            phase,
            "--worker",
            worker,
            "--backend-url",
            base_url,
            "--task-id",
            task_id,
            "--requester-id",
            requester_id,
        ],
        cwd=agent_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    return {
        "returncode": completed.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def _phase_seed(
    run_root: Path,
    *,
    worker: str,
    base_url: str,
    task_id: str,
    requester_id: str,
) -> None:
    from civitasos_runtime.memory import HybridMemory
    from civitasos_runtime.runner import AgentRunner

    identity_path = run_root / "identity" / f"{worker}.identity.json"
    data_dir = run_root / worker / "data"
    agent = authenticated_agent(
        base_url=base_url,
        login_agent_id=f"h2-seed:{worker}",
        identity_path=identity_path,
    )
    claim = agent.pool_claim(task_id, agent_id=agent.agent_id, stake_amount=0)
    runner = AgentRunner(llm=_NoopLLM(), data_dir=str(data_dir))
    runner._agent = _OfflineAgent(str(agent.agent_id), str(agent.public_key_hex))  # noqa: SLF001
    runner._memory = HybridMemory(agent=None, data_dir=data_dir)  # noqa: SLF001
    runner._memory.remember(  # noqa: SLF001
        "h2_backend_continuity_seed",
        {
            "worker": worker,
            "task_id": task_id,
            "requester_id": requester_id,
            "worker_id": agent.agent_id,
            "prior_expectation": PRIOR_EXPECTATION,
            "prior_history": ["failure:pre_restart_delivery_concern"],
            "claimed_at": _now(),
        },
    )
    runner._memory.remember(  # noqa: SLF001
        "identity_iem_state",
        {
            "identity_id": agent.agent_id,
            "relation_peer": requester_id,
            "history": ["failure:pre_restart_delivery_concern"],
        },
    )
    asyncio.run(runner._shutdown_cleanup())  # noqa: SLF001
    memory = HybridMemory(agent=None, data_dir=data_dir)
    shutdown_state = memory.recall("shutdown_state")
    memory.close()
    _write_json(
        run_root / worker / "phase1.json",
        {
            "schema_version": PHASE_SCHEMA_VERSION,
            "phase": "seed",
            "worker": worker,
            "pid": os.getpid(),
            "runtime_instance_id": runner._runtime_instance_id,  # noqa: SLF001
            "agent_id": agent.agent_id,
            "public_key_hex": agent.public_key_hex,
            "identity_file_sha256": _sha256(identity_path),
            "identity_file_mode": stat.S_IMODE(identity_path.stat().st_mode),
            "task_id": task_id,
            "claim_response": claim,
            "shutdown_state": shutdown_state,
            "phase_finished_at": _now(),
        },
    )


def _create_post_shutdown_outcomes(
    *,
    run_root: Path,
    base_url: str,
    identities: dict[str, dict[str, Any]],
    tasks: dict[str, str],
) -> dict[str, dict[str, Any]]:
    requester = authenticated_agent(
        base_url=base_url,
        login_agent_id="h2-outcome-requester",
        identity_path=Path(identities["requester"]["identity_path"]),
    )
    receipts: dict[str, dict[str, Any]] = {}
    for worker, event_kind in WORKER_CASES.items():
        agent = authenticated_agent(
            base_url=base_url,
            login_agent_id=f"h2-outcome:{worker}",
            identity_path=Path(identities[worker]["identity_path"]),
        )
        task_id = tasks[worker]
        if event_kind == "post_delivery_failure":
            execute = agent.task_execute(
                task_id=task_id,
                output={"worker": worker, "result": "failed after worker shutdown"},
                success=False,
            )
            transition = execute
        else:
            execute = agent.task_execute(
                task_id=task_id,
                output={"worker": worker, "result": "delivered after worker shutdown"},
                success=True,
            )
            transition = (
                requester.pool_confirm(task_id)
                if event_kind == "settlement_confirmed"
                else requester.pool_dispute(task_id, reason="controlled post-shutdown dispute")
            )
        receipt = {
            "worker": worker,
            "task_id": task_id,
            "event_kind": event_kind,
            "created_at": _now(),
            "execute_response": execute,
            "transition_response": transition,
            "final_task": requester.pool_get_task(task_id),
        }
        receipts[worker] = receipt
        _write_json(run_root / worker / "post_shutdown_outcome_receipt.json", receipt)
    return receipts


def _export_outcomes(
    *,
    run_root: Path,
    base_url: str,
    identities: dict[str, dict[str, Any]],
    phase1_processes: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    exports: dict[str, dict[str, Any]] = {}
    for worker in WORKER_CASES:
        if phase1_processes[worker]["returncode"] != 0:
            continue
        phase1 = _read_json(run_root / worker / "phase1.json")
        shutdown_at = str((phase1.get("shutdown_state") or {}).get("shutdown_at") or "")
        path = run_root / worker / "backend_outcome_events.json"
        exports[worker] = export_backend_outcome_events(
            backend_url=base_url,
            output_path=path,
            agent_id=identities[worker]["agent_id"],
            event_kind=WORKER_CASES[worker],
            since=shutdown_at,
            limit=20,
            demo_login_agent_id=f"h2-export:{worker}",
        )
    return exports


def _phase_recover(
    run_root: Path,
    *,
    worker: str,
    base_url: str,
    task_id: str,
    requester_id: str,
) -> None:
    from civitasos_runtime.memory import HybridMemory
    from civitasos_runtime.models import TickContext
    from civitasos_runtime.relation_expectation import apply_relation_matrix_expectation
    from civitasos_runtime.runner import AgentRunner

    identity_path = run_root / "identity" / f"{worker}.identity.json"
    data_dir = run_root / worker / "data"
    agent = authenticated_agent(
        base_url=base_url,
        login_agent_id=f"h2-recover:{worker}",
        identity_path=identity_path,
    )
    runner = AgentRunner(llm=_NoopLLM(), data_dir=str(data_dir))
    runner._agent = _OfflineAgent(str(agent.agent_id), str(agent.public_key_hex))  # noqa: SLF001
    runner._memory = HybridMemory(agent=None, data_dir=data_dir)  # noqa: SLF001
    continuity = asyncio.run(runner._recover())  # noqa: SLF001
    memory = runner._memory  # noqa: SLF001
    seed = memory.recall("h2_backend_continuity_seed")
    iem_state = memory.recall("identity_iem_state")
    outcome_payload = export_backend_outcome_events(
        backend_url=base_url,
        output_path=run_root / worker / "phase2_backend_outcome_events.json",
        agent_id=str(agent.agent_id),
        event_kind=WORKER_CASES[worker],
        since=str(continuity.get("previous_shutdown_at") or ""),
        limit=20,
        demo_login_agent_id=f"h2-phase2-export:{worker}",
    )
    events = [
        event
        for event in outcome_payload.get("events", [])
        if isinstance(event, dict) and event.get("task_id") == task_id
    ]
    event = events[0] if events else {}
    relation_id = str(event.get("relation_id") or "")
    relation_key = f"{relation_id}|{agent.agent_id}->{requester_id}|predicted"
    prior = dict((seed or {}).get("prior_expectation") or PRIOR_EXPECTATION)
    memory.remember(
        f"relation_expectation:{relation_key}",
        {"expectation": prior, "source_event_ids": ["failure:pre_restart_delivery_concern"]},
    )
    relation_context = {
        "relation_id": relation_id,
        "relation_pair": {
            "requester": requester_id,
            "worker": agent.agent_id,
            "agents": [requester_id, agent.agent_id],
        },
    }
    event_kind = str(event.get("event_kind") or "")
    event_record = {
        "task_id": task_id,
        "relation_id": relation_id,
        "event_id": event.get("event_id"),
        "observed_at": event.get("observed_at"),
    }
    if event_kind == "settlement_confirmed":
        relation_context["recent_repairs"] = [event_record]
    else:
        relation_context["recent_failures"] = [event_record]
    ctx = TickContext(briefing={"relation_context": relation_context})
    applied = apply_relation_matrix_expectation(
        ctx,
        local_identity=str(agent.agent_id),
        recall=memory.recall,
    )
    update = ctx.expectations.get("relation", {}).get(relation_key, {})
    after = update.get("expectation", {}) if isinstance(update, dict) else {}
    action_bias = ctx.action_bias.get("relation", {}).get(relation_key, {})
    updates = [_jsonable(asdict(item)) for item in ctx.expectation_updates]
    memory.remember(
        "h2_backend_delayed_consequence_state",
        {
            "event": event,
            "before": prior,
            "after": after,
            "action_bias": action_bias,
            "expectation_updates": updates,
        },
    )
    asyncio.run(runner._shutdown_cleanup())  # noqa: SLF001
    _write_json(
        run_root / worker / "phase2.json",
        {
            "schema_version": PHASE_SCHEMA_VERSION,
            "phase": "recover",
            "worker": worker,
            "pid": os.getpid(),
            "runtime_instance_id": runner._runtime_instance_id,  # noqa: SLF001
            "agent_id": agent.agent_id,
            "public_key_hex": agent.public_key_hex,
            "identity_file_sha256": _sha256(identity_path),
            "continuity": continuity,
            "recalled": {"seed": seed, "identity_iem_state": iem_state},
            "backend_outcome": event,
            "backend_outcome_payload_source": outcome_payload.get("source"),
            "consequence_applied": applied,
            "relation_update": {
                "relation_key": relation_key,
                "before": prior,
                "after": after,
                "action_bias": action_bias,
                "expectation_updates": updates,
            },
            "phase_finished_at": _now(),
        },
    )


def _evaluate_gate(
    *,
    run_root: Path,
    backend_url: str,
    identities: dict[str, dict[str, Any]],
    tasks: dict[str, str],
    phase1_processes: dict[str, dict[str, Any]],
    phase2_processes: dict[str, dict[str, Any]],
    outcome_receipts: dict[str, dict[str, Any]],
    outcome_exports: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    _check(checks, failures, "three_distinct_worker_identities", len({identities[w]["agent_id"] for w in WORKER_CASES}) == 3)
    _check(checks, failures, "three_distinct_tasks", len(set(tasks.values())) == 3)
    _check(checks, failures, "all_phase1_processes_passed", len(phase1_processes) == 3 and all(item["returncode"] == 0 for item in phase1_processes.values()))
    _check(checks, failures, "all_phase2_processes_passed", len(phase2_processes) == 3 and all(item["returncode"] == 0 for item in phase2_processes.values()))
    _check(checks, failures, "all_post_shutdown_outcomes_created", len(outcome_receipts) == 3)
    _check(checks, failures, "all_backend_outcomes_exported", len(outcome_exports) == 3)

    worker_summaries: dict[str, Any] = {}
    for worker, expected_kind in WORKER_CASES.items():
        phase1 = _read_json_optional(run_root / worker / "phase1.json")
        phase2 = _read_json_optional(run_root / worker / "phase2.json")
        if not phase1 or not phase2:
            worker_summaries[worker] = {"reports_present": False}
            continue
        event = phase2.get("backend_outcome") or {}
        shutdown = phase1.get("shutdown_state") or {}
        continuity = phase2.get("continuity") or {}
        update = phase2.get("relation_update") or {}
        before = update.get("before") or {}
        after = update.get("after") or {}
        action_bias = update.get("action_bias") or {}
        expectation_updates = update.get("expectation_updates") or []
        prefix = f"{worker}_"
        _check(checks, failures, prefix + "separate_processes", phase1.get("pid") != phase2.get("pid"))
        _check(checks, failures, prefix + "separate_runtime_instances", phase1.get("runtime_instance_id") != phase2.get("runtime_instance_id"))
        _check(checks, failures, prefix + "same_identity", phase1.get("agent_id") == phase2.get("agent_id") == identities[worker]["agent_id"])
        _check(checks, failures, prefix + "same_public_key", phase1.get("public_key_hex") == phase2.get("public_key_hex"))
        _check(checks, failures, prefix + "identity_file_stable", phase1.get("identity_file_sha256") == phase2.get("identity_file_sha256"))
        _check(checks, failures, prefix + "identity_file_private", phase1.get("identity_file_mode") == 0o600)
        _check(checks, failures, prefix + "runtime_identity_continuous", continuity.get("identity_continuous") is True)
        _check(checks, failures, prefix + "memory_recalled", bool((phase2.get("recalled") or {}).get("seed")) and bool((phase2.get("recalled") or {}).get("identity_iem_state")))
        _check(checks, failures, prefix + "event_from_backend", event.get("source") == "backend_task_pool_read_model" and phase2.get("backend_outcome_payload_source") == "backend_task_pool_read_model")
        _check(checks, failures, prefix + "expected_event_kind", event.get("event_kind") == expected_kind)
        _check(checks, failures, prefix + "event_matches_task", event.get("task_id") == tasks[worker])
        _check(checks, failures, prefix + "event_after_shutdown", _timestamp(event.get("observed_at")) > _timestamp(shutdown.get("shutdown_at")))
        _check(checks, failures, prefix + "consequence_applied", phase2.get("consequence_applied") is True)
        _check(
            checks,
            failures,
            prefix + "normative_local_update_blocked",
            any(
                item.get("local_update_blocked") is True
                and str(item.get("constitution_verdict") or "").startswith("blocked:")
                for item in expectation_updates
                if isinstance(item, dict)
            ),
        )
        if expected_kind == "settlement_confirmed":
            _check(checks, failures, prefix + "positive_trust_update", _float(after.get("expected_trust")) > _float(before.get("expected_trust")))
            _check(checks, failures, prefix + "positive_repair_update", _float(after.get("expected_repair_probability")) > _float(before.get("expected_repair_probability")))
        else:
            _check(checks, failures, prefix + "negative_trust_update", _float(after.get("expected_trust")) < _float(before.get("expected_trust")))
            _check(checks, failures, prefix + "negative_risk_update", _float(after.get("expected_betrayal_risk")) > _float(before.get("expected_betrayal_risk")))
            _check(checks, failures, prefix + "future_behavior_biased", action_bias.get("verification_level") in {"elevated", "strict"} and _float(action_bias.get("required_stake_multiplier")) > 1.0)
        worker_summaries[worker] = {
            "reports_present": True,
            "agent_id": phase2.get("agent_id"),
            "task_id": event.get("task_id"),
            "event_kind": event.get("event_kind"),
            "observed_at": event.get("observed_at"),
            "shutdown_at": shutdown.get("shutdown_at"),
            "relation_update": update,
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "passed": not failures and all(checks.values()),
        "checks": checks,
        "failure_reasons": failures,
        "run_root": str(run_root),
        "backend_url": backend_url,
        "identities": identities,
        "tasks": tasks,
        "phase1_processes": phase1_processes,
        "phase2_processes": phase2_processes,
        "outcome_receipts": outcome_receipts,
        "worker_summaries": worker_summaries,
        "non_claims": [
            "controlled_multi_agent_probe_not_seven_day_soak",
            "isolated_backend_not_production_evidence",
            "demo_login_enabled_only_inside_isolated_backend",
            "no_llm_invocation",
            "local_memory_persistence_does_not_prove_remote_csp_recovery",
        ],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--backend-binary", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--min-delay-seconds", type=float, default=0.02)
    parser.add_argument("--phase", choices=("seed", "recover"), help=argparse.SUPPRESS)
    parser.add_argument("--worker", choices=tuple(WORKER_CASES), help=argparse.SUPPRESS)
    parser.add_argument("--backend-url", help=argparse.SUPPRESS)
    parser.add_argument("--task-id", help=argparse.SUPPRESS)
    parser.add_argument("--requester-id", help=argparse.SUPPRESS)
    return parser


def main() -> None:
    args = _parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    run_root = _resolve(args.run_root, agent_root)
    if args.phase:
        if not all((args.worker, args.backend_url, args.task_id, args.requester_id)):
            raise SystemExit("phase execution requires worker, backend-url, task-id, and requester-id")
        phase_fn = _phase_seed if args.phase == "seed" else _phase_recover
        phase_fn(
            run_root,
            worker=args.worker,
            base_url=args.backend_url,
            task_id=args.task_id,
            requester_id=args.requester_id,
        )
        return
    report = run_gate(
        run_root=run_root,
        output=args.output,
        backend_binary=args.backend_binary,
        overwrite=args.overwrite,
        min_delay_seconds=args.min_delay_seconds,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 3)


if __name__ == "__main__":
    main()
