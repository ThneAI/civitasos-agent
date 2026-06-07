"""Remote phase probe for the H.2 VM/CSP continuity soak.

This module runs on the Agent VM. It deliberately avoids an LLM and exercises
the real SDK, Runtime HybridMemory, backend task pool, and remote CSP paths.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.h2_backend_outcome_export import (
    _demo_login_token,
    export_backend_outcome_events,
)
from benchmarks.h2_multi_agent_backend_continuity_gate import (
    PRIOR_EXPECTATION,
    WORKER_CASES,
)
from benchmarks.h2_restart_continuity_gate import (
    _NoopLLM,
    _check,
    _float,
    _jsonable,
    _read_json,
    _sha256,
    _timestamp,
    _write_json,
)


SCHEMA_VERSION = "h2-vm-csp-phase:v1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _agent(
    *,
    backend_url: str,
    csp_url: str,
    login_agent_id: str,
    identity_path: Path | None = None,
) -> Any:
    from civitasos import CivitasAgent

    agent = CivitasAgent(
        backend_url,
        auto_discover=False,
        cognitive_provider={"url": csp_url, "services": ["memory", "briefing"]},
    )
    if identity_path is not None:
        agent.load_identity(str(identity_path))
    token = _demo_login_token(
        backend_url=backend_url,
        agent_id=login_agent_id,
        timeout_s=20.0,
    )
    if not token:
        raise RuntimeError(f"demo-login returned no token for {login_agent_id}")
    agent._jwt_token = token  # noqa: SLF001 - controlled host-only VM environment
    agent._jwt_expires_at = time.time() + 3600  # noqa: SLF001
    return agent


def _provision_identity(
    *,
    run_root: Path,
    backend_url: str,
    csp_url: str,
    agent_address: str,
    alias: str,
    name: str,
) -> dict[str, Any]:
    identity_path = run_root / "identity" / f"{alias}.identity.json"
    agent = _agent(
        backend_url=backend_url,
        csp_url=csp_url,
        login_agent_id=f"h2-vm-provision:{alias}",
    )
    public_key = agent.generate_keys()
    response = agent.a2a_quickstart(
        name=name,
        endpoint=f"http://{agent_address}:0/h2-vm/{alias}",
        description="H.2 VM/CSP restart continuity identity",
        alias=f"h2_vm_{alias}_{public_key[:10]}",
        public_key=public_key,
    )
    if not agent.agent_id:
        raise RuntimeError(f"quickstart response missing DID for {alias}: {response}")
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    agent.save_identity(str(identity_path))
    return {
        "alias": alias,
        "agent_id": str(agent.agent_id),
        "public_key_hex": public_key,
        "identity_path": str(identity_path),
        "identity_file_sha256": _sha256(identity_path),
        "identity_file_mode": stat.S_IMODE(identity_path.stat().st_mode),
        "quickstart_response": response,
    }


def bootstrap(
    run_root: Path,
    *,
    backend_url: str,
    csp_url: str,
    agent_address: str,
) -> dict[str, Any]:
    identities = {
        "requester": _provision_identity(
            run_root=run_root,
            backend_url=backend_url,
            csp_url=csp_url,
            agent_address=agent_address,
            alias="requester",
            name="H2 VM Continuity Requester",
        )
    }
    for worker in WORKER_CASES:
        identities[worker] = _provision_identity(
            run_root=run_root,
            backend_url=backend_url,
            csp_url=csp_url,
            agent_address=agent_address,
            alias=worker,
            name=f"H2 VM Continuity {worker.title()}",
        )

    requester = _agent(
        backend_url=backend_url,
        csp_url=csp_url,
        login_agent_id="h2-vm-bootstrap-requester",
        identity_path=Path(identities["requester"]["identity_path"]),
    )
    tasks: dict[str, str] = {}
    for worker, event_kind in WORKER_CASES.items():
        response = requester.pool_post(
            required_capability="general",
            input_data={
                "kind": "h2_vm_csp_continuity_probe",
                "worker": worker,
                "expected_post_shutdown_event_kind": event_kind,
            },
            reward=1,
            allowed_agents=[identities[worker]["agent_id"]],
            required_stake=0,
            deadline_secs=604800,
        )
        task_id = str(response.get("task_id") or "")
        if not task_id:
            raise RuntimeError(f"pool_post missing task_id for {worker}: {response}")
        tasks[worker] = task_id

    payload = {
        "schema_version": SCHEMA_VERSION,
        "phase": "bootstrap",
        "created_at": _now(),
        "backend_url": backend_url,
        "csp_url": csp_url,
        "identities": identities,
        "tasks": tasks,
    }
    _write_json(run_root / "bootstrap.json", payload)
    return payload


def seed(
    run_root: Path,
    *,
    backend_url: str,
    csp_url: str,
    worker: str,
) -> dict[str, Any]:
    from civitasos_runtime.memory import HybridMemory
    from civitasos_runtime.runner import AgentRunner

    bootstrap_report = _read_json(run_root / "bootstrap.json")
    identities = bootstrap_report["identities"]
    task_id = str(bootstrap_report["tasks"][worker])
    requester_id = str(identities["requester"]["agent_id"])
    identity_path = Path(identities[worker]["identity_path"])
    data_dir = run_root / worker / "data"
    agent = _agent(
        backend_url=backend_url,
        csp_url=csp_url,
        login_agent_id=f"h2-vm-seed:{worker}",
        identity_path=identity_path,
    )
    claim = agent.pool_claim(task_id, agent_id=agent.agent_id, stake_amount=0)
    runner = AgentRunner(
        llm=_NoopLLM(),
        data_dir=str(data_dir),
        cognitive_provider={"url": csp_url, "services": ["memory", "briefing"]},
    )
    runner._agent = agent  # noqa: SLF001 - lifecycle probe
    runner._memory = HybridMemory(agent=agent, data_dir=data_dir)  # noqa: SLF001
    relation_id = f"h2-vm-rel:{task_id}:{requester_id}:{agent.agent_id}"
    relation_key = f"{relation_id}|{agent.agent_id}->{requester_id}|predicted"
    seed_value = {
        "worker": worker,
        "task_id": task_id,
        "requester_id": requester_id,
        "worker_id": agent.agent_id,
        "relation_id": relation_id,
        "relation_key": relation_key,
        "prior_expectation": PRIOR_EXPECTATION,
        "prior_history": ["failure:pre_restart_delivery_concern"],
        "seeded_at": _now(),
    }
    runner._memory.remember("h2_vm_csp_seed", seed_value)  # noqa: SLF001
    runner._memory.remember(  # noqa: SLF001
        "identity_iem_state",
        {
            "identity_id": agent.agent_id,
            "relation_peer": requester_id,
            "history": seed_value["prior_history"],
        },
    )
    runner._memory.remember(  # noqa: SLF001
        f"relation_expectation:{relation_key}",
        {
            "expectation": PRIOR_EXPECTATION,
            "source_event_ids": seed_value["prior_history"],
        },
    )
    asyncio.run(runner._shutdown_cleanup())  # noqa: SLF001

    verifier = _agent(
        backend_url=backend_url,
        csp_url=csp_url,
        login_agent_id=f"h2-vm-seed-verify:{worker}",
        identity_path=identity_path,
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
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
        "shutdown_state": verifier.recall("shutdown_state"),
        "remote_seed": verifier.recall("h2_vm_csp_seed"),
        "remote_iem_state": verifier.recall("identity_iem_state"),
        "remote_relation_expectation": verifier.recall(
            f"relation_expectation:{relation_key}"
        ),
        "phase_finished_at": _now(),
    }
    _write_json(run_root / worker / "seed.json", payload)
    return payload


def create_outcomes(
    run_root: Path,
    *,
    backend_url: str,
    csp_url: str,
) -> dict[str, Any]:
    report = _read_json(run_root / "bootstrap.json")
    identities = report["identities"]
    tasks = report["tasks"]
    requester = _agent(
        backend_url=backend_url,
        csp_url=csp_url,
        login_agent_id="h2-vm-outcome-requester",
        identity_path=Path(identities["requester"]["identity_path"]),
    )
    receipts: dict[str, Any] = {}
    for worker, event_kind in WORKER_CASES.items():
        agent = _agent(
            backend_url=backend_url,
            csp_url=csp_url,
            login_agent_id=f"h2-vm-outcome:{worker}",
            identity_path=Path(identities[worker]["identity_path"]),
        )
        task_id = str(tasks[worker])
        execute = agent.task_execute(
            task_id=task_id,
            output={"worker": worker, "source": "h2_vm_csp_soak"},
            success=event_kind != "post_delivery_failure",
        )
        transition: dict[str, Any] = execute
        if event_kind == "settlement_confirmed":
            transition = requester.pool_confirm(task_id)
        elif event_kind == "post_delivery_dispute":
            transition = requester.pool_dispute(
                task_id,
                reason="controlled VM/CSP post-shutdown dispute",
            )
        receipts[worker] = {
            "worker": worker,
            "task_id": task_id,
            "event_kind": event_kind,
            "created_at": _now(),
            "execute_response": execute,
            "transition_response": transition,
            "final_task": requester.pool_get_task(task_id),
        }
    payload = {
        "schema_version": SCHEMA_VERSION,
        "phase": "outcomes",
        "created_at": _now(),
        "receipts": receipts,
    }
    _write_json(run_root / "post_shutdown_outcomes.json", payload)
    return payload


def recover(
    run_root: Path,
    *,
    backend_url: str,
    csp_url: str,
    worker: str,
    report_name: str,
) -> dict[str, Any]:
    from civitasos_runtime.memory import HybridMemory
    from civitasos_runtime.models import TickContext
    from civitasos_runtime.relation_expectation import (
        apply_relation_matrix_expectation,
    )
    from civitasos_runtime.runner import AgentRunner

    bootstrap_report = _read_json(run_root / "bootstrap.json")
    identities = bootstrap_report["identities"]
    task_id = str(bootstrap_report["tasks"][worker])
    requester_id = str(identities["requester"]["agent_id"])
    identity_path = Path(identities[worker]["identity_path"])
    data_dir = run_root / worker / "data"
    local_db_existed_before = (data_dir / "memory.db").is_file()
    agent = _agent(
        backend_url=backend_url,
        csp_url=csp_url,
        login_agent_id=f"h2-vm-recover:{worker}",
        identity_path=identity_path,
    )
    runner = AgentRunner(
        llm=_NoopLLM(),
        data_dir=str(data_dir),
        cognitive_provider={"url": csp_url, "services": ["memory", "briefing"]},
    )
    runner._agent = agent  # noqa: SLF001
    runner._memory = HybridMemory(agent=agent, data_dir=data_dir)  # noqa: SLF001
    continuity = asyncio.run(runner._recover())  # noqa: SLF001
    memory = runner._memory  # noqa: SLF001
    seed_value = memory.recall("h2_vm_csp_seed")
    iem_state = memory.recall("identity_iem_state")
    relation_key = str((seed_value or {}).get("relation_key") or "")
    relation_value = memory.recall(f"relation_expectation:{relation_key}")
    seed_report = _read_json(run_root / worker / "seed.json")
    outcome_payload = export_backend_outcome_events(
        backend_url=backend_url,
        output_path=run_root / worker / f"{report_name}.backend_outcomes.json",
        agent_id=str(agent.agent_id),
        event_kind=WORKER_CASES[worker],
        since=str((seed_report.get("shutdown_state") or {}).get("shutdown_at") or ""),
        limit=20,
        demo_login_agent_id=f"h2-vm-export:{worker}",
    )
    events = [
        event
        for event in outcome_payload.get("events", [])
        if isinstance(event, dict) and event.get("task_id") == task_id
    ]
    event = events[0] if events else {}
    backend_relation_id = str(event.get("relation_id") or "")
    applied = False
    update: dict[str, Any] = {}
    if backend_relation_id:
        backend_relation_key = (
            f"{backend_relation_id}|{agent.agent_id}->{requester_id}|predicted"
        )
        prior = dict((seed_value or {}).get("prior_expectation") or PRIOR_EXPECTATION)
        memory.remember(
            f"relation_expectation:{backend_relation_key}",
            {"expectation": prior, "source_event_ids": ["h2-vm-seed"]},
        )
        event_record = {
            "task_id": task_id,
            "relation_id": backend_relation_id,
            "event_id": event.get("event_id"),
            "observed_at": event.get("observed_at"),
        }
        relation_context: dict[str, Any] = {
            "relation_id": backend_relation_id,
            "relation_pair": {
                "requester": requester_id,
                "worker": agent.agent_id,
                "agents": [requester_id, agent.agent_id],
            },
        }
        if event.get("event_kind") == "settlement_confirmed":
            relation_context["recent_repairs"] = [event_record]
        else:
            relation_context["recent_failures"] = [event_record]
        ctx = TickContext(briefing={"relation_context": relation_context})
        applied = apply_relation_matrix_expectation(
            ctx,
            local_identity=str(agent.agent_id),
            recall=memory.recall,
        )
        value = ctx.expectations.get("relation", {}).get(backend_relation_key, {})
        update = {
            "relation_key": backend_relation_key,
            "before": prior,
            "after": value.get("expectation", {}) if isinstance(value, dict) else {},
            "action_bias": ctx.action_bias.get("relation", {}).get(
                backend_relation_key, {}
            ),
            "expectation_updates": [
                _jsonable(asdict(item)) for item in ctx.expectation_updates
            ],
        }
    asyncio.run(runner._shutdown_cleanup())  # noqa: SLF001
    payload = {
        "schema_version": SCHEMA_VERSION,
        "phase": "recover",
        "worker": worker,
        "report_name": report_name,
        "pid": os.getpid(),
        "runtime_instance_id": runner._runtime_instance_id,  # noqa: SLF001
        "agent_id": agent.agent_id,
        "public_key_hex": agent.public_key_hex,
        "identity_file_sha256": _sha256(identity_path),
        "identity_file_mode": stat.S_IMODE(identity_path.stat().st_mode),
        "local_db_existed_before": local_db_existed_before,
        "local_db_exists_after": (data_dir / "memory.db").is_file(),
        "continuity": continuity,
        "recalled": {
            "seed": seed_value,
            "identity_iem_state": iem_state,
            "relation_expectation": relation_value,
        },
        "backend_outcome": event,
        "backend_outcome_payload_source": outcome_payload.get("source"),
        "consequence_applied": applied,
        "relation_update": update,
        "phase_finished_at": _now(),
    }
    _write_json(run_root / worker / f"{report_name}.json", payload)
    return payload


def evaluate_cycle(run_root: Path, *, report_name: str) -> dict[str, Any]:
    bootstrap_report = _read_json(run_root / "bootstrap.json")
    checks: dict[str, bool] = {}
    failures: list[str] = []
    summaries: dict[str, Any] = {}
    for worker, expected_kind in WORKER_CASES.items():
        seed_report = _read_json(run_root / worker / "seed.json")
        recovered = _read_json(run_root / worker / f"{report_name}.json")
        event = recovered.get("backend_outcome") or {}
        continuity = recovered.get("continuity") or {}
        update = recovered.get("relation_update") or {}
        before = update.get("before") or {}
        after = update.get("after") or {}
        prefix = f"{worker}_"
        _check(
            checks,
            failures,
            prefix + "different_process",
            seed_report.get("pid") != recovered.get("pid"),
        )
        _check(
            checks,
            failures,
            prefix + "different_runtime_instance",
            seed_report.get("runtime_instance_id")
            != recovered.get("runtime_instance_id"),
        )
        _check(
            checks,
            failures,
            prefix + "identity_stable",
            seed_report.get("agent_id") == recovered.get("agent_id"),
        )
        _check(
            checks,
            failures,
            prefix + "public_key_stable",
            seed_report.get("public_key_hex") == recovered.get("public_key_hex"),
        )
        _check(
            checks,
            failures,
            prefix + "identity_hash_stable",
            seed_report.get("identity_file_sha256")
            == recovered.get("identity_file_sha256"),
        )
        _check(
            checks,
            failures,
            prefix + "identity_private",
            recovered.get("identity_file_mode") == 0o600,
        )
        _check(
            checks,
            failures,
            prefix + "runtime_identity_continuous",
            continuity.get("identity_continuous") is True,
        )
        recalled = recovered.get("recalled") or {}
        _check(
            checks,
            failures,
            prefix + "csp_memory_recalled",
            all(
                recalled.get(key)
                for key in ("seed", "identity_iem_state", "relation_expectation")
            ),
        )
        _check(
            checks,
            failures,
            prefix + "expected_backend_outcome",
            event.get("event_kind") == expected_kind,
        )
        _check(
            checks,
            failures,
            prefix + "outcome_after_shutdown",
            _timestamp(event.get("observed_at"))
            > _timestamp((seed_report.get("shutdown_state") or {}).get("shutdown_at")),
        )
        _check(
            checks,
            failures,
            prefix + "consequence_applied",
            recovered.get("consequence_applied") is True,
        )
        if expected_kind == "settlement_confirmed":
            _check(
                checks,
                failures,
                prefix + "positive_trust_update",
                _float(after.get("expected_trust"))
                > _float(before.get("expected_trust")),
            )
        else:
            _check(
                checks,
                failures,
                prefix + "negative_trust_update",
                _float(after.get("expected_trust"))
                < _float(before.get("expected_trust")),
            )
        summaries[worker] = {
            "agent_id": recovered.get("agent_id"),
            "event_kind": event.get("event_kind"),
            "local_db_existed_before": recovered.get("local_db_existed_before"),
            "continuity": continuity,
        }
    return {
        "schema_version": "h2-vm-csp-cycle-evaluation:v1",
        "passed": not failures and all(checks.values()),
        "checks": checks,
        "failure_reasons": failures,
        "report_name": report_name,
        "bootstrap": bootstrap_report,
        "worker_summaries": summaries,
        "evaluated_at": _now(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "phase",
        choices=("bootstrap", "seed", "outcomes", "recover", "evaluate"),
    )
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--backend-url", required=True)
    parser.add_argument("--csp-url", required=True)
    parser.add_argument("--agent-address", required=True)
    parser.add_argument("--worker", choices=tuple(WORKER_CASES))
    parser.add_argument("--report-name", default="recover")
    return parser


def main() -> None:
    args = _parser().parse_args()
    args.run_root.mkdir(parents=True, exist_ok=True)
    if args.phase == "bootstrap":
        report = bootstrap(
            args.run_root,
            backend_url=args.backend_url,
            csp_url=args.csp_url,
            agent_address=args.agent_address,
        )
    elif args.phase == "outcomes":
        report = create_outcomes(
            args.run_root,
            backend_url=args.backend_url,
            csp_url=args.csp_url,
        )
    elif args.phase == "evaluate":
        report = evaluate_cycle(args.run_root, report_name=args.report_name)
        _write_json(args.run_root / f"{args.report_name}.evaluation.json", report)
    else:
        if not args.worker:
            raise SystemExit(f"{args.phase} requires --worker")
        fn = seed if args.phase == "seed" else recover
        kwargs = {
            "backend_url": args.backend_url,
            "csp_url": args.csp_url,
            "worker": args.worker,
        }
        if args.phase == "recover":
            kwargs["report_name"] = args.report_name
        report = fn(args.run_root, **kwargs)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    if args.phase == "evaluate" and not report["passed"]:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
