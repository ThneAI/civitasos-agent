"""Reusable H.2 cross-machine Backend/CSP/Runtime soak orchestrator.

The runner deploys a controlled host-only topology over SSH, executes real
Runtime dual-write/recovery phases, injects process restarts and local-memory
loss, and writes fail-closed evidence without invoking an LLM.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from benchmarks.h2_multi_agent_backend_continuity_gate import WORKER_CASES
from benchmarks.h2_restart_continuity_gate import _read_json, _write_json
from benchmarks.h2_vm_csp_remote import (
    CommandRunner,
    VmHost,
    VmTopology,
    load_topology,
    quote_command,
    shell_path,
    wait_for_url,
)


SCHEMA_VERSION = "h2-vm-csp-soak:v1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class VmCspSoakRunner:
    def __init__(
        self,
        *,
        workspace: Path,
        run_root: Path,
        topology: VmTopology,
        commands: CommandRunner | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self.run_root = run_root.resolve()
        self.topology = topology
        self.commands = commands or CommandRunner()
        self.remote_homes: dict[str, str] = {}

    def preflight(self) -> dict[str, Any]:
        hosts: dict[str, Any] = {}
        for host in self._hosts():
            result = self.commands.ssh(
                host,
                "python3 -c 'import json,os,platform; "
                'print(json.dumps({"home":os.path.expanduser("~"),'
                '"hostname":platform.node(),"python":platform.python_version()}))\'',
                timeout=20,
            )
            payload = json.loads(result.stdout.strip().splitlines()[-1])
            home = str(payload["home"])
            self.remote_homes[host.role] = home
            disk = self.commands.ssh(
                host,
                "df -Pk \"$HOME\" | awk 'NR==2 {print $4}'",
                timeout=20,
            )
            hosts[host.role] = {
                "ssh_alias": host.ssh_alias,
                "address": host.address,
                "hostname": payload.get("hostname"),
                "python": payload.get("python"),
                "home": home,
                "disk_free_kib": int(disk.stdout.strip()),
                "ssh_duration_seconds": result.duration_seconds,
            }
        checks = {
            "three_distinct_addresses": len({h.address for h in self._hosts()}) == 3,
            "all_python_3_11_plus": all(
                tuple(int(v) for v in str(item["python"]).split(".")[:2]) >= (3, 11)
                for item in hosts.values()
            ),
            "all_disk_free_at_least_2_gib": all(
                int(item["disk_free_kib"]) >= 2 * 1024 * 1024
                for item in hosts.values()
            ),
        }
        report = {
            "schema_version": "h2-vm-csp-preflight:v1",
            "passed": all(checks.values()),
            "checks": checks,
            "hosts": hosts,
            "topology": self._topology_payload(),
            "checked_at": _now(),
        }
        self._write("preflight.json", report)
        return report

    def deploy(self) -> dict[str, Any]:
        self._ensure_homes()
        backend_root = self.workspace / "civitasos-backend"
        csp_root = self.workspace / "civitasos-csp"
        agent_root = self.workspace / "civitasos-agent"
        runtime_root = self.workspace / "civitasos-runtime"
        sdk_root = self.workspace / "civitasos-sdk" / "python"
        build_results = [
            self.commands.run(
                ["cargo", "build", "--release", "--bin", "api_only"],
                cwd=backend_root,
                timeout=1800,
            ),
            self.commands.run(
                ["cargo", "build", "--release"],
                cwd=csp_root,
                timeout=1800,
            ),
        ]
        for host in self._hosts():
            root = self._remote_root(host)
            self.commands.ssh(
                host,
                f"mkdir -p {quote_command([root + '/' + name for name in ['bin', 'data', 'logs', 'identity', 'evidence', 'src', 'runs']])}",
            )
        self.commands.scp(
            backend_root / "target" / "release" / "api_only",
            self.topology.core,
            f"{self._remote_root(self.topology.core)}/bin/api_only.new",
            timeout=600,
        )
        self.commands.ssh(
            self.topology.core,
            f"chmod 0755 {self._remote_root(self.topology.core)}/bin/api_only.new "
            f"&& mv {self._remote_root(self.topology.core)}/bin/api_only.new "
            f"{self._remote_root(self.topology.core)}/bin/api_only",
        )
        self.commands.scp(
            csp_root / "target" / "release" / "civitasos-csp",
            self.topology.csp,
            f"{self._remote_root(self.topology.csp)}/bin/civitasos-csp.new",
            timeout=600,
        )
        self.commands.ssh(
            self.topology.csp,
            f"chmod 0755 {self._remote_root(self.topology.csp)}/bin/civitasos-csp.new "
            f"&& mv {self._remote_root(self.topology.csp)}/bin/civitasos-csp.new "
            f"{self._remote_root(self.topology.csp)}/bin/civitasos-csp",
        )
        agent_src = f"{self._remote_root(self.topology.agent)}/src"
        self.commands.rsync(
            agent_root,
            self.topology.agent,
            f"{agent_src}/civitasos-agent",
            timeout=1200,
        )
        self.commands.rsync(
            runtime_root,
            self.topology.agent,
            f"{agent_src}/civitasos-runtime",
            timeout=1200,
        )
        self.commands.rsync(
            sdk_root,
            self.topology.agent,
            f"{agent_src}/civitasos-sdk-python",
            timeout=1200,
        )
        agent_vm_root = self._remote_root(self.topology.agent)
        wheelhouse = self.run_root / "deployment_wheelhouse"
        wheelhouse.mkdir(parents=True, exist_ok=True)
        python_tag = self._agent_python_tag()
        self.commands.run(
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                "--quiet",
                "--dest",
                str(wheelhouse),
                "--only-binary=:all:",
                "--platform",
                "manylinux_2_17_x86_64",
                "--python-version",
                python_tag,
                "--implementation",
                "cp",
                "--abi",
                f"cp{python_tag}",
                "pip",
                "PyNaCl",
            ],
            timeout=600,
        )
        self.commands.rsync(
            wheelhouse,
            self.topology.agent,
            f"{agent_vm_root}/wheelhouse",
            timeout=600,
        )
        setup = (
            "set -e; "
            f"python3 -m venv --without-pip --clear {agent_vm_root}/venv; "
            f"{agent_vm_root}/venv/bin/python -c "
            f"\"import glob,sysconfig,zipfile; "
            f"zipfile.ZipFile(glob.glob('{agent_vm_root}/wheelhouse/pip-*.whl')[0])"
            f".extractall(sysconfig.get_paths()['purelib'])\"; "
            f"{agent_vm_root}/venv/bin/python -m pip install "
            f"--no-index --find-links {agent_vm_root}/wheelhouse PyNaCl"
        )
        self.commands.ssh(self.topology.agent, setup, timeout=1200)
        report = {
            "schema_version": "h2-vm-csp-deployment:v1",
            "passed": True,
            "topology": self._topology_payload(),
            "builds": [
                {
                    "command": list(result.argv),
                    "duration_seconds": result.duration_seconds,
                }
                for result in build_results
            ],
            "deployed_at": _now(),
        }
        self._write("deployment.json", report)
        return report

    def start_services(self) -> dict[str, Any]:
        self._ensure_homes()
        self._start_backend()
        backend_health = wait_for_url(
            f"{self.topology.backend_url}/healthz",
            timeout_seconds=45,
        )
        self._start_csp()
        csp_health = wait_for_url(
            f"{self.topology.csp_url}/healthz",
            timeout_seconds=45,
            expected_core_reachable=True,
        )
        report = {
            "schema_version": "h2-vm-csp-services:v1",
            "passed": True,
            "backend_health": backend_health,
            "csp_health": csp_health,
            "started_at": _now(),
        }
        self._write("services.json", report)
        return report

    def smoke(self, *, overwrite_remote_run: bool = False) -> dict[str, Any]:
        self._ensure_homes()
        remote_run = self._remote_run_root()
        if overwrite_remote_run:
            self.commands.ssh(
                self.topology.agent,
                f"rm -rf {quote_command([remote_run])}",
            )
        exists = self.commands.ssh(
            self.topology.agent,
            f"test -e {quote_command([remote_run])}",
            check=False,
        )
        if exists.returncode == 0:
            raise FileExistsError(f"remote run root already exists: {remote_run}")
        self.commands.ssh(
            self.topology.agent,
            f"mkdir -p {quote_command([remote_run])}",
        )
        timeline: list[dict[str, Any]] = []
        timeline.append(self._phase("bootstrap"))
        for worker in WORKER_CASES:
            timeline.append(self._phase("seed", worker=worker))
        timeline.append(self._phase("outcomes"))

        self._quarantine_local_memory("before_csp_recover")
        for worker in WORKER_CASES:
            timeline.append(
                self._phase(
                    "recover",
                    worker=worker,
                    report_name="csp_recover",
                )
            )
        timeline.append(self._phase("evaluate", report_name="csp_recover"))

        self._restart_csp()
        self._quarantine_local_memory("before_csp_restart_recover")
        for worker in WORKER_CASES:
            timeline.append(
                self._phase(
                    "recover",
                    worker=worker,
                    report_name="csp_restart_recover",
                )
            )
        timeline.append(
            self._phase("evaluate", report_name="csp_restart_recover")
        )
        self._collect_remote_evidence()
        report = self._summarize_smoke(timeline)
        self._write("h2_vm_csp_smoke.json", report)
        return report

    def soak(
        self,
        *,
        cycles: int,
        cycle_offset: int,
        interval_seconds: float,
        restart_csp_cycles: Iterable[int] = (),
        restart_backend_cycles: Iterable[int] = (),
        clear_local_each_cycle: bool = True,
    ) -> dict[str, Any]:
        if cycles < 1:
            raise ValueError("cycles must be at least 1")
        if cycle_offset < 0:
            raise ValueError("cycle_offset must not be negative")
        self._ensure_homes()
        restart_csp = set(restart_csp_cycles)
        restart_backend = set(restart_backend_cycles)
        timeline: list[dict[str, Any]] = []
        started = time.monotonic()
        for cycle_index in range(1, cycles + 1):
            cycle = cycle_offset + cycle_index
            if cycle_index in restart_backend:
                self._restart_backend()
                timeline.append(
                    {"cycle": cycle, "event": "backend_restarted", "at": _now()}
                )
            if cycle_index in restart_csp:
                self._restart_csp()
                timeline.append(
                    {"cycle": cycle, "event": "csp_restarted", "at": _now()}
                )
            report_name = f"soak_{cycle:04d}"
            if clear_local_each_cycle:
                self._quarantine_local_memory(f"before_{report_name}")
            for worker in WORKER_CASES:
                event = self._phase(
                    "recover",
                    worker=worker,
                    report_name=report_name,
                )
                event["cycle"] = cycle
                timeline.append(event)
            evaluation = self._phase("evaluate", report_name=report_name)
            evaluation["cycle"] = cycle
            timeline.append(evaluation)
            completed = len(
                [item for item in timeline if item.get("phase") == "evaluate"]
            )
            self._write(
                "h2_vm_csp_soak_checkpoint.json",
                {
                    "schema_version": "h2-vm-csp-soak-checkpoint:v1",
                    "passed": evaluation["returncode"] == 0,
                    "cycle_offset": cycle_offset,
                    "last_completed_cycle": cycle,
                    "cycles_completed_this_run": completed,
                    "updated_at": _now(),
                },
            )
            if evaluation["returncode"] != 0:
                break
            if cycle_index < cycles and interval_seconds > 0:
                time.sleep(interval_seconds)
        self._collect_remote_evidence()
        evaluations = [
            item for item in timeline if item.get("phase") == "evaluate"
        ]
        report = {
            "schema_version": SCHEMA_VERSION,
            "passed": len(evaluations) == cycles
            and all(item["returncode"] == 0 for item in evaluations),
            "mode": "soak",
            "cycles_requested": cycles,
            "cycles_completed": len(evaluations),
            "cycle_offset": cycle_offset,
            "first_cycle": cycle_offset + 1,
            "last_cycle": cycle_offset + len(evaluations),
            "interval_seconds": interval_seconds,
            "duration_seconds": time.monotonic() - started,
            "restart_csp_cycles": sorted(restart_csp),
            "restart_backend_cycles": sorted(restart_backend),
            "clear_local_each_cycle": clear_local_each_cycle,
            "timeline": timeline,
            "finished_at": _now(),
            "non_claims": [
                "controlled_virtualbox_evidence_not_production_evidence",
                "no_llm_invocation",
                "process_restart_soak_does_not_prove_wan_partition_tolerance",
            ],
        }
        self._write("h2_vm_csp_soak.json", report)
        return report

    def status(self) -> dict[str, Any]:
        self._ensure_homes()
        processes: dict[str, Any] = {}
        for host, pid_name in (
            (self.topology.core, "backend.pid"),
            (self.topology.csp, "csp.pid"),
        ):
            root = self._remote_root(host)
            command = (
                f"if test -s {root}/{pid_name}; then "
                f"pid=$(cat {root}/{pid_name}); "
                'if kill -0 "$pid" 2>/dev/null; then echo running:$pid; '
                "else echo stopped:$pid; fi; else echo missing; fi"
            )
            result = self.commands.ssh(host, command, check=False)
            processes[host.role] = result.stdout.strip()
        health: dict[str, Any] = {}
        for name, url in (
            ("backend", f"{self.topology.backend_url}/healthz"),
            ("csp", f"{self.topology.csp_url}/healthz"),
        ):
            try:
                health[name] = wait_for_url(url, timeout_seconds=2)
            except TimeoutError as exc:
                health[name] = {"error": str(exc)}
        report = {
            "schema_version": "h2-vm-csp-status:v1",
            "processes": processes,
            "health": health,
            "checked_at": _now(),
        }
        self._write("status.json", report)
        return report

    def stop(self) -> dict[str, Any]:
        self._ensure_homes()
        for host, pid_name in (
            (self.topology.core, "backend.pid"),
            (self.topology.csp, "csp.pid"),
        ):
            root = self._remote_root(host)
            self.commands.ssh(
                host,
                f"if test -s {root}/{pid_name}; then "
                f"kill $(cat {root}/{pid_name}) 2>/dev/null || true; "
                f"rm -f {root}/{pid_name}; fi",
                check=False,
            )
        report = {
            "schema_version": "h2-vm-csp-stop:v1",
            "stopped": True,
            "stopped_at": _now(),
        }
        self._write("stop.json", report)
        return report

    def cleanup_remote(self) -> dict[str, Any]:
        self._ensure_homes()
        removed: dict[str, str] = {}
        for host in self._hosts():
            root = self._remote_root(host)
            if (
                not self.topology.remote_root
                or not root
                or root in {"/", ".", self.remote_homes.get(host.role)}
            ):
                raise ValueError(f"refusing unsafe remote cleanup path: {root!r}")
            self.commands.ssh(
                host,
                f"rm -rf -- {quote_command([root])}",
                timeout=120,
            )
            removed[host.role] = root
        report = {
            "schema_version": "h2-vm-csp-cleanup:v1",
            "cleaned": True,
            "removed_remote_roots": removed,
            "cleaned_at": _now(),
        }
        self._write("cleanup.json", report)
        return report

    def _start_backend(self) -> None:
        root = self._remote_root(self.topology.core)
        command = (
            "set -e; "
            f"mkdir -p {root}/data/core {root}/data/core-storage {root}/logs; "
            f"test -s {root}/jwt.secret || "
            f"(umask 077 && openssl rand -hex 32 > {root}/jwt.secret); "
            f"if test -s {root}/backend.pid; then "
            f"kill $(cat {root}/backend.pid) 2>/dev/null || true; fi; "
            "sleep 1; "
            "nohup env "
            f"CIVITASOS_DATA_DIR={root}/data/core "
            f"CIVITASOS_STORAGE_DATA_DIR={root}/data/core-storage "
            f'CIVITASOS_JWT_SECRET="$(cat {root}/jwt.secret)" '
            "CIVITASOS_DEMO_LOGIN_ENABLED=true "
            "CIVITASOS_DEV_FAUCET=true "
            "CIVITASOS_POOL_SWEEP_AUTO_ENABLED=true "
            "CIVITASOS_TASK_CHALLENGE_WINDOW_ENABLED=false "
            "CIVITASOS_EPOCH_AUTO_ENABLED=false "
            f"{root}/bin/api_only --api-port {self.topology.backend_port} "
            f">{root}/logs/backend.log 2>&1 </dev/null & "
            f"echo $! > {root}/backend.pid"
        )
        self.commands.ssh(self.topology.core, command, timeout=30)

    def _start_csp(self) -> None:
        root = self._remote_root(self.topology.csp)
        command = (
            "set -e; "
            f"mkdir -p {root}/data/csp {root}/logs; "
            f"if test -s {root}/csp.pid; then "
            f"kill $(cat {root}/csp.pid) 2>/dev/null || true; fi; "
            "sleep 1; "
            "nohup env "
            f"CIVITASOS_CORE_URL={self.topology.backend_url} "
            f"CSP_PORT={self.topology.csp_port} "
            f"CSP_DATA_DIR={root}/data/csp "
            f"{root}/bin/civitasos-csp "
            f">{root}/logs/csp.log 2>&1 </dev/null & "
            f"echo $! > {root}/csp.pid"
        )
        self.commands.ssh(self.topology.csp, command, timeout=30)

    def _restart_backend(self) -> None:
        self._start_backend()
        wait_for_url(f"{self.topology.backend_url}/healthz", timeout_seconds=45)

    def _restart_csp(self) -> None:
        self._start_csp()
        wait_for_url(
            f"{self.topology.csp_url}/healthz",
            timeout_seconds=45,
            expected_core_reachable=True,
        )

    def _phase(
        self,
        phase: str,
        *,
        worker: str | None = None,
        report_name: str | None = None,
    ) -> dict[str, Any]:
        root = self._remote_root(self.topology.agent)
        remote_run = self._remote_run_root()
        src = f"{root}/src"
        argv = [
            f"{root}/venv/bin/python",
            "-m",
            "benchmarks.h2_vm_csp_phase",
            phase,
            "--run-root",
            remote_run,
            "--backend-url",
            self.topology.backend_url,
            "--csp-url",
            self.topology.csp_url,
            "--agent-address",
            self.topology.agent.address,
        ]
        if worker:
            argv.extend(["--worker", worker])
        if report_name:
            argv.extend(["--report-name", report_name])
        env = (
            f"PYTHONPATH={src}/civitasos-agent:"
            f"{src}/civitasos-runtime:{src}/civitasos-sdk-python"
        )
        command = (
            f"cd {src}/civitasos-agent && {env} {quote_command(argv)}"
        )
        started = time.monotonic()
        result = self.commands.ssh(
            self.topology.agent,
            command,
            timeout=300,
            check=False,
        )
        event = {
            "phase": phase,
            "worker": worker,
            "report_name": report_name,
            "returncode": result.returncode,
            "duration_seconds": time.monotonic() - started,
            "at": _now(),
            "stderr": result.stderr[-2000:],
        }
        timeline_path = self.run_root / "orchestrator_timeline.jsonl"
        timeline_path.parent.mkdir(parents=True, exist_ok=True)
        with timeline_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        if result.returncode != 0:
            raise RuntimeError(
                f"remote phase failed: {phase}/{worker or '-'}\n"
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        return event

    def _quarantine_local_memory(self, label: str) -> None:
        remote_run = self._remote_run_root()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        commands = []
        for worker in WORKER_CASES:
            data = f"{remote_run}/{worker}/data"
            quarantine = f"{remote_run}/{worker}/quarantine/{label}_{stamp}"
            commands.append(
                f"if test -d {data}; then mkdir -p {quarantine}; "
                f"mv {data}/* {quarantine}/ 2>/dev/null || true; fi; "
                f"mkdir -p {data}"
            )
        self.commands.ssh(
            self.topology.agent,
            "set -e; " + "; ".join(commands),
            timeout=30,
        )

    def _collect_remote_evidence(self) -> None:
        self.commands.pull_rsync(
            self.topology.agent,
            self._remote_run_root(),
            self.run_root / "remote_agent",
            timeout=600,
        )
        for host, log_name in (
            (self.topology.core, "backend.log"),
            (self.topology.csp, "csp.log"),
        ):
            root = self._remote_root(host)
            result = self.commands.ssh(
                host,
                f"tail -n 2000 {root}/logs/{log_name}",
                check=False,
            )
            (self.run_root / f"{host.role}_{log_name}").write_text(
                result.stdout,
                encoding="utf-8",
            )

    def _summarize_smoke(self, timeline: list[dict[str, Any]]) -> dict[str, Any]:
        remote = self.run_root / "remote_agent"
        evaluations = {
            name: _read_json(remote / f"{name}.evaluation.json")
            for name in ("csp_recover", "csp_restart_recover")
        }
        local_loss_checks = {}
        for name in evaluations:
            for worker in WORKER_CASES:
                report = _read_json(remote / worker / f"{name}.json")
                local_loss_checks[f"{name}_{worker}_started_without_local_db"] = (
                    report.get("local_db_existed_before") is False
                )
        checks = {
            "csp_recovery_passed": evaluations["csp_recover"].get("passed") is True,
            "csp_restart_recovery_passed": evaluations[
                "csp_restart_recover"
            ].get("passed")
            is True,
            **local_loss_checks,
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "passed": all(checks.values()),
            "mode": "smoke",
            "checks": checks,
            "failure_reasons": [name for name, passed in checks.items() if not passed],
            "topology": self._topology_payload(),
            "evaluations": evaluations,
            "timeline": timeline,
            "finished_at": _now(),
            "non_claims": [
                "controlled_virtualbox_evidence_not_production_evidence",
                "demo_login_enabled_on_host_only_network",
                "no_llm_invocation",
                "smoke_does_not_replace_24h_or_7d_soak",
            ],
        }

    def _ensure_homes(self) -> None:
        if len(self.remote_homes) == 3:
            return
        report_path = self.run_root / "preflight.json"
        if report_path.is_file():
            report = _read_json(report_path)
            self.remote_homes = {
                role: str(payload["home"])
                for role, payload in report.get("hosts", {}).items()
            }
        if len(self.remote_homes) != 3:
            self.preflight()

    def _remote_root(self, host: VmHost) -> str:
        home = self.remote_homes.get(host.role)
        if not home:
            raise RuntimeError(f"remote home not known for {host.role}")
        return shell_path(home, self.topology.remote_root)

    def _agent_python_tag(self) -> str:
        report = _read_json(self.run_root / "preflight.json")
        version = str(report["hosts"]["agent"]["python"]).split(".")
        if len(version) < 2:
            raise ValueError("agent VM Python version is invalid")
        return f"{int(version[0])}{int(version[1])}"

    def _remote_run_root(self) -> str:
        return shell_path(
            self._remote_root(self.topology.agent),
            "runs",
            self.run_root.name,
        )

    def _hosts(self) -> tuple[VmHost, VmHost, VmHost]:
        return (self.topology.core, self.topology.csp, self.topology.agent)

    def _topology_payload(self) -> dict[str, Any]:
        return {
            "core": vars(self.topology.core),
            "csp": vars(self.topology.csp),
            "agent": vars(self.topology.agent),
            "backend_url": self.topology.backend_url,
            "csp_url": self.topology.csp_url,
            "remote_root": self.topology.remote_root,
        }

    def _write(self, name: str, payload: dict[str, Any]) -> None:
        self.run_root.mkdir(parents=True, exist_ok=True)
        _write_json(self.run_root / name, payload)


def _prepare_host_run_root(run_root: Path, *, overwrite: bool) -> None:
    if not run_root.exists():
        run_root.mkdir(parents=True)
        return
    if not any(run_root.iterdir()):
        return
    if not overwrite:
        return
    shutil.rmtree(run_root)
    run_root.mkdir(parents=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "preflight",
            "deploy",
            "start",
            "smoke",
            "soak",
            "status",
            "stop",
            "cleanup",
        ),
    )
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--topology", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--cycles", type=int, default=1)
    parser.add_argument("--cycle-offset", type=int, default=0)
    parser.add_argument("--interval-seconds", type=float, default=600.0)
    parser.add_argument("--restart-csp-cycle", type=int, action="append", default=[])
    parser.add_argument(
        "--restart-backend-cycle",
        type=int,
        action="append",
        default=[],
    )
    parser.add_argument("--keep-local-memory", action="store_true")
    return parser


def main() -> None:
    args = _parser().parse_args()
    agent_root = Path(__file__).resolve().parents[1]
    workspace = agent_root.parent
    run_root = (
        args.run_root
        if args.run_root.is_absolute()
        else (agent_root / args.run_root).resolve()
    )
    _prepare_host_run_root(
        run_root,
        overwrite=args.overwrite and args.command == "preflight",
    )
    runner = VmCspSoakRunner(
        workspace=workspace,
        run_root=run_root,
        topology=load_topology(args.topology),
    )
    if args.command == "preflight":
        report = runner.preflight()
    elif args.command == "deploy":
        report = runner.deploy()
    elif args.command == "start":
        report = runner.start_services()
    elif args.command == "smoke":
        report = runner.smoke(overwrite_remote_run=args.overwrite)
    elif args.command == "soak":
        report = runner.soak(
            cycles=args.cycles,
            cycle_offset=args.cycle_offset,
            interval_seconds=args.interval_seconds,
            restart_csp_cycles=args.restart_csp_cycle,
            restart_backend_cycles=args.restart_backend_cycle,
            clear_local_each_cycle=not args.keep_local_memory,
        )
    elif args.command == "status":
        report = runner.status()
    elif args.command == "stop":
        report = runner.stop()
    else:
        report = runner.cleanup_remote()
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    if "passed" in report and not report["passed"]:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
