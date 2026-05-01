"""Orchestrator — runs benchmark tasks against a configured agent command.

Per task lifecycle (F.0.c v1.1):

    1. Materialise tasks/{task_id}/briefing.json + sentinel dir + raw csv path.
    2. Spawn agent subprocess with BENCHMARK_* env vars set.
    3. Watcher polls every poll_interval_s:
         - sentinel dir for done|failed|give_up   -> SIGTERM, exit code from sentinel
         - raw_ticks csv tail for tick_seq        -> SIGTERM if >= max_ticks
         - elapsed wall-clock                     -> SIGTERM (then SIGKILL after grace)
         - subprocess.poll() returned             -> record exit_code
    4. Write summary entry into runs/{run_id}/summary.json.

Designed for `--max-parallel 1` per F.0; concurrency is a future concern.
"""
from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from collections import deque
import csv
import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .backend_task_client import BackendTaskClient, state_to_sentinel
from .briefing_renderer import write_briefing
from .task_loader import Manifest, TaskSpec, load_manifest

logger = logging.getLogger(__name__)

EXIT_AGENT_DONE = 0
EXIT_TICK_LIMIT = 1
EXIT_ABNORMAL = 2
EXIT_AGENT_FAILED = 3
EXIT_AGENT_GAVE_UP = 4
EXIT_WALL_CLOCK = 124

SENTINEL_NAMES = ("done", "failed", "give_up")
SENTINEL_TO_EXIT = {
    "done": EXIT_AGENT_DONE,
    "failed": EXIT_AGENT_FAILED,
    "give_up": EXIT_AGENT_GAVE_UP,
}

_CLAIM_SPIN_GRACE_TICKS_DEFAULT = 10
_CLAIM_SPIN_WINDOW_DEFAULT = 5
_IDENTITY_PROBE_GRACE_TICKS_DEFAULT = 2
_ORCH_BOOTSTRAP_AUTH_AGENT_ID = "f1c_orchestrator_bootstrap"

# F.1.b backend-mode flag values.
BACKEND_MODE_LEGACY_FAKE = "legacy-fake"   # F.0 path: BENCHMARK_BRIEFING_FILE, agent writes sentinel
BACKEND_MODE_BACKEND_TASKS = "backend-tasks"  # F.1 path: real backend task lifecycle
_VALID_BACKEND_MODES = (BACKEND_MODE_LEGACY_FAKE, BACKEND_MODE_BACKEND_TASKS)


@dataclass
class OrchestratorConfig:
    agent_command: str                  # e.g. "/path/to/venv/bin/python -m benchmarks._fake_agent"
    runs_root: Path                      # e.g. runs/
    wall_clock_per_tick_s: float = 60.0  # F.0.c default
    sigterm_grace_s: float = 10.0        # extra time after SIGTERM before SIGKILL
    poll_interval_s: float = 0.2
    extra_env: dict[str, str] = field(default_factory=dict)
    # ── F.1.b additions ─────────────────────────────────────────────
    backend_mode: str = BACKEND_MODE_LEGACY_FAKE
    backend_client: BackendTaskClient | None = None
    target_agent_id: str | None = None
    backend_capability: str = "general"
    backend_reward: int = 100
    backend_deadline_secs: int = 3600
    backend_poll_interval_s: float = 1.0
    # S5: reuse one long-lived agent.py subprocess across all tasks in a stage.
    reuse_agent_process: bool = False
    # ── auto-rotation of orchestrator identity when wallet drains ──
    # Each fresh quickstart grants ~990 CIV (≈9 task escrows). For long
    # baselines we transparently rotate to a new identity on HTTP 402.
    backend_url: str = "http://localhost:8099"
    orch_agent_name: str = "benchmark-orchestrator"
    orch_identity_path: str | None = None

    def __post_init__(self) -> None:
        if self.backend_mode not in _VALID_BACKEND_MODES:
            raise ValueError(
                f"backend_mode={self.backend_mode!r} must be one of {_VALID_BACKEND_MODES}"
            )
        if self.backend_mode == BACKEND_MODE_BACKEND_TASKS:
            if self.backend_client is None:
                raise ValueError(
                    "backend_mode='backend-tasks' requires backend_client (BackendTaskClient)"
                )
            if not self.target_agent_id:
                raise ValueError(
                    "backend_mode='backend-tasks' requires target_agent_id"
                )


@dataclass
class TaskResult:
    task_id: str
    exit_code: int
    tick_count: int
    wall_clock_ms: float
    raw_csv_rows: int
    agent_self_reported_success: bool | None
    sentinel_kind: str | None
    sentinel_reason: str


@dataclass
class _PersistentAgentSession:
    proc: subprocess.Popen[Any]
    task_id_file: Path
    backend_task_id_file: Path


@dataclass
class RunResult:
    run_id: str
    started_at: str
    finished_at: str
    manifest_path: str
    wall_clock_per_tick_s: float
    tasks_total: int
    tasks_completed: int
    tasks_terminated_abnormally: int
    tasks: list[TaskResult] = field(default_factory=list)


class Orchestrator:
    def __init__(self, manifest: Manifest, config: OrchestratorConfig) -> None:
        self._manifest = manifest
        self._cfg = config

    def run(self, task_ids: list[str] | None = None, *, run_id: str | None = None,
            resume: bool = False) -> RunResult:
        run_id = run_id or _generate_run_id()
        run_dir = self._cfg.runs_root / run_id
        if run_dir.exists() and not resume:
            archived = run_dir.with_suffix(f".archived-{int(time.time())}")
            shutil.move(str(run_dir), str(archived))
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "raw_ticks").mkdir(exist_ok=True)
        (run_dir / "tasks").mkdir(exist_ok=True)

        # Snapshot manifest for reproducibility (don't overwrite on resume).
        snap = run_dir / "manifest.yaml"
        if not snap.exists():
            shutil.copy(self._manifest.path, snap)

        targets = (
            [self._manifest.task_by_id(tid) for tid in task_ids]
            if task_ids
            else list(self._manifest.tasks)
        )

        started = _now_iso()
        t_start = time.monotonic()
        results: list[TaskResult] = []
        skipped = 0
        total = len(targets)
        shared_session: _PersistentAgentSession | None = None
        try:
            for idx, task in enumerate(targets, 1):
                cached = _load_cached_result(run_dir, task.id) if resume else None
                if cached is not None:
                    results.append(cached)
                    skipped += 1
                    print(
                        f"[progress] {idx}/{total} {task.id} SKIP (cached:{cached.sentinel_kind})",
                        flush=True,
                    )
                    continue
                print(f"[progress] {idx}/{total} {task.id} START", flush=True)
                if (
                    self._cfg.reuse_agent_process
                    and self._cfg.backend_mode == BACKEND_MODE_BACKEND_TASKS
                ):
                    if shared_session is None:
                        shared_session = self._spawn_shared_agent(
                            run_id=run_id, run_dir=run_dir, initial_task_id=task.id,
                        )
                    r = self._run_one_reuse(
                        task, run_id=run_id, run_dir=run_dir, session=shared_session,
                    )
                else:
                    r = self._run_one(task, run_id=run_id, run_dir=run_dir)
                results.append(r)
                done = idx
                elapsed = time.monotonic() - t_start
                done_runs = max(done - skipped, 1)
                avg = elapsed / done_runs
                remaining = total - done
                eta_s = int(avg * remaining)
                eta_h, eta_rem = divmod(eta_s, 3600)
                eta_m, _ = divmod(eta_rem, 60)
                print(
                    f"[progress] {idx}/{total} {task.id} "
                    f"{r.sentinel_kind or 'none'} ({r.wall_clock_ms/1000:.1f}s, "
                    f"{r.tick_count} ticks)  elapsed={elapsed/60:.1f}m "
                    f"ETA={eta_h}h{eta_m:02d}m",
                    flush=True,
                )
        finally:
            if shared_session is not None:
                _terminate(shared_session.proc, self._cfg.sigterm_grace_s, then_kill=True)
        finished = _now_iso()

        if resume and skipped:
            logger.info("resume: skipped %d / %d tasks", skipped, len(results))

        run_result = RunResult(
            run_id=run_id,
            started_at=started,
            finished_at=finished,
            manifest_path=str(self._manifest.path),
            wall_clock_per_tick_s=self._cfg.wall_clock_per_tick_s,
            tasks_total=len(results),
            tasks_completed=sum(
                1 for r in results
                if r.exit_code in (EXIT_AGENT_DONE, EXIT_AGENT_FAILED, EXIT_AGENT_GAVE_UP)
            ),
            tasks_terminated_abnormally=sum(
                1 for r in results
                if r.exit_code in (EXIT_TICK_LIMIT, EXIT_ABNORMAL, EXIT_WALL_CLOCK)
            ),
            tasks=results,
        )
        _write_summary(run_dir, run_result)
        return run_result

    # ---------------------------------------------------------------- internals

    def _topup_orchestrator_via_faucet(self, amount: int = 5000) -> bool:
        """Request CIV from the dev faucet for the active orchestrator agent.

        Requires the backend to have ``CIVITASOS_DEV_FAUCET=true`` in its env.
        Returns True on success, False on any failure (caller falls back to
        identity rotation).
        """
        cfg = self._cfg
        try:
            sdk = cfg.backend_client._sdk  # type: ignore[attr-defined]
            agent_id = getattr(sdk, "_agent_id", None)
            if not agent_id:
                return False
            if not getattr(sdk, "_jwt_token", None):
                _bootstrap_demo_jwt(sdk, cfg.backend_url, agent_id)
            import urllib.request as _ur
            import urllib.error as _ue
            import json as _json
            headers = {"Content-Type": "application/json"}
            token = getattr(sdk, "_jwt_token", None)
            if token:
                headers["Authorization"] = f"Bearer {token}"
            req = _ur.Request(
                f"{cfg.backend_url}/api/v1/a2a/economics/faucet/{agent_id}",
                data=_json.dumps({"amount": amount}).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with _ur.urlopen(req, timeout=10) as resp:
                body = _json.loads(resp.read().decode("utf-8"))
            logger.info(
                "[orch-faucet] granted=%s balance=%s circulation_remaining=%s",
                body.get("granted"), body.get("balance"), body.get("circulation_remaining"),
            )
            return True
        except _ue.HTTPError as exc:  # noqa: F821 — _ue defined just above
            logger.warning("[orch-faucet] HTTP %s: %s", exc.code, exc.read()[:200])
            return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("[orch-faucet] unexpected error: %s", exc)
            return False

    def _backend_task_extra_input(self, task: TaskSpec, *, task_dir: Path) -> dict[str, Any]:
        """Build extra backend task input for stage-specific read models."""
        if "h0e" not in task.id.lower():
            return {}
        if not _env_bool("BENCHMARK_H0E_BACKEND_REVISION_SEED_ENABLED", default=True):
            return {}
        client = self._cfg.backend_client
        if client is None:
            return {}
        try:
            sdk = client._sdk  # type: ignore[attr-defined]
            proposer = str(getattr(sdk, "_agent_id", "") or self._cfg.orch_agent_name)
            profile = _h0e_revision_seed_profile(task.id)
            replay = _h0e_iem_anchor_replay_payload(task.id, profile)
            (task_dir / "h0e_iem_anchor_replay.json").write_text(
                json.dumps(replay, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            revision_payload = client.create_normative_revision(
                proposer=proposer,
                rule_id=str(profile["rule_id"]),
                old_value=profile["old_value"],
                new_value=profile["new_value"],
                authority=str(profile["authority"]),
                iem_anchor=replay["anchor"],
            )
            revision = revision_payload.get("governed_revision_context") or {}
            proposal = revision_payload.get("proposal") or {}
            proposal_id = str(revision.get("proposal_id") or proposal.get("id") or "")
            revision_id = str(revision.get("revision_id") or "")
            if not proposal_id or not revision_id:
                raise ValueError(f"normative revision response missing ids: {revision_payload}")
            self._seed_h0e_governance_votes(client, proposal_id, proposer=proposer)
            finalized = client.finalize_governance_proposal(proposal_id, approved=True)
            finalized_revision = finalized.get("governed_revision_context") or revision
            (task_dir / "h0e_governed_revision.json").write_text(
                json.dumps(finalized_revision, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return {
                "benchmark_task_id": task.id,
                "governed_revision_id": revision_id,
                "governance_proposal_id": proposal_id,
            }
        except Exception as exc:  # noqa: BLE001
            if _env_bool("BENCHMARK_H0E_REQUIRE_BACKEND_SOURCE", default=False):
                raise
            logger.warning(
                "[orch-h0e] task=%s backend governed revision seed failed; "
                "benchmark_mode may fall back to synthetic context: %s",
                task.id,
                exc,
            )
            return {}

    def _seed_h0e_governance_votes(
        self,
        client: BackendTaskClient,
        proposal_id: str,
        *,
        proposer: str,
    ) -> None:
        voters: list[str] = []
        for candidate in (proposer, self._cfg.target_agent_id):
            if candidate and candidate not in voters:
                voters.append(candidate)
        for idx, voter_id in enumerate(voters[:2]):
            client.cast_governance_vote(
                proposal_id,
                voter_id=voter_id,
                choice="yes",
                stake=144 if idx == 0 else 121,
                delegated=False,
            )

    def _rotate_orchestrator_identity(self) -> None:
        """Generate a fresh orchestrator key and re-register it for continued escrow."""
        from civitasos import CivitasAgent  # type: ignore[import-not-found]
        from pathlib import Path as _P

        cfg = self._cfg
        assert cfg.backend_client is not None
        old_path = _P(cfg.orch_identity_path) if cfg.orch_identity_path else None
        if old_path and old_path.exists():
            archived = old_path.with_suffix(
                old_path.suffix + f".drained-{int(time.time())}"
            )
            try:
                shutil.move(str(old_path), str(archived))
                logger.info("[orch-rotate] archived drained key: %s", archived)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[orch-rotate] could not archive old key: %s", exc)

        sdk = CivitasAgent(base_url=cfg.backend_url)
        sdk.generate_keys()  # type: ignore[attr-defined]
        unique_name = f"{cfg.orch_agent_name}-r{int(time.time())}"
        bootstrap_id = (
            _ORCH_BOOTSTRAP_AUTH_AGENT_ID
            if _institutional_identity_enabled()
            else unique_name
        )
        _bootstrap_demo_jwt(sdk, cfg.backend_url, bootstrap_id)
        did = _register_orchestrator_identity(
            sdk,
            backend_url=cfg.backend_url,
            name=unique_name,
            alias=unique_name,
            description="F.1.c benchmark orchestrator (rotated identity)",
        )
        if old_path is not None:
            old_path.parent.mkdir(parents=True, exist_ok=True)
            sdk.save_identity(str(old_path))  # type: ignore[attr-defined]
        logger.info(
            "[orch-rotate] new orchestrator agent_id=%s",
            did,
        )
        # Swap the SDK inside the existing BackendTaskClient.
        cfg.backend_client._sdk = sdk  # type: ignore[attr-defined]

    def _spawn_shared_agent(
        self, *, run_id: str, run_dir: Path, initial_task_id: str,
    ) -> _PersistentAgentSession:
        """Start one long-lived agent subprocess reused across multiple tasks."""
        runtime_dir = run_dir / "shared_runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        raw_dir = run_dir / "raw_ticks"
        raw_dir.mkdir(parents=True, exist_ok=True)

        task_id_file = runtime_dir / "current_task_id.txt"
        backend_task_id_file = runtime_dir / "current_backend_task_id.txt"
        task_id_file.write_text(initial_task_id, encoding="utf-8")
        backend_task_id_file.write_text("", encoding="utf-8")

        env = {
            **os.environ,
            **self._cfg.extra_env,
            "BENCHMARK_RUN_ID": run_id,
            # BENCHMARK_TASK_ID is only used as the install switch at startup.
            "BENCHMARK_TASK_ID": initial_task_id,
            # BENCHMARK_BACKEND_TASK_ID must be non-empty so benchmark mode
            # installs the target-task rule; real ids come from the file below.
            "BENCHMARK_BACKEND_TASK_ID": "bootstrap-target",
            "BENCHMARK_TASK_ID_FILE": str(task_id_file),
            "BENCHMARK_BACKEND_TASK_ID_FILE": str(backend_task_id_file),
            # Keep legacy var for compatibility; collector rotates by *_DIR + *_FILE.
            "BENCHMARK_RAW_CSV": str(raw_dir / f"{initial_task_id}.csv"),
            "BENCHMARK_RAW_CSV_DIR": str(raw_dir),
            "BENCHMARK_SENTINEL_DIR": str(runtime_dir / "sentinel"),
        }
        (runtime_dir / "sentinel").mkdir(exist_ok=True)

        cmd = shlex.split(self._cfg.agent_command)
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=(run_dir / "agent_stdout.log").open("ab"),
            stderr=(run_dir / "agent_stderr.log").open("ab"),
        )
        logger.info("spawned shared benchmark agent process pid=%s", proc.pid)
        return _PersistentAgentSession(
            proc=proc,
            task_id_file=task_id_file,
            backend_task_id_file=backend_task_id_file,
        )

    def _run_one_reuse(
        self, task: TaskSpec, *, run_id: str, run_dir: Path, session: _PersistentAgentSession,
    ) -> TaskResult:
        """Run one task while reusing a shared long-lived agent process."""
        task_dir = run_dir / "tasks" / task.id
        task_dir.mkdir(parents=True, exist_ok=True)
        sentinel_dir = task_dir / "sentinel"
        sentinel_dir.mkdir(exist_ok=True)
        raw_csv = run_dir / "raw_ticks" / f"{task.id}.csv"

        assert self._cfg.backend_mode == BACKEND_MODE_BACKEND_TASKS
        assert self._cfg.backend_client is not None
        assert self._cfg.target_agent_id is not None

        # Publish current task ids for benchmark_mode rule/collector inside agent.py.
        session.task_id_file.write_text(task.id, encoding="utf-8")
        pre_task_probe_ticks = 0
        if _env_bool("BENCHMARK_G2_MODE_PROBE_ENABLED", default=False):
            # Hold back the backend target id briefly so benchmark_mode can let
            # the real LLM make one no-active-task subjective-time decision.
            session.backend_task_id_file.write_text("", encoding="utf-8")
            pre_task_probe_ticks = _wait_for_g2_mode_probe_ticks(
                raw_csv=raw_csv,
                proc=session.proc,
                min_ticks=_env_int("BENCHMARK_G2_MODE_PROBE_TICKS", 1, min_value=0),
                timeout_s=_env_float("BENCHMARK_G2_MODE_PROBE_TIMEOUT_S", 90.0, min_value=0.0),
                poll_interval_s=self._cfg.poll_interval_s,
            )
            if pre_task_probe_ticks > 0:
                logger.info(
                    "[orch-g2-probe] task=%s observed %d pre-task tick(s)",
                    task.id,
                    pre_task_probe_ticks,
                )
            else:
                logger.warning(
                    "[orch-g2-probe] task=%s produced no pre-task tick before timeout",
                    task.id,
                )

            self._seed_backend_relation_failures(task, task_dir=task_dir)
            pre_target_ticks = _tail_tick_seq(raw_csv)
            if pre_target_ticks > pre_task_probe_ticks:
                logger.info(
                    "[orch-g3-seed] task=%s counted %d pre-target tick(s) after failure seeding",
                    task.id,
                    pre_target_ticks,
                )

        backend_task_id: str
        extra_input = self._backend_task_extra_input(task, task_dir=task_dir)
        try:
            backend_task_id = self._cfg.backend_client.create(
                briefing=task.briefing,
                target_agent_id=self._cfg.target_agent_id,
                capability=self._cfg.backend_capability,
                reward=self._cfg.backend_reward,
                deadline_secs=self._cfg.backend_deadline_secs,
                extra_input=extra_input,
            )
        except Exception as exc:  # noqa: BLE001
            status = getattr(exc, "status_code", None)
            msg_l = str(exc).lower()
            is_402 = status == 402 or "insufficient funds" in msg_l or "402" in msg_l
            if not is_402:
                raise
            logger.warning(
                "[orch-recover] task=%s hit 402 — trying dev faucet first",
                task.id,
            )
            if not self._topup_orchestrator_via_faucet():
                logger.warning(
                    "[orch-recover] faucet unavailable, falling back to identity rotation",
                )
                self._rotate_orchestrator_identity()
            backend_task_id = self._cfg.backend_client.create(
                briefing=task.briefing,
                target_agent_id=self._cfg.target_agent_id,
                capability=self._cfg.backend_capability,
                reward=self._cfg.backend_reward,
                deadline_secs=self._cfg.backend_deadline_secs,
                extra_input=extra_input,
            )

        (task_dir / "backend_task_id.txt").write_text(backend_task_id, encoding="utf-8")
        session.backend_task_id_file.write_text(backend_task_id, encoding="utf-8")

        wall_clock_budget_s = task.max_ticks * self._cfg.wall_clock_per_tick_s
        claim_spin_grace_ticks = _env_int(
            "BENCHMARK_CLAIM_SPIN_GRACE_TICKS",
            _CLAIM_SPIN_GRACE_TICKS_DEFAULT,
            min_value=0,
        )
        claim_spin_window = _env_int(
            "BENCHMARK_CLAIM_SPIN_WINDOW",
            _CLAIM_SPIN_WINDOW_DEFAULT,
            min_value=2,
        )
        identity_probe_grace_ticks = _env_int(
            "BENCHMARK_IDENTITY_PROBE_GRACE_TICKS",
            _IDENTITY_PROBE_GRACE_TICKS_DEFAULT,
            min_value=0,
        )
        tick_limit_budget = task.max_ticks + pre_target_ticks
        claim_spin_grace_used = False
        identity_probe_grace_used = False
        t0 = time.monotonic()
        sentinel_kind: str | None = None
        sentinel_reason = ""
        exit_code: int | None = None

        while True:
            # 1) shared process crashed
            if session.proc.poll() is not None:
                code = session.proc.returncode
                sentinel_kind, sentinel_reason = self._sentinel_from_backend(
                    backend_task_id, sentinel_dir,
                )
                if sentinel_kind is not None:
                    exit_code = SENTINEL_TO_EXIT[sentinel_kind]
                elif code == 0:
                    exit_code = EXIT_AGENT_DONE
                else:
                    exit_code = EXIT_ABNORMAL
                break

            # 2) backend task state
            sentinel_kind, sentinel_reason = self._sentinel_from_backend(
                backend_task_id, sentinel_dir,
            )
            if sentinel_kind is not None:
                exit_code = SENTINEL_TO_EXIT[sentinel_kind]
                break

            # 3) tick limit
            tick_seq = _tail_tick_seq(raw_csv)
            if tick_seq >= tick_limit_budget:
                if (
                    not identity_probe_grace_used
                    and identity_probe_grace_ticks > 0
                ):
                    eligible, reason = self._can_grant_identity_probe_grace(
                        backend_task_id=backend_task_id,
                        raw_csv=raw_csv,
                    )
                    if eligible:
                        identity_probe_grace_used = True
                        prev = tick_limit_budget
                        tick_limit_budget += identity_probe_grace_ticks
                        logger.warning(
                            "[orch-identity-grace] task=%s extending tick limit %d -> %d (%s)",
                            task.id,
                            prev,
                            tick_limit_budget,
                            reason,
                        )
                        continue
                if (
                    not claim_spin_grace_used
                    and claim_spin_grace_ticks > 0
                ):
                    eligible, reason = self._can_grant_claim_spin_grace(
                        backend_task_id=backend_task_id,
                        raw_csv=raw_csv,
                        window=claim_spin_window,
                    )
                    if eligible:
                        claim_spin_grace_used = True
                        prev = tick_limit_budget
                        tick_limit_budget += claim_spin_grace_ticks
                        logger.warning(
                            "[orch-claim-grace] task=%s extending tick limit %d -> %d (%s)",
                            task.id,
                            prev,
                            tick_limit_budget,
                            reason,
                        )
                        continue
                exit_code = EXIT_TICK_LIMIT
                self._cfg.backend_client.force_fail(backend_task_id)
                break

            # 4) wall-clock
            if (time.monotonic() - t0) >= wall_clock_budget_s:
                exit_code = EXIT_WALL_CLOCK
                self._cfg.backend_client.force_fail(backend_task_id)
                break

            time.sleep(self._cfg.poll_interval_s)

        (task_dir / "exit_code.txt").write_text(
            str(exit_code if exit_code is not None else EXIT_ABNORMAL),
            encoding="utf-8",
        )

        wall_ms = (time.monotonic() - t0) * 1000.0
        tick_count = _tail_tick_seq(raw_csv)
        raw_rows = _csv_row_count(raw_csv)
        if sentinel_kind == "done":
            self_reported = True
        elif sentinel_kind in ("failed", "give_up"):
            self_reported = False
        else:
            self_reported = None

        result = TaskResult(
            task_id=task.id,
            exit_code=exit_code if exit_code is not None else EXIT_ABNORMAL,
            tick_count=tick_count,
            wall_clock_ms=wall_ms,
            raw_csv_rows=raw_rows,
            agent_self_reported_success=self_reported,
            sentinel_kind=sentinel_kind,
            sentinel_reason=sentinel_reason,
        )
        (task_dir / "result.json").write_text(
            json.dumps(asdict(result), default=str), encoding="utf-8",
        )
        return result

    def _run_one(self, task: TaskSpec, *, run_id: str, run_dir: Path) -> TaskResult:
        task_dir = run_dir / "tasks" / task.id
        task_dir.mkdir(parents=True, exist_ok=True)
        sentinel_dir = task_dir / "sentinel"
        sentinel_dir.mkdir(exist_ok=True)
        raw_csv = run_dir / "raw_ticks" / f"{task.id}.csv"

        env = {
            **os.environ,
            **self._cfg.extra_env,
            "BENCHMARK_RUN_ID": run_id,
            "BENCHMARK_TASK_ID": task.id,
            "BENCHMARK_RAW_CSV": str(raw_csv),
            "BENCHMARK_SENTINEL_DIR": str(sentinel_dir),
        }

        # F.1.b: branch on backend_mode for briefing delivery.
        backend_task_id: str | None = None
        if self._cfg.backend_mode == BACKEND_MODE_BACKEND_TASKS:
            assert self._cfg.backend_client is not None  # guaranteed by __post_init__
            assert self._cfg.target_agent_id is not None
            self._seed_backend_relation_failures(task, task_dir=task_dir)
            extra_input = self._backend_task_extra_input(task, task_dir=task_dir)
            try:
                backend_task_id = self._cfg.backend_client.create(
                    briefing=task.briefing,
                    target_agent_id=self._cfg.target_agent_id,
                    capability=self._cfg.backend_capability,
                    reward=self._cfg.backend_reward,
                    deadline_secs=self._cfg.backend_deadline_secs,
                    extra_input=extra_input,
                )
            except Exception as exc:  # noqa: BLE001
                # On 402 (Insufficient funds) rotate the orchestrator identity
                # to obtain a fresh quickstart grant and retry once.
                status = getattr(exc, "status_code", None)
                msg_l = str(exc).lower()
                is_402 = status == 402 or "insufficient funds" in msg_l or "402" in msg_l
                if not is_402:
                    raise
                logger.warning(
                    "[orch-recover] task=%s hit 402 \u2014 trying dev faucet first",
                    task.id,
                )
                if not self._topup_orchestrator_via_faucet():
                    logger.warning(
                        "[orch-recover] faucet unavailable, falling back to identity rotation",
                    )
                    self._rotate_orchestrator_identity()
                backend_task_id = self._cfg.backend_client.create(
                    briefing=task.briefing,
                    target_agent_id=self._cfg.target_agent_id,
                    capability=self._cfg.backend_capability,
                    reward=self._cfg.backend_reward,
                    deadline_secs=self._cfg.backend_deadline_secs,
                    extra_input=extra_input,
                )
            (task_dir / "backend_task_id.txt").write_text(backend_task_id, encoding="utf-8")
            env["BENCHMARK_BACKEND_TASK_ID"] = backend_task_id
        else:
            briefing_path = task_dir / "briefing.json"
            write_briefing(task, run_id=run_id, out_path=briefing_path)
            env["BENCHMARK_BRIEFING_FILE"] = str(briefing_path)

        wall_clock_budget_s = task.max_ticks * self._cfg.wall_clock_per_tick_s
        claim_spin_grace_ticks = _env_int(
            "BENCHMARK_CLAIM_SPIN_GRACE_TICKS",
            _CLAIM_SPIN_GRACE_TICKS_DEFAULT,
            min_value=0,
        )
        claim_spin_window = _env_int(
            "BENCHMARK_CLAIM_SPIN_WINDOW",
            _CLAIM_SPIN_WINDOW_DEFAULT,
            min_value=2,
        )
        identity_probe_grace_ticks = _env_int(
            "BENCHMARK_IDENTITY_PROBE_GRACE_TICKS",
            _IDENTITY_PROBE_GRACE_TICKS_DEFAULT,
            min_value=0,
        )
        tick_limit_budget = task.max_ticks
        claim_spin_grace_used = False
        identity_probe_grace_used = False

        cmd = shlex.split(self._cfg.agent_command)
        t0 = time.monotonic()
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=(task_dir / "agent_stdout.log").open("wb"),
            stderr=(task_dir / "agent_stderr.log").open("wb"),
        )

        sentinel_kind: str | None = None
        sentinel_reason = ""
        exit_code: int | None = None

        try:
            while True:
                # 1. natural exit
                if proc.poll() is not None:
                    code = proc.returncode
                    # F.1.b backend-mode: backend state may have flipped before our poll;
                    # check it first so we attribute correctly.
                    if backend_task_id is not None:
                        sentinel_kind, sentinel_reason = self._sentinel_from_backend(
                            backend_task_id, sentinel_dir,
                        )
                    if sentinel_kind is None:
                        sentinel_kind, sentinel_reason = _read_sentinel(sentinel_dir)
                    if sentinel_kind is not None:
                        exit_code = SENTINEL_TO_EXIT[sentinel_kind]
                    elif code == 0:
                        exit_code = EXIT_AGENT_DONE
                    else:
                        exit_code = EXIT_ABNORMAL
                    break

                # 2. backend task state (F.1.b) OR file sentinel (F.0)
                if backend_task_id is not None:
                    sentinel_kind, sentinel_reason = self._sentinel_from_backend(
                        backend_task_id, sentinel_dir,
                    )
                else:
                    sentinel_kind, sentinel_reason = _read_sentinel(sentinel_dir)
                if sentinel_kind is not None:
                    exit_code = SENTINEL_TO_EXIT[sentinel_kind]
                    _terminate(proc, self._cfg.sigterm_grace_s)
                    break

                # 3. tick limit
                tick_seq = _tail_tick_seq(raw_csv)
                if tick_seq >= tick_limit_budget:
                    if (
                        not identity_probe_grace_used
                        and backend_task_id is not None
                        and identity_probe_grace_ticks > 0
                    ):
                        eligible, reason = self._can_grant_identity_probe_grace(
                            backend_task_id=backend_task_id,
                            raw_csv=raw_csv,
                        )
                        if eligible:
                            identity_probe_grace_used = True
                            prev = tick_limit_budget
                            tick_limit_budget += identity_probe_grace_ticks
                            logger.warning(
                                "[orch-identity-grace] task=%s extending tick limit %d -> %d (%s)",
                                task.id,
                                prev,
                                tick_limit_budget,
                                reason,
                            )
                            continue
                    if (
                        not claim_spin_grace_used
                        and backend_task_id is not None
                        and claim_spin_grace_ticks > 0
                    ):
                        eligible, reason = self._can_grant_claim_spin_grace(
                            backend_task_id=backend_task_id,
                            raw_csv=raw_csv,
                            window=claim_spin_window,
                        )
                        if eligible:
                            claim_spin_grace_used = True
                            prev = tick_limit_budget
                            tick_limit_budget += claim_spin_grace_ticks
                            logger.warning(
                                "[orch-claim-grace] task=%s extending tick limit %d -> %d (%s)",
                                task.id,
                                prev,
                                tick_limit_budget,
                                reason,
                            )
                            continue
                    exit_code = EXIT_TICK_LIMIT
                    _terminate(proc, self._cfg.sigterm_grace_s)
                    if backend_task_id is not None:
                        self._cfg.backend_client.force_fail(backend_task_id)  # type: ignore[union-attr]
                    break

                # 4. wall-clock
                if (time.monotonic() - t0) >= wall_clock_budget_s:
                    exit_code = EXIT_WALL_CLOCK
                    _terminate(proc, self._cfg.sigterm_grace_s, then_kill=True)
                    if backend_task_id is not None:
                        self._cfg.backend_client.force_fail(backend_task_id)  # type: ignore[union-attr]
                    break

                time.sleep(self._cfg.poll_interval_s)
        finally:
            (task_dir / "exit_code.txt").write_text(
                str(exit_code if exit_code is not None else EXIT_ABNORMAL),
                encoding="utf-8",
            )

        wall_ms = (time.monotonic() - t0) * 1000.0
        tick_count = _tail_tick_seq(raw_csv)
        raw_rows = _csv_row_count(raw_csv)
        # agent_self_reported_success: True iff sentinel == done; False iff sentinel == failed/give_up;
        # None if no sentinel was written (i.e. terminated by orchestrator without agent opinion).
        if sentinel_kind == "done":
            self_reported = True
        elif sentinel_kind in ("failed", "give_up"):
            self_reported = False
        else:
            self_reported = None

        result = TaskResult(
            task_id=task.id,
            exit_code=exit_code if exit_code is not None else EXIT_ABNORMAL,
            tick_count=tick_count,
            wall_clock_ms=wall_ms,
            raw_csv_rows=raw_rows,
            agent_self_reported_success=self_reported,
            sentinel_kind=sentinel_kind,
            sentinel_reason=sentinel_reason,
        )
        # Per-task checkpoint enables --resume.
        (task_dir / "result.json").write_text(
            json.dumps(asdict(result), default=str), encoding="utf-8",
        )
        return result

    def _seed_backend_relation_failures(self, task: TaskSpec, *, task_dir: Path) -> list[str]:
        """Materialise task-declared G.3 failure-memory preconditions."""
        count = max(0, int(getattr(task, "backend_seed_failures", 0) or 0))
        if count <= 0:
            return []
        if not _env_bool("BENCHMARK_G3_SEED_FAILURES_ENABLED", default=True):
            return []
        if self._cfg.backend_mode != BACKEND_MODE_BACKEND_TASKS:
            return []
        client = self._cfg.backend_client
        target_agent_id = self._cfg.target_agent_id
        if client is None or not target_agent_id:
            raise RuntimeError("backend failure seeding requires backend_client and target_agent_id")

        reward = _env_int("BENCHMARK_G3_SEED_FAILURE_REWARD", 1, min_value=1)
        deadline_secs = _env_int("BENCHMARK_G3_SEED_FAILURE_DEADLINE_SECS", 60, min_value=1)
        claim_timeout_s = _env_float(
            "BENCHMARK_G3_SEED_FAILURE_CLAIM_TIMEOUT_S",
            40.0,
            min_value=0.0,
        )
        claim_retry_interval_s = _env_float(
            "BENCHMARK_G3_SEED_FAILURE_CLAIM_RETRY_INTERVAL_S",
            1.0,
            min_value=0.05,
        )
        seeded_ids: list[str] = []
        for idx in range(count):
            seed_id = client.seed_failure(
                briefing=(
                    f"G.3 relation failure seed {idx + 1}/{count} for {task.id}. "
                    "This hidden precondition exists only to ground relation-pair "
                    "failure-memory observability."
                ),
                target_agent_id=target_agent_id,
                capability=self._cfg.backend_capability,
                reward=reward,
                deadline_secs=deadline_secs,
                claim_timeout_s=claim_timeout_s,
                claim_retry_interval_s=claim_retry_interval_s,
            )
            seeded_ids.append(seed_id)
        if seeded_ids:
            (task_dir / "backend_seed_failure_ids.json").write_text(
                json.dumps(seeded_ids),
                encoding="utf-8",
            )
            logger.info("seeded %d backend failure(s) for %s", len(seeded_ids), task.id)
        return seeded_ids

    # ---- F.1.b: backend-task state polling ---------------------------

    def _sentinel_from_backend(
        self, backend_task_id: str, sentinel_dir: Path,
    ) -> tuple[str | None, str]:
        """Translate backend task state into (sentinel_kind, reason) when terminal.

        Side effects: when terminal, materialises ``<sentinel_dir>/<kind>`` so
        downstream tooling that scans the sentinel dir (e.g. F.0 callers,
        debuggers) sees a uniform record. On Delivered/Completed, performs
        best-effort settlement cleanup (D1).
        """
        client = self._cfg.backend_client
        assert client is not None  # type-narrow; callers gate on backend_task_id
        try:
            state = client.get_state(backend_task_id)
        except LookupError:
            # Vanished mid-run \u2192 treat as Cancelled per backend_task_client policy.
            kind, reason = "give_up", f"backend task {backend_task_id} vanished from pool"
            self._materialise_sentinel(sentinel_dir, kind, reason)
            return kind, reason
        except Exception as exc:  # noqa: BLE001 \u2014 transient backend errors must not abort run
            logger.warning("get_state(%s) failed: %s", backend_task_id, exc)
            return None, ""
        if not state.is_terminal:
            return None, ""
        kind, reason = state_to_sentinel(state)
        self._materialise_sentinel(sentinel_dir, kind, reason)
        # D1 settlement cleanup on success path.
        if state.status in ("Delivered", "Completed"):
            client.confirm(backend_task_id)
        return kind, reason

    def _can_grant_claim_spin_grace(
        self,
        *,
        backend_task_id: str,
        raw_csv: Path,
        window: int,
    ) -> tuple[bool, str]:
        """Allow one tick-budget extension only for benchmark claim-cooldown spin."""
        client = self._cfg.backend_client
        if client is None:
            return False, "backend client unavailable"
        if not _tail_actions_all_pool_claim(raw_csv, window=window):
            return False, "tail actions are not pure pool_claim failures"
        try:
            state = client.get_state(backend_task_id)
        except Exception as exc:  # noqa: BLE001
            return False, f"cannot read backend state: {exc}"
        if state.status != "Open":
            return False, f"backend status={state.status}"
        return True, "backend status=Open with sustained pool_claim retries"

    def _can_grant_identity_probe_grace(
        self,
        *,
        backend_task_id: str,
        raw_csv: Path,
    ) -> tuple[bool, str]:
        """Allow one tiny extension when an identity probe consumed the last tick."""
        client = self._cfg.backend_client
        if client is None:
            return False, "backend client unavailable"
        last_action = _tail_last_action(raw_csv)
        if not last_action.startswith("identity_probe_"):
            return False, f"last action is {last_action or 'none'}"
        try:
            state = client.get_state(backend_task_id)
        except Exception as exc:  # noqa: BLE001
            return False, f"cannot read backend state: {exc}"
        if state.status != "Claimed":
            return False, f"backend status={state.status}"
        return True, f"backend status=Claimed after {last_action}"

    @staticmethod
    def _materialise_sentinel(sentinel_dir: Path, kind: str, reason: str) -> None:
        path = sentinel_dir / kind
        if path.exists():
            return  # do not overwrite earlier write
        payload = {"success": kind == "done", "reason": reason, "final_artifact": None}
        path.write_text(json.dumps(payload), encoding="utf-8")


# ----------------------------------------------------------------- helpers

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_run_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:4]
    return f"baseline-{ts}-{suffix}"


def _load_cached_result(run_dir: Path, task_id: str) -> "TaskResult | None":
    """Load a previously persisted per-task result for --resume mode.

    Tries result.json first; if absent, reconstructs a best-effort result
    from exit_code.txt + sentinel/<kind> + raw_ticks/<task_id>.csv so that
    runs created before the result.json checkpoint format are resumable.
    Returns None when no usable evidence exists (task will be re-run).
    """
    task_dir = run_dir / "tasks" / task_id
    p = task_dir / "result.json"
    if p.is_file():
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            cached = TaskResult(**d)
            # Resume should re-run unfinished/abnormal tasks even if result.json
            # exists (e.g., prior EXIT_TICK_LIMIT with no terminal sentinel).
            if (
                cached.sentinel_kind is None
                and cached.exit_code in (EXIT_TICK_LIMIT, EXIT_ABNORMAL, EXIT_WALL_CLOCK)
            ):
                return None
            return cached
        except Exception as exc:  # noqa: BLE001
            logger.warning("resume: dropping unreadable result for %s: %s", task_id, exc)
            return None
    # Backfill path: require exit_code.txt + a terminal sentinel.
    exit_path = task_dir / "exit_code.txt"
    sentinel_dir = task_dir / "sentinel"
    if not exit_path.is_file() or not sentinel_dir.is_dir():
        return None
    kind, reason = _read_sentinel(sentinel_dir)
    if kind is None:
        return None  # never reached terminal state — re-run
    try:
        exit_code = int(exit_path.read_text().strip())
    except Exception:  # noqa: BLE001
        return None
    raw_csv = run_dir / "raw_ticks" / f"{task_id}.csv"
    tick_count = _tail_tick_seq(raw_csv)
    raw_rows = _csv_row_count(raw_csv)
    self_reported = (
        True if kind == "done"
        else False if kind in ("failed", "give_up")
        else None
    )
    result = TaskResult(
        task_id=task_id,
        exit_code=exit_code,
        tick_count=tick_count,
        wall_clock_ms=0.0,  # not recoverable from disk
        raw_csv_rows=raw_rows,
        agent_self_reported_success=self_reported,
        sentinel_kind=kind,
        sentinel_reason=reason,
    )
    # Persist so future resumes use the fast path.
    try:
        p.write_text(json.dumps(asdict(result), default=str), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    return result


def _read_sentinel(sentinel_dir: Path) -> tuple[str | None, str]:
    for name in SENTINEL_NAMES:
        p = sentinel_dir / name
        if p.exists():
            try:
                payload = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = {}
            return name, str(payload.get("reason", ""))
    return None, ""


def _tail_tick_seq(csv_path: Path) -> int:
    """Read last data row's tick_seq from raw_ticks CSV. 0 if none yet."""
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return 0
    try:
        with csv_path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = 4096
            data = b""
            while size > 0 and data.count(b"\n") < 2:
                read_size = min(block, size)
                size -= read_size
                fh.seek(size)
                data = fh.read(read_size) + data
            lines = data.splitlines()
            if not lines or len(lines) < 2:
                return 0
            last = lines[-1].decode("utf-8", errors="replace")
            cells = last.split(",")
            # tick_seq is the 4th column (index 3) per RAW_COLUMNS.
            return int(cells[3]) if cells[3].strip().isdigit() else 0
    except (OSError, ValueError):
        return 0


def _csv_row_count(csv_path: Path) -> int:
    if not csv_path.exists():
        return 0
    with csv_path.open("rb") as fh:
        return max(0, sum(1 for _ in fh) - 1)  # subtract header


def _tail_last_action(csv_path: Path) -> str:
    if not csv_path.exists():
        return ""
    last_action = ""
    try:
        with csv_path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                action = str(row.get("decision_action", "")).strip()
                if action:
                    last_action = action
    except OSError:
        return ""
    return last_action


def _count_llm_mode_selected_after(csv_path: Path, *, start_seq: int) -> int:
    if not csv_path.exists():
        return 0
    selected = 0
    try:
        with csv_path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    tick_seq = int(str(row.get("tick_seq") or "0").strip())
                except ValueError:
                    continue
                if tick_seq <= start_seq:
                    continue
                value = str(row.get("llm_mode_selected") or "").strip().lower()
                if value in {"true", "1", "yes"}:
                    selected += 1
    except OSError:
        return 0
    return selected


def _tail_actions_all_pool_claim(csv_path: Path, *, window: int) -> bool:
    """True iff the last `window` rows are all pool_claim with non-success eval."""
    if window <= 0:
        return False
    rows: deque[dict[str, str]] = deque(maxlen=window)
    try:
        with csv_path.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                rows.append(row)
    except OSError:
        return False

    if len(rows) < window:
        return False

    saw_failed_eval = False
    for row in rows:
        if str(row.get("decision_action", "")).strip() != "pool_claim":
            return False
        eval_success = str(row.get("eval_success", "")).strip().lower()
        if eval_success in {"true", "1"}:
            return False
        if eval_success in {"false", "0"}:
            saw_failed_eval = True
    return saw_failed_eval


def _h0e_revision_seed_profile(task_id: str) -> dict[str, Any]:
    task_key = task_id.lower()
    if "arbitration" in task_key:
        return {
            "authority": "arbitration_panel",
            "rule_id": "h0e_arbitration_guard",
            "old_value": "appeal_review_required_v1",
            "new_value": "appeal_review_required_v2",
        }
    if "constitutional" in task_key or "constitution" in task_key:
        return {
            "authority": "constitutional_stewards",
            "rule_id": "h0e_constitutional_steward_guard",
            "old_value": "steward_ratification_required_v1",
            "new_value": "steward_ratification_required_v2",
        }
    return {
        "authority": "governance_council",
        "rule_id": "h0e_constitutional_guard",
        "old_value": "review_required_v1",
        "new_value": "review_required_v2",
    }


def _h0e_iem_anchor_replay_payload(task_id: str, profile: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(profile["rule_id"])
    authority = str(profile["authority"])
    state = {
        "schema_version": "iem:v1",
        "identity_id": f"benchmark:{task_id}",
        "expectation_vector": {
            rule_id: {
                "state_kind": "normative",
                "lifecycle_state": "revised",
                "authority": authority,
            },
        },
        "precision_vector": {rule_id: 1.0},
        "desire_vector": {},
        "domain_weight_matrix": {"constitutional": 1.0},
        "drift_parameters": {},
        "relation_expectation_matrix": {},
    }
    update_log = [
        {
            "target": "normative_state",
            "parameter_name": rule_id,
            "old_value": profile["old_value"],
            "new_value": profile["new_value"],
            "rule": "governed_revision",
            "update_params": {
                "authority": authority,
                "domain": "constitutional",
                "rule_id": rule_id,
            },
            "constitution_verdict": "approved: governed revision read model",
            "local_update_blocked": False,
        },
    ]
    state_hash = _canonical_json_hash(state)
    update_log_hash = _canonical_json_hash(update_log)
    anchor = {
        "schema_version": "iem:v1",
        "version_id": f"iem:v1:{state_hash.removeprefix('sha256:')[:12]}",
        "state_hash": state_hash,
        "latest_update_log_hash": update_log_hash,
        "storage_hint": f"civitasos://benchmark/{task_id}/iem/latest",
        "benchmark_task_id": task_id,
    }
    return {"state": state, "update_log": update_log, "anchor": anchor}


def _canonical_json_hash(payload: Any) -> str:
    blob = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(blob).hexdigest()}"


def _env_int(name: str, default: int, *, min_value: int = 0) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("invalid %s=%r; fallback to %d", name, raw, default)
        return default
    if value < min_value:
        return min_value
    return value


def _env_float(name: str, default: float, *, min_value: float = 0.0) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("invalid %s=%r; fallback to %.1f", name, raw, default)
        return default
    if value < min_value:
        return min_value
    return value


def _env_bool(name: str, *, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw not in {"0", "false", "off", "no"}


def _wait_for_g2_mode_probe_ticks(
    *,
    raw_csv: Path,
    proc: subprocess.Popen[Any],
    min_ticks: int,
    timeout_s: float,
    poll_interval_s: float,
) -> int:
    """Wait for benchmark-mode pre-task subjective-time probe rows."""
    if min_ticks <= 0 or timeout_s <= 0:
        return 0
    start_seq = _tail_tick_seq(raw_csv)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return _count_llm_mode_selected_after(raw_csv, start_seq=start_seq)
        selected = _count_llm_mode_selected_after(raw_csv, start_seq=start_seq)
        if selected >= min_ticks:
            return selected
        time.sleep(max(poll_interval_s, 0.05))
    return _count_llm_mode_selected_after(raw_csv, start_seq=start_seq)


def _terminate(proc: subprocess.Popen[Any], grace_s: float, *, then_kill: bool = False) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
    except OSError:
        return
    try:
        proc.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:
        if then_kill or True:  # always escalate after grace
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass


def _write_summary(run_dir: Path, run: RunResult) -> None:
    payload = {
        "run_id": run.run_id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "manifest_path": run.manifest_path,
        "wall_clock_per_tick_s": run.wall_clock_per_tick_s,
        "tasks_total": run.tasks_total,
        "tasks_completed": run.tasks_completed,
        "tasks_terminated_abnormally": run.tasks_terminated_abnormally,
        "tasks": [asdict(t) for t in run.tasks],
    }
    (run_dir / "summary.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8",
    )


# ----------------------------------------------------------------- CLI

def _bootstrap_demo_jwt(sdk: Any, backend_url: str, agent_id: str) -> bool:
    """Best-effort demo-login bootstrap for JWT-protected A2A endpoints."""
    if not agent_id:
        return False
    try:
        import urllib.request as _ur

        req = _ur.Request(
            f"{backend_url}/api/v1/auth/demo-login",
            data=json.dumps({"agent_id": agent_id}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _ur.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        token = body.get("token") or body.get("data", {}).get("token")
        if not token:
            return False
        sdk._jwt_token = token  # type: ignore[attr-defined]
        expires_in = body.get("expires_in") or body.get("data", {}).get("expires_in") or 3600
        sdk._jwt_expires_at = time.time() + int(expires_in)  # type: ignore[attr-defined]
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("[orch-auth] demo-login failed for %s: %s", agent_id, exc)
        return False


def _institutional_identity_enabled() -> bool:
    return os.getenv("CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _resolve_birth_sponsor() -> str:
    for key in ("BENCHMARK_BIRTH_SPONSOR", "CIVITASOS_BIRTH_SPONSOR"):
        sponsor = os.getenv(key, "").strip()
        if sponsor:
            return sponsor
    return "@guardian"


def _register_orchestrator_identity(
    sdk: Any,
    *,
    backend_url: str,
    name: str,
    alias: str,
    description: str,
) -> str:
    """Register the requester/orchestrator identity and return its DID."""
    endpoint = f"http://localhost:0/{alias}"
    if _institutional_identity_enabled():
        public_key = getattr(sdk, "public_key_hex", None)
        if not public_key:
            raise RuntimeError("orchestrator identity missing public_key_hex")
        payload: dict[str, Any] = {
            "public_key": public_key,
            "name": name,
            "alias": alias,
            "endpoint": endpoint,
            "description": description,
            "sponsor": _resolve_birth_sponsor(),
            "intent": "F.1.c benchmark requester registration",
            "stake": int(os.getenv("BENCHMARK_BIRTH_STAKE", "100")),
            "capabilities": [
                {
                    "id": "requester",
                    "name": "Requester",
                    "description": "Benchmark requester/orchestrator identity",
                    "input_schema": None,
                    "output_schema": None,
                }
            ],
            "obligations": ["fund_assigned_tasks"],
        }
        incubation_epochs_raw = os.getenv("BENCHMARK_BIRTH_INCUBATION_EPOCHS", "").strip()
        if incubation_epochs_raw:
            payload["incubation_epochs"] = int(incubation_epochs_raw)
        resp = sdk._post("/agents/birth-proposal", payload)  # type: ignore[attr-defined]
        if not getattr(resp, "success", False):
            msg = getattr(resp, "error", None) or "birth-proposal failed"
            hint = getattr(resp, "hint", None)
            if hint:
                msg = f"{msg} (hint: {hint})"
            raise RuntimeError(str(msg))
        data = getattr(resp, "data", None) or {}
        agent = data.get("agent", {}) if isinstance(data, dict) else {}
        did = agent.get("did") or data.get("did")
        if not did:
            raise RuntimeError(f"birth-proposal response missing did: {data!r}")
        sdk._agent_id = str(did)  # type: ignore[attr-defined]
        _bootstrap_demo_jwt(sdk, backend_url, str(did))
        return str(did)

    sdk.a2a_quickstart(  # type: ignore[attr-defined]
        name=name,
        endpoint=endpoint,
        description=description,
    )
    did = getattr(sdk, "_agent_id", None)
    if not did:
        raise RuntimeError("a2a_quickstart did not populate agent_id")
    _bootstrap_demo_jwt(sdk, backend_url, str(did))
    return str(did)


def _build_backend_client(
    *, backend_url: str, orch_agent_id: str | None, orch_agent_name: str,
    orch_identity_path: str | None = None,
) -> BackendTaskClient:
    """Construct a real CivitasAgent SDK + wrap it as BackendTaskClient.

    Registers the orchestrator via ``a2a_quickstart`` (giving it a default
    1000 CIV balance to escrow per-task rewards). The legacy ``register()``
    /agents endpoint is unsuitable because it ignores client-supplied IDs.

    Lazy import keeps the SDK off the unit-test import path.
    """
    from civitasos import CivitasAgent  # type: ignore[import-not-found]

    sdk = CivitasAgent(base_url=backend_url)
    identity_path_obj: Path | None = None
    loaded_registered_identity = False
    # Persistent identity → idempotent DID across orchestrator restarts.
    if orch_identity_path:
        identity_path_obj = Path(orch_identity_path)
        if identity_path_obj.exists():
            sdk.load_identity(str(identity_path_obj))  # type: ignore[attr-defined]
            loaded_registered_identity = bool(getattr(sdk, "_agent_id", None))
        else:
            sdk.generate_keys()  # type: ignore[attr-defined]
            identity_path_obj.parent.mkdir(parents=True, exist_ok=True)
    else:
        sdk.generate_keys()  # type: ignore[attr-defined]

    if loaded_registered_identity:
        _bootstrap_demo_jwt(sdk, backend_url, str(getattr(sdk, "_agent_id", "")))
        logger.info("orchestrator identity reused did=%s", getattr(sdk, "_agent_id", None))
    else:
        bootstrap_id = (
            orch_agent_id
            or getattr(sdk, "_agent_id", None)
            or (
                _ORCH_BOOTSTRAP_AUTH_AGENT_ID
                if _institutional_identity_enabled()
                else orch_agent_name
            )
        )
        _bootstrap_demo_jwt(sdk, backend_url, str(bootstrap_id))

        try:
            did = _register_orchestrator_identity(
                sdk,
                backend_url=backend_url,
                name=orch_agent_name,
                alias=orch_agent_name,
                description="F.1.c benchmark orchestrator (requester role)",
            )
            logger.info("orchestrator registered did=%s", did)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "already registered to did" in msg.lower():
                unique_name = f"{orch_agent_name}-r{int(time.time())}"
                did = _register_orchestrator_identity(
                    sdk,
                    backend_url=backend_url,
                    name=unique_name,
                    alias=unique_name,
                    description="F.1.c benchmark orchestrator (requester role, rotated alias)",
                )
                logger.info(
                    "orchestrator alias %s conflicted; registered unique alias did=%s",
                    orch_agent_name,
                    did,
                )
            else:
                raise RuntimeError(f"orchestrator registration failed: {exc}") from exc

    if identity_path_obj is not None:
        sdk.save_identity(str(identity_path_obj))  # type: ignore[attr-defined]
    logger.info("orchestrator agent_id=%s", sdk._agent_id)  # type: ignore[attr-defined]
    return BackendTaskClient(sdk)


def _cli() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Run benchmark baseline.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--agent-command", required=True)
    parser.add_argument("--runs-root", default="runs")
    parser.add_argument("--wall-clock-per-tick-s", type=float, default=60.0)
    parser.add_argument("--task", action="append", help="Run only specified task id(s)")
    parser.add_argument("--run-id")
    parser.add_argument("--resume", action="store_true",
                        help="Reuse existing run-dir; skip tasks whose result.json is already present.")
    parser.add_argument(
        "--backend-mode",
        choices=_VALID_BACKEND_MODES,
        default=BACKEND_MODE_LEGACY_FAKE,
        help=(
            "F.1.b: 'legacy-fake' (default) keeps F.0 BENCHMARK_BRIEFING_FILE "
            "behavior. 'backend-tasks' creates real backend tasks via SDK and "
            "polls pool_list for terminal state."
        ),
    )
    parser.add_argument("--backend-url", default="http://localhost:8099",
                        help="Backend base URL (used when --backend-mode=backend-tasks)")
    parser.add_argument("--orch-agent-id", help="Requester agent id to register on backend")
    parser.add_argument("--orch-agent-name", default="benchmark-orchestrator")
    parser.add_argument("--orch-identity",
                        help="Path to Ed25519 identity file for the orchestrator (idempotent DID)")
    parser.add_argument("--target-agent-id",
                        help="Agent id allowed to claim tasks (allowed_agents=[this])")
    parser.add_argument("--backend-capability", default="general")
    parser.add_argument("--backend-reward", type=int, default=100)
    parser.add_argument("--backend-deadline-secs", type=int, default=3600)
    parser.add_argument(
        "--reuse-agent-process",
        action="store_true",
        help=(
            "S5 optimization: reuse one long-lived agent subprocess for all "
            "tasks in this run (backend-tasks mode only)."
        ),
    )
    args = parser.parse_args()

    m = load_manifest(args.manifest)

    backend_client: BackendTaskClient | None = None
    if args.backend_mode == BACKEND_MODE_BACKEND_TASKS:
        if not args.target_agent_id:
            parser.error("--backend-mode=backend-tasks requires --target-agent-id")
        backend_client = _build_backend_client(
            backend_url=args.backend_url,
            orch_agent_id=args.orch_agent_id,
            orch_agent_name=args.orch_agent_name,
            orch_identity_path=args.orch_identity,
        )

    cfg = OrchestratorConfig(
        agent_command=args.agent_command,
        runs_root=Path(args.runs_root),
        wall_clock_per_tick_s=args.wall_clock_per_tick_s,
        backend_mode=args.backend_mode,
        backend_client=backend_client,
        target_agent_id=args.target_agent_id,
        backend_capability=args.backend_capability,
        backend_reward=args.backend_reward,
        backend_deadline_secs=args.backend_deadline_secs,
        reuse_agent_process=args.reuse_agent_process,
        backend_url=args.backend_url,
        orch_agent_name=args.orch_agent_name,
        orch_identity_path=args.orch_identity,
    )
    o = Orchestrator(m, cfg)
    result = o.run(task_ids=args.task, run_id=args.run_id, resume=args.resume)
    print(json.dumps({
        "run_id": result.run_id,
        "tasks_total": result.tasks_total,
        "tasks_completed": result.tasks_completed,
        "tasks_terminated_abnormally": result.tasks_terminated_abnormally,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
