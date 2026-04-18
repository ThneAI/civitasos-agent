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
        results: list[TaskResult] = []
        skipped = 0
        for task in targets:
            cached = _load_cached_result(run_dir, task.id) if resume else None
            if cached is not None:
                results.append(cached)
                skipped += 1
                logger.info("resume: skipping %s (cached: %s)", task.id, cached.sentinel_kind)
                continue
            results.append(self._run_one(task, run_id=run_id, run_dir=run_dir))
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
            backend_task_id = self._cfg.backend_client.create(
                briefing=task.briefing,
                target_agent_id=self._cfg.target_agent_id,
                capability=self._cfg.backend_capability,
                reward=self._cfg.backend_reward,
                deadline_secs=self._cfg.backend_deadline_secs,
            )
            (task_dir / "backend_task_id.txt").write_text(backend_task_id, encoding="utf-8")
            env["BENCHMARK_BACKEND_TASK_ID"] = backend_task_id
        else:
            briefing_path = task_dir / "briefing.json"
            write_briefing(task, run_id=run_id, out_path=briefing_path)
            env["BENCHMARK_BRIEFING_FILE"] = str(briefing_path)

        wall_clock_budget_s = task.max_ticks * self._cfg.wall_clock_per_tick_s

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
                if tick_seq >= task.max_ticks:
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

    Skips if the file is missing or unparseable; the task will be re-run.
    """
    p = run_dir / "tasks" / task_id / "result.json"
    if not p.is_file():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return TaskResult(**d)
    except Exception as exc:  # noqa: BLE001
        logger.warning("resume: dropping unreadable result for %s: %s", task_id, exc)
        return None


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
    # Persistent identity → idempotent DID across orchestrator restarts.
    if orch_identity_path:
        from pathlib import Path as _P
        p = _P(orch_identity_path)
        if p.exists():
            sdk.load_identity(str(p))  # type: ignore[attr-defined]
        else:
            sdk.generate_keys()  # type: ignore[attr-defined]
            p.parent.mkdir(parents=True, exist_ok=True)
            sdk.save_identity(str(p))  # type: ignore[attr-defined]
    else:
        sdk.generate_keys()  # type: ignore[attr-defined]

    try:
        sdk.a2a_quickstart(  # type: ignore[attr-defined]
            name=orch_agent_name,
            endpoint=f"http://localhost:0/{orch_agent_name}",
            description="F.1.c benchmark orchestrator (requester role)",
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("orchestrator a2a_quickstart failed (may already exist): %s", exc)
    if not sdk._agent_id and orch_agent_id:  # type: ignore[attr-defined]
        sdk._agent_id = orch_agent_id  # type: ignore[attr-defined]
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
