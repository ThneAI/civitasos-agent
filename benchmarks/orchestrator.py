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

from .briefing_renderer import write_briefing
from .task_loader import Manifest, TaskSpec, load_manifest

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


@dataclass
class OrchestratorConfig:
    agent_command: str                  # e.g. "/path/to/venv/bin/python -m benchmarks._fake_agent"
    runs_root: Path                      # e.g. runs/
    wall_clock_per_tick_s: float = 60.0  # F.0.c default
    sigterm_grace_s: float = 10.0        # extra time after SIGTERM before SIGKILL
    poll_interval_s: float = 0.2
    extra_env: dict[str, str] = field(default_factory=dict)


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

    def run(self, task_ids: list[str] | None = None, *, run_id: str | None = None) -> RunResult:
        run_id = run_id or _generate_run_id()
        run_dir = self._cfg.runs_root / run_id
        if run_dir.exists():
            archived = run_dir.with_suffix(f".archived-{int(time.time())}")
            shutil.move(str(run_dir), str(archived))
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "raw_ticks").mkdir(exist_ok=True)
        (run_dir / "tasks").mkdir(exist_ok=True)

        # Snapshot manifest for reproducibility.
        shutil.copy(self._manifest.path, run_dir / "manifest.yaml")

        targets = (
            [self._manifest.task_by_id(tid) for tid in task_ids]
            if task_ids
            else list(self._manifest.tasks)
        )

        started = _now_iso()
        results: list[TaskResult] = []
        for task in targets:
            results.append(self._run_one(task, run_id=run_id, run_dir=run_dir))
        finished = _now_iso()

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
        briefing_path = task_dir / "briefing.json"
        write_briefing(task, run_id=run_id, out_path=briefing_path)

        env = {
            **os.environ,
            **self._cfg.extra_env,
            "BENCHMARK_RUN_ID": run_id,
            "BENCHMARK_TASK_ID": task.id,
            "BENCHMARK_BRIEFING_FILE": str(briefing_path),
            "BENCHMARK_RAW_CSV": str(raw_csv),
            "BENCHMARK_SENTINEL_DIR": str(sentinel_dir),
        }

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
                    # If the agent left a sentinel before exiting, prefer that.
                    sentinel_kind, sentinel_reason = _read_sentinel(sentinel_dir)
                    if sentinel_kind is not None:
                        exit_code = SENTINEL_TO_EXIT[sentinel_kind]
                    elif code == 0:
                        exit_code = EXIT_AGENT_DONE
                    else:
                        exit_code = EXIT_ABNORMAL
                    break

                # 2. sentinel
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
                    break

                # 4. wall-clock
                if (time.monotonic() - t0) >= wall_clock_budget_s:
                    exit_code = EXIT_WALL_CLOCK
                    _terminate(proc, self._cfg.sigterm_grace_s, then_kill=True)
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

        return TaskResult(
            task_id=task.id,
            exit_code=exit_code if exit_code is not None else EXIT_ABNORMAL,
            tick_count=tick_count,
            wall_clock_ms=wall_ms,
            raw_csv_rows=raw_rows,
            agent_self_reported_success=self_reported,
            sentinel_kind=sentinel_kind,
            sentinel_reason=sentinel_reason,
        )


# ----------------------------------------------------------------- helpers

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_run_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:4]
    return f"baseline-{ts}-{suffix}"


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

def _cli() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Run benchmark baseline.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--agent-command", required=True)
    parser.add_argument("--runs-root", default="runs")
    parser.add_argument("--wall-clock-per-tick-s", type=float, default=60.0)
    parser.add_argument("--task", action="append", help="Run only specified task id(s)")
    parser.add_argument("--run-id")
    args = parser.parse_args()

    m = load_manifest(args.manifest)
    cfg = OrchestratorConfig(
        agent_command=args.agent_command,
        runs_root=Path(args.runs_root),
        wall_clock_per_tick_s=args.wall_clock_per_tick_s,
    )
    o = Orchestrator(m, cfg)
    result = o.run(task_ids=args.task, run_id=args.run_id)
    print(json.dumps({
        "run_id": result.run_id,
        "tasks_total": result.tasks_total,
        "tasks_completed": result.tasks_completed,
        "tasks_terminated_abnormally": result.tasks_terminated_abnormally,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
