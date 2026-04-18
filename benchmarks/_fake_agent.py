"""Fake agent for orchestrator tests and the F.0 smoke run.

Behaviour controlled via env vars:
  BENCHMARK_FAKE_TICKS         -> int, number of CSV rows to write (default 3)
  BENCHMARK_FAKE_SLEEP_S       -> float per row (default 0.0)
  BENCHMARK_FAKE_SENTINEL      -> "done"|"failed"|"give_up"|"none" (default "done")
  BENCHMARK_FAKE_ABORT_AFTER   -> int, abnormally exit (no sentinel) after this many rows
  BENCHMARK_FAKE_HANG          -> if "1", sleep forever after writing rows (test wall-clock)
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Make the package importable when run via `python -m benchmarks._fake_agent`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from observability.metrics.writer import RawWriter  # noqa: E402


def main() -> int:
    run_id = os.environ["BENCHMARK_RUN_ID"]
    task_id = os.environ["BENCHMARK_TASK_ID"]
    raw_csv = Path(os.environ["BENCHMARK_RAW_CSV"])
    sentinel_dir = Path(os.environ["BENCHMARK_SENTINEL_DIR"])

    n = int(os.environ.get("BENCHMARK_FAKE_TICKS", "3"))
    sleep_s = float(os.environ.get("BENCHMARK_FAKE_SLEEP_S", "0.0"))
    sentinel = os.environ.get("BENCHMARK_FAKE_SENTINEL", "done")
    abort_after = int(os.environ.get("BENCHMARK_FAKE_ABORT_AFTER", "0"))
    hang = os.environ.get("BENCHMARK_FAKE_HANG") == "1"

    with RawWriter(raw_csv) as w:
        for seq in range(1, n + 1):
            if abort_after and seq > abort_after:
                # abnormal: exit before writing remaining rows
                return 13
            w.write({
                "run_id": run_id,
                "agent_id": "fake-agent",
                "task_id": task_id,
                "tick_seq": seq,
                "tick_id": f"t{seq:04d}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "phase_reached": "reflect",
                "decision_action": "wait" if seq % 2 == 0 else "noop",
                "decision_source": "rules",
                "decision_reasoning": f"fake tick {seq}",
                "eval_success": (seq == n and sentinel == "done"),
                "eval_cost": 0.001,
                "eval_duration_ms": 10 + seq,
                "aspect_gap": 0.85 if seq == 2 else 0.1,
                "peer_trust_avg": 0.5,
                "balance": 100.0,
                "mode": "active",
                "is_wait": (seq % 2 == 0),
                "wait_references_telos": False,
            })
            if sleep_s > 0:
                time.sleep(sleep_s)

    if hang:
        while True:
            time.sleep(60)

    if sentinel != "none":
        payload = {
            "success": sentinel == "done",
            "reason": f"fake agent finished with {sentinel}",
            "final_artifact": None,
        }
        (sentinel_dir / sentinel).write_text(
            json.dumps(payload), encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
