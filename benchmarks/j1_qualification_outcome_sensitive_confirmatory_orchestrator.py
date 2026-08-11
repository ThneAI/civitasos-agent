"""Run the prospective confirmatory contract through offline-only adapters."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_outcome_sensitive_confirmatory_orchestrator import (
    run_offline_orchestrator,
)


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--task-limit", type=int)
    args = parser.parse_args()
    report = run_offline_orchestrator(
        contract=_read_object(args.contract),
        run_id=args.run_id,
        root=args.root,
        task_limit=args.task_limit,
    )
    write_private_json(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
