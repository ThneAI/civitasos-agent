"""Run the J1-D r4 orchestrator with strictly offline adapters."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_orchestrator_v4 import run_offline_orchestrator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    if not isinstance(contract, dict):
        raise ValueError("r4 contract must be a JSON object")
    if args.output_root.exists():
        raise FileExistsError(f"r4 offline output exists: {args.output_root}")
    args.output_root.mkdir(parents=True, mode=0o700)
    args.output_root.chmod(0o700)
    report = run_offline_orchestrator(
        contract=contract,
        run_id=args.run_id,
        root=args.output_root,
    )
    write_private_json(args.output_root / "offline-orchestrator-report.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
