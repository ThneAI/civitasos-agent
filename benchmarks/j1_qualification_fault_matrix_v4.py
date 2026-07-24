"""Run and persist the J1-D r4 offline fault matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_fault_matrix_v4 import run_fault_matrix


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    if not isinstance(contract, dict):
        raise ValueError("r4 contract must be a JSON object")
    report = run_fault_matrix(contract=contract, root=args.output_root)
    write_private_json(args.output_root / "fault-matrix-report.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
