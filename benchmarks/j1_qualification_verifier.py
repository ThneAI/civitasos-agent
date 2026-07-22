"""CLI for deterministic J1-D qualification task verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.j1.controlled_comparison import read_json_object, write_private_json
from benchmarks.j1.qualification_verifier import verify_task


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--expected-reviewed-assignment-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = read_json_object(args.evidence)
    except (OSError, ValueError, json.JSONDecodeError):
        evidence = {}
    try:
        assignment_bytes = args.reviewed_assignment.read_bytes()
    except OSError:
        assignment_bytes = b""
    report = verify_task(
        evidence,
        reviewed_assignment_bytes=assignment_bytes,
        expected_reviewed_assignment_sha256=args.expected_reviewed_assignment_sha256,
    )
    write_private_json(args.output, report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
