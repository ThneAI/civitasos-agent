"""CLI for private J1-D qualification material preparation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.j1.qualification_materials import prepare_materials


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-source", type=Path, required=True)
    parser.add_argument("--verifier-source", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    packet = prepare_materials(
        task_source_path=args.task_source,
        verifier_source_path=args.verifier_source,
        source_revision=args.source_revision,
        output_root=args.output_root,
    )
    print(json.dumps(packet, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if packet["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
