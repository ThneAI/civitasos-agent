"""Consume one exact outcome-sensitive J1-D provider-probe authorization."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from benchmarks.j1.qualification_outcome_sensitive_provider_admission import (
    validate_probe_sources,
)
from benchmarks.j1_qualification_outcome_sensitive_provider_admission import (
    replay_source_binding,
)
from benchmarks.j1_qualification_provider_admission_probe import execute_probe


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--claimed-at", required=True)
    parser.add_argument("--authorization-statement", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--provider-env", type=Path, required=True)
    parser.add_argument("--claim-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).parents[1],
    )
    args = parser.parse_args()
    report = execute_probe(
        probe_id=args.probe_id,
        claimed_at=args.claimed_at,
        authorization_statement=args.authorization_statement,
        plan_path=args.plan,
        preflight_path=args.preflight,
        provider_env_path=args.provider_env,
        claim_root=args.claim_root,
        output_root=args.output_root,
        repository_root=args.repository_root,
        source_validator=validate_probe_sources,
        source_replayer=replay_source_binding,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
