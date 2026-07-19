"""Prepare fixed I.1 verifier assets without starting the I.1 gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.i1.corpus_materialization import (
    materialize_cases,
    negative_controls_effective,
)
from benchmarks.i1.data import check, read_json
from benchmarks.i1.identity_preparation import prepare_identities
from benchmarks.i1.reporting import build_report
from benchmarks.i1.validation import (
    REQUIRED_CONTROL_TYPES as REQUIRED_CONTROL_TYPES,
    validate_controls,
    validate_corpus,
    validate_roster,
)


def prepare_i1_verifier_assets(
    *,
    roster_path: Path,
    corpus_path: Path,
    negative_controls_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    roster = read_json(roster_path, failures, "identity roster")
    corpus = read_json(corpus_path, failures, "fixed corpus")
    controls = read_json(negative_controls_path, failures, "negative controls")

    identities = validate_roster(roster, checks, failures)
    cases = validate_corpus(corpus, checks, failures)
    control_records = validate_controls(controls, cases, checks, failures)
    prepared_identities = (
        prepare_identities(identities, output_root / "identities")
        if not failures
        else []
    )
    materialized_cases = (
        materialize_cases(
            cases=cases,
            controls=control_records,
            output_root=output_root / "corpus",
        )
        if not failures
        else []
    )

    check(
        checks,
        failures,
        "prepared_identity_count_meets_minimum",
        len(prepared_identities) >= int(roster.get("minimum_stable_identities", 5)),
    )
    check(
        checks,
        failures,
        "materialized_case_count_complete",
        len(materialized_cases) == len(cases) + len(control_records),
    )
    check(
        checks,
        failures,
        "negative_controls_effective",
        negative_controls_effective(
            materialized_cases=materialized_cases,
            identities=identities,
            proposer_alias=str(roster.get("proposer_identity_alias") or ""),
        ),
    )
    passed = not failures and all(checks.values())
    report = build_report(
        passed=passed,
        failures=failures,
        checks=checks,
        roster=roster,
        prepared_identities=prepared_identities,
        cases=cases,
        control_records=control_records,
        materialized_cases=materialized_cases,
        roster_path=roster_path,
        corpus_path=corpus_path,
        negative_controls_path=negative_controls_path,
    )
    output_root.mkdir(parents=True, exist_ok=True)
    output = output_root / "i1_verifier_preparation_report.json"
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--identity-roster",
        type=Path,
        default=root / "i1" / "verifier_identity_roster.json",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=root / "i1" / "verifier_corpus.json",
    )
    parser.add_argument(
        "--negative-controls",
        type=Path,
        default=root / "i1" / "verifier_negative_controls.json",
    )
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    report = prepare_i1_verifier_assets(
        roster_path=args.identity_roster,
        corpus_path=args.corpus,
        negative_controls_path=args.negative_controls,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
