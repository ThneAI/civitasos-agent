#!/usr/bin/env python3
"""Evaluate Beta-3 controlled-apply candidates from Beta-2 review artifacts.

Beta-3 starts with a read-only candidate gate. It selects approved, unapplied,
low-risk Beta-2 patch proposals for later controlled-apply design. This script
never applies patches, commits, pushes, merges, deploys, executes production
runtime actions, or writes production receipts.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta2_patch_review_outcome import inspect_review_outcome


SCHEMA_VERSION = "beta3-controlled-apply-candidate:v1"
DEFAULT_ALLOWED_PATH_PREFIXES = (
    "README.md",
    "doc/",
    "docs/",
    "benchmarks/tests/",
    "tests/",
)
NON_CLAIMS = (
    "beta3_candidate_is_l1_controlled_pilot_only",
    "beta3_candidate_does_not_apply_patch",
    "beta3_candidate_does_not_authorize_commit_push_merge_or_deploy",
    "beta3_candidate_does_not_claim_h3_production_readiness",
    "beta3_candidate_does_not_write_production_receipts",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True, help="Beta-2 run root to evaluate.")
    parser.add_argument("--operator-selection-reason", required=True)
    parser.add_argument("--operator-id", default="l1-controlled-pilot-operator")
    parser.add_argument("--output", help="Optional candidate report output path.")
    parser.add_argument(
        "--allow-path-prefix",
        action="append",
        default=[],
        help=(
            "Low-risk target path prefix for this candidate. Repeatable. "
            "If omitted, only docs/README/test prefixes are allowed."
        ),
    )
    args = parser.parse_args(argv)

    report = evaluate_candidate(
        run_root=Path(args.run_root),
        operator_selection_reason=args.operator_selection_reason,
        operator_id=args.operator_id,
        allow_path_prefixes=args.allow_path_prefix,
    )
    if args.output:
        _write_json(Path(args.output), report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def evaluate_candidate(
    *,
    run_root: Path,
    operator_selection_reason: str,
    operator_id: str,
    allow_path_prefixes: list[str] | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    reason = operator_selection_reason.strip()
    if not reason:
        failures.append("operator_selection_reason must be a non-empty string")
    operator_id = operator_id.strip()
    if not operator_id:
        failures.append("operator_id must be a non-empty string")

    outcome = inspect_review_outcome(run_root)
    if outcome["passed"] is not True:
        failures.extend(f"beta2 review outcome invalid: {reason}" for reason in outcome["failure_reasons"])
    if outcome.get("operator_decision") != "approved":
        failures.append("candidate requires Beta-2 operator decision approved")
    if outcome.get("review_outcome") != "approved_pending_apply":
        failures.append("candidate requires Beta-2 review outcome approved_pending_apply")
    if outcome.get("operator_apply", {}).get("present") is True:
        failures.append("candidate requires an unapplied Beta-2 proposal")

    proposal_paths = _string_list(outcome.get("proposal", {}).get("target_paths"))
    if not proposal_paths:
        failures.append("candidate requires non-empty proposal target paths")
    allowed_prefixes = _normalize_prefixes(allow_path_prefixes or list(DEFAULT_ALLOWED_PATH_PREFIXES))
    if not allowed_prefixes:
        failures.append("candidate allow_path_prefixes must not be empty")
    for target in proposal_paths:
        if not _is_allowed_path(target, allowed_prefixes):
            failures.append(f"candidate target path is outside low-risk allowlist: {target}")

    return {
        "schema_version": SCHEMA_VERSION,
        "passed": not failures,
        "candidate_status": "eligible_for_controlled_apply_design" if not failures else "blocked",
        "failure_reasons": failures,
        "checked_at": _now(),
        "run_root": str(run_root.resolve()),
        "operator_selection": {
            "operator_id": operator_id or None,
            "reason": reason or None,
        },
        "low_risk_allow_path_prefixes": allowed_prefixes,
        "source_beta2_outcome": {
            "passed": outcome.get("passed"),
            "review_outcome": outcome.get("review_outcome"),
            "operator_decision": outcome.get("operator_decision"),
            "request_id": outcome.get("request_id"),
            "target_paths": proposal_paths,
        },
        "execution_boundary": {
            "patch_application_allowed_by_this_gate": False,
            "commit_allowed_by_this_gate": False,
            "push_allowed_by_this_gate": False,
            "merge_allowed_by_this_gate": False,
            "deploy_allowed_by_this_gate": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "h3_boundary": {
            "h3_remains_blocked": True,
            "h3_production_readiness_claimed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }


def _normalize_prefixes(prefixes: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw in prefixes:
        prefix = raw.strip().replace("\\", "/")
        if not prefix:
            continue
        if prefix.startswith("/") or prefix.startswith("../") or "/../" in prefix:
            continue
        if prefix not in normalized:
            normalized.append(prefix)
    return normalized


def _is_allowed_path(target: str, prefixes: list[str]) -> bool:
    normalized = target.replace("\\", "/")
    return any(normalized.startswith(prefix) if prefix.endswith("/") else normalized == prefix for prefix in prefixes)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
