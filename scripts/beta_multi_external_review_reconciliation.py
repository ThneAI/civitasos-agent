#!/usr/bin/env python3
"""Aggregate multiple Beta-6 -> Beta-9 external Agent review summaries.

This is a read-only reconciliation layer over completed bounded review runners.
It requires multiple approved external Agent verdicts before allowing downstream
Beta preview readiness to treat the review side as multi-Agent observed. It does
not merge, deploy, call providers, or authorize production.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORT_SCHEMA = "beta-multi-external-review-reconciliation:v1"
SUMMARY_SCHEMA = "beta6-9-real-api-review-run-summary:v1"
NON_CLAIMS = (
    "multi_external_review_reconciliation_is_l1_controlled_pilot_only",
    "multi_external_review_reconciliation_does_not_call_external_providers",
    "multi_external_review_reconciliation_does_not_create_github_approval",
    "multi_external_review_reconciliation_does_not_execute_merge_or_deploy",
    "multi_external_review_reconciliation_does_not_authorize_production_runtime_execution",
    "multi_external_review_reconciliation_does_not_write_production_receipts",
    "multi_external_review_reconciliation_does_not_claim_h3_production_readiness",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--min-reviewers", type=int, default=2)
    parser.add_argument("--require-distinct-providers", action="store_true")
    args = parser.parse_args(argv)

    report = reconcile_multi_external_reviews(
        summary_paths=[Path(path) for path in args.summary],
        output_path=Path(args.output),
        min_reviewers=args.min_reviewers,
        require_distinct_providers=bool(args.require_distinct_providers),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def reconcile_multi_external_reviews(
    *,
    summary_paths: list[Path],
    output_path: Path,
    min_reviewers: int = 2,
    require_distinct_providers: bool = False,
) -> dict[str, Any]:
    failures: list[str] = []
    if min_reviewers < 2:
        failures.append("min_reviewers must be >= 2")
    if len(summary_paths) < min_reviewers:
        failures.append(f"summary count must be >= {min_reviewers}")

    records: list[dict[str, Any]] = []
    seen_summary_hashes: set[str] = set()
    for path in summary_paths:
        summary = _read_json(path, failures)
        if not summary:
            continue
        summary_hash = _sha256(path)
        if summary_hash in seen_summary_hashes:
            failures.append(f"duplicate summary artifact: {path}")
            continue
        seen_summary_hashes.add(summary_hash)
        record = _validate_summary(path, summary, summary_hash, failures)
        records.append(record)

    agent_ids = [record["agent_id"] for record in records if record.get("agent_id")]
    providers = [record["provider"] for record in records if record.get("provider")]
    unique_agents = sorted(set(agent_ids))
    unique_providers = sorted(set(providers))
    if len(unique_agents) < min_reviewers:
        failures.append(f"unique external Agent count must be >= {min_reviewers}")
    if require_distinct_providers and len(unique_providers) < min_reviewers:
        failures.append(f"unique external provider count must be >= {min_reviewers}")

    report = {
        "schema_version": REPORT_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "decision": "multi_external_review_ready" if not failures else "blocked",
        "failure_reasons": failures,
        "summary_count": len(records),
        "min_reviewers": min_reviewers,
        "require_distinct_providers": require_distinct_providers,
        "unique_external_agent_count": len(unique_agents),
        "unique_external_provider_count": len(unique_providers),
        "unique_external_agents": unique_agents,
        "unique_external_providers": unique_providers,
        "all_external_verdicts_approved": bool(records) and all(record["external_review_verdict"] == "approved" for record in records),
        "records": records,
        "readiness": {
            "multi_external_review_ready": not failures,
            "production_deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
            "h3_production_readiness_claimed": False,
        },
        "h3_boundary": {
            "h3_remains_blocked": True,
            "h3_production_readiness_claimed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, report)
    return report


def _validate_summary(path: Path, summary: dict[str, Any], summary_hash: str, failures: list[str]) -> dict[str, Any]:
    prefix = str(path)
    if summary.get("schema_version") != SUMMARY_SCHEMA:
        failures.append(f"{prefix}: schema_version must be {SUMMARY_SCHEMA}")
    for key in ("passed", "beta5_authorization_input_ready", "merge_authorized"):
        if summary.get(key) is not True:
            failures.append(f"{prefix}: {key} must be true")
    for key in (
        "merge_performed",
        "deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
    ):
        if summary.get(key) is not False:
            failures.append(f"{prefix}: {key} must be false")
    if summary.get("external_review_verdict") != "approved":
        failures.append(f"{prefix}: external_review_verdict must be approved")
    boundary = summary.get("h3_boundary") if isinstance(summary.get("h3_boundary"), dict) else {}
    if boundary.get("h3_remains_blocked") is not True:
        failures.append(f"{prefix}: h3_boundary.h3_remains_blocked must be true")
    if boundary.get("h3_production_readiness_claimed") is not False:
        failures.append(f"{prefix}: h3_boundary.h3_production_readiness_claimed must be false")
    external_agent = summary.get("external_agent") if isinstance(summary.get("external_agent"), dict) else {}
    return {
        "summary": _artifact_ref(path, summary_hash),
        "run_root": summary.get("run_root"),
        "agent_id": external_agent.get("agent_id"),
        "display_name": external_agent.get("display_name"),
        "provider": external_agent.get("provider"),
        "model": external_agent.get("model"),
        "external_review_verdict": summary.get("external_review_verdict"),
        "beta5_authorization_input_ready": summary.get("beta5_authorization_input_ready"),
        "merge_authorized": summary.get("merge_authorized"),
        "merge_performed": summary.get("merge_performed"),
        "deploy_allowed": summary.get("deploy_allowed"),
        "production_runtime_execution_allowed": summary.get("production_runtime_execution_allowed"),
        "production_receipt_write_allowed": summary.get("production_receipt_write_allowed"),
    }


def _read_json(path: Path, failures: list[str]) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing summary: {path}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        failures.append(f"invalid summary JSON {path}: {exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"summary must be a JSON object: {path}")
        return {}
    return value


def _artifact_ref(path: Path, sha256: str | None = None) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": sha256 or _sha256(path)}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
