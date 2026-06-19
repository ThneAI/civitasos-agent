#!/usr/bin/env python3
"""Close out and index CivitasOS-mediated frontend release chains.

The tool validates one four-Agent mediation artifact plus FE-3..FE-10 receipts,
writes a read-only chain summary and operator handoff, and can aggregate
multiple handoffs into a cumulative evidence index. It never executes Git,
GitHub, model, backend, preview, deploy, or production runtime actions.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from beta_evidence import artifact_ref, read_json_or_empty, sha256_file, write_json
except ModuleNotFoundError:
    from scripts.beta_evidence import artifact_ref, read_json_or_empty, sha256_file, write_json

try:
    from beta_fe_chain_closeout_evidence import (
        STAGES,
        build_chain_summary as _build_chain_summary,
        build_cumulative_index as _build_cumulative_index,
        build_operator_handoff as _build_operator_handoff,
        required_text as _required_text,
        validate_handoff as _validate_handoff,
        validate_mediation as _validate_mediation,
        validate_stages as _validate_stages,
    )
except ModuleNotFoundError:
    from scripts.beta_fe_chain_closeout_evidence import (
        STAGES,
        build_chain_summary as _build_chain_summary,
        build_cumulative_index as _build_cumulative_index,
        build_operator_handoff as _build_operator_handoff,
        required_text as _required_text,
        validate_handoff as _validate_handoff,
        validate_mediation as _validate_mediation,
        validate_stages as _validate_stages,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    closeout = sub.add_parser("closeout", help="write one chain summary and operator handoff")
    closeout.add_argument("--chain-id", required=True)
    closeout.add_argument("--mediation-summary", required=True)
    for stage in STAGES:
        closeout.add_argument(f"--{stage}-receipt", required=True)
    closeout.add_argument("--output-root", required=True)
    closeout.add_argument("--operator-id", default="local-operator-cc")
    closeout.add_argument("--monitoring-owner", default="observability_owner")
    closeout.add_argument("--audit-owner", default="audit_owner")

    index = sub.add_parser("index", help="aggregate frontend chain handoffs")
    index.add_argument("--handoff", action="append", required=True)
    index.add_argument("--output", required=True)
    index.add_argument("--min-chains", type=int, default=1)

    args = parser.parse_args(argv)
    if args.command == "closeout":
        report = closeout_frontend_chain(
            chain_id=args.chain_id,
            mediation_summary=Path(args.mediation_summary),
            stage_paths={stage: Path(getattr(args, f"{stage}_receipt")) for stage in STAGES},
            output_root=Path(args.output_root),
            roles={
                "operator": args.operator_id,
                "monitoring_owner": args.monitoring_owner,
                "audit_owner": args.audit_owner,
            },
        )
    else:
        report = write_cumulative_index(
            handoff_paths=[Path(path) for path in args.handoff],
            output_path=Path(args.output),
            min_chains=args.min_chains,
        )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def closeout_frontend_chain(
    *,
    chain_id: str,
    mediation_summary: Path,
    stage_paths: dict[str, Path],
    output_root: Path,
    roles: dict[str, str],
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    chain_id = _required_text(chain_id, failures, "chain_id")
    normalized_roles = {
        key: _required_text(roles.get(key), failures, f"roles.{key}")
        for key in ("operator", "monitoring_owner", "audit_owner")
    }
    mediation = _read_json(mediation_summary, failures, "mediation summary")
    stages = {
        stage: _read_json(stage_paths.get(stage), failures, f"{stage} receipt")
        for stage in STAGES
    }
    _validate_mediation(mediation, failures)
    _validate_stages(stages, stage_paths, mediation_summary, failures)

    summary_path = output_root / "frontend_release_chain_summary.json"
    mediation_ref = _artifact_ref(mediation_summary)
    stage_refs = {stage: _artifact_ref(stage_paths[stage]) for stage in STAGES}
    summary = _build_chain_summary(
        chain_id=chain_id,
        mediation_ref=mediation_ref,
        stage_refs=stage_refs,
        mediation=mediation,
        stages=stages,
        failures=failures,
        checked_at=_now(),
    )
    _write_json(summary_path, summary)

    handoff_failures = list(failures)
    if _sha256(summary_path) != _artifact_ref(summary_path)["sha256"]:
        handoff_failures.append("chain summary hash must be stable")
    handoff = _build_operator_handoff(
        chain_id=chain_id,
        chain_summary_ref=_artifact_ref(summary_path),
        roles=normalized_roles,
        chain_summary=summary,
        failures=handoff_failures,
        checked_at=_now(),
    )
    _write_json(output_root / "frontend_release_operator_handoff.json", handoff)
    return handoff


def write_cumulative_index(
    *,
    handoff_paths: list[Path],
    output_path: Path,
    min_chains: int,
) -> dict[str, Any]:
    failures: list[str] = []
    if min_chains < 1:
        failures.append("min_chains must be >= 1")
    records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for path in sorted({item.resolve() for item in handoff_paths}):
        handoff = _read_json(path, failures, "operator handoff")
        if not handoff:
            continue
        _validate_handoff(handoff, path, failures)
        chain_id = str(handoff.get("chain_id") or "")
        if chain_id in seen_ids:
            failures.append(f"duplicate chain_id: {chain_id}")
            continue
        seen_ids.add(chain_id)
        metrics = handoff.get("handoff_metrics") if isinstance(handoff.get("handoff_metrics"), dict) else {}
        records.append(
            {
                "chain_id": chain_id,
                "handoff": _artifact_ref(path),
                "chain_summary": handoff.get("chain_summary"),
                "merge_commit": metrics.get("merge_commit"),
                "pr_number": metrics.get("pr_number"),
                "participant_ids": metrics.get("participant_ids") or [],
                "pool_task_count": int(metrics.get("pool_task_count") or 0),
                "reviewer_count": int(metrics.get("reviewer_count") or 0),
                "preview_check_count": int(metrics.get("preview_check_count") or 0),
                "changed_file_count": int(metrics.get("changed_file_count") or 0),
                "runtime_evidence": handoff.get("runtime_evidence"),
                "governance_evidence": handoff.get("governance_evidence"),
                "release_provenance": handoff.get("release_provenance"),
            }
        )
    if len(records) < min_chains:
        failures.append(f"validated chain count {len(records)} below min_chains {min_chains}")

    index = _build_cumulative_index(
        records=records,
        failures=failures,
        min_chains=min_chains,
        indexed_at=_now(),
    )
    _write_json(output_path, index)
    return index


def _read_json(path: Path | None, failures: list[str], label: str) -> dict[str, Any]:
    return read_json_or_empty(path, failures, label)


def _artifact_ref(path: Path) -> dict[str, str | None]:
    return artifact_ref(path)


def _sha256(path: Path) -> str:
    return sha256_file(path)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json(path, payload)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
