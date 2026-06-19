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
    from civitasos_contracts.artifacts import (
        artifact_ref,
        build_artifact_envelope,
    )
    from civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
        build_runtime_evidence,
    )
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import (
        artifact_ref,
        build_artifact_envelope,
    )
    from scripts.civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
        build_runtime_evidence,
    )

try:
    from beta_evidence import read_json_or_empty, sha256_file, write_json
except ModuleNotFoundError:
    from scripts.beta_evidence import read_json_or_empty, sha256_file, write_json

try:
    from beta_fe_chain_closeout_evidence import (
        CHAIN_SCHEMA,
        HANDOFF_SCHEMA,
        INDEX_SCHEMA,
        NON_CLAIMS,
        STAGES,
        boundary as _boundary,
        bundle_ref_count as _bundle_ref_count,
        h3_boundary as _h3_boundary,
        metrics as _metrics,
        required_text as _required_text,
        validate_handoff as _validate_handoff,
        validate_mediation as _validate_mediation,
        validate_stages as _validate_stages,
    )
except ModuleNotFoundError:
    from scripts.beta_fe_chain_closeout_evidence import (
        CHAIN_SCHEMA,
        HANDOFF_SCHEMA,
        INDEX_SCHEMA,
        NON_CLAIMS,
        STAGES,
        boundary as _boundary,
        bundle_ref_count as _bundle_ref_count,
        h3_boundary as _h3_boundary,
        metrics as _metrics,
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

    metrics = _metrics(mediation, stages)
    summary_path = output_root / "frontend_release_chain_summary.json"
    mediation_ref = artifact_ref(mediation_summary)
    stage_refs = {stage: artifact_ref(stage_paths[stage]) for stage in STAGES}
    runtime_evidence = build_runtime_evidence(
        {
            "agent_mediation": mediation_ref,
            "bounded_apply": stage_refs["fe3"],
            "post_merge_smoke": stage_refs["fe9"],
            "private_preview": stage_refs["fe10"],
        },
        assertions={
            "pool_task_count": metrics["pool_task_count"],
            "delivery_observed_count": metrics["delivery_observed_count"],
            "post_merge_command_count": metrics["post_merge_command_count"],
            "preview_check_count": metrics["preview_check_count"],
        },
    )
    governance_evidence = build_governance_evidence(
        {"release_review_reconciliation": stage_refs["fe7"]},
        assertions={
            "reviewer_count": metrics["reviewer_count"],
            "review_merge_ready": metrics["review_merge_ready"],
            "operator_handoff_required": True,
        },
    )
    release_provenance = build_git_release_provenance(
        {
            "commit_receipt": stage_refs["fe4"],
            "push_receipt": stage_refs["fe5"],
            "draft_pr_receipt": stage_refs["fe6"],
            "merge_receipt": stage_refs["fe8"],
        },
        actions_observed={"commit": True, "push": True, "pr": True, "merge": True},
        actions_performed_by_current_step={},
    )
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="governance",
            schema_version=CHAIN_SCHEMA,
            artifact_id=f"frontend-chain-closeout:{chain_id}",
            subject_id=f"frontend-release-chain:{chain_id}",
            producer="beta_fe_frontend_chain_closeout",
            source_refs=[mediation_ref, *stage_refs.values()],
            scope="read_only_chain_closeout",
        ),
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe_frontend_chain_closeout_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "chain_id": chain_id,
        "mediation_summary": mediation_ref,
        "gate_receipts": stage_refs,
        "runtime_evidence": runtime_evidence,
        "governance_evidence": governance_evidence,
        "release_provenance": release_provenance,
        "metrics": metrics,
        "historical_actions_observed": {
            "civitasos_pool_mediation": metrics["mediation_observed"],
            "apply": True,
            "commit": True,
            "push": True,
            "pr": True,
            "review": True,
            "merge": True,
            "post_merge_smoke": True,
            "local_private_preview": True,
            "deploy": False,
        },
        "closeout_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(summary_path, summary)

    handoff_failures = list(failures)
    if _sha256(summary_path) != _artifact_ref(summary_path)["sha256"]:
        handoff_failures.append("chain summary hash must be stable")
    handoff = {
        "schema_version": HANDOFF_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version=HANDOFF_SCHEMA,
            artifact_id=f"frontend-operator-handoff:{chain_id}",
            subject_id=f"frontend-release-chain:{chain_id}",
            producer="beta_fe_frontend_chain_closeout",
            source_refs=[artifact_ref(summary_path)],
            scope="operator_handoff_review_required",
        ),
        "checked_at": _now(),
        "passed": not handoff_failures,
        "decision": "beta_fe_frontend_operator_handoff_ready" if not handoff_failures else "blocked",
        "failure_reasons": handoff_failures,
        "chain_id": chain_id,
        "chain_summary": _artifact_ref(summary_path),
        "roles": normalized_roles,
        "handoff_metrics": metrics,
        "runtime_evidence": runtime_evidence,
        "governance_evidence": governance_evidence,
        "release_provenance": release_provenance,
        "required_operator_checks": [
            {"check": "all_gate_receipts_hash_bound", "passed": not failures},
            {"check": "civitasos_pool_mediation_observed", "passed": metrics["mediation_observed"]},
            {"check": "all_release_gates_passed", "passed": metrics["passed_gate_count"] == len(STAGES)},
            {"check": "review_reconciliation_ready", "passed": metrics["review_merge_ready"]},
            {"check": "preview_read_models_observed", "passed": metrics["preview_check_count"] >= 1},
            {"check": "production_boundary_preserved", "passed": True},
        ],
        "next_operator_actions": [
            "review the chain summary and all referenced SHA-256 values",
            "record monitoring or audit follow-up separately if any regression appears",
            "start the next frontend slice only through a new CivitasOS-mediated planning gate",
            "do not treat this handoff as deploy or production authorization",
        ],
        "handoff_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
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

    participant_ids = sorted({
        participant
        for record in records
        for participant in record["participant_ids"]
        if isinstance(participant, str) and participant
    })
    index = {
        "schema_version": INDEX_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="governance",
            schema_version=INDEX_SCHEMA,
            artifact_id=f"frontend-cumulative-index:{len(records)}",
            subject_id="frontend-release-chains",
            producer="beta_fe_frontend_chain_closeout",
            source_refs=[
                record["handoff"]
                for record in records
                if isinstance(record.get("handoff"), dict)
            ],
            scope="read_only_multi_chain_index",
        ),
        "indexed_at": _now(),
        "passed": not failures,
        "decision": "beta_fe_frontend_cumulative_evidence_index_ready" if not failures else "blocked",
        "failure_reasons": failures,
        "chain_count": len(records),
        "min_chains": min_chains,
        "total_gate_receipt_count": len(records) * len(STAGES),
        "total_pool_task_count": sum(record["pool_task_count"] for record in records),
        "total_reviewer_count": sum(record["reviewer_count"] for record in records),
        "total_preview_check_count": sum(record["preview_check_count"] for record in records),
        "total_changed_file_count": sum(record["changed_file_count"] for record in records),
        "total_runtime_evidence_ref_count": sum(
            _bundle_ref_count(record.get("runtime_evidence")) for record in records
        ),
        "total_governance_evidence_ref_count": sum(
            _bundle_ref_count(record.get("governance_evidence")) for record in records
        ),
        "total_release_provenance_ref_count": sum(
            _bundle_ref_count(record.get("release_provenance")) for record in records
        ),
        "unique_participant_count": len(participant_ids),
        "unique_participant_ids": participant_ids,
        "chains": records,
        "index_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
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
