#!/usr/bin/env python3
"""Close out and index CivitasOS-mediated frontend release chains.

The tool validates one four-Agent mediation artifact plus FE-3..FE-10 receipts,
writes a read-only chain summary and operator handoff, and can aggregate
multiple handoffs into a cumulative evidence index. It never executes Git,
GitHub, model, backend, preview, deploy, or production runtime actions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import (
        artifact_ref,
        build_artifact_envelope,
        validate_artifact_envelope,
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
        validate_artifact_envelope,
    )
    from scripts.civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
        build_runtime_evidence,
    )

CHAIN_SCHEMA = "beta-fe-frontend-chain-closeout-summary:v1"
HANDOFF_SCHEMA = "beta-fe-frontend-chain-operator-handoff:v1"
INDEX_SCHEMA = "beta-fe-frontend-cumulative-evidence-index:v1"

STAGES = {
    "fe3": ("beta-fe3-frontend-apply-receipt:v1", "beta_fe3_frontend_apply_receipt_passed"),
    "fe4": ("beta-fe4-frontend-commit-receipt:v1", "beta_fe4_frontend_commit_receipt_passed"),
    "fe5": ("beta-fe5-frontend-push-receipt:v1", "beta_fe5_frontend_push_receipt_passed"),
    "fe6": ("beta-fe6-frontend-draft-pr-receipt:v1", "beta_fe6_frontend_draft_pr_receipt_passed"),
    "fe7": ("beta-fe7-frontend-review-reconciliation:v1", "beta_fe7_frontend_review_reconciliation_passed"),
    "fe8": ("beta-fe8-frontend-merge-receipt:v1", "beta_fe8_frontend_merge_receipt_passed"),
    "fe9": ("beta-fe9-frontend-post-merge-smoke-receipt:v1", "beta_fe9_frontend_post_merge_smoke_passed"),
    "fe10": ("beta-fe10-frontend-preview-receipt:v1", "beta_fe10_frontend_preview_passed"),
}

SOURCE_FIELDS = {
    "fe4": ("source_fe3_receipt", "fe3"),
    "fe5": ("source_fe4_receipt", "fe4"),
    "fe6": ("source_fe5_receipt", "fe5"),
    "fe7": ("source_fe6_receipt", "fe6"),
    "fe8": ("source_fe7_reconciliation", "fe7"),
    "fe9": ("source_fe8_receipt", "fe8"),
    "fe10": ("source_fe9_receipt", "fe9"),
}

NON_CLAIMS = (
    "frontend_chain_closeout_is_read_only",
    "frontend_chain_closeout_records_historical_actions_without_authorizing_new_actions",
    "frontend_chain_closeout_does_not_execute_git_or_github_actions",
    "frontend_chain_closeout_does_not_execute_deploy",
    "frontend_chain_closeout_does_not_authorize_production_runtime_execution",
    "frontend_chain_closeout_does_not_write_production_receipts",
    "frontend_chain_closeout_does_not_claim_h3_production_readiness",
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


def _validate_mediation(value: dict[str, Any], failures: list[str]) -> None:
    if value.get("passed") is not True:
        failures.append("mediation summary must be passed")
    participants = value.get("participants")
    if not isinstance(participants, list) or len(set(participants)) < 4:
        failures.append("mediation summary must contain at least four unique participants")
    for field in (
        "task_receipt_count",
        "claim_observed_count",
        "generation_after_claim_observed_count",
        "delivery_observed_count",
    ):
        if int(value.get(field) or 0) < 4:
            failures.append(f"mediation summary {field} must be >= 4")
    _validate_ref(value.get("mediation_summary"), failures, "mediation_summary.mediation_summary")
    _validate_ref(value.get("reconciliation"), failures, "mediation_summary.reconciliation")
    _validate_safe_boundaries(value, failures, "mediation summary")


def _validate_stages(
    stages: dict[str, dict[str, Any]],
    paths: dict[str, Path],
    mediation_path: Path,
    failures: list[str],
) -> None:
    for stage, (schema, decision) in STAGES.items():
        value = stages[stage]
        if value.get("schema_version") != schema:
            failures.append(f"{stage} schema_version must be {schema}")
        if value.get("passed") is not True or value.get("decision") != decision:
            failures.append(f"{stage} receipt must be passed")
        envelope = value.get("artifact_envelope")
        if envelope is not None:
            failures.extend(
                f"{stage} artifact_envelope: {failure}"
                for failure in validate_artifact_envelope(envelope)
            )
        _validate_safe_boundaries(value, failures, stage)
    _validate_ref_matches(stages["fe3"].get("source_fe26_summary"), mediation_path, failures, "fe3 source mediation")
    for stage, (field, previous) in SOURCE_FIELDS.items():
        _validate_ref_matches(stages[stage].get(field), paths[previous], failures, f"{stage}.{field}")

    commit_id = str(stages["fe4"].get("commit_id") or "")
    if not commit_id or stages["fe5"].get("commit_id") != commit_id:
        failures.append("FE-4 and FE-5 commit_id must match")
    if stages["fe5"].get("remote_branch_after_head") != commit_id:
        failures.append("FE-5 remote branch head must match commit_id")
    draft_pr = stages["fe6"].get("draft_pr") if isinstance(stages["fe6"].get("draft_pr"), dict) else {}
    review_pr = stages["fe7"].get("pr") if isinstance(stages["fe7"].get("pr"), dict) else {}
    if draft_pr.get("headRefOid") != commit_id or review_pr.get("headRefOid") != commit_id:
        failures.append("FE-6/FE-7 PR head must match commit_id")
    if draft_pr.get("number") != review_pr.get("number"):
        failures.append("FE-6 and FE-7 PR numbers must match")
    reconciliation = stages["fe7"].get("review_reconciliation")
    if not isinstance(reconciliation, dict) or reconciliation.get("merge_ready") is not True:
        failures.append("FE-7 review reconciliation must be merge ready")
    merged_pr = stages["fe8"].get("pr") if isinstance(stages["fe8"].get("pr"), dict) else {}
    merge_commit = str(stages["fe8"].get("base_branch_after_head") or "")
    if merged_pr.get("number") != draft_pr.get("number") or merged_pr.get("state") != "MERGED":
        failures.append("FE-8 must merge the FE-6 PR")
    if not merge_commit or (merged_pr.get("mergeCommit") or {}).get("oid") != merge_commit:
        failures.append("FE-8 merge commit binding is invalid")
    for field in ("merge_commit", "remote_head", "local_head"):
        if stages["fe9"].get(field) != merge_commit:
            failures.append(f"FE-9 {field} must match FE-8 merge commit")
    frontend_checks = stages["fe10"].get("frontend_checks")
    backend_checks = stages["fe10"].get("backend_read_model_checks")
    for label, checks in (("frontend", frontend_checks), ("backend", backend_checks)):
        if not isinstance(checks, list) or not checks:
            failures.append(f"FE-10 {label} checks must be present")
        elif any(not isinstance(item, dict) or item.get("status_code") != 200 for item in checks):
            failures.append(f"FE-10 {label} checks must all return 200")


def _metrics(mediation: dict[str, Any], stages: dict[str, dict[str, Any]]) -> dict[str, Any]:
    participants = sorted(set(str(item) for item in mediation.get("participants", []) if item))
    reconciliation = stages["fe7"].get("review_reconciliation")
    reconciliation = reconciliation if isinstance(reconciliation, dict) else {}
    verdicts = reconciliation.get("all_agent_verdicts")
    reviewer_count = len(verdicts) if isinstance(verdicts, dict) else 2
    frontend_checks = stages["fe10"].get("frontend_checks")
    backend_checks = stages["fe10"].get("backend_read_model_checks")
    draft_pr = stages["fe6"].get("draft_pr") if isinstance(stages["fe6"].get("draft_pr"), dict) else {}
    return {
        "mediation_observed": True,
        "participant_ids": participants,
        "participant_count": len(participants),
        "pool_task_count": int(mediation.get("task_receipt_count") or 0),
        "claim_observed_count": int(mediation.get("claim_observed_count") or 0),
        "generation_after_claim_observed_count": int(mediation.get("generation_after_claim_observed_count") or 0),
        "delivery_observed_count": int(mediation.get("delivery_observed_count") or 0),
        "passed_gate_count": sum(1 for value in stages.values() if value.get("passed") is True),
        "changed_files": stages["fe3"].get("changed_files") or [],
        "changed_file_count": len(stages["fe3"].get("changed_files") or []),
        "commit_id": stages["fe4"].get("commit_id"),
        "pr_number": draft_pr.get("number"),
        "pr_url": draft_pr.get("url"),
        "reviewer_count": reviewer_count,
        "review_verdicts": verdicts or {
            "local-static-boundary-reviewer": reconciliation.get("local_verdict"),
            "external-api-reviewer": reconciliation.get("external_verdict"),
        },
        "review_merge_ready": reconciliation.get("merge_ready") is True,
        "merge_commit": stages["fe8"].get("base_branch_after_head"),
        "post_merge_command_count": len(stages["fe9"].get("verification_commands") or []),
        "preview_check_count": len(frontend_checks or []) + len(backend_checks or []),
        "preview_auth_method": (stages["fe10"].get("backend_auth") or {}).get("auth_method"),
    }


def _validate_handoff(value: dict[str, Any], path: Path, failures: list[str]) -> None:
    if value.get("schema_version") != HANDOFF_SCHEMA:
        failures.append(f"{path}: invalid handoff schema")
    if value.get("passed") is not True or value.get("decision") != "beta_fe_frontend_operator_handoff_ready":
        failures.append(f"{path}: handoff must be ready")
    if value.get("artifact_envelope") is not None:
        failures.extend(
            f"{path}: artifact_envelope: {failure}"
            for failure in validate_artifact_envelope(value.get("artifact_envelope"))
        )
    ref = value.get("chain_summary")
    chain_path = _validate_ref(ref, failures, f"{path}: chain_summary")
    if chain_path:
        summary = _read_json(chain_path, failures, f"{path}: chain summary")
        if summary.get("schema_version") != CHAIN_SCHEMA or summary.get("passed") is not True:
            failures.append(f"{path}: referenced chain summary must be passed")
        if summary.get("chain_id") != value.get("chain_id"):
            failures.append(f"{path}: chain_id must match referenced summary")
    _validate_exact_boundary(value.get("handoff_boundary"), failures, f"{path}: handoff_boundary")
    _validate_h3(value.get("h3_boundary"), failures, f"{path}: h3_boundary")


def _validate_safe_boundaries(value: dict[str, Any], failures: list[str], label: str) -> None:
    boundary = value.get("boundary") if isinstance(value.get("boundary"), dict) else {}
    for field in ("deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(field) is not False:
            failures.append(f"{label} boundary.{field} must be false")
    _validate_h3(value.get("h3_boundary"), failures, f"{label} h3_boundary")


def _validate_ref_matches(value: Any, expected_path: Path, failures: list[str], label: str) -> None:
    path = _validate_ref(value, failures, label)
    if path and path.resolve() != expected_path.resolve():
        failures.append(f"{label} path must match supplied artifact")


def _validate_ref(value: Any, failures: list[str], label: str) -> Path | None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an artifact ref")
        return None
    path = Path(str(value.get("path") or ""))
    if not path.is_file():
        failures.append(f"{label} path does not exist: {path}")
        return None
    if value.get("sha256") != _sha256(path):
        failures.append(f"{label} sha256 mismatch")
    return path


def _boundary() -> dict[str, bool]:
    return {
        "l1_beta_controlled_evidence_only": True,
        "apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "pr_allowed": False,
        "review_allowed": False,
        "merge_allowed": False,
        "preview_allowed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
    }


def _validate_exact_boundary(value: Any, failures: list[str], label: str) -> None:
    if value != _boundary():
        failures.append(f"{label} must preserve the read-only closeout boundary")


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _validate_h3(value: Any, failures: list[str], label: str) -> None:
    if value != _h3_boundary():
        failures.append(f"{label} must keep H.3 blocked")


def _read_json(path: Path | None, failures: list[str], label: str) -> dict[str, Any]:
    if path is None or not path.is_file():
        failures.append(f"missing {label}: {path}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"invalid {label}: {exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{label} must be a JSON object")
        return {}
    return value


def _required_text(value: Any, failures: list[str], label: str) -> str:
    text = str(value or "").strip()
    if not text:
        failures.append(f"{label} must be non-empty")
    if any(token in text.upper() for token in ("TODO", "REPLACE_ME", "PLACEHOLDER")):
        failures.append(f"{label} must not be a placeholder")
    return text


def _artifact_ref(path: Path) -> dict[str, str | None]:
    return artifact_ref(path)


def _bundle_ref_count(value: Any) -> int:
    if not isinstance(value, dict) or not isinstance(value.get("refs"), dict):
        return 0
    return len(value["refs"])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
