"""Evidence validation primitives for frontend chain closeout.

The closeout CLI writes summaries, handoffs, and cumulative indexes. This module
owns the stable read-only chain validation rules and metrics so the CLI does not
mix evidence policy with file-writing orchestration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import (
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
        build_artifact_envelope,
        validate_artifact_envelope,
    )
    from scripts.civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
        build_runtime_evidence,
    )

try:
    from beta_evidence import read_json_or_empty, sha256_file
except ModuleNotFoundError:
    from scripts.beta_evidence import read_json_or_empty, sha256_file


CHAIN_SCHEMA = "beta-fe-frontend-chain-closeout-summary:v1"
HANDOFF_SCHEMA = "beta-fe-frontend-chain-operator-handoff:v1"
INDEX_SCHEMA = "beta-fe-frontend-cumulative-evidence-index:v1"
PRIVATE_BETA_CLOSEOUT_SUMMARY_SCHEMA = "private-beta-controlled-proposer-reviewer-closeout-summary:v1"
PRIVATE_BETA_CLOSEOUT_SCHEMA = "private-beta-controlled-proposer-reviewer-closeout:v1"

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


def boundary() -> dict[str, bool]:
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


def h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def required_text(value: Any, failures: list[str], label: str) -> str:
    text = str(value or "").strip()
    if not text:
        failures.append(f"{label} must be non-empty")
    if any(token in text.upper() for token in ("TODO", "REPLACE_ME", "PLACEHOLDER")):
        failures.append(f"{label} must not be a placeholder")
    return text


def validate_mediation(value: dict[str, Any], failures: list[str]) -> None:
    if value.get("schema_version") == PRIVATE_BETA_CLOSEOUT_SUMMARY_SCHEMA:
        validate_private_beta_closeout_summary(value, failures)
        return
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
    validate_ref(value.get("mediation_summary"), failures, "mediation_summary.mediation_summary")
    validate_ref(value.get("reconciliation"), failures, "mediation_summary.reconciliation")
    validate_safe_boundaries(value, failures, "mediation summary")


def validate_private_beta_closeout_summary(value: dict[str, Any], failures: list[str]) -> None:
    if value.get("passed") is not True:
        failures.append("private Beta closeout summary must be passed")
    if value.get("decision") != "controlled_proposer_reviewer_ready_for_bounded_apply_request":
        failures.append("private Beta closeout summary must be ready for bounded apply request")
    if value.get("operator_decision") != "approve_bounded_apply_request":
        failures.append("private Beta closeout summary must record operator approve_bounded_apply_request")
    readiness = value.get("readiness") if isinstance(value.get("readiness"), dict) else {}
    if readiness.get("bounded_apply_authorization_request_ready") is not True:
        failures.append("private Beta closeout summary must mark bounded apply request ready")
    if readiness.get("bounded_apply_authorization_granted") is not False:
        failures.append("private Beta closeout summary must not grant bounded apply authorization")
    verdict_counts = value.get("verdict_counts") if isinstance(value.get("verdict_counts"), dict) else {}
    if int(verdict_counts.get("reject") or 0) != 0:
        failures.append("private Beta closeout summary must not contain reject verdicts")
    validate_safe_boundaries(value, failures, "private Beta closeout summary")

    closeout_path = validate_ref(value.get("closeout"), failures, "private Beta closeout summary.closeout")
    if closeout_path is None:
        return
    closeout = read_json_or_empty(closeout_path, failures, "private Beta closeout detail")
    if closeout.get("schema_version") != PRIVATE_BETA_CLOSEOUT_SCHEMA:
        failures.append(f"private Beta closeout detail schema_version must be {PRIVATE_BETA_CLOSEOUT_SCHEMA}")
    if closeout.get("passed") is not True:
        failures.append("private Beta closeout detail must be passed")
    if closeout.get("decision") != "controlled_proposer_reviewer_ready_for_bounded_apply_request":
        failures.append("private Beta closeout detail must be ready for bounded apply request")
    validate_safe_boundaries(closeout, failures, "private Beta closeout detail")
    validate_ref(closeout.get("source_execution_summary"), failures, "private Beta closeout source_execution_summary")
    validate_ref(closeout.get("source_mediation_summary"), failures, "private Beta closeout source_mediation_summary")

    output_summary = closeout.get("agent_output_summary") if isinstance(closeout.get("agent_output_summary"), dict) else {}
    outputs = output_summary.get("outputs") if isinstance(output_summary.get("outputs"), list) else []
    if len(outputs) < 3:
        failures.append("private Beta closeout detail must contain at least three delivered participant outputs")
    participant_ids = {
        str(output.get("participant_id") or "").strip()
        for output in outputs
        if isinstance(output, dict)
    }
    participant_ids.discard("")
    if len(participant_ids) != len(outputs):
        failures.append("private Beta closeout detail participant ids must be unique and non-empty")
    for output in outputs:
        if not isinstance(output, dict):
            failures.append("private Beta closeout output must be an object")
            continue
        participant = str(output.get("participant_id") or "unknown")
        if output.get("claim_observed") is not True:
            failures.append(f"private Beta closeout output {participant} must observe claim")
        if output.get("generation_observed_after_claim") is not True:
            failures.append(f"private Beta closeout output {participant} must observe generation after claim")
        if output.get("delivery_observed") is not True:
            failures.append(f"private Beta closeout output {participant} must observe delivery")


def validate_stages(
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
        validate_safe_boundaries(value, failures, stage)
    validate_ref_matches(stages["fe3"].get("source_fe26_summary"), mediation_path, failures, "fe3 source mediation")
    for stage, (field, previous) in SOURCE_FIELDS.items():
        validate_ref_matches(stages[stage].get(field), paths[previous], failures, f"{stage}.{field}")

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


def metrics(mediation: dict[str, Any], stages: dict[str, dict[str, Any]]) -> dict[str, Any]:
    mediation_metrics = mediation_observation_metrics(mediation)
    participants = mediation_metrics["participants"]
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
        "pool_task_count": mediation_metrics["task_receipt_count"],
        "claim_observed_count": mediation_metrics["claim_observed_count"],
        "generation_after_claim_observed_count": mediation_metrics["generation_after_claim_observed_count"],
        "delivery_observed_count": mediation_metrics["delivery_observed_count"],
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


def mediation_observation_metrics(mediation: dict[str, Any]) -> dict[str, Any]:
    if mediation.get("schema_version") == PRIVATE_BETA_CLOSEOUT_SUMMARY_SCHEMA:
        detail = private_beta_closeout_detail(mediation)
        output_summary = detail.get("agent_output_summary") if isinstance(detail.get("agent_output_summary"), dict) else {}
        outputs = output_summary.get("outputs") if isinstance(output_summary.get("outputs"), list) else []
        participants = sorted({
            str(output.get("participant_id") or "")
            for output in outputs
            if isinstance(output, dict) and str(output.get("participant_id") or "")
        })
        return {
            "participants": participants,
            "task_receipt_count": len(outputs),
            "claim_observed_count": sum(1 for output in outputs if isinstance(output, dict) and output.get("claim_observed") is True),
            "generation_after_claim_observed_count": sum(1 for output in outputs if isinstance(output, dict) and output.get("generation_observed_after_claim") is True),
            "delivery_observed_count": sum(1 for output in outputs if isinstance(output, dict) and output.get("delivery_observed") is True),
        }
    return {
        "participants": sorted(set(str(item) for item in mediation.get("participants", []) if item)),
        "task_receipt_count": int(mediation.get("task_receipt_count") or 0),
        "claim_observed_count": int(mediation.get("claim_observed_count") or 0),
        "generation_after_claim_observed_count": int(mediation.get("generation_after_claim_observed_count") or 0),
        "delivery_observed_count": int(mediation.get("delivery_observed_count") or 0),
    }


def private_beta_closeout_detail(mediation: dict[str, Any]) -> dict[str, Any]:
    ref = mediation.get("closeout")
    if not isinstance(ref, dict):
        return {}
    path = Path(str(ref.get("path") or ""))
    if not path.is_file():
        return {}
    return read_json_or_empty(path, [], "private Beta closeout detail")


def build_chain_summary(
    *,
    chain_id: str,
    mediation_ref: dict[str, Any],
    stage_refs: dict[str, dict[str, Any]],
    mediation: dict[str, Any],
    stages: dict[str, dict[str, Any]],
    failures: list[str],
    checked_at: str,
) -> dict[str, Any]:
    chain_metrics = metrics(mediation, stages)
    runtime_evidence = build_runtime_evidence_bundle(
        mediation_ref=mediation_ref,
        stage_refs=stage_refs,
        chain_metrics=chain_metrics,
    )
    governance_evidence = build_governance_evidence_bundle(
        stage_refs=stage_refs,
        chain_metrics=chain_metrics,
    )
    release_provenance = build_release_provenance_bundle(stage_refs=stage_refs)
    return {
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
        "checked_at": checked_at,
        "passed": not failures,
        "decision": "beta_fe_frontend_chain_closeout_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "chain_id": chain_id,
        "mediation_summary": mediation_ref,
        "gate_receipts": stage_refs,
        "runtime_evidence": runtime_evidence,
        "governance_evidence": governance_evidence,
        "release_provenance": release_provenance,
        "metrics": chain_metrics,
        "historical_actions_observed": {
            "civitasos_pool_mediation": chain_metrics["mediation_observed"],
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
        "closeout_boundary": boundary(),
        "h3_boundary": h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def build_operator_handoff(
    *,
    chain_id: str,
    chain_summary_ref: dict[str, Any],
    roles: dict[str, str],
    chain_summary: dict[str, Any],
    failures: list[str],
    checked_at: str,
) -> dict[str, Any]:
    chain_metrics = chain_summary.get("metrics")
    chain_metrics = chain_metrics if isinstance(chain_metrics, dict) else {}
    return {
        "schema_version": HANDOFF_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="approval",
            plane="governance",
            schema_version=HANDOFF_SCHEMA,
            artifact_id=f"frontend-operator-handoff:{chain_id}",
            subject_id=f"frontend-release-chain:{chain_id}",
            producer="beta_fe_frontend_chain_closeout",
            source_refs=[chain_summary_ref],
            scope="operator_handoff_review_required",
        ),
        "checked_at": checked_at,
        "passed": not failures,
        "decision": "beta_fe_frontend_operator_handoff_ready" if not failures else "blocked",
        "failure_reasons": failures,
        "chain_id": chain_id,
        "chain_summary": chain_summary_ref,
        "roles": roles,
        "handoff_metrics": chain_metrics,
        "runtime_evidence": chain_summary.get("runtime_evidence"),
        "governance_evidence": chain_summary.get("governance_evidence"),
        "release_provenance": chain_summary.get("release_provenance"),
        "required_operator_checks": [
            {"check": "all_gate_receipts_hash_bound", "passed": not failures},
            {"check": "civitasos_pool_mediation_observed", "passed": chain_metrics.get("mediation_observed") is True},
            {"check": "all_release_gates_passed", "passed": chain_metrics.get("passed_gate_count") == len(STAGES)},
            {"check": "review_reconciliation_ready", "passed": chain_metrics.get("review_merge_ready") is True},
            {"check": "preview_read_models_observed", "passed": int(chain_metrics.get("preview_check_count") or 0) >= 1},
            {"check": "production_boundary_preserved", "passed": True},
        ],
        "next_operator_actions": [
            "review the chain summary and all referenced SHA-256 values",
            "record monitoring or audit follow-up separately if any regression appears",
            "start the next frontend slice only through a new CivitasOS-mediated planning gate",
            "do not treat this handoff as deploy or production authorization",
        ],
        "handoff_boundary": boundary(),
        "h3_boundary": h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def build_cumulative_index(
    *,
    records: list[dict[str, Any]],
    failures: list[str],
    min_chains: int,
    indexed_at: str,
) -> dict[str, Any]:
    participant_ids = sorted({
        participant
        for record in records
        for participant in record["participant_ids"]
        if isinstance(participant, str) and participant
    })
    return {
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
        "indexed_at": indexed_at,
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
            bundle_ref_count(record.get("runtime_evidence")) for record in records
        ),
        "total_governance_evidence_ref_count": sum(
            bundle_ref_count(record.get("governance_evidence")) for record in records
        ),
        "total_release_provenance_ref_count": sum(
            bundle_ref_count(record.get("release_provenance")) for record in records
        ),
        "unique_participant_count": len(participant_ids),
        "unique_participant_ids": participant_ids,
        "chains": records,
        "index_boundary": boundary(),
        "h3_boundary": h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def build_runtime_evidence_bundle(
    *,
    mediation_ref: dict[str, Any],
    stage_refs: dict[str, dict[str, Any]],
    chain_metrics: dict[str, Any],
) -> dict[str, Any]:
    return build_runtime_evidence(
        {
            "agent_mediation": mediation_ref,
            "bounded_apply": stage_refs["fe3"],
            "post_merge_smoke": stage_refs["fe9"],
            "private_preview": stage_refs["fe10"],
        },
        assertions={
            "pool_task_count": chain_metrics["pool_task_count"],
            "delivery_observed_count": chain_metrics["delivery_observed_count"],
            "post_merge_command_count": chain_metrics["post_merge_command_count"],
            "preview_check_count": chain_metrics["preview_check_count"],
        },
    )


def build_governance_evidence_bundle(
    *,
    stage_refs: dict[str, dict[str, Any]],
    chain_metrics: dict[str, Any],
) -> dict[str, Any]:
    return build_governance_evidence(
        {"release_review_reconciliation": stage_refs["fe7"]},
        assertions={
            "reviewer_count": chain_metrics["reviewer_count"],
            "review_merge_ready": chain_metrics["review_merge_ready"],
            "operator_handoff_required": True,
        },
    )


def build_release_provenance_bundle(
    *,
    stage_refs: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return build_git_release_provenance(
        {
            "commit_receipt": stage_refs["fe4"],
            "push_receipt": stage_refs["fe5"],
            "draft_pr_receipt": stage_refs["fe6"],
            "merge_receipt": stage_refs["fe8"],
        },
        actions_observed={"commit": True, "push": True, "pr": True, "merge": True},
        actions_performed_by_current_step={},
    )


def validate_handoff(value: dict[str, Any], path: Path, failures: list[str]) -> None:
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
    chain_path = validate_ref(ref, failures, f"{path}: chain_summary")
    if chain_path:
        summary = read_json_or_empty(chain_path, failures, f"{path}: chain summary")
        if summary.get("schema_version") != CHAIN_SCHEMA or summary.get("passed") is not True:
            failures.append(f"{path}: referenced chain summary must be passed")
        if summary.get("chain_id") != value.get("chain_id"):
            failures.append(f"{path}: chain_id must match referenced summary")
    validate_exact_boundary(value.get("handoff_boundary"), failures, f"{path}: handoff_boundary")
    validate_h3(value.get("h3_boundary"), failures, f"{path}: h3_boundary")


def validate_safe_boundaries(value: dict[str, Any], failures: list[str], label: str) -> None:
    safe_boundary = value.get("boundary") if isinstance(value.get("boundary"), dict) else {}
    for field in ("deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if safe_boundary.get(field) is not False:
            failures.append(f"{label} boundary.{field} must be false")
    validate_h3(value.get("h3_boundary"), failures, f"{label} h3_boundary")


def validate_ref_matches(value: Any, expected_path: Path, failures: list[str], label: str) -> None:
    path = validate_ref(value, failures, label)
    if path and path.resolve() != expected_path.resolve():
        failures.append(f"{label} path must match supplied artifact")


def validate_ref(value: Any, failures: list[str], label: str) -> Path | None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an artifact ref")
        return None
    path = Path(str(value.get("path") or ""))
    if not path.is_file():
        failures.append(f"{label} path does not exist: {path}")
        return None
    if value.get("sha256") != sha256_file(path):
        failures.append(f"{label} sha256 mismatch")
    return path


def validate_exact_boundary(value: Any, failures: list[str], label: str) -> None:
    if value != boundary():
        failures.append(f"{label} must preserve the read-only closeout boundary")


def validate_h3(value: Any, failures: list[str], label: str) -> None:
    if value != h3_boundary():
        failures.append(f"{label} must keep H.3 blocked")


def bundle_ref_count(value: Any) -> int:
    if not isinstance(value, dict) or not isinstance(value.get("refs"), dict):
        return 0
    return len(value["refs"])
