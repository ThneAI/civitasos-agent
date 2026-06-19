"""Evidence validation primitives for frontend chain closeout.

The closeout CLI writes summaries, handoffs, and cumulative indexes. This module
owns the stable read-only chain validation rules and metrics so the CLI does not
mix evidence policy with file-writing orchestration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import validate_artifact_envelope
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import validate_artifact_envelope

try:
    from beta_evidence import read_json_or_empty, sha256_file
except ModuleNotFoundError:
    from scripts.beta_evidence import read_json_or_empty, sha256_file


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
