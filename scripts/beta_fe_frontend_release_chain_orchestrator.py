#!/usr/bin/env python3
"""Run FE-3..FE-10 frontend release gates as one controlled chain.

This script intentionally does not generate or apply code. It assumes the
operator has already created a bounded frontend diff matching the supplied
allowed files. The chain then executes apply receipt, local commit, remote
branch push, draft PR, review reconciliation, merge, post-merge smoke, and
optional preview gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import build_artifact_envelope
    from civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
        build_runtime_evidence,
    )
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import build_artifact_envelope
    from scripts.civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_governance_evidence,
        build_runtime_evidence,
    )

import beta_fe3_frontend_apply_receipt as fe3
import beta_fe3_bounded_apply_authorization as fe3_auth
import beta_fe4_frontend_commit_gate as fe4
import beta_fe5_8_frontend_release_gates as fe5_8
import beta_fe9_frontend_post_merge_smoke as fe9
import beta_fe10_frontend_preview_gate as fe10

SUMMARY_SCHEMA = "beta-fe-frontend-release-chain-orchestrator-summary:v1"
NON_CLAIMS = (
    "beta_fe_release_chain_orchestrator_does_not_generate_or_apply_code",
    "beta_fe_release_chain_orchestrator_requires_existing_bounded_diff",
    "beta_fe_release_chain_orchestrator_keeps_deploy_and_production_boundaries_false",
    "beta_fe_release_chain_orchestrator_does_not_claim_h3_production_readiness",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-mediation-summary", required=True)
    parser.add_argument("--frontend-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--allowed-changed-file", action="append", required=True)
    parser.add_argument("--test-command", action="append", required=True)
    parser.add_argument("--commit-message", required=True)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--target-branch", required=True)
    parser.add_argument("--github-repo", required=True)
    parser.add_argument("--base-branch", default="main")
    parser.add_argument("--pr-title", required=True)
    parser.add_argument("--pr-body-file", required=True)
    parser.add_argument("--external-env-file", required=True)
    parser.add_argument("--additional-reviewer-spec", action="append", default=[])
    parser.add_argument("--operator-decision", default="ready_to_merge")
    parser.add_argument("--merge-method", choices=("rebase", "squash", "merge"), default="rebase")
    parser.add_argument("--delete-branch", action="store_true")
    parser.add_argument("--post-merge-command", action="append", default=[])
    parser.add_argument("--frontend-url")
    parser.add_argument("--backend-url")
    parser.add_argument("--skip-preview", action="store_true")
    parser.add_argument(
        "--preview-auth-mode",
        choices=("bearer-token", "service-token"),
        default="service-token",
        help="Release preview is fail-closed; demo-login remains available only on the standalone FE-10 dev command.",
    )
    parser.add_argument("--preview-bearer-token")
    parser.add_argument("--preview-bearer-token-file")
    parser.add_argument("--preview-service-token-secret")
    parser.add_argument("--preview-service-token-secret-file")
    parser.add_argument("--preview-service-id", default="beta_fe_release_chain_preview")
    parser.add_argument("--preview-service-token-scope", action="append", default=[])
    parser.add_argument("--demo-login-agent-id", default="beta_fe_release_chain_preview")
    parser.add_argument("--operator-id", default="local-operator-cc")
    parser.add_argument("--operator-authorization", default="current_chat_beta_fe_release_chain_request")
    parser.add_argument("--ack-fe3-bounded-apply-authorization", action="store_true")
    args = parser.parse_args(argv)

    report = run_release_chain(
        source_mediation_summary=Path(args.source_mediation_summary),
        frontend_root=Path(args.frontend_root),
        output_root=Path(args.output_root),
        allowed_changed_files=args.allowed_changed_file,
        test_commands=args.test_command,
        commit_message=args.commit_message,
        remote=args.remote,
        target_branch=args.target_branch,
        github_repo=args.github_repo,
        base_branch=args.base_branch,
        pr_title=args.pr_title,
        pr_body_file=Path(args.pr_body_file),
        external_env_file=Path(args.external_env_file),
        additional_reviewer_specs=args.additional_reviewer_spec,
        operator_decision=args.operator_decision,
        merge_method=args.merge_method,
        delete_branch=bool(args.delete_branch),
        post_merge_commands=args.post_merge_command or args.test_command,
        frontend_url=args.frontend_url,
        backend_url=args.backend_url,
        skip_preview=bool(args.skip_preview),
        preview_auth_mode=args.preview_auth_mode,
        preview_bearer_token=args.preview_bearer_token,
        preview_bearer_token_file=Path(args.preview_bearer_token_file) if args.preview_bearer_token_file else None,
        preview_service_token_secret=args.preview_service_token_secret,
        preview_service_token_secret_file=Path(args.preview_service_token_secret_file) if args.preview_service_token_secret_file else None,
        preview_service_id=args.preview_service_id,
        preview_service_token_scopes=args.preview_service_token_scope,
        demo_login_agent_id=args.demo_login_agent_id,
        operator_id=args.operator_id,
        operator_authorization=args.operator_authorization,
        ack_fe3_bounded_apply_authorization=bool(args.ack_fe3_bounded_apply_authorization),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def run_release_chain(
    *,
    source_mediation_summary: Path,
    frontend_root: Path,
    output_root: Path,
    allowed_changed_files: list[str],
    test_commands: list[str],
    commit_message: str,
    remote: str,
    target_branch: str,
    github_repo: str,
    base_branch: str,
    pr_title: str,
    pr_body_file: Path,
    external_env_file: Path,
    additional_reviewer_specs: list[str],
    operator_decision: str,
    merge_method: str,
    delete_branch: bool,
    post_merge_commands: list[str],
    frontend_url: str | None,
    backend_url: str | None,
    skip_preview: bool,
    preview_auth_mode: str,
    preview_bearer_token: str | None,
    preview_bearer_token_file: Path | None,
    preview_service_token_secret: str | None,
    preview_service_token_secret_file: Path | None,
    preview_service_id: str,
    preview_service_token_scopes: list[str],
    demo_login_agent_id: str,
    operator_id: str,
    operator_authorization: str,
    ack_fe3_bounded_apply_authorization: bool = False,
) -> dict[str, Any]:
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    gate_refs: dict[str, Any] = {}

    fe3_request = fe3_auth.write_authorization_request(
        source_mediation_summary=source_mediation_summary,
        output_root=output_root / "fe3_authorization_request",
        operator_id=operator_id,
        operator_statement=f"Request bounded FE-3 apply for release chain: {operator_authorization}",
        allowed_changed_files=allowed_changed_files,
        ack_authorization_request=ack_fe3_bounded_apply_authorization,
    )
    gate_refs["fe3_authorization_request"] = _artifact_ref(
        output_root / "fe3_authorization_request" / "beta_fe3_bounded_apply_authorization_request.json"
    )
    if fe3_request.get("passed") is not True:
        failures.extend(fe3_request.get("failure_reasons", []))
        return _summary(output_root, failures, gate_refs)

    fe3_authorization = fe3_auth.write_authorization_decision(
        authorization_request=output_root / "fe3_authorization_request" / "beta_fe3_bounded_apply_authorization_request.json",
        output_root=output_root / "fe3_authorization",
        operator_id=operator_id,
        operator_decision="authorize_once",
        operator_statement=f"Authorize one bounded FE-3 apply for release chain: {operator_authorization}",
        ack_authorization_decision=ack_fe3_bounded_apply_authorization,
    )
    gate_refs["fe3_authorization"] = _artifact_ref(
        output_root / "fe3_authorization" / "beta_fe3_bounded_apply_authorization.json"
    )
    if fe3_authorization.get("passed") is not True:
        failures.extend(fe3_authorization.get("failure_reasons", []))
        return _summary(output_root, failures, gate_refs)

    fe3_report = fe3.write_receipt(
        source_fe26_summary=source_mediation_summary,
        single_use_authorization=output_root / "fe3_authorization" / "beta_fe3_bounded_apply_authorization.json",
        frontend_root=frontend_root,
        output_root=output_root / "fe3",
        operator_id=operator_id,
        operator_authorization=operator_authorization,
        allowed_changed_files=allowed_changed_files,
        test_commands=test_commands,
    )
    gate_refs["fe3"] = _artifact_ref(output_root / "fe3" / "beta_fe3_frontend_apply_receipt.json")
    if fe3_report.get("passed") is not True:
        failures.extend(fe3_report.get("failure_reasons", []))
        return _summary(output_root, failures, gate_refs)

    fe4_report = fe4.run_commit_gate(
        frontend_root=frontend_root,
        source_fe3_receipt=output_root / "fe3" / "beta_fe3_frontend_apply_receipt.json",
        output_root=output_root / "fe4",
        commit_message=commit_message,
        operator_id=operator_id,
        operator_authorization=operator_authorization,
    )
    gate_refs["fe4"] = _artifact_ref(output_root / "fe4" / "beta_fe4_frontend_commit_receipt.json") if (output_root / "fe4" / "beta_fe4_frontend_commit_receipt.json").is_file() else None
    if fe4_report.get("passed") is not True:
        failures.extend(fe4_report.get("failure_reasons", []))
        return _summary(output_root, failures, gate_refs)

    fe5_report = fe5_8.run_fe5_push(
        source_fe4_receipt=output_root / "fe4" / "beta_fe4_frontend_commit_receipt.json",
        frontend_root=frontend_root,
        output_root=output_root / "fe5",
        remote=remote,
        target_branch=target_branch,
        operator_id=operator_id,
        operator_authorization=operator_authorization,
    )
    gate_refs["fe5"] = _artifact_ref(output_root / "fe5" / "beta_fe5_frontend_push_receipt.json")
    if fe5_report.get("passed") is not True:
        failures.extend(fe5_report.get("failure_reasons", []))
        return _summary(output_root, failures, gate_refs)

    fe6_report = fe5_8.run_fe6_pr(
        source_fe5_receipt=output_root / "fe5" / "beta_fe5_frontend_push_receipt.json",
        frontend_root=frontend_root,
        output_root=output_root / "fe6",
        github_repo=github_repo,
        base_branch=base_branch,
        title=pr_title,
        body_file=pr_body_file,
        operator_id=operator_id,
        operator_authorization=operator_authorization,
    )
    gate_refs["fe6"] = _artifact_ref(output_root / "fe6" / "beta_fe6_frontend_draft_pr_receipt.json")
    if fe6_report.get("passed") is not True:
        failures.extend(fe6_report.get("failure_reasons", []))
        return _summary(output_root, failures, gate_refs)

    fe7_report = fe5_8.run_fe7_review(
        source_fe6_receipt=output_root / "fe6" / "beta_fe6_frontend_draft_pr_receipt.json",
        frontend_root=frontend_root,
        output_root=output_root / "fe7",
        external_env_file=external_env_file,
        operator_decision=operator_decision,
        operator_id=operator_id,
        operator_authorization=operator_authorization,
        max_diff_chars=24000,
        additional_reviewer_specs=additional_reviewer_specs,
    )
    gate_refs["fe7"] = _artifact_ref(output_root / "fe7" / "beta_fe7_frontend_review_reconciliation.json")
    if fe7_report.get("passed") is not True:
        failures.extend(fe7_report.get("failure_reasons", []))
        return _summary(output_root, failures, gate_refs)

    fe8_report = fe5_8.run_fe8_merge(
        source_fe7_reconciliation=output_root / "fe7" / "beta_fe7_frontend_review_reconciliation.json",
        frontend_root=frontend_root,
        output_root=output_root / "fe8",
        merge_method=merge_method,
        delete_branch=delete_branch,
        operator_id=operator_id,
        operator_authorization=operator_authorization,
    )
    gate_refs["fe8"] = _artifact_ref(output_root / "fe8" / "beta_fe8_frontend_merge_receipt.json")
    if fe8_report.get("passed") is not True:
        failures.extend(fe8_report.get("failure_reasons", []))
        return _summary(output_root, failures, gate_refs)

    fe9_report = fe9.run_post_merge_smoke(
        source_fe8_receipt=output_root / "fe8" / "beta_fe8_frontend_merge_receipt.json",
        frontend_root=frontend_root,
        output_root=output_root / "fe9",
        remote=remote,
        base_branch=base_branch,
        verification_commands=post_merge_commands,
        operator_id=operator_id,
        operator_authorization=operator_authorization,
    )
    gate_refs["fe9"] = _artifact_ref(output_root / "fe9" / "beta_fe9_frontend_post_merge_smoke_receipt.json")
    if fe9_report.get("passed") is not True:
        failures.extend(fe9_report.get("failure_reasons", []))
        return _summary(output_root, failures, gate_refs)

    if not skip_preview:
        if not frontend_url or not backend_url:
            failures.append("frontend_url and backend_url are required unless --skip-preview is set")
            return _summary(output_root, failures, gate_refs)
        fe10_report = fe10.run_preview_gate(
            source_fe9_receipt=output_root / "fe9" / "beta_fe9_frontend_post_merge_smoke_receipt.json",
            frontend_root=frontend_root,
            output_root=output_root / "fe10",
            frontend_url=frontend_url,
            backend_url=backend_url,
            auth_mode=preview_auth_mode,
            bearer_token=preview_bearer_token,
            bearer_token_file=preview_bearer_token_file,
            service_token_secret=preview_service_token_secret,
            service_token_secret_file=preview_service_token_secret_file,
            service_id=preview_service_id,
            service_token_scopes=preview_service_token_scopes,
            demo_login_agent_id=demo_login_agent_id,
            operator_id=operator_id,
            operator_authorization=operator_authorization,
        )
        gate_refs["fe10"] = _artifact_ref(output_root / "fe10" / "beta_fe10_frontend_preview_receipt.json")
        if fe10_report.get("passed") is not True:
            failures.extend(fe10_report.get("failure_reasons", []))
            return _summary(output_root, failures, gate_refs)

    return _summary(output_root, failures, gate_refs)


def _summary(output_root: Path, failures: list[str], gate_refs: dict[str, Any]) -> dict[str, Any]:
    source_refs = [
        ref for ref in gate_refs.values()
        if isinstance(ref, dict) and ref.get("sha256")
    ]
    report = {
        "schema_version": SUMMARY_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="governance",
            schema_version=SUMMARY_SCHEMA,
            artifact_id=f"frontend-release-chain:{output_root.name}",
            subject_id=f"frontend-release-chain:{output_root.name}",
            producer="beta_fe_frontend_release_chain_orchestrator",
            source_refs=source_refs,
            scope="controlled_frontend_release_chain",
        ),
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe_frontend_release_chain_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "gate_receipts": gate_refs,
        "runtime_evidence": build_runtime_evidence(
            {
                key: gate_refs.get(key)
                for key in ("fe3", "fe9", "fe10")
            },
            assertions={"release_chain_passed": not failures},
        ),
        "governance_evidence": build_governance_evidence(
            {"fe7_review_reconciliation": gate_refs.get("fe7")},
            assertions={"release_chain_passed": not failures},
        ),
        "release_provenance": build_git_release_provenance(
            {
                key: gate_refs.get(key)
                for key in ("fe4", "fe5", "fe6", "fe8")
            },
            actions_observed={
                "commit": "fe4" in gate_refs,
                "push": "fe5" in gate_refs,
                "pr": "fe6" in gate_refs,
                "merge": "fe8" in gate_refs,
            },
            actions_performed_by_current_step={},
        ),
        "boundary": {
            "frontend_code_modified": True,
            "apply_allowed": True,
            "commit_allowed": True,
            "push_allowed": True,
            "pr_allowed": True,
            "review_allowed": True,
            "merge_allowed": True,
            "preview_allowed": True,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "frontend_release_chain_summary.json", report)
    return report


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
