#!/usr/bin/env python3
"""Run a bounded Beta preview chain in one command.

Pipeline:
1. Beta-6 -> Beta-9 real API Agent review runner.
2. Optional additional external Agent review runners and multi-review reconciliation.
3. Beta-5 repeatable VirtualBox preview deploy + rollback.
4. Owner feedback packet + cumulative index.
5. Beta deployment preview readiness inspection.

The chain is still L1/Beta controlled preview only. It never performs GitHub
merge, production deploy, production runtime execution, or production receipt
writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from beta5_owner_feedback_packet import record_owner_feedback_packet
from beta5_owner_feedback_packet import write_owner_feedback_index
from beta5_real_multivm_preview_prepare import DEFAULT_BACKEND_PORT
from beta5_real_multivm_preview_prepare import DEFAULT_FRONTEND_PORT
from beta5_real_multivm_preview_prepare import DEFAULT_REMOTE_ROOT
from beta5_real_multivm_preview_prepare import PreviewNode
from beta5_real_multivm_preview_prepare import parse_node
from beta5_real_multivm_preview_prepare import write_real_multivm_preview_run
from beta6_9_real_api_review_runner import DEFAULT_MAX_TOKENS
from beta6_9_real_api_review_runner import run_real_api_review_chain
from beta_deployment_preview_readiness import inspect_beta_deployment_preview_readiness
from beta_multi_external_review_reconciliation import reconcile_multi_external_reviews

CHAIN_SCHEMA = "beta-preview-chain-run-summary:v1"
DEFAULT_NODES = (
    "vm1,vm1,192.168.56.4",
    "vm2,vm2,192.168.56.5",
    "vm3,vm3,192.168.56.6",
)
NON_CLAIMS = (
    "beta_preview_chain_is_l1_controlled_preview_only",
    "beta_preview_chain_does_not_execute_github_merge",
    "beta_preview_chain_does_not_authorize_production_deploy",
    "beta_preview_chain_does_not_authorize_production_runtime_execution",
    "beta_preview_chain_does_not_write_production_receipts",
    "beta_preview_chain_does_not_claim_h3_production_readiness",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--env-file", default=".env.beta6.external.local")
    parser.add_argument("--additional-env-file", action="append", default=[])
    parser.add_argument("--additional-agent-id", action="append", default=[])
    parser.add_argument("--seed-feedback-index", required=True)
    parser.add_argument("--seed-preview-summary", required=True)
    parser.add_argument("--pr-review-evidence", required=True)
    parser.add_argument("--local-deploy-receipt", required=True)
    parser.add_argument("--previous-owner-feedback-packet", action="append", default=[])
    parser.add_argument("--previous-owner-feedback-packet-glob", action="append", default=[])
    parser.add_argument("--backend-bin", default="../civitasos-backend/target/debug/api_only")
    parser.add_argument("--frontend-build-dir", default="../civitasos-frontend/build")
    parser.add_argument("--node", action="append", default=[])
    parser.add_argument("--remote-root", default=DEFAULT_REMOTE_ROOT)
    parser.add_argument("--backend-port", type=int, default=DEFAULT_BACKEND_PORT)
    parser.add_argument("--frontend-port", type=int, default=DEFAULT_FRONTEND_PORT)
    parser.add_argument("--operator-id", default="local-operator-cc")
    parser.add_argument("--owner-id", default="local-owner-cc")
    parser.add_argument("--owner-feedback-verdict", choices=("accepted", "needs_followup", "rejected"), default="accepted")
    parser.add_argument("--model-max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--min-owner-feedback-packets", type=int, default=3)
    parser.add_argument("--min-owner-feedback-accepted-ratio", type=float, default=0.66)
    parser.add_argument("--min-smoke-checks", type=int, default=15)
    parser.add_argument("--require-distinct-providers", action="store_true")
    args = parser.parse_args(argv)

    summary = run_beta_preview_chain(
        output_root=Path(args.output_root),
        env_file=Path(args.env_file),
        additional_env_files=[Path(path) for path in args.additional_env_file],
        additional_agent_ids=list(args.additional_agent_id),
        seed_feedback_index=Path(args.seed_feedback_index),
        seed_preview_summary=Path(args.seed_preview_summary),
        pr_review_evidence=Path(args.pr_review_evidence),
        local_deploy_receipt=Path(args.local_deploy_receipt),
        previous_owner_feedback_packets=[Path(path) for path in args.previous_owner_feedback_packet],
        previous_owner_feedback_packet_globs=list(args.previous_owner_feedback_packet_glob),
        backend_bin=Path(args.backend_bin),
        frontend_build_dir=Path(args.frontend_build_dir),
        nodes=[parse_node(raw) for raw in (args.node or list(DEFAULT_NODES))],
        remote_root=args.remote_root,
        backend_port=args.backend_port,
        frontend_port=args.frontend_port,
        operator_id=args.operator_id,
        owner_id=args.owner_id,
        owner_feedback_verdict=args.owner_feedback_verdict,
        model_max_tokens=args.model_max_tokens,
        temperature=args.temperature,
        min_owner_feedback_packets=args.min_owner_feedback_packets,
        min_owner_feedback_accepted_ratio=args.min_owner_feedback_accepted_ratio,
        min_smoke_checks=args.min_smoke_checks,
        require_distinct_providers=bool(args.require_distinct_providers),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


def run_beta_preview_chain(
    *,
    output_root: Path,
    env_file: Path,
    additional_env_files: list[Path],
    additional_agent_ids: list[str],
    seed_feedback_index: Path,
    seed_preview_summary: Path,
    pr_review_evidence: Path,
    local_deploy_receipt: Path,
    previous_owner_feedback_packets: list[Path],
    previous_owner_feedback_packet_globs: list[str],
    backend_bin: Path,
    frontend_build_dir: Path,
    nodes: list[PreviewNode],
    remote_root: str,
    backend_port: int,
    frontend_port: int,
    operator_id: str,
    owner_id: str,
    owner_feedback_verdict: str,
    model_max_tokens: int,
    temperature: float,
    min_owner_feedback_packets: int,
    min_owner_feedback_accepted_ratio: float,
    min_smoke_checks: int,
    require_distinct_providers: bool,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    review_root = output_root / "external_reviews"
    review_root.mkdir(parents=True, exist_ok=True)

    review_summaries = []
    primary_root = review_root / "reviewer_001"
    primary_summary = _run_external_review(
        output_root=primary_root,
        env_file=env_file,
        feedback_index=seed_feedback_index,
        preview_summary=seed_preview_summary,
        pr_review_evidence=pr_review_evidence,
        rollback_evidence_ref=str(local_deploy_receipt),
        external_agent_id="external-real-reviewer-002",
        display_name="External Real Reviewer 002",
        contact_ref="external-api:controlled-reviewer-002",
        model_max_tokens=model_max_tokens,
        temperature=temperature,
    )
    review_summaries.append(primary_summary)

    if additional_agent_ids and len(additional_agent_ids) != len(additional_env_files):
        raise ValueError("additional_agent_id count must match additional_env_file count")
    for index, extra_env in enumerate(additional_env_files, start=2):
        agent_id = additional_agent_ids[index - 2] if additional_agent_ids else f"external-real-reviewer-{index + 1:03d}"
        extra_summary = _run_external_review(
            output_root=review_root / f"reviewer_{index:03d}",
            env_file=extra_env,
            feedback_index=seed_feedback_index,
            preview_summary=seed_preview_summary,
            pr_review_evidence=pr_review_evidence,
            rollback_evidence_ref=str(local_deploy_receipt),
            external_agent_id=agent_id,
            display_name=f"External Real Reviewer {index + 1:03d}",
            contact_ref=f"external-api:controlled-reviewer-{index + 1:03d}",
            model_max_tokens=model_max_tokens,
            temperature=temperature,
        )
        review_summaries.append(extra_summary)

    multi_review_path = None
    multi_review = None
    if len(review_summaries) >= 2:
        multi_review_path = output_root / "multi_external_review_reconciliation.json"
        multi_review = reconcile_multi_external_reviews(
            summary_paths=review_summaries,
            output_path=multi_review_path,
            min_reviewers=2,
            require_distinct_providers=require_distinct_providers,
        )
        if multi_review.get("passed") is not True:
            raise ValueError(f"multi external review reconciliation failed: {multi_review.get('failure_reasons')}")

    preview_root = output_root / "preview"
    preview_summary_path = output_root / "beta5_repeatable_preview_summary.json"
    _run_repeatable_preview(
        preview_root=preview_root,
        preview_summary_path=preview_summary_path,
        local_deploy_receipt=local_deploy_receipt,
        backend_bin=backend_bin,
        frontend_build_dir=frontend_build_dir,
        nodes=nodes,
        remote_root=remote_root,
        backend_port=backend_port,
        frontend_port=frontend_port,
        operator_id=operator_id,
    )

    owner_packet_path = output_root / "beta5_owner_feedback_packet.json"
    external_evidence_ref = _external_evidence_ref(review_summaries, multi_review_path)
    record_owner_feedback_packet(
        preview_summary_path=preview_summary_path,
        output_path=owner_packet_path,
        owner_id=owner_id,
        operator_id=operator_id,
        feedback_verdict=owner_feedback_verdict,
        feedback_ref=f"owner-feedback:beta-preview-chain:{_sha256(preview_summary_path)}",
        audit_ref=f"audit:beta-preview-chain:{_sha256(review_summaries[0])}",
        external_evidence_ref=external_evidence_ref,
        notes="Owner feedback recorded by bounded Beta preview chain runner.",
    )

    owner_index_path = output_root / "beta5_owner_feedback_index.json"
    owner_index = write_owner_feedback_index(
        packet_paths=[*previous_owner_feedback_packets, owner_packet_path],
        packet_globs=previous_owner_feedback_packet_globs,
        output_path=owner_index_path,
        min_packets=min_owner_feedback_packets,
    )
    if owner_index.get("passed") is not True:
        raise ValueError(f"owner feedback index failed: {owner_index.get('failure_reasons')}")

    readiness_path = output_root / "beta_deployment_preview_readiness.json"
    readiness = inspect_beta_deployment_preview_readiness(
        beta6_9_summary_path=review_summaries[0],
        preview_summary_path=preview_summary_path,
        owner_feedback_index_path=owner_index_path,
        multi_external_review_path=multi_review_path,
        output_path=readiness_path,
        min_owner_feedback_packets=min_owner_feedback_packets,
        min_owner_feedback_accepted_ratio=min_owner_feedback_accepted_ratio,
        min_smoke_checks=min_smoke_checks,
    )
    if readiness.get("passed") is not True:
        raise ValueError(f"Beta deployment preview readiness failed: {readiness.get('failure_reasons')}")

    summary = {
        "schema_version": CHAIN_SCHEMA,
        "checked_at": _now(),
        "passed": True,
        "decision": "beta_preview_chain_passed",
        "run_root": str(output_root.resolve()),
        "review_summary_count": len(review_summaries),
        "multi_external_review_observed": multi_review is not None,
        "multi_external_review": _artifact_ref(multi_review_path) if multi_review_path else None,
        "preview_summary": _artifact_ref(preview_summary_path),
        "owner_feedback_packet": _artifact_ref(owner_packet_path),
        "owner_feedback_index": _artifact_ref(owner_index_path),
        "readiness": _artifact_ref(readiness_path),
        "readiness_decision": readiness.get("decision"),
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_preview_chain_summary.json", summary)
    return summary


def _run_external_review(
    *,
    output_root: Path,
    env_file: Path,
    feedback_index: Path,
    preview_summary: Path,
    pr_review_evidence: Path,
    rollback_evidence_ref: str,
    external_agent_id: str,
    display_name: str,
    contact_ref: str,
    model_max_tokens: int,
    temperature: float,
) -> Path:
    run_real_api_review_chain(
        output_root=output_root,
        env_file=env_file,
        feedback_index=feedback_index,
        pr_review_evidence=pr_review_evidence,
        preview_summary=preview_summary,
        rollback_evidence_ref=rollback_evidence_ref,
        external_agent_id=external_agent_id,
        display_name=display_name,
        contact_ref=contact_ref,
        model_max_tokens=model_max_tokens,
        temperature=temperature,
    )
    return output_root / "beta6_9_real_api_review_summary.json"


def _run_repeatable_preview(
    *,
    preview_root: Path,
    preview_summary_path: Path,
    local_deploy_receipt: Path,
    backend_bin: Path,
    frontend_build_dir: Path,
    nodes: list[PreviewNode],
    remote_root: str,
    backend_port: int,
    frontend_port: int,
    operator_id: str,
) -> None:
    write_real_multivm_preview_run(
        run_root=preview_root,
        backend_bin=backend_bin,
        frontend_build_dir=frontend_build_dir,
        nodes=nodes,
        remote_root=remote_root,
        backend_port=backend_port,
        frontend_port=frontend_port,
        owner=operator_id,
    )
    env = os.environ.copy()
    env.update(
        {
            "CIVITASOS_AGENT_ROOT": str(ROOT.resolve()),
            "BETA5_LOCAL_DEPLOY_RECEIPT": str(local_deploy_receipt.resolve()),
            "BETA5_OPERATOR_ID": operator_id,
        }
    )
    stdout_path = preview_root / "operator_commands.stdout"
    stderr_path = preview_root / "operator_commands.stderr"
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
        subprocess.run([str(preview_root / "operator_commands.sh")], cwd=ROOT, env=env, stdout=stdout, stderr=stderr, check=True)
    _write_repeatable_preview_summary(preview_root, preview_summary_path)


def _write_repeatable_preview_summary(preview_root: Path, summary_path: Path) -> None:
    prepare = _read_json(preview_root / "prepare_report.json")
    deploy = _read_json(preview_root / "beta5_external_deploy_execution_report.json")
    rollback = _read_json(preview_root / "beta5_external_deploy_rollback_drill_execution_report.json")
    deploy_validation = _read_json(preview_root / "beta5_external_deploy_receipt_validation.json")
    rollback_validation = _read_json(preview_root / "beta5_external_deploy_rollback_drill_receipt_validation.json")
    smoke = _read_json(preview_root / "multivm_real_service_smoke_summary.json")
    for label, report in (
        ("deploy", deploy),
        ("rollback", rollback),
        ("deploy_validation", deploy_validation),
        ("rollback_validation", rollback_validation),
        ("smoke", smoke),
    ):
        if report.get("passed") is not True:
            raise ValueError(f"repeatable preview {label} did not pass")
    summary = {
        "schema_version": "beta5-repeatable-preview-nightly-artifact:v1",
        "passed": True,
        "run_root": str(preview_root),
        "prepare_report": str((preview_root / "prepare_report.json").resolve()),
        "deploy_receipt": deploy["deploy_receipt_path"],
        "deploy_receipt_sha256": deploy_validation["receipt_sha256"],
        "rollback_receipt": rollback["rollback_receipt_path"],
        "rollback_receipt_sha256": rollback_validation["receipt_sha256"],
        "nodes": smoke["nodes"],
        "smoke_cycles": smoke["cycles"],
        "smoke_total_checks": smoke["total_checks"],
        "latency_ms_min": smoke["latency_ms_min"],
        "latency_ms_median": smoke["latency_ms_median"],
        "latency_ms_max": smoke["latency_ms_max"],
        "environment_proof": prepare["environment_proof"],
        "external_environment_classification": "external_preview",
        "external_environment_provider": "virtualbox",
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
    }
    _write_json(summary_path, summary)


def _external_evidence_ref(review_summaries: list[Path], multi_review_path: Path | None) -> str:
    if multi_review_path:
        return f"multi-external-review:{_sha256(multi_review_path)}"
    return f"external-agent-review:{_sha256(review_summaries[0])}"


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return value


def _artifact_ref(path: Path | None) -> dict[str, str] | None:
    if path is None:
        return None
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
