#!/usr/bin/env python3
"""Build a private Beta deployment package from bounded readiness evidence.

The package is an artifact-only handoff. It promotes read-only pool-mediated
Agent participation into a controlled proposer/reviewer operating model, but it
never authorizes apply, commit, push, merge, deploy, public ingress, production
runtime execution, or production receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope

SCHEMA_VERSION = "private-beta-deployment-package:v1"
OBSERVER_BASELINE_SCHEMA = "post-h3-observer-mode-baseline-gate:v1"
PATH_STABILITY_SCHEMA = "post-h3-minimal-production-task-path-stability-index:v1"
P0J_SCHEMA = "p0j-multi-vm-private-preview-chain:v1"
FOUR_AGENT_SCHEMA = "beta-fe-four-agent-frontend-orchestration-summary:v1"
FE26_SCHEMA = "beta-fe26-agent-runner-mediation-summary:v1"
REQUIRED_PARTICIPANTS = ("deepseek-api-agent", "claude-cli-agent", "hermes-cli-agent", "local-gpu-agent")
NON_CLAIMS = (
    "private_beta_package_is_artifact_only",
    "private_beta_package_does_not_authorize_apply_commit_push_merge_or_deploy",
    "private_beta_package_does_not_open_public_ingress",
    "private_beta_package_does_not_authorize_production_runtime_execution",
    "private_beta_package_does_not_write_production_receipts",
    "controlled_proposer_reviewer_requires_followup_single_use_authorization",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer-baseline-summary", required=True)
    parser.add_argument("--path-stability-index", required=True)
    parser.add_argument("--private-preview-summary", required=True)
    parser.add_argument("--four-agent-summary", required=True)
    parser.add_argument("--mediation-summary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--operator-id", default="local-operator-cc")
    parser.add_argument("--service-id", default="private_beta_external_agent_pool")
    parser.add_argument("--service-token-scope", action="append", default=[])
    args = parser.parse_args(argv)
    report = build_package(
        observer_baseline_summary=Path(args.observer_baseline_summary),
        path_stability_index=Path(args.path_stability_index),
        private_preview_summary=Path(args.private_preview_summary),
        four_agent_summary=Path(args.four_agent_summary),
        mediation_summary=Path(args.mediation_summary),
        output=Path(args.output),
        operator_id=args.operator_id,
        service_id=args.service_id,
        service_token_scopes=args.service_token_scope or _default_service_scopes(),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def build_package(
    *,
    observer_baseline_summary: Path,
    path_stability_index: Path,
    private_preview_summary: Path,
    four_agent_summary: Path,
    mediation_summary: Path,
    output: Path,
    operator_id: str,
    service_id: str,
    service_token_scopes: list[str],
) -> dict[str, Any]:
    failures: list[str] = []
    observer = _read_json(observer_baseline_summary, failures, "observer baseline summary")
    stability = _read_json(path_stability_index, failures, "path stability index")
    preview = _read_json(private_preview_summary, failures, "private preview summary")
    four_agent = _read_json(four_agent_summary, failures, "four-Agent summary")
    mediation = _read_json(mediation_summary, failures, "FE26 mediation summary")

    _validate_observer(observer, failures)
    _validate_stability(stability, failures)
    _validate_preview(preview, failures)
    _validate_four_agent(four_agent, failures)
    _validate_mediation(mediation, failures)
    _validate_service_token(service_token_scopes, failures)
    if not operator_id.strip():
        failures.append("operator_id is required")
    if not service_id.strip():
        failures.append("service_id is required")

    passed = not failures
    source_artifacts = {
        "observer_baseline_summary": artifact_ref(observer_baseline_summary) if observer_baseline_summary.is_file() else None,
        "path_stability_index": artifact_ref(path_stability_index) if path_stability_index.is_file() else None,
        "private_preview_summary": artifact_ref(private_preview_summary) if private_preview_summary.is_file() else None,
        "four_agent_summary": artifact_ref(four_agent_summary) if four_agent_summary.is_file() else None,
        "mediation_summary": artifact_ref(mediation_summary) if mediation_summary.is_file() else None,
    }
    source_refs = [ref for ref in source_artifacts.values() if ref]
    report = {
        "schema_version": SCHEMA_VERSION,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="governance",
            schema_version=SCHEMA_VERSION,
            artifact_id="private-beta-package:bounded-agent-collaboration",
            subject_id="private-beta-deployment",
            producer="private_beta_deployment_package",
            source_refs=source_refs,
            scope="private_beta_readiness_and_controlled_agent_collaboration",
        ),
        "checked_at": _now(),
        "passed": passed,
        "decision": "private_beta_deployment_package_ready" if passed else "blocked",
        "failure_reasons": failures,
        "operator_id": operator_id,
        "source_artifacts": source_artifacts,
        "service_token_policy": {
            "service_id": service_id,
            "scopes": sorted(service_token_scopes),
            "secret_material_recorded": False,
            "demo_login_allowed": False,
            "service_token_required": True,
        },
        "agent_operating_model": {
            "participants": list(REQUIRED_PARTICIPANTS),
            "allowed_modes": ["read_only_pool_task", "patch_proposal", "release_review"],
            "disallowed_without_followup_gate": ["apply", "commit", "push", "merge", "deploy", "public_ingress", "production_runtime_execution", "production_receipt_write"],
            "controlled_proposer_reviewer_extension_ready": passed,
            "bounded_apply_requires_single_use_authorization": True,
        },
        "readiness": {
            "private_beta_deployment_package_ready": passed,
            "observer_baseline_ready": observer.get("readiness", {}).get("post_h3_observer_mode_baseline_ready") is True,
            "minimal_path_stable": stability.get("readiness", {}).get("minimal_production_task_path_stable") is True,
            "private_vm_preview_ready": preview.get("readiness", {}).get("p0j_multi_vm_private_preview_complete") is True,
            "read_only_pool_mediated_task_ready": mediation.get("passed") is True,
            "controlled_proposer_reviewer_extension_ready": passed,
            "next_step": "start_controlled_proposer_reviewer_authorization_gate" if passed else "fix_blocking_readiness_evidence",
        },
        "boundary": _boundary(),
        "h3_boundary": {"h3_remains_blocked": False, "h3_production_readiness_claimed": False},
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output, report)
    return report


def _validate_observer(summary: dict[str, Any], failures: list[str]) -> None:
    if summary.get("schema_version") != OBSERVER_BASELINE_SCHEMA:
        failures.append(f"observer baseline schema_version must be {OBSERVER_BASELINE_SCHEMA}")
    if summary.get("passed") is not True:
        failures.append("observer baseline must be passed")
    readiness = summary.get("readiness") if isinstance(summary.get("readiness"), dict) else {}
    if readiness.get("post_h3_observer_mode_baseline_ready") is not True:
        failures.append("observer baseline readiness must be true")


def _validate_stability(summary: dict[str, Any], failures: list[str]) -> None:
    if summary.get("schema_version") != PATH_STABILITY_SCHEMA:
        failures.append(f"path stability schema_version must be {PATH_STABILITY_SCHEMA}")
    if summary.get("passed") is not True:
        failures.append("path stability index must be passed")
    readiness = summary.get("readiness") if isinstance(summary.get("readiness"), dict) else {}
    if readiness.get("minimal_production_task_path_stable") is not True:
        failures.append("minimal production task path must be stable")


def _validate_preview(summary: dict[str, Any], failures: list[str]) -> None:
    if summary.get("schema_version") != P0J_SCHEMA:
        failures.append(f"private preview schema_version must be {P0J_SCHEMA}")
    if summary.get("passed") is not True:
        failures.append("private preview summary must be passed")
    targets = summary.get("vm_target_ids") if isinstance(summary.get("vm_target_ids"), list) else []
    if sorted(str(item) for item in targets) != ["vm1", "vm2", "vm3"]:
        failures.append("private preview must cover vm1/vm2/vm3")
    boundary = summary.get("boundary") if isinstance(summary.get("boundary"), dict) else {}
    if boundary.get("external_public_ingress_opened") is not False:
        failures.append("private preview must keep public ingress closed")
    if boundary.get("production_transition_allowed") is not False:
        failures.append("private preview must not authorize production transition")


def _validate_four_agent(summary: dict[str, Any], failures: list[str]) -> None:
    if summary.get("schema_version") != FOUR_AGENT_SCHEMA:
        failures.append(f"four-Agent summary schema_version must be {FOUR_AGENT_SCHEMA}")
    if summary.get("passed") is not True:
        failures.append("four-Agent orchestration must be passed")
    participants = summary.get("participants") if isinstance(summary.get("participants"), list) else []
    if sorted(str(item) for item in participants) != sorted(REQUIRED_PARTICIPANTS):
        failures.append("four-Agent orchestration must include DeepSeek/Claude/Hermes/local GPU")
    for key in ("task_receipt_count", "claim_observed_count", "generation_after_claim_observed_count", "delivery_observed_count"):
        if int(summary.get(key) or 0) < 4:
            failures.append(f"four-Agent orchestration must have {key} >= 4")
    _validate_closed_boundary(summary, failures, "four-Agent orchestration")


def _validate_mediation(summary: dict[str, Any], failures: list[str]) -> None:
    if summary.get("schema_version") != FE26_SCHEMA:
        failures.append(f"mediation summary schema_version must be {FE26_SCHEMA}")
    if summary.get("passed") is not True:
        failures.append("FE26 mediation summary must be passed")
    auth = summary.get("backend_auth") if isinstance(summary.get("backend_auth"), dict) else {}
    if auth.get("auth_method") != "service_token":
        failures.append("FE26 mediation must use service_token auth")
    if auth.get("token_recorded") is not False:
        failures.append("FE26 mediation must not record service token")
    if auth.get("production_allowed") is not False:
        failures.append("FE26 mediation service token must not allow production")
    _validate_closed_boundary(summary, failures, "FE26 mediation")


def _validate_service_token(scopes: list[str], failures: list[str]) -> None:
    required = {"agents:read", "agents:write", "pool:post", "pool:read", "pool:claim", "pool:write"}
    scope_set = set(scopes)
    if not required.issubset(scope_set):
        failures.append(f"service token scopes missing required scopes: {sorted(required - scope_set)}")
    forbidden = {"evidence:write", "production:write", "deploy:write", "git:write"}
    if scope_set & forbidden:
        failures.append(f"service token scopes include forbidden scopes: {sorted(scope_set & forbidden)}")


def _validate_closed_boundary(summary: dict[str, Any], failures: list[str], label: str) -> None:
    boundary = summary.get("boundary") if isinstance(summary.get("boundary"), dict) else {}
    for key in ("apply_allowed", "commit_allowed", "push_allowed", "merge_allowed", "deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(key) is not False:
            failures.append(f"{label} boundary must keep {key}=false")


def _boundary() -> dict[str, Any]:
    return {
        "artifact_only": True,
        "private_beta_package_written": True,
        "frontend_code_modified": False,
        "apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "external_public_ingress_opened": False,
        "runtime_execution_performed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "secrets_recorded": False,
    }


def _default_service_scopes() -> list[str]:
    return ["agents:read", "agents:write", "pool:post", "pool:read", "pool:claim", "pool:write"]


def _read_json(path: Path, failures: list[str], label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
        return {}
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
