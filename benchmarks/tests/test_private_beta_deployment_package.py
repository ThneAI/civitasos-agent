from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load("private_beta_deployment_package", SCRIPTS / "private_beta_deployment_package.py")


def test_private_beta_deployment_package_accepts_ready_evidence(tmp_path: Path) -> None:
    report = module.build_package(
        observer_baseline_summary=_write_observer(tmp_path / "observer.json"),
        path_stability_index=_write_stability(tmp_path / "stability.json"),
        private_preview_summary=_write_preview(tmp_path / "preview.json"),
        four_agent_summary=_write_four_agent(tmp_path / "four_agent.json"),
        mediation_summary=_write_mediation(tmp_path / "mediation.json"),
        output=tmp_path / "package.json",
        operator_id="operator",
        service_id="private_beta_external_agent_pool",
        service_token_scopes=["agents:read", "agents:write", "pool:post", "pool:read", "pool:claim", "pool:write"],
    )

    assert report["passed"] is True
    assert report["readiness"]["private_beta_deployment_package_ready"] is True
    assert report["agent_operating_model"]["controlled_proposer_reviewer_extension_ready"] is True
    assert report["agent_operating_model"]["bounded_apply_requires_single_use_authorization"] is True
    assert report["boundary"]["deploy_allowed"] is False
    assert report["service_token_policy"]["demo_login_allowed"] is False


def test_private_beta_deployment_package_blocks_demo_like_scope(tmp_path: Path) -> None:
    report = module.build_package(
        observer_baseline_summary=_write_observer(tmp_path / "observer.json"),
        path_stability_index=_write_stability(tmp_path / "stability.json"),
        private_preview_summary=_write_preview(tmp_path / "preview.json"),
        four_agent_summary=_write_four_agent(tmp_path / "four_agent.json"),
        mediation_summary=_write_mediation(tmp_path / "mediation.json"),
        output=tmp_path / "package.json",
        operator_id="operator",
        service_id="private_beta_external_agent_pool",
        service_token_scopes=["agents:read", "agents:write", "pool:post", "pool:read", "pool:claim", "pool:write", "production:write"],
    )

    assert report["passed"] is False
    assert any("forbidden scopes" in reason for reason in report["failure_reasons"])


def _write_observer(path: Path) -> Path:
    payload = {
        "schema_version": "post-h3-observer-mode-baseline-gate:v1",
        "passed": True,
        "readiness": {"post_h3_observer_mode_baseline_ready": True},
    }
    return _write(path, payload)


def _write_stability(path: Path) -> Path:
    payload = {
        "schema_version": "post-h3-minimal-production-task-path-stability-index:v1",
        "passed": True,
        "readiness": {"minimal_production_task_path_stable": True},
    }
    return _write(path, payload)


def _write_preview(path: Path) -> Path:
    payload = {
        "schema_version": "p0j-multi-vm-private-preview-chain:v1",
        "passed": True,
        "vm_target_ids": ["vm1", "vm2", "vm3"],
        "readiness": {"p0j_multi_vm_private_preview_complete": True},
        "boundary": {"external_public_ingress_opened": False, "production_transition_allowed": False},
    }
    return _write(path, payload)


def _write_four_agent(path: Path) -> Path:
    payload = {
        "schema_version": "beta-fe-four-agent-frontend-orchestration-summary:v1",
        "passed": True,
        "participants": ["deepseek-api-agent", "claude-cli-agent", "hermes-cli-agent", "local-gpu-agent"],
        "task_receipt_count": 4,
        "claim_observed_count": 4,
        "generation_after_claim_observed_count": 4,
        "delivery_observed_count": 4,
        "boundary": {
            "apply_allowed": False,
            "commit_allowed": False,
            "push_allowed": False,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
    }
    return _write(path, payload)


def _write_mediation(path: Path) -> Path:
    payload = {
        "schema_version": "beta-fe26-agent-runner-mediation-summary:v1",
        "passed": True,
        "backend_auth": {"auth_method": "service_token", "token_recorded": False, "production_allowed": False},
        "boundary": {
            "apply_allowed": False,
            "commit_allowed": False,
            "push_allowed": False,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
    }
    return _write(path, payload)


def _write(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
