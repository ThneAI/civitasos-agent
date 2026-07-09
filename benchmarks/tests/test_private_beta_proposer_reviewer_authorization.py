from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


module = _load("private_beta_proposer_reviewer_authorization", SCRIPTS / "private_beta_proposer_reviewer_authorization.py")


def test_private_beta_proposer_reviewer_request_decision_and_validation(tmp_path: Path) -> None:
    package = _write_package(tmp_path)
    request = module.write_authorization_request(
        private_beta_package=package,
        output_root=tmp_path / "request",
        operator_id="operator-cc",
        operator_statement="Authorize one bounded proposer/reviewer request.",
        proposer_agents=["deepseek-api-agent"],
        reviewer_agents=["claude-cli-agent", "hermes-cli-agent", "local-gpu-agent"],
        allowed_modes=["patch_proposal", "release_review"],
        max_proposals=1,
        max_reviews=3,
        service_token_scopes=["agents:read", "pool:post", "pool:read", "pool:claim", "pool:write"],
        scenario_id="fe14-runtime-data-adapter-decomposition",
        patch_slice_id="runtime_data_adapter_decomposition",
        ack_authorization_request=True,
    )
    assert request["passed"] is True
    assert request["readiness"]["authorization_request_ready"] is True
    assert request["boundary"]["patch_proposal_allowed"] is False
    assert request["requested_scope"]["service_token_scopes"] == ["agents:read", "pool:claim", "pool:post", "pool:read", "pool:write"]
    assert request["requested_scope"]["scenario_id"] == "fe14-runtime-data-adapter-decomposition"
    assert request["requested_scope"]["patch_slice_id"] == "runtime_data_adapter_decomposition"

    decision = module.write_authorization_decision(
        authorization_request=tmp_path / "request" / "private_beta_proposer_reviewer_authorization_request.json",
        output_root=tmp_path / "decision",
        operator_id="operator-cc",
        operator_decision="authorize_once",
        operator_statement="Authorize one controlled proposer/reviewer run.",
        ack_authorization_decision=True,
    )
    assert decision["passed"] is True
    assert decision["single_use"] is True
    assert decision["consumed"] is False
    assert decision["boundary"]["patch_proposal_allowed"] is True
    assert decision["boundary"]["release_review_allowed"] is True
    assert decision["boundary"]["apply_allowed"] is False
    assert decision["authorized_scope"]["scenario_id"] == "fe14-runtime-data-adapter-decomposition"
    assert decision["authorized_scope"]["patch_slice_id"] == "runtime_data_adapter_decomposition"

    validation = module.validate_authorization(tmp_path / "decision" / "private_beta_proposer_reviewer_authorization.json")
    assert validation["passed"] is True
    assert validation["readiness"]["controlled_proposer_reviewer_execution_ready"] is True


def test_private_beta_proposer_reviewer_request_blocks_forbidden_scope(tmp_path: Path) -> None:
    package = _write_package(tmp_path)
    request = module.write_authorization_request(
        private_beta_package=package,
        output_root=tmp_path / "request",
        operator_id="operator-cc",
        operator_statement="Request with too much scope.",
        proposer_agents=["deepseek-api-agent"],
        reviewer_agents=["claude-cli-agent"],
        allowed_modes=["patch_proposal"],
        max_proposals=1,
        max_reviews=1,
        service_token_scopes=["agents:read", "agents:write", "pool:post", "pool:read", "pool:claim", "pool:write"],
        ack_authorization_request=True,
    )
    assert request["passed"] is False
    assert any("forbidden scopes" in item for item in request["failure_reasons"])


def test_private_beta_proposer_reviewer_request_blocks_overlapping_roles(tmp_path: Path) -> None:
    package = _write_package(tmp_path)
    request = module.write_authorization_request(
        private_beta_package=package,
        output_root=tmp_path / "request",
        operator_id="operator-cc",
        operator_statement="Request overlapping proposer/reviewer roles.",
        proposer_agents=["deepseek-api-agent"],
        reviewer_agents=["deepseek-api-agent"],
        allowed_modes=["release_review"],
        max_proposals=1,
        max_reviews=1,
        service_token_scopes=["agents:read", "pool:post", "pool:read", "pool:claim", "pool:write"],
        ack_authorization_request=True,
    )
    assert request["passed"] is False
    assert "proposer and reviewer sets must be disjoint" in request["failure_reasons"]


def _write_package(tmp_path: Path) -> Path:
    path = tmp_path / "private_beta_deployment_package.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "private-beta-deployment-package:v1",
                "passed": True,
                "decision": "private_beta_deployment_package_ready",
                "readiness": {"controlled_proposer_reviewer_extension_ready": True},
                "agent_operating_model": {
                    "participants": ["deepseek-api-agent", "claude-cli-agent", "hermes-cli-agent", "local-gpu-agent"],
                    "allowed_modes": ["read_only_pool_task", "patch_proposal", "release_review"],
                },
                "boundary": {
                    "apply_allowed": False,
                    "commit_allowed": False,
                    "push_allowed": False,
                    "merge_allowed": False,
                    "deploy_allowed": False,
                    "external_public_ingress_opened": False,
                    "production_runtime_execution_allowed": False,
                    "production_receipt_write_allowed": False,
                },
            }
        ),
        encoding="utf-8",
    )
    return path
