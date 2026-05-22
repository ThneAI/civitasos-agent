from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[2]
_load("beta1_repo_review_proposal", ROOT / "scripts" / "beta1_repo_review_proposal.py")
_load("beta2_patch_proposal", ROOT / "scripts" / "beta2_patch_proposal.py")
_load("beta2_operator_apply_receipt", ROOT / "scripts" / "beta2_operator_apply_receipt.py")
_load("beta2_patch_review_outcome", ROOT / "scripts" / "beta2_patch_review_outcome.py")
_load("beta3_controlled_apply_candidate", ROOT / "scripts" / "beta3_controlled_apply_candidate.py")
_load("beta3_controlled_apply_sandbox", ROOT / "scripts" / "beta3_controlled_apply_sandbox.py")
_load("beta3_post_sandbox_operator_receipt", ROOT / "scripts" / "beta3_post_sandbox_operator_receipt.py")
_load("beta3_multi_agent_review_packet", ROOT / "scripts" / "beta3_multi_agent_review_packet.py")
_load("beta3_source_apply_authorization", ROOT / "scripts" / "beta3_source_apply_authorization.py")
_load("beta3_source_apply_executor", ROOT / "scripts" / "beta3_source_apply_executor.py")
_load("beta3_git_publication_authorization", ROOT / "scripts" / "beta3_git_publication_authorization.py")
_load("beta3_git_commit_executor", ROOT / "scripts" / "beta3_git_commit_executor.py")
_load("beta3_git_push_executor", ROOT / "scripts" / "beta3_git_push_executor.py")
merge = _load("beta3_git_merge_executor", ROOT / "scripts" / "beta3_git_merge_executor.py")
merge_tests = _load(
    "beta3_git_merge_executor_fixture_for_deploy",
    ROOT / "benchmarks" / "tests" / "test_beta3_git_merge_executor.py",
)
module = _load("beta3_local_deploy_executor", ROOT / "scripts" / "beta3_local_deploy_executor.py")


def test_local_deploy_executor_runs_explicit_command_after_merge(tmp_path: Path) -> None:
    target_repo, merge_receipt = _write_merge_receipt(tmp_path)
    authorization_path = tmp_path / "local_deploy_authorization.json"
    module.record_deploy_authorization(
        merge_receipt_path=merge_receipt,
        deploy_target="local-preview-fixture",
        deploy_command="git rev-parse HEAD",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="probe merged fixture in local deploy gate",
        rollback_evidence_ref="rollback:local-preview-fixture",
        ack_local_controlled_deploy=True,
    )

    report = module.run_local_deploy(
        authorization_path=authorization_path,
        output_root=tmp_path / "local-deploy",
    )
    receipt = json.loads(Path(report["deploy_receipt_path"]).read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["deploy_status"] == "local_deployed_with_receipt"
    assert report["receipt_validation"]["passed"] is True
    assert report["local_deploy_performed"] is True
    assert report["deploy"]["stdout"].strip() == report["source_merge_commit_id"]
    assert receipt["receipt_scope"] == "local_controlled_deploy_only"
    assert receipt["deployment_mode"] == "local_controlled"
    assert receipt["deploy_command"]["shell"] is False
    assert receipt["production_deploy_allowed"] is False
    assert _status(target_repo) == ""


def test_local_deploy_authorization_requires_local_ack(tmp_path: Path) -> None:
    _, merge_receipt = _write_merge_receipt(tmp_path)

    with pytest.raises(ValueError, match="explicit acknowledgement"):
        module.record_deploy_authorization(
            merge_receipt_path=merge_receipt,
            deploy_target="local-preview-fixture",
            deploy_command="git rev-parse HEAD",
            output_path=tmp_path / "blocked_authorization.json",
            operator_id="operator-001",
            reason="prove explicit local deploy ack is required",
            rollback_evidence_ref="rollback:missing-ack",
            ack_local_controlled_deploy=False,
        )


def test_local_deploy_executor_refuses_merge_receipt_as_deploy_authorization(tmp_path: Path) -> None:
    _, merge_receipt = _write_merge_receipt(tmp_path)

    report = module.run_local_deploy(
        authorization_path=merge_receipt,
        output_root=tmp_path / "merge-receipt-is-not-authorization",
    )

    assert report["passed"] is False
    assert report["failure_codes"] == ["local_deploy_authorization_refused"]
    assert report["local_deploy_performed"] is False
    assert any(
        "schema_version must be beta3-local-deploy-authorization:v1" in reason
        for reason in report["failure_reasons"]
    )


def test_local_deploy_receipt_validation_rejects_production_claim(tmp_path: Path) -> None:
    _, merge_receipt = _write_merge_receipt(tmp_path)
    authorization_path = tmp_path / "local_deploy_authorization.json"
    module.record_deploy_authorization(
        merge_receipt_path=merge_receipt,
        deploy_target="local-preview-fixture",
        deploy_command="git rev-parse HEAD",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="authorize receipt boundary fixture",
        rollback_evidence_ref="rollback:receipt-boundary",
        ack_local_controlled_deploy=True,
    )
    report = module.run_local_deploy(authorization_path=authorization_path, output_root=tmp_path / "deploy")
    receipt_path = Path(report["deploy_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["production_deploy_allowed"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_local_deploy_receipt(receipt_path)

    assert validation["passed"] is False
    assert "production_deploy_allowed must be false" in validation["failure_reasons"]


def _write_merge_receipt(tmp_path: Path) -> tuple[Path, Path]:
    _, push_receipt, remote = merge_tests._write_push_receipt(tmp_path)
    target_repo = merge_tests._write_controlled_target_repo(tmp_path, remote, "beta3-source-fixture")
    authorization_path = tmp_path / "git_merge_authorization.json"
    merge.record_merge_authorization(
        push_receipt_path=push_receipt,
        target_repo=target_repo,
        target_branch="beta3-integration-fixture",
        merge_message="merge: deploy fixture",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="merge fixture before local deploy",
        rollback_evidence_ref="rollback:deploy-fixture-merge",
    )
    report = merge.run_git_merge(authorization_path=authorization_path, output_root=tmp_path / "git-merge")
    return target_repo, Path(report["merge_receipt_path"])


def _status(repo: Path) -> str:
    import subprocess

    return subprocess.run(
        ["git", "status", "--short"],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    ).stdout
