from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

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
authorization = _load("beta3_source_apply_authorization", ROOT / "scripts" / "beta3_source_apply_authorization.py")
authorization_tests = _load(
    "beta3_source_apply_authorization_fixture_for_executor",
    ROOT / "benchmarks" / "tests" / "test_beta3_source_apply_authorization.py",
)
module = _load("beta3_source_apply_executor", ROOT / "scripts" / "beta3_source_apply_executor.py")


def test_source_apply_executor_applies_patch_and_writes_post_apply_receipt(tmp_path: Path) -> None:
    repo, authorization_path = _write_authorization(tmp_path)

    report = module.run_source_apply(
        authorization_path=authorization_path,
        output_root=tmp_path / "source-apply",
        test_commands=["grep -q 'beta3 sandbox change' README.md"],
    )
    receipt_path = Path(report["post_apply_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["source_apply_outcome"] == "applied_tests_passed"
    assert report["test_evidence_status"] == "passed"
    assert report["source_repo_apply_performed"] is True
    assert report["receipt_validation"]["passed"] is True
    assert "beta3 sandbox change" in (repo / "README.md").read_text(encoding="utf-8")
    assert receipt["receipt_scope"] == "source_worktree_apply_only"
    assert receipt["source_repo_apply_performed"] is True
    assert receipt["commit_allowed"] is False
    assert _git(repo, "status", "--short")


def test_source_apply_executor_blocks_expired_authorization(tmp_path: Path) -> None:
    repo, authorization_path = _write_authorization(tmp_path)
    (repo / "README.md").write_text("drift before apply\n", encoding="utf-8")

    report = module.run_source_apply(
        authorization_path=authorization_path,
        output_root=tmp_path / "blocked",
        test_commands=[],
    )

    assert report["passed"] is False
    assert report["apply_status"] == "authorization_refused"
    assert report["source_apply_outcome"] == "authorization_refused"
    assert report["failure_codes"] == ["source_apply_authorization_refused"]
    assert report["source_repo_apply_performed"] is False
    assert report["operator_followup"]["required"] is True
    assert (tmp_path / "blocked" / "beta3_source_apply_execution_report.json").is_file()


def test_source_apply_executor_classifies_post_apply_test_failure(tmp_path: Path) -> None:
    repo, authorization_path = _write_authorization(tmp_path)

    report = module.run_source_apply(
        authorization_path=authorization_path,
        output_root=tmp_path / "test-failed",
        test_commands=["grep -q 'missing expectation' README.md"],
    )
    receipt = json.loads(Path(report["post_apply_receipt_path"]).read_text(encoding="utf-8"))

    assert report["passed"] is False
    assert report["source_apply_outcome"] == "applied_tests_failed"
    assert report["failure_codes"] == ["post_apply_test_failed"]
    assert report["test_evidence_status"] == "failed"
    assert report["receipt_validation"]["passed"] is True
    assert report["operator_followup"]["rollback_decision_required"] is True
    assert "beta3 sandbox change" in (repo / "README.md").read_text(encoding="utf-8")
    assert receipt["test_evidence_status"] == "failed"


def test_post_apply_receipt_validation_rejects_commit_authority(tmp_path: Path) -> None:
    _, authorization_path = _write_authorization(tmp_path)
    report = module.run_source_apply(
        authorization_path=authorization_path,
        output_root=tmp_path / "receipt-boundary",
        test_commands=[],
    )
    receipt_path = Path(report["post_apply_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["commit_allowed"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_post_source_apply_receipt(receipt_path)

    assert validation["passed"] is False
    assert "commit_allowed must be false" in validation["failure_reasons"]


def _write_authorization(tmp_path: Path) -> tuple[Path, Path]:
    repo, review_packet = authorization_tests._write_review_packet(tmp_path)
    path = tmp_path / "beta3_source_apply_authorization.json"
    authorization.record_source_apply_authorization(
        review_packet_path=review_packet,
        repo=repo,
        output_path=path,
        operator_id="operator-001",
        reason="authorize source apply fixture",
        rollback_evidence_ref="rollback:source-apply-fixture",
        allow_path_prefixes=["README.md"],
    )
    return repo, path


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, text=True, capture_output=True).stdout
