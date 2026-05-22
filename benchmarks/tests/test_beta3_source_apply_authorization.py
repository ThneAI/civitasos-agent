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
packet = _load("beta3_multi_agent_review_packet", ROOT / "scripts" / "beta3_multi_agent_review_packet.py")
packet_tests = _load(
    "beta3_multi_agent_review_packet_fixture_for_authorization",
    ROOT / "benchmarks" / "tests" / "test_beta3_multi_agent_review_packet.py",
)
module = _load("beta3_source_apply_authorization", ROOT / "scripts" / "beta3_source_apply_authorization.py")


def test_source_apply_authorization_records_clean_snapshot_and_explicit_paths(tmp_path: Path) -> None:
    repo, review_packet = _write_review_packet(tmp_path)
    output = tmp_path / "beta3_source_apply_authorization.json"

    report = module.record_source_apply_authorization(
        review_packet_path=review_packet,
        repo=repo,
        output_path=output,
        operator_id="operator-001",
        reason="authorize reviewed README fixture patch for source worktree apply",
        rollback_evidence_ref="rollback:git-diff-before-source-apply",
        allow_path_prefixes=["README.md"],
    )
    authorization = json.loads(output.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert authorization["authorization_scope"] == "source_worktree_apply_only"
    assert authorization["source_repo_apply_authorized"] is True
    assert authorization["source_repo_apply_performed"] is False
    assert authorization["authorized_target_paths"] == ["README.md"]
    assert authorization["commit_allowed"] is False


def test_source_apply_authorization_blocks_dirty_repo(tmp_path: Path) -> None:
    repo, review_packet = _write_review_packet(tmp_path)
    (repo / "README.md").write_text("dirty after sandbox\n", encoding="utf-8")

    with pytest.raises(ValueError, match="worktree must be clean"):
        module.record_source_apply_authorization(
            review_packet_path=review_packet,
            repo=repo,
            output_path=tmp_path / "blocked.json",
            operator_id="operator-001",
            reason="do not authorize dirty worktree",
            rollback_evidence_ref="rollback:fixture",
            allow_path_prefixes=["README.md"],
        )


def test_source_apply_authorization_validation_expires_on_snapshot_drift(tmp_path: Path) -> None:
    repo, review_packet = _write_review_packet(tmp_path)
    output = tmp_path / "authorization.json"
    module.record_source_apply_authorization(
        review_packet_path=review_packet,
        repo=repo,
        output_path=output,
        operator_id="operator-001",
        reason="authorize before later drift",
        rollback_evidence_ref="rollback:fixture",
        allow_path_prefixes=["README.md"],
    )
    (repo / "README.md").write_text("drift after authorization\n", encoding="utf-8")

    validation = module.validate_source_apply_authorization(output)

    assert validation["passed"] is False
    assert "target repo snapshot drifted after authorization" in validation["failure_reasons"]
    assert "target repo worktree must be clean" in validation["failure_reasons"]


def _write_review_packet(tmp_path: Path) -> tuple[Path, Path]:
    operator_receipt = packet_tests._write_operator_receipt(tmp_path)
    review = packet_tests._write_verdict(tmp_path, operator_receipt, role="review_agent")
    risk = packet_tests._write_verdict(tmp_path, operator_receipt, role="risk_agent")
    review_packet = tmp_path / "beta3_multi_agent_review_packet.json"
    packet.build_review_packet(
        operator_receipt_path=operator_receipt,
        review_verdict_path=review,
        risk_verdict_path=risk,
        output_path=review_packet,
    )
    receipt_payload = json.loads(operator_receipt.read_text(encoding="utf-8"))
    sandbox_path = Path(receipt_payload["source_sandbox_report"]["path"])
    sandbox = json.loads(sandbox_path.read_text(encoding="utf-8"))
    return Path(sandbox["source_repo"]["repo_root"]), review_packet
