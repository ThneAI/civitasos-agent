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
push_tests = _load(
    "beta3_git_merge_executor_fixture_for_review_evidence",
    ROOT / "benchmarks" / "tests" / "test_beta3_git_merge_executor.py",
)
draft = _load("beta4_draft_pr_executor", ROOT / "scripts" / "beta4_draft_pr_executor.py")
draft_tests = _load(
    "beta4_draft_pr_executor_fixture_for_review_evidence",
    ROOT / "benchmarks" / "tests" / "test_beta4_draft_pr_executor.py",
)
module = _load("beta4_pr_review_evidence", ROOT / "scripts" / "beta4_pr_review_evidence.py")


def test_review_evidence_captures_pending_github_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    receipt = _write_draft_receipt(tmp_path, monkeypatch)
    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_review_gh(receipt_payload))

    report = module.capture_review_evidence(
        draft_pr_receipt_path=receipt,
        output_path=tmp_path / "beta4_pr_review_evidence.json",
    )
    packet = json.loads(Path(report["packet_path"]).read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["validation"]["passed"] is True
    assert packet["review_observation"]["review_state"] == "pending_no_review"
    assert packet["github_review_approval_observed"] is False
    assert packet["merge_authorization_required"] is True
    assert packet["merge_allowed"] is False
    assert packet["deploy_allowed"] is False


def test_review_evidence_rejects_drifted_github_head(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    receipt = _write_draft_receipt(tmp_path, monkeypatch)
    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_review_gh(receipt_payload, head_oid="drifted-head"))

    report = module.capture_review_evidence(
        draft_pr_receipt_path=receipt,
        output_path=tmp_path / "drifted.json",
    )

    assert report["passed"] is False
    assert report["packet_written"] is False
    assert any("headRefOid must match draft PR receipt" in reason for reason in report["failure_reasons"])


def test_review_evidence_refuses_draft_authorization_as_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, push_receipt, _ = push_tests._write_push_receipt(tmp_path)
    authorization = draft_tests._write_authorization(tmp_path, push_receipt)

    report = module.capture_review_evidence(
        draft_pr_receipt_path=authorization,
        output_path=tmp_path / "authorization-is-not-receipt.json",
    )

    assert report["passed"] is False
    assert report["packet_written"] is False
    assert any("draft PR receipt schema_version" in reason for reason in report["failure_reasons"])


def test_review_evidence_validation_rejects_merge_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    receipt = _write_draft_receipt(tmp_path, monkeypatch)
    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    monkeypatch.setattr(module, "_gh", _fake_review_gh(receipt_payload))
    report = module.capture_review_evidence(
        draft_pr_receipt_path=receipt,
        output_path=tmp_path / "packet.json",
    )
    packet_path = Path(report["packet_path"])
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["merge_allowed"] = True
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_review_evidence_packet(packet_path)

    assert validation["passed"] is False
    assert "merge_allowed must be false" in validation["failure_reasons"]


def _write_draft_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _, push_receipt, _ = push_tests._write_push_receipt(tmp_path)
    authorization_path = draft_tests._write_authorization(tmp_path, push_receipt)
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(draft, "_gh", draft_tests._fake_gh(authorization))
    report = draft.run_draft_pr_create(authorization_path=authorization_path, output_root=tmp_path / "draft-pr")
    return Path(report["draft_pr_receipt_path"])


def _fake_review_gh(receipt: dict[str, object], *, head_oid: str | None = None):
    def run(_failures: list[str], *args: str) -> dict[str, object]:
        assert args[:2] == ("pr", "view")
        draft_pr = receipt["draft_pr"]
        assert isinstance(draft_pr, dict)
        metadata = {
            **draft_pr,
            "headRefOid": head_oid or receipt["source_commit_id"],
            "reviewDecision": "",
            "reviews": [],
            "latestReviews": [],
            "comments": [],
            "statusCheckRollup": [],
            "mergeStateStatus": "CLEAN",
        }
        return {
            "command": " ".join(["gh", *args]),
            "returncode": 0,
            "stdout": json.dumps(metadata),
            "stderr": "",
        }

    return run
