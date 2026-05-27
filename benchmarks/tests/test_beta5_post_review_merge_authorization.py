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
draft = _load("beta4_draft_pr_executor", ROOT / "scripts" / "beta4_draft_pr_executor.py")
_load("beta4_ready_pr_transition_executor", ROOT / "scripts" / "beta4_ready_pr_transition_executor.py")
review = _load("beta4_pr_review_evidence", ROOT / "scripts" / "beta4_pr_review_evidence.py")
_load("beta_approval_sandbox_observation", ROOT / "scripts" / "beta_approval_sandbox_observation.py")
ready_review = _load("beta4_ready_pr_review_evidence", ROOT / "scripts" / "beta4_ready_pr_review_evidence.py")
review_tests = _load(
    "beta4_pr_review_evidence_fixture_for_beta5",
    ROOT / "benchmarks" / "tests" / "test_beta4_pr_review_evidence.py",
)
module = _load(
    "beta5_post_review_merge_authorization",
    ROOT / "scripts" / "beta5_post_review_merge_authorization.py",
)


def test_post_review_merge_authorization_records_observed_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = _write_review_packet(tmp_path, monkeypatch, approved=True)
    authorization_path = tmp_path / "beta5_post_review_merge_authorization.json"

    report = module.record_post_review_merge_authorization(
        review_evidence_packet_path=packet,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="approve merge execution review after GitHub approval evidence",
        rollback_evidence_ref="rollback:revert-reviewed-pr-merge",
    )
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert authorization["merge_authorized"] is True
    assert authorization["merge_performed"] is False
    assert authorization["github_review_approval_observed"] is True
    assert authorization["deploy_allowed"] is False
    assert authorization["review_observation"]["review_state"] == "approved_review_observed"


def test_post_review_merge_authorization_accepts_ready_pr_approval_packet(tmp_path: Path) -> None:
    packet = _write_ready_review_packet(tmp_path)
    authorization_path = tmp_path / "beta5_ready_post_review_merge_authorization.json"

    report = module.record_post_review_merge_authorization(
        review_evidence_packet_path=packet,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="approve sandbox ready PR after real cross-account approval evidence",
        rollback_evidence_ref="rollback:close-ready-pr-without-merge",
    )
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert authorization["source_review_evidence_packet_schema"] == ready_review.PACKET_SCHEMA
    assert authorization["source_approval_observation"]["path"]
    assert authorization["source_draft_pr_receipt"] is None
    assert authorization["pr"]["isDraft"] is False
    assert authorization["merge_authorized"] is True
    assert authorization["merge_performed"] is False


def test_post_review_merge_authorization_blocks_pending_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = _write_review_packet(tmp_path, monkeypatch, approved=False)

    with pytest.raises(ValueError, match="approved_review_observed"):
        module.record_post_review_merge_authorization(
            review_evidence_packet_path=packet,
            output_path=tmp_path / "must-not-write.json",
            operator_id="operator-001",
            reason="pending review cannot authorize merge",
            rollback_evidence_ref="rollback:not-authorized",
        )


def test_post_review_merge_authorization_validation_rejects_packet_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = _write_review_packet(tmp_path, monkeypatch, approved=True)
    authorization_path = tmp_path / "authorization.json"
    module.record_post_review_merge_authorization(
        review_evidence_packet_path=packet,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="record drift fixture",
        rollback_evidence_ref="rollback:drift-fixture",
    )
    payload = json.loads(packet.read_text(encoding="utf-8"))
    payload["review_observation"]["comment_count"] = 99
    packet.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_post_review_merge_authorization(authorization_path)

    assert validation["passed"] is False
    assert "source_review_evidence_packet.sha256 does not match file bytes" in validation["failure_reasons"]


def test_post_review_merge_authorization_validation_rejects_deploy_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = _write_review_packet(tmp_path, monkeypatch, approved=True)
    authorization_path = tmp_path / "authorization.json"
    module.record_post_review_merge_authorization(
        review_evidence_packet_path=packet,
        output_path=authorization_path,
        operator_id="operator-001",
        reason="record deploy boundary fixture",
        rollback_evidence_ref="rollback:deploy-boundary",
    )
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    authorization["deploy_allowed"] = True
    authorization_path.write_text(json.dumps(authorization, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_post_review_merge_authorization(authorization_path)

    assert validation["passed"] is False
    assert "deploy_allowed must be false" in validation["failure_reasons"]


def _write_review_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, approved: bool) -> Path:
    receipt = review_tests._write_draft_receipt(tmp_path, monkeypatch)
    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    monkeypatch.setattr(review, "_gh", _fake_gh(receipt_payload, approved=approved))
    packet = tmp_path / ("approved_review_packet.json" if approved else "pending_review_packet.json")
    report = review.capture_review_evidence(draft_pr_receipt_path=receipt, output_path=packet)
    assert report["passed"] is True
    return packet


def _write_ready_review_packet(tmp_path: Path) -> Path:
    observation = tmp_path / "approval_observation.json"
    observation.write_text(
        json.dumps(
            {
                "schema_version": "beta-approval-sandbox-observation:v1",
                "captured_at": "2099-01-01T00:00:00+00:00",
                "observation_scope": "github_cross_account_approval_observation_only",
                "github_repo": "ThneAI/civitasos-approval-sandbox",
                "pr_number": 2,
                "pr_url": "https://github.com/ThneAI/civitasos-approval-sandbox/pull/2",
                "pr_title": "Approval observed fixture",
                "pr_state": "OPEN",
                "is_draft": False,
                "head_ref_name": "approval-observed-fixture",
                "head_ref_oid": "abc123",
                "base_ref_name": "main",
                "expected_author": "ThneAI",
                "expected_approver": "Thneoly",
                "pr_author": "ThneAI",
                "review_decision": "APPROVED",
                "approval_observed": True,
                "approvers": ["Thneoly"],
                "review_count": 1,
                "latest_review_count": 1,
                "comment_count": 0,
                "status_check_count": 0,
                "merge_state_status": "CLEAN",
                "gh_view": {"returncode": 0},
                "beta4_review_packet_replaced": False,
                "beta5_authorization_executed": False,
                "merge_performed": False,
                "deploy_allowed": False,
                "production_runtime_execution_allowed": False,
                "production_receipt_write_allowed": False,
                "h3_boundary": {
                    "h3_production_readiness_claimed": False,
                    "h3_remains_blocked": True,
                },
                "non_claims": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    packet = tmp_path / "ready_review_packet.json"
    report = ready_review.record_ready_pr_review_evidence(
        approval_observation_path=observation,
        output_path=packet,
    )
    assert report["validation"]["passed"] is True
    return packet


def _fake_gh(receipt: dict[str, object], *, approved: bool):
    def run(_failures: list[str], *args: str) -> dict[str, object]:
        assert args[:2] == ("pr", "view")
        draft_pr = receipt["draft_pr"]
        assert isinstance(draft_pr, dict)
        review_state = "APPROVED" if approved else ""
        review_rows = [{"state": "APPROVED", "author": {"login": "reviewer-fixture"}}] if approved else []
        metadata = {
            **draft_pr,
            "reviewDecision": review_state,
            "reviews": review_rows,
            "latestReviews": review_rows,
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
