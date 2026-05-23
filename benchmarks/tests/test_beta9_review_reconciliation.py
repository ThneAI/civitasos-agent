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
for script in (
    "beta1_repo_review_proposal.py",
    "beta2_patch_proposal.py",
    "beta2_operator_apply_receipt.py",
    "beta2_patch_review_outcome.py",
    "beta3_controlled_apply_candidate.py",
    "beta3_controlled_apply_sandbox.py",
    "beta3_post_sandbox_operator_receipt.py",
    "beta3_multi_agent_review_packet.py",
    "beta3_source_apply_authorization.py",
    "beta3_source_apply_executor.py",
    "beta3_git_publication_authorization.py",
    "beta3_git_commit_executor.py",
    "beta3_git_push_executor.py",
    "beta4_draft_pr_executor.py",
    "beta4_pr_review_evidence.py",
    "beta6_external_agent_onboarding.py",
    "beta7_external_agent_task_invitation.py",
    "beta8_external_agent_review_response.py",
):
    _load(script[:-3], ROOT / "scripts" / script)

beta6 = sys.modules["beta6_external_agent_onboarding"]
beta6_tests = _load(
    "beta6_external_agent_onboarding_fixture_for_beta9",
    ROOT / "benchmarks" / "tests" / "test_beta6_external_agent_onboarding.py",
)
beta7 = sys.modules["beta7_external_agent_task_invitation"]
beta8 = sys.modules["beta8_external_agent_review_response"]
beta4_review = sys.modules["beta4_pr_review_evidence"]
beta4_review_tests = _load(
    "beta4_pr_review_evidence_fixture_for_beta9",
    ROOT / "benchmarks" / "tests" / "test_beta4_pr_review_evidence.py",
)
module = _load("beta9_review_reconciliation", ROOT / "scripts" / "beta9_review_reconciliation.py")


def test_review_reconciliation_blocks_pending_github_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pr_packet = _write_pr_review_packet(tmp_path, monkeypatch, approved=False)
    response = _write_review_response(tmp_path, pr_packet, verdict="commented")
    reconciliation = tmp_path / "reconciliation.json"

    report = module.record_reconciliation(
        review_response_path=response,
        pr_review_evidence_path=pr_packet,
        operator_decision="blocked_pending_github_approval",
        reason="external comment exists but GitHub approval is not observed",
        output_path=reconciliation,
        operator_id="post-review-reconciliation-operator-001",
    )
    payload = json.loads(reconciliation.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert payload["post_review_evidence_complete"] is True
    assert payload["beta5_authorization_input_ready"] is False
    assert payload["blocking_reason"] == "github_review_approval_missing"
    assert payload["merge_authorized"] is False
    assert payload["deploy_allowed"] is False


def test_review_reconciliation_refuses_ready_without_github_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pr_packet = _write_pr_review_packet(tmp_path, monkeypatch, approved=False)
    response = _write_review_response(tmp_path, pr_packet, verdict="approved")

    with pytest.raises(ValueError, match="requires external approved verdict and GitHub approval evidence"):
        module.record_reconciliation(
            review_response_path=response,
            pr_review_evidence_path=pr_packet,
            operator_decision="ready_for_beta5_authorization",
            reason="must not be ready without GitHub approval",
            output_path=tmp_path / "must-not-write.json",
            operator_id="post-review-reconciliation-operator-001",
        )


def test_review_reconciliation_ready_when_external_and_github_approved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pr_packet = _write_pr_review_packet(tmp_path, monkeypatch, approved=True)
    response = _write_review_response(tmp_path, pr_packet, verdict="approved")
    reconciliation = tmp_path / "ready.json"

    report = module.record_reconciliation(
        review_response_path=response,
        pr_review_evidence_path=pr_packet,
        operator_decision="ready_for_beta5_authorization",
        reason="both external verdict and GitHub approval are observed",
        output_path=reconciliation,
        operator_id="post-review-reconciliation-operator-001",
    )
    payload = json.loads(reconciliation.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert payload["beta5_authorization_input_ready"] is True
    assert payload["blocking_reason"] == "none"
    assert payload["merge_authorized"] is False
    assert payload["merge_performed"] is False


def test_review_reconciliation_requires_pr_packet_in_task_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pr_packet = _write_pr_review_packet(tmp_path, monkeypatch, approved=False)
    other_packet = _write_pr_review_packet(tmp_path / "other", monkeypatch, approved=False)
    response = _write_review_response(tmp_path, pr_packet, verdict="commented")

    with pytest.raises(ValueError, match="must be included"):
        module.record_reconciliation(
            review_response_path=response,
            pr_review_evidence_path=other_packet,
            operator_decision="blocked_pending_github_approval",
            reason="mismatched packet should fail",
            output_path=tmp_path / "must-not-write.json",
            operator_id="post-review-reconciliation-operator-001",
        )


def test_review_reconciliation_validation_rejects_merge_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pr_packet = _write_pr_review_packet(tmp_path, monkeypatch, approved=False)
    response = _write_review_response(tmp_path, pr_packet, verdict="commented")
    reconciliation = tmp_path / "reconciliation.json"
    module.record_reconciliation(
        review_response_path=response,
        pr_review_evidence_path=pr_packet,
        operator_decision="blocked_pending_github_approval",
        reason="record merge boundary fixture",
        output_path=reconciliation,
        operator_id="post-review-reconciliation-operator-001",
    )
    payload = json.loads(reconciliation.read_text(encoding="utf-8"))
    payload["merge_authorized"] = True
    reconciliation.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_reconciliation(reconciliation)

    assert validation["passed"] is False
    assert "merge_authorized must be false" in validation["failure_reasons"]


def _write_pr_review_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, approved: bool) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    receipt = beta4_review_tests._write_draft_receipt(tmp_path, monkeypatch)
    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    monkeypatch.setattr(beta4_review, "_gh", _fake_gh(receipt_payload, approved=approved))
    packet = tmp_path / ("approved_pr_review_packet.json" if approved else "pending_pr_review_packet.json")
    report = beta4_review.capture_review_evidence(draft_pr_receipt_path=receipt, output_path=packet)
    assert report["passed"] is True
    return packet


def _write_registration(tmp_path: Path) -> Path:
    invitation = tmp_path / "invitation.json"
    beta6.record_invitation(
        external_agent_id="external-reviewer-001",
        display_name="External Reviewer 001",
        agent_kind="ai_agent",
        capabilities=["code_review", "boundary_review"],
        allowed_scopes=["review_only", "l1_controlled_message"],
        contact_ref="github:external-reviewer-001",
        reason="invite an external reviewer for controlled L1 review evidence",
        output_path=invitation,
        operator_id="external-agent-registrar-001",
        expires_at="2099-01-01T00:00:00+00:00",
    )
    card = beta6_tests._write_agent_card(tmp_path)
    registration = tmp_path / "registration.json"
    beta6.record_registration(
        invitation_path=invitation,
        agent_card_path=card,
        attestation_ref="attestation:external-reviewer-001:accepted-l1-boundary",
        observer_actor_id="external-agent-observer-001",
        output_path=registration,
    )
    return registration


def _write_review_response(tmp_path: Path, pr_packet: Path, *, verdict: str) -> Path:
    registration = _write_registration(tmp_path)
    brief = tmp_path / "task_brief.md"
    brief.write_text("Review the PR review-state packet as upstream evidence only.\n", encoding="utf-8")
    task_invitation = tmp_path / "task_invitation.json"
    beta7.record_task_invitation(
        registration_path=registration,
        task_kind="github_pr_review",
        task_title="Review PR review-state boundary",
        task_brief_file=brief,
        expected_output="review_verdict",
        source_artifacts=[pr_packet],
        reason="ask registered external reviewer for controlled PR review",
        output_path=task_invitation,
        operator_id="external-agent-task-coordinator-001",
        due_at="2099-01-02T00:00:00+00:00",
    )
    response_file = tmp_path / "response.md"
    response_file.write_text(f"Verdict: {verdict}. Upstream evidence only.\n", encoding="utf-8")
    response = tmp_path / "review_response.json"
    beta8.record_review_response(
        task_invitation_path=task_invitation,
        external_agent_id="external-reviewer-001",
        response_channel="github_comment",
        review_verdict=verdict,
        response_file=response_file,
        attestation_ref="attestation:external-reviewer-001:review-response-observed",
        observer_actor_id="external-agent-observer-001",
        reason="record external reviewer verdict as upstream evidence only",
        output_path=response,
    )
    return response


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
