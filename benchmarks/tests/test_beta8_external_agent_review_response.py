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
beta6 = _load("beta6_external_agent_onboarding", ROOT / "scripts" / "beta6_external_agent_onboarding.py")
beta6_tests = _load(
    "beta6_external_agent_onboarding_fixture_for_beta8",
    ROOT / "benchmarks" / "tests" / "test_beta6_external_agent_onboarding.py",
)
beta7 = _load("beta7_external_agent_task_invitation", ROOT / "scripts" / "beta7_external_agent_task_invitation.py")
module = _load("beta8_external_agent_review_response", ROOT / "scripts" / "beta8_external_agent_review_response.py")


def test_external_agent_review_response_records_upstream_verdict(tmp_path: Path) -> None:
    task_invitation = _write_task_invitation(tmp_path)
    response_file = _write_response_file(tmp_path)
    response = tmp_path / "review_response.json"

    report = module.record_review_response(
        task_invitation_path=task_invitation,
        external_agent_id="external-reviewer-001",
        response_channel="github_comment",
        review_verdict="changes_requested",
        response_file=response_file,
        attestation_ref="attestation:external-reviewer-001:review-response-observed",
        observer_actor_id="external-agent-observer-001",
        reason="record external reviewer verdict as upstream evidence only",
        output_path=response,
    )
    payload = json.loads(response.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert payload["external_agent_response_observed"] is True
    assert payload["upstream_evidence_only"] is True
    assert payload["review_verdict"] == "changes_requested"
    assert payload["github_review_approval_observed"] is False
    assert payload["beta5_merge_authorization_allowed"] is False
    assert payload["merge_allowed"] is False
    assert payload["deploy_allowed"] is False


def test_external_agent_review_response_refuses_registration_as_task_invitation(tmp_path: Path) -> None:
    registration = _write_registration(tmp_path)
    response_file = _write_response_file(tmp_path)

    with pytest.raises(ValueError, match="task invitation"):
        module.record_review_response(
            task_invitation_path=registration,
            external_agent_id="external-reviewer-001",
            response_channel="github_comment",
            review_verdict="commented",
            response_file=response_file,
            attestation_ref="attestation:external-reviewer-001:review-response-observed",
            observer_actor_id="external-agent-observer-001",
            reason="prove registration is not a task invitation",
            output_path=tmp_path / "must-not-write.json",
        )


def test_external_agent_review_response_requires_matching_agent_id(tmp_path: Path) -> None:
    task_invitation = _write_task_invitation(tmp_path)
    response_file = _write_response_file(tmp_path)

    with pytest.raises(ValueError, match="external_agent_id must match task invitation"):
        module.record_review_response(
            task_invitation_path=task_invitation,
            external_agent_id="other-reviewer",
            response_channel="github_comment",
            review_verdict="commented",
            response_file=response_file,
            attestation_ref="attestation:external-reviewer-001:review-response-observed",
            observer_actor_id="external-agent-observer-001",
            reason="prove response cannot switch identity",
            output_path=tmp_path / "must-not-write.json",
        )


def test_external_agent_review_response_validation_rejects_github_approval_claim(tmp_path: Path) -> None:
    task_invitation = _write_task_invitation(tmp_path)
    response_file = _write_response_file(tmp_path)
    response = tmp_path / "review_response.json"
    module.record_review_response(
        task_invitation_path=task_invitation,
        external_agent_id="external-reviewer-001",
        response_channel="github_review",
        review_verdict="approved",
        response_file=response_file,
        attestation_ref="attestation:external-reviewer-001:review-response-observed",
        observer_actor_id="external-agent-observer-001",
        reason="record approval-like verdict without GitHub approval claim",
        output_path=response,
    )
    payload = json.loads(response.read_text(encoding="utf-8"))
    payload["github_review_approval_observed"] = True
    payload["beta5_merge_authorization_allowed"] = True
    response.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_review_response(response)

    assert validation["passed"] is False
    assert "github_review_approval_observed must be false" in validation["failure_reasons"]
    assert "beta5_merge_authorization_allowed must be false" in validation["failure_reasons"]


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


def _write_task_invitation(tmp_path: Path) -> Path:
    registration = _write_registration(tmp_path)
    brief = tmp_path / "task_brief.md"
    brief.write_text("Review the controlled PR boundary. Do not merge or deploy.\n", encoding="utf-8")
    task_invitation = tmp_path / "task_invitation.json"
    beta7.record_task_invitation(
        registration_path=registration,
        task_kind="github_pr_review",
        task_title="Review Beta-4 draft PR boundary",
        task_brief_file=brief,
        expected_output="review_verdict",
        source_artifacts=[],
        reason="ask registered external reviewer for controlled PR review",
        output_path=task_invitation,
        operator_id="external-agent-task-coordinator-001",
        due_at="2099-01-02T00:00:00+00:00",
    )
    return task_invitation


def _write_response_file(tmp_path: Path) -> Path:
    path = tmp_path / "response.md"
    path.write_text(
        "Verdict: changes requested. Boundary is preserved, but wording should clarify H.3 remains blocked.\n",
        encoding="utf-8",
    )
    return path
