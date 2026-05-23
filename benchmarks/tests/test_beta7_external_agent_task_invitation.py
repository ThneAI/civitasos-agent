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
    "beta6_external_agent_onboarding_fixture_for_beta7",
    ROOT / "benchmarks" / "tests" / "test_beta6_external_agent_onboarding.py",
)
module = _load("beta7_external_agent_task_invitation", ROOT / "scripts" / "beta7_external_agent_task_invitation.py")


def test_external_agent_task_invitation_records_bounded_review_task(tmp_path: Path) -> None:
    registration = _write_registration(tmp_path)
    brief = _write_brief(tmp_path)
    source = _write_source_artifact(tmp_path)
    invitation = tmp_path / "task_invitation.json"

    report = module.record_task_invitation(
        registration_path=registration,
        task_kind="github_pr_review",
        task_title="Review Beta-4 draft PR boundary",
        task_brief_file=brief,
        expected_output="review_verdict",
        source_artifacts=[source],
        reason="ask registered external reviewer for controlled PR review",
        output_path=invitation,
        operator_id="external-agent-task-coordinator-001",
        due_at="2099-01-02T00:00:00+00:00",
    )
    payload = json.loads(invitation.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert payload["task_invitation_recorded"] is True
    assert payload["message_delivered"] is False
    assert payload["response_observed"] is False
    assert payload["direct_task_execution_allowed"] is False
    assert payload["merge_allowed"] is False
    assert payload["deploy_allowed"] is False
    assert payload["external_agent_id"] == "external-reviewer-001"


def test_external_agent_task_invitation_refuses_invitation_as_registration(tmp_path: Path) -> None:
    invitation = beta6_tests._write_invitation(tmp_path)
    brief = _write_brief(tmp_path)

    with pytest.raises(ValueError, match="registration"):
        module.record_task_invitation(
            registration_path=invitation,
            task_kind="github_pr_review",
            task_title="Review must require registration",
            task_brief_file=brief,
            expected_output="review_verdict",
            source_artifacts=[],
            reason="prove invitation is not registration",
            output_path=tmp_path / "must-not-write.json",
            operator_id="external-agent-task-coordinator-001",
            due_at="2099-01-02T00:00:00+00:00",
        )


def test_external_agent_task_invitation_requires_review_scope(tmp_path: Path) -> None:
    registration = _write_registration(tmp_path, scopes=["proposal_only"])
    brief = _write_brief(tmp_path)

    with pytest.raises(ValueError, match="requires external Agent scope review_only"):
        module.record_task_invitation(
            registration_path=registration,
            task_kind="github_pr_review",
            task_title="Review scope required",
            task_brief_file=brief,
            expected_output="review_verdict",
            source_artifacts=[],
            reason="prove task kind checks registration scope",
            output_path=tmp_path / "must-not-write.json",
            operator_id="external-agent-task-coordinator-001",
            due_at="2099-01-02T00:00:00+00:00",
        )


def test_external_agent_task_invitation_validation_rejects_response_claim(tmp_path: Path) -> None:
    registration = _write_registration(tmp_path)
    brief = _write_brief(tmp_path)
    invitation = tmp_path / "task_invitation.json"
    module.record_task_invitation(
        registration_path=registration,
        task_kind="github_pr_review",
        task_title="Review Beta-4 draft PR boundary",
        task_brief_file=brief,
        expected_output="review_verdict",
        source_artifacts=[],
        reason="record response boundary fixture",
        output_path=invitation,
        operator_id="external-agent-task-coordinator-001",
        due_at="2099-01-02T00:00:00+00:00",
    )
    payload = json.loads(invitation.read_text(encoding="utf-8"))
    payload["response_observed"] = True
    invitation.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_task_invitation(invitation)

    assert validation["passed"] is False
    assert "response_observed must be false" in validation["failure_reasons"]


def _write_registration(tmp_path: Path, *, scopes: list[str] | None = None) -> Path:
    invitation = tmp_path / "invitation.json"
    beta6.record_invitation(
        external_agent_id="external-reviewer-001",
        display_name="External Reviewer 001",
        agent_kind="ai_agent",
        capabilities=["code_review", "boundary_review"],
        allowed_scopes=scopes or ["review_only", "l1_controlled_message"],
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


def _write_brief(tmp_path: Path) -> Path:
    path = tmp_path / "task_brief.md"
    path.write_text(
        "Review the draft PR boundary. Do not merge, deploy, or execute production actions.\n",
        encoding="utf-8",
    )
    return path


def _write_source_artifact(tmp_path: Path) -> Path:
    path = tmp_path / "source_artifact.json"
    path.write_text('{"schema_version":"fixture-source-artifact:v1"}\n', encoding="utf-8")
    return path
