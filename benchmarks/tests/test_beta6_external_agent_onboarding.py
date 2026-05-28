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
module = _load("beta6_external_agent_onboarding", ROOT / "scripts" / "beta6_external_agent_onboarding.py")


def test_external_agent_onboarding_records_invitation_and_registration(tmp_path: Path) -> None:
    invitation = _write_invitation(tmp_path)
    agent_card = _write_agent_card(tmp_path)
    registration = tmp_path / "registration.json"

    report = module.record_registration(
        invitation_path=invitation,
        agent_card_path=agent_card,
        attestation_ref="attestation:external-reviewer-001:accepted-l1-boundary",
        observer_actor_id="external-agent-observer-001",
        output_path=registration,
    )
    payload = json.loads(registration.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert payload["registration_observed"] is True
    assert payload["controlled_task_invitation_allowed"] is True
    assert payload["direct_task_execution_allowed"] is False
    assert payload["merge_allowed"] is False
    assert payload["deploy_allowed"] is False
    assert payload["external_agent_id"] == "external-reviewer-001"


def test_external_agent_registration_refuses_agent_id_mismatch(tmp_path: Path) -> None:
    invitation = _write_invitation(tmp_path)
    agent_card = _write_agent_card(tmp_path, agent_id="different-agent")

    with pytest.raises(ValueError, match="agent_id must match invitation"):
        module.record_registration(
            invitation_path=invitation,
            agent_card_path=agent_card,
            attestation_ref="attestation:external-reviewer-001:mismatch",
            observer_actor_id="external-agent-observer-001",
            output_path=tmp_path / "must-not-write.json",
        )


def test_external_agent_invitation_rejects_placeholder_contact(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="PLACEHOLDER"):
        module.record_invitation(
            external_agent_id="external-reviewer-001",
            display_name="External Reviewer 001",
            agent_kind="ai_agent",
            capabilities=["code_review"],
            allowed_scopes=["review_only"],
            contact_ref="PLACEHOLDER-contact",
            reason="invite external reviewer for L1 boundary review",
            output_path=tmp_path / "placeholder.json",
            operator_id="external-agent-registrar-001",
            expires_at="2099-01-01T00:00:00+00:00",
        )


def test_external_agent_registration_validation_rejects_direct_execution_claim(tmp_path: Path) -> None:
    invitation = _write_invitation(tmp_path)
    agent_card = _write_agent_card(tmp_path)
    registration = tmp_path / "registration.json"
    module.record_registration(
        invitation_path=invitation,
        agent_card_path=agent_card,
        attestation_ref="attestation:external-reviewer-001:accepted-l1-boundary",
        observer_actor_id="external-agent-observer-001",
        output_path=registration,
    )
    payload = json.loads(registration.read_text(encoding="utf-8"))
    payload["direct_task_execution_allowed"] = True
    registration.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_registration(registration)

    assert validation["passed"] is False
    assert "direct_task_execution_allowed must be false" in validation["failure_reasons"]


def test_external_agent_onboarding_cli_validate_invitation(tmp_path: Path) -> None:
    invitation = _write_invitation(tmp_path)
    validation = tmp_path / "invitation_validation.json"

    exit_code = module.main([
        "validate-invitation",
        "--invitation",
        str(invitation),
        "--output",
        str(validation),
    ])
    payload = json.loads(validation.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["passed"] is True


def test_readiness_backed_invitation_hash_binds_beta6_readiness(tmp_path: Path) -> None:
    readiness = _write_readiness(tmp_path)
    invitation = tmp_path / "readiness_backed_invitation.json"

    report = module.record_invitation(
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
        readiness_path=readiness,
    )
    payload = json.loads(invitation.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert payload["source_onboarding_readiness"]["sha256"] == module._sha256(readiness)
    assert payload["readiness_state"] == "ready_with_owner_followup"
    assert payload["owner_followup_required"] is True
    assert payload["registration_observed"] is False


def test_readiness_backed_invitation_rejects_blocked_readiness(tmp_path: Path) -> None:
    readiness = _write_readiness(tmp_path)
    payload = json.loads(readiness.read_text(encoding="utf-8"))
    payload["passed"] = False
    payload["controlled_external_agent_invitation_allowed"] = False
    payload["failure_reasons"] = ["blocked for test"]
    readiness.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="readiness must have passed=true"):
        module.record_invitation(
            external_agent_id="external-reviewer-001",
            display_name="External Reviewer 001",
            agent_kind="ai_agent",
            capabilities=["code_review"],
            allowed_scopes=["review_only"],
            contact_ref="github:external-reviewer-001",
            reason="invite external reviewer for L1 boundary review",
            output_path=tmp_path / "blocked.json",
            operator_id="external-agent-registrar-001",
            expires_at="2099-01-01T00:00:00+00:00",
            readiness_path=readiness,
        )


def test_registration_request_hash_binds_invitation_without_opening_task_scope(tmp_path: Path) -> None:
    readiness = _write_readiness(tmp_path)
    invitation = tmp_path / "readiness_backed_invitation.json"
    module.record_invitation(
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
        readiness_path=readiness,
    )
    request_path = tmp_path / "registration_request.json"

    report = module.record_registration_request(
        invitation_path=invitation,
        output_path=request_path,
        requester_id="external-agent-registrar-001",
    )
    request = json.loads(request_path.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert request["source_invitation"]["sha256"] == module._sha256(invitation)
    assert request["expected_agent_card"]["agent_id"] == "external-reviewer-001"
    assert request["required_attestation"]["attestation_ref_required"] is True
    assert request["registration_observed"] is False
    assert request["controlled_task_invitation_allowed"] is False
    assert request["direct_task_execution_allowed"] is False


def test_registration_request_rejects_expected_card_drift(tmp_path: Path) -> None:
    invitation = _write_invitation(tmp_path)
    request_path = tmp_path / "registration_request.json"
    module.record_registration_request(
        invitation_path=invitation,
        output_path=request_path,
        requester_id="external-agent-registrar-001",
    )
    payload = json.loads(request_path.read_text(encoding="utf-8"))
    payload["expected_agent_card"]["contact_ref"] = "github:different-agent"
    request_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_registration_request(request_path)

    assert validation["passed"] is False
    assert "external Agent card contact_ref must match invitation contact_ref" in validation["failure_reasons"]


def test_agent_card_from_env_redacts_api_key_and_can_register(tmp_path: Path) -> None:
    invitation = _write_invitation(tmp_path)
    request_path = tmp_path / "registration_request.json"
    module.record_registration_request(
        invitation_path=invitation,
        output_path=request_path,
        requester_id="external-agent-registrar-001",
    )
    env_file = tmp_path / ".env.beta6.external.local"
    secret = "sk-test-secret-must-not-appear"
    env_file.write_text(
        "\n".join([
            "BETA6_EXTERNAL_AGENT_PROVIDER=openai_compatible",
            "BETA6_EXTERNAL_AGENT_API_BASE_URL=https://external-agent.example/v1",
            "BETA6_EXTERNAL_AGENT_MODEL=external-reviewer-model",
            f"BETA6_EXTERNAL_AGENT_API_KEY={secret}",
        ]) + "\n",
        encoding="utf-8",
    )
    agent_card = tmp_path / "agent_card.json"

    report = module.write_agent_card_from_env(
        registration_request_path=request_path,
        env_file_path=env_file,
        output_path=agent_card,
    )
    card_bytes = agent_card.read_bytes()
    report_text = json.dumps(report, sort_keys=True)
    registration = tmp_path / "registration.json"
    registration_report = module.record_registration(
        invitation_path=invitation,
        agent_card_path=agent_card,
        attestation_ref="operator-attested-api-endpoint:external-reviewer-001",
        observer_actor_id="external-agent-observer-001",
        output_path=registration,
    )

    assert report["api_key_present"] is True
    assert report["api_key_recorded"] is False
    assert secret.encode("utf-8") not in card_bytes
    assert secret not in report_text
    assert report["external_api"]["base_url"] == "https://external-agent.example/v1"
    assert registration_report["validation"]["passed"] is True


def test_agent_card_from_env_requires_api_key(tmp_path: Path) -> None:
    invitation = _write_invitation(tmp_path)
    request_path = tmp_path / "registration_request.json"
    module.record_registration_request(
        invitation_path=invitation,
        output_path=request_path,
        requester_id="external-agent-registrar-001",
    )
    env_file = tmp_path / ".env.beta6.external.local"
    env_file.write_text(
        "\n".join([
            "BETA6_EXTERNAL_AGENT_API_BASE_URL=https://external-agent.example/v1",
            "BETA6_EXTERNAL_AGENT_MODEL=external-reviewer-model",
        ]) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="BETA6_EXTERNAL_AGENT_API_KEY must be set"):
        module.write_agent_card_from_env(
            registration_request_path=request_path,
            env_file_path=env_file,
            output_path=tmp_path / "agent_card.json",
        )


def test_beta6_readiness_accepts_beta5_feedback_index_with_followup(tmp_path: Path) -> None:
    index = _write_feedback_index(tmp_path, accepted=1, followup=1)

    readiness = module.validate_onboarding_readiness(feedback_index_path=index)

    assert readiness["passed"] is True
    assert readiness["readiness_state"] == "ready_with_owner_followup"
    assert readiness["controlled_external_agent_invitation_allowed"] is True
    assert readiness["owner_followup_required"] is True
    assert readiness["observed_packet_count"] == 2
    assert readiness["observed_accepted_ratio"] == 0.5
    assert readiness["production_runtime_execution_allowed"] is False
    assert readiness["h3_boundary"]["h3_remains_blocked"] is True


def test_beta6_readiness_blocks_rejected_feedback_or_low_acceptance(tmp_path: Path) -> None:
    rejected = _write_feedback_index(tmp_path / "rejected", accepted=1, followup=0, rejected=1)
    rejected_readiness = module.validate_onboarding_readiness(feedback_index_path=rejected)

    assert rejected_readiness["passed"] is False
    assert "feedback index must not contain rejected owner feedback" in rejected_readiness["failure_reasons"]
    assert rejected_readiness["controlled_external_agent_invitation_allowed"] is False

    low_acceptance = _write_feedback_index(tmp_path / "low", accepted=0, followup=2)
    low_readiness = module.validate_onboarding_readiness(feedback_index_path=low_acceptance)

    assert low_readiness["passed"] is False
    assert "feedback index accepted_ratio 0.0 below required 0.5" in low_readiness["failure_reasons"]


def _write_invitation(tmp_path: Path) -> Path:
    invitation = tmp_path / "invitation.json"
    module.record_invitation(
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
    return invitation


def _write_agent_card(tmp_path: Path, *, agent_id: str = "external-reviewer-001") -> Path:
    card = {
        "schema_version": module.AGENT_CARD_SCHEMA,
        "agent_id": agent_id,
        "display_name": "External Reviewer 001",
        "agent_kind": "ai_agent",
        "capabilities": ["boundary_review", "code_review"],
        "contact_ref": "github:external-reviewer-001",
        "non_claims": [
            "external_agent_card_does_not_authorize_task_execution",
            "external_agent_card_does_not_authorize_merge_or_deploy",
        ],
    }
    path = tmp_path / "agent_card.json"
    path.write_text(json.dumps(card, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_feedback_index(
    tmp_path: Path,
    *,
    accepted: int,
    followup: int,
    rejected: int = 0,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    packet_count = accepted + followup + rejected
    index = {
        "schema_version": module.BETA5_FEEDBACK_INDEX_SCHEMA,
        "passed": True,
        "packet_count": packet_count,
        "accepted_ratio": accepted / packet_count if packet_count else 0.0,
        "verdict_counts": {
            "accepted": accepted,
            "needs_followup": followup,
            "rejected": rejected,
        },
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
        "h3_boundary": module._h3_boundary(),
    }
    path = tmp_path / "beta5_owner_feedback_index.json"
    path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_readiness(tmp_path: Path) -> Path:
    feedback_index = _write_feedback_index(tmp_path, accepted=1, followup=1)
    readiness = module.validate_onboarding_readiness(feedback_index_path=feedback_index)
    path = tmp_path / "beta6_readiness.json"
    path.write_text(json.dumps(readiness, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
