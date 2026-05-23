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
