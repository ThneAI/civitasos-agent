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
_load("beta_approval_sandbox_observation", ROOT / "scripts" / "beta_approval_sandbox_observation.py")
module = _load("beta4_ready_pr_review_evidence", ROOT / "scripts" / "beta4_ready_pr_review_evidence.py")


def test_ready_pr_review_evidence_records_valid_approval_packet(tmp_path: Path) -> None:
    observation = _write_observation(tmp_path)
    packet = tmp_path / "ready_review_packet.json"

    report = module.record_ready_pr_review_evidence(
        approval_observation_path=observation,
        output_path=packet,
    )
    payload = json.loads(packet.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert payload["schema_version"] == module.PACKET_SCHEMA
    assert payload["review_observation_scope"] == "github_ready_pr_review_state_only"
    assert payload["review_observation"]["review_state"] == "approved_review_observed"
    assert payload["github_review_approval_observed"] is True
    assert payload["pr"]["isDraft"] is False
    assert payload["merge_allowed"] is False
    assert payload["deploy_allowed"] is False


def test_ready_pr_review_evidence_rejects_non_approved_observation(tmp_path: Path) -> None:
    observation = _write_observation(tmp_path)
    payload = json.loads(observation.read_text(encoding="utf-8"))
    payload["review_decision"] = ""
    payload["approval_observed"] = False
    observation.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="approval observation invalid"):
        module.record_ready_pr_review_evidence(
            approval_observation_path=observation,
            output_path=tmp_path / "must-not-write.json",
        )


def test_ready_pr_review_evidence_validation_rejects_packet_drift(tmp_path: Path) -> None:
    observation = _write_observation(tmp_path)
    packet = tmp_path / "ready_review_packet.json"
    module.record_ready_pr_review_evidence(approval_observation_path=observation, output_path=packet)
    payload = json.loads(packet.read_text(encoding="utf-8"))
    payload["merge_allowed"] = True
    packet.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_ready_pr_review_evidence_packet(packet)

    assert validation["passed"] is False
    assert "merge_allowed must be false" in validation["failure_reasons"]


def _write_observation(tmp_path: Path) -> Path:
    path = tmp_path / "observation.json"
    payload = {
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
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
