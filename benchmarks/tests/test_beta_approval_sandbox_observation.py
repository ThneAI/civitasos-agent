from __future__ import annotations

import importlib.util
import json
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
module = _load("beta_approval_sandbox_observation", ROOT / "scripts" / "beta_approval_sandbox_observation.py")


def test_approval_sandbox_validation_accepts_cross_account_approval(tmp_path: Path) -> None:
    observation = _write_observation(tmp_path)

    validation = module.validate_approval_observation(observation)

    assert validation["passed"] is True


def test_approval_sandbox_validation_rejects_self_approval(tmp_path: Path) -> None:
    observation = _write_observation(tmp_path)
    payload = json.loads(observation.read_text(encoding="utf-8"))
    payload["expected_approver"] = "ThneAI"
    payload["approvers"] = ["ThneAI"]
    observation.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_approval_observation(observation)

    assert validation["passed"] is False
    assert "expected_approver must differ from pr_author" in validation["failure_reasons"]


def test_approval_sandbox_validation_rejects_merge_claim(tmp_path: Path) -> None:
    observation = _write_observation(tmp_path)
    payload = json.loads(observation.read_text(encoding="utf-8"))
    payload["merge_performed"] = True
    observation.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_approval_observation(observation)

    assert validation["passed"] is False
    assert "merge_performed must be false" in validation["failure_reasons"]


def test_approval_sandbox_capture_writes_valid_observation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(module, "_gh", _fake_gh)

    report = module.capture_approval_observation(
        github_repo="ThneAI/civitasos-approval-sandbox",
        pr_number=2,
        expected_author="ThneAI",
        expected_approver="Thneoly",
        output_path=tmp_path / "observation.json",
    )

    assert report["passed"] is True
    assert report["validation"]["passed"] is True


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


def _fake_gh(_failures: list[str], *args: str):
    assert args[:2] == ("pr", "view")
    return {
        "command": "gh " + " ".join(args),
        "returncode": 0,
        "stdout": json.dumps(
            {
                "number": 2,
                "url": "https://github.com/ThneAI/civitasos-approval-sandbox/pull/2",
                "isDraft": False,
                "state": "OPEN",
                "headRefName": "approval-observed-fixture",
                "headRefOid": "abc123",
                "baseRefName": "main",
                "title": "Approval observed fixture",
                "author": {"login": "ThneAI"},
                "reviewDecision": "APPROVED",
                "reviews": [{"state": "APPROVED", "author": {"login": "Thneoly"}}],
                "latestReviews": [{"state": "APPROVED", "author": {"login": "Thneoly"}}],
                "comments": [],
                "statusCheckRollup": [],
                "mergeStateStatus": "CLEAN",
            }
        ),
        "stderr": "",
    }
