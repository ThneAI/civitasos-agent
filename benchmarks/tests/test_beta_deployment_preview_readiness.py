from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load("beta_deployment_preview_readiness", SCRIPTS / "beta_deployment_preview_readiness.py")


def test_beta_deployment_preview_readiness_passes_for_bounded_inputs(tmp_path: Path) -> None:
    beta6_9 = _write_json(tmp_path / "beta6_9_summary.json", _beta6_9_summary())
    preview = _write_json(tmp_path / "preview_summary.json", _preview_summary())
    owner_index = _write_json(tmp_path / "owner_index.json", _owner_index())
    report_path = tmp_path / "readiness.json"

    report = module.inspect_beta_deployment_preview_readiness(
        beta6_9_summary_path=beta6_9,
        preview_summary_path=preview,
        owner_feedback_index_path=owner_index,
        output_path=report_path,
    )

    assert report["passed"] is True
    assert report["decision"] == "beta_preview_ready"
    assert report["readiness"]["beta_preview_repeat_ready"] is True
    assert report["readiness"]["production_deploy_allowed"] is False
    assert report["readiness"]["production_runtime_execution_allowed"] is False
    assert report["readiness"]["production_receipt_write_allowed"] is False
    assert report["h3_boundary"] == {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}
    assert json.loads(report_path.read_text(encoding="utf-8"))["passed"] is True


def test_beta_deployment_preview_readiness_blocks_production_or_rejected_feedback(tmp_path: Path) -> None:
    beta6_9_payload = _beta6_9_summary()
    beta6_9_payload["deploy_allowed"] = True
    owner_payload = _owner_index()
    owner_payload["verdict_counts"]["rejected"] = 1
    beta6_9 = _write_json(tmp_path / "beta6_9_summary.json", beta6_9_payload)
    preview = _write_json(tmp_path / "preview_summary.json", _preview_summary())
    owner_index = _write_json(tmp_path / "owner_index.json", owner_payload)

    report = module.inspect_beta_deployment_preview_readiness(
        beta6_9_summary_path=beta6_9,
        preview_summary_path=preview,
        owner_feedback_index_path=owner_index,
        output_path=tmp_path / "readiness.json",
    )

    assert report["passed"] is False
    assert report["decision"] == "blocked"
    assert "beta6_9_summary.deploy_allowed must be false" in report["failure_reasons"]
    assert "owner_feedback_index.verdict_counts.rejected must be 0" in report["failure_reasons"]


def test_beta_deployment_preview_readiness_blocks_low_owner_signal(tmp_path: Path) -> None:
    owner_payload = _owner_index()
    owner_payload["packet_count"] = 2
    owner_payload["accepted_ratio"] = 0.5
    report = module.inspect_beta_deployment_preview_readiness(
        beta6_9_summary_path=_write_json(tmp_path / "beta6_9_summary.json", _beta6_9_summary()),
        preview_summary_path=_write_json(tmp_path / "preview_summary.json", _preview_summary()),
        owner_feedback_index_path=_write_json(tmp_path / "owner_index.json", owner_payload),
        output_path=tmp_path / "readiness.json",
    )

    assert report["passed"] is False
    assert "owner_feedback_index.packet_count must be >= 3" in report["failure_reasons"]
    assert "owner_feedback_index.accepted_ratio must be >= 0.66" in report["failure_reasons"]


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _beta6_9_summary() -> dict:
    return {
        "schema_version": "beta6-9-real-api-review-run-summary:v1",
        "passed": True,
        "external_review_verdict": "approved",
        "beta5_authorization_input_ready": True,
        "merge_authorized": True,
        "merge_performed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }


def _preview_summary() -> dict:
    return {
        "schema_version": "beta5-repeatable-preview-nightly-artifact:v1",
        "passed": True,
        "external_environment_provider": "virtualbox",
        "external_environment_classification": "external_preview",
        "smoke_total_checks": 15,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
    }


def _owner_index() -> dict:
    return {
        "schema_version": "beta5-owner-feedback-evidence-index:v1",
        "passed": True,
        "packet_count": 3,
        "accepted_ratio": 2 / 3,
        "verdict_counts": {"accepted": 2, "needs_followup": 1, "rejected": 0},
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
