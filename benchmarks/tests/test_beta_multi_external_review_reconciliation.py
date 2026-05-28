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


module = _load("beta_multi_external_review_reconciliation", SCRIPTS / "beta_multi_external_review_reconciliation.py")


def test_multi_external_review_reconciliation_passes_for_two_agents(tmp_path: Path) -> None:
    first = _write_summary(tmp_path / "first.json", agent_id="agent-a", provider="provider-a")
    second = _write_summary(tmp_path / "second.json", agent_id="agent-b", provider="provider-b")

    report = module.reconcile_multi_external_reviews(
        summary_paths=[first, second],
        output_path=tmp_path / "multi.json",
        min_reviewers=2,
        require_distinct_providers=True,
    )

    assert report["passed"] is True
    assert report["decision"] == "multi_external_review_ready"
    assert report["unique_external_agent_count"] == 2
    assert report["unique_external_provider_count"] == 2
    assert report["all_external_verdicts_approved"] is True
    assert report["readiness"]["production_deploy_allowed"] is False


def test_multi_external_review_reconciliation_blocks_duplicate_or_production_claim(tmp_path: Path) -> None:
    first = _write_summary(tmp_path / "first.json", agent_id="agent-a", provider="provider-a")
    bad_payload = _summary(agent_id="agent-a", provider="provider-a")
    bad_payload["deploy_allowed"] = True
    bad = _write_json(tmp_path / "bad.json", bad_payload)

    report = module.reconcile_multi_external_reviews(
        summary_paths=[first, bad],
        output_path=tmp_path / "multi.json",
        min_reviewers=2,
    )

    assert report["passed"] is False
    assert "unique external Agent count must be >= 2" in report["failure_reasons"]
    assert any("deploy_allowed must be false" in reason for reason in report["failure_reasons"])


def _write_summary(path: Path, *, agent_id: str, provider: str) -> Path:
    return _write_json(path, _summary(agent_id=agent_id, provider=provider))


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _summary(*, agent_id: str, provider: str) -> dict:
    return {
        "schema_version": "beta6-9-real-api-review-run-summary:v1",
        "passed": True,
        "run_root": f"/tmp/{agent_id}",
        "external_agent": {
            "agent_id": agent_id,
            "display_name": agent_id,
            "contact_ref": f"external-api:{agent_id}",
            "provider": provider,
            "model": "fixture-model",
            "api_key_recorded": False,
        },
        "external_review_verdict": "approved",
        "beta5_authorization_input_ready": True,
        "merge_authorized": True,
        "merge_performed": False,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
