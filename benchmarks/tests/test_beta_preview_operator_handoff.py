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


module = _load("beta_preview_operator_handoff", SCRIPTS / "beta_preview_operator_handoff.py")


def test_beta_preview_operator_handoff_accepts_ready_chain(tmp_path: Path) -> None:
    chain = _write_ready_chain(tmp_path)

    report = module.write_beta_preview_operator_handoff(
        chain_summary_path=chain,
        output_path=tmp_path / "handoff.json",
        roles={"operator": "operator-cc", "preview_owner": "owner-cc"},
    )

    assert report["passed"] is True
    assert report["decision"] == "beta_preview_operator_handoff_ready"
    assert report["roles"]["operator"] == "operator-cc"
    assert report["handoff_metrics"]["provider_identity_count"] == 2
    assert report["handoff_boundary"]["production_runtime_execution_allowed"] is False
    assert report["h3_boundary"]["h3_remains_blocked"] is True
    assert all(check["passed"] is True for check in report["required_operator_checks"])


def test_beta_preview_operator_handoff_blocks_recorded_api_key(tmp_path: Path) -> None:
    chain = _write_ready_chain(tmp_path)
    provider_path = tmp_path / "provider.json"
    provider = json.loads(provider_path.read_text(encoding="utf-8"))
    provider["api_key_recorded"] = True
    _write_json(provider_path, provider)

    report = module.write_beta_preview_operator_handoff(
        chain_summary_path=chain,
        output_path=tmp_path / "handoff.json",
    )

    assert report["passed"] is False
    assert report["decision"] == "blocked"
    assert "provider_env_preflight.api_key_recorded must be false" in report["failure_reasons"]


def _write_ready_chain(tmp_path: Path) -> Path:
    provider = _write_json(
        tmp_path / "provider.json",
        {
            "schema_version": "beta-external-provider-env-preflight:v1",
            "passed": True,
            "decision": "provider_env_ready",
            "api_key_recorded": False,
            "unique_provider_identity_count": 2,
            "unique_provider_identities": ["provider-a@example", "provider-b@example"],
            "production_deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
            "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        },
    )
    readiness = _write_json(
        tmp_path / "readiness.json",
        {
            "schema_version": "beta-deployment-preview-readiness-report:v1",
            "passed": True,
            "decision": "beta_preview_ready",
            "readiness": {
                "beta_preview_repeat_ready": True,
                "multi_external_review_observed": True,
                "production_deploy_allowed": False,
                "production_runtime_execution_allowed": False,
                "production_receipt_write_allowed": False,
                "h3_production_readiness_claimed": False,
            },
            "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        },
    )
    preview = _write_json(
        tmp_path / "preview.json",
        {
            "schema_version": "beta5-repeatable-preview-nightly-artifact:v1",
            "passed": True,
            "smoke_total_checks": 15,
            "rollback_receipt": str(tmp_path / "rollback.json"),
            "production_deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
            "h3_production_readiness_claimed": False,
            "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        },
    )
    owner_index = _write_json(
        tmp_path / "owner_index.json",
        {
            "schema_version": "beta5-owner-feedback-evidence-index:v1",
            "passed": True,
            "packet_count": 3,
            "accepted_ratio": 0.67,
            "verdict_counts": {"accepted": 2, "needs_followup": 1, "rejected": 0},
            "production_deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
            "h3_production_readiness_claimed": False,
            "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        },
    )
    multi_review = _write_json(
        tmp_path / "multi_review.json",
        {
            "schema_version": "beta-multi-external-review-reconciliation:v1",
            "passed": True,
            "decision": "multi_external_review_ready",
            "all_external_verdicts_approved": True,
            "unique_external_agent_count": 2,
            "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        },
    )
    return _write_json(
        tmp_path / "chain.json",
        {
            "schema_version": "beta-preview-chain-run-summary:v1",
            "passed": True,
            "decision": "beta_preview_chain_passed",
            "readiness_decision": "beta_preview_ready",
            "review_summary_count": 2,
            "provider_identity_count": 2,
            "require_distinct_providers": True,
            "multi_external_review_observed": True,
            "provider_env_preflight": _ref(provider),
            "readiness": _ref(readiness),
            "preview_summary": _ref(preview),
            "owner_feedback_index": _ref(owner_index),
            "multi_external_review": _ref(multi_review),
            "production_deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
            "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        },
    )


def _ref(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": module._sha256(path)}


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
