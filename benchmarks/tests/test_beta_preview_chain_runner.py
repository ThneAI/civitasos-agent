from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


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


owner = _load("beta5_owner_feedback_packet_for_chain", SCRIPTS / "beta5_owner_feedback_packet.py")
module = _load("beta_preview_chain_runner", SCRIPTS / "beta_preview_chain_runner.py")


def test_beta_preview_chain_runner_orchestrates_multi_agent_preview_feedback_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous_a = _write_owner_packet(tmp_path / "prev_a", verdict="accepted")
    previous_b = _write_owner_packet(tmp_path / "prev_b", verdict="needs_followup")
    seed_feedback = tmp_path / "seed_feedback.json"
    seed_feedback.write_text('{"passed":true}\n', encoding="utf-8")
    seed_preview = _write_preview_summary(tmp_path / "seed_preview")
    primary_env = _write_env(
        tmp_path / "primary.env",
        provider="fixture-provider-a",
        base_url="https://fixture-provider-a.example/v1",
        model="fixture-model-a",
    )
    second_env = _write_env(
        tmp_path / "second.env",
        provider="fixture-provider-b",
        base_url="https://fixture-provider-b.example/v1",
        model="fixture-model-b",
    )
    pr_review = tmp_path / "pr_review.json"
    pr_review.write_text('{"review":"approved"}\n', encoding="utf-8")
    local_receipt = tmp_path / "local_receipt.json"
    local_receipt.write_text('{"receipt":"local"}\n', encoding="utf-8")
    backend = tmp_path / "api_only"
    backend.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    backend.chmod(0o755)
    frontend = tmp_path / "build"
    frontend.mkdir()
    (frontend / "index.html").write_text("<!doctype html><div id='root'></div>\n", encoding="utf-8")

    def fake_external_review(**kwargs):
        output_root = kwargs["output_root"]
        output_root.mkdir(parents=True, exist_ok=True)
        path = output_root / "beta6_9_real_api_review_summary.json"
        _write_json(path, _review_summary(kwargs["external_agent_id"]))
        return path

    def fake_preview(**kwargs):
        _write_preview_summary(kwargs["preview_summary_path"].parent / "preview_fixture", output=kwargs["preview_summary_path"])

    monkeypatch.setattr(module, "_run_external_review", fake_external_review)
    monkeypatch.setattr(module, "_run_repeatable_preview", fake_preview)

    summary = module.run_beta_preview_chain(
        output_root=tmp_path / "chain",
        env_file=primary_env,
        additional_env_files=[second_env],
        additional_agent_ids=["external-agent-second"],
        seed_feedback_index=seed_feedback,
        seed_preview_summary=seed_preview,
        pr_review_evidence=pr_review,
        local_deploy_receipt=local_receipt,
        previous_owner_feedback_packets=[previous_a, previous_b],
        previous_owner_feedback_packet_globs=[],
        backend_bin=backend,
        frontend_build_dir=frontend,
        nodes=[module.parse_node("vm1,vm1,192.168.56.4")],
        remote_root="/tmp/civitasos-preview",
        backend_port=18181,
        frontend_port=18182,
        operator_id="operator-cc",
        owner_id="owner-cc",
        owner_feedback_verdict="accepted",
        model_max_tokens=1200,
        temperature=0.0,
        min_owner_feedback_packets=3,
        min_owner_feedback_accepted_ratio=0.66,
        min_smoke_checks=15,
        require_distinct_providers=False,
    )

    assert summary["passed"] is True
    assert summary["decision"] == "beta_preview_chain_passed"
    assert summary["review_summary_count"] == 2
    assert summary["provider_identity_count"] == 2
    assert summary["multi_external_review_observed"] is True
    readiness = json.loads(Path(summary["readiness"]["path"]).read_text(encoding="utf-8"))
    assert readiness["decision"] == "beta_preview_ready"
    assert readiness["readiness"]["multi_external_review_observed"] is True
    owner_index = json.loads(Path(summary["owner_feedback_index"]["path"]).read_text(encoding="utf-8"))
    assert owner_index["packet_count"] == 3
    assert owner_index["verdict_counts"]["accepted"] == 2
    handoff = json.loads((tmp_path / "chain" / "beta_preview_operator_handoff.json").read_text(encoding="utf-8"))
    assert handoff["decision"] == "beta_preview_operator_handoff_ready"
    assert handoff["roles"]["operator"] == "operator-cc"
    assert handoff["handoff_boundary"]["production_runtime_execution_allowed"] is False


def _write_owner_packet(root: Path, *, verdict: str) -> Path:
    preview = _write_preview_summary(root / "preview")
    packet = root / "owner_packet.json"
    owner.record_owner_feedback_packet(
        preview_summary_path=preview,
        output_path=packet,
        owner_id="owner-cc",
        operator_id="operator-cc",
        feedback_verdict=verdict,
        feedback_ref=f"owner-feedback:{verdict}",
        audit_ref=f"audit:{verdict}",
        external_evidence_ref=f"external:{verdict}",
    )
    return packet


def _write_preview_summary(root: Path, *, output: Path | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    deploy = root / "deploy_receipt.json"
    rollback = root / "rollback_receipt.json"
    deploy.write_text('{"receipt":"deploy"}\n', encoding="utf-8")
    rollback.write_text('{"receipt":"rollback"}\n', encoding="utf-8")
    path = output or (root / "preview_summary.json")
    _write_json(
        path,
        {
            "schema_version": "beta5-repeatable-preview-nightly-artifact:v1",
            "passed": True,
            "run_root": str(root),
            "deploy_receipt": str(deploy),
            "deploy_receipt_sha256": owner._sha256(deploy),
            "rollback_receipt": str(rollback),
            "rollback_receipt_sha256": owner._sha256(rollback),
            "nodes": ["vm1", "vm2", "vm3"],
            "smoke_cycles": 5,
            "smoke_total_checks": 15,
            "latency_ms_min": 1,
            "latency_ms_median": 2,
            "latency_ms_max": 3,
            "external_environment_classification": "external_preview",
            "external_environment_provider": "virtualbox",
            "production_deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
            "h3_production_readiness_claimed": False,
            "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        },
    )
    return path


def _review_summary(agent_id: str) -> dict:
    return {
        "schema_version": "beta6-9-real-api-review-run-summary:v1",
        "passed": True,
        "run_root": f"/tmp/{agent_id}",
        "external_agent": {
            "agent_id": agent_id,
            "display_name": agent_id,
            "contact_ref": f"external-api:{agent_id}",
            "provider": "fixture-provider",
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


def _write_env(path: Path, *, provider: str, base_url: str, model: str) -> Path:
    path.write_text(
        "\n".join(
            [
                f"BETA6_EXTERNAL_AGENT_PROVIDER={provider}",
                f"BETA6_EXTERNAL_AGENT_API_BASE_URL={base_url}",
                f"BETA6_EXTERNAL_AGENT_MODEL={model}",
                "BETA6_EXTERNAL_AGENT_API_KEY=fixture-secret",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
