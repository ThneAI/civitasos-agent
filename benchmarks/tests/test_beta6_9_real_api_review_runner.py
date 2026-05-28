from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

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


beta9_fixture = _load(
    "beta9_review_reconciliation_fixture_for_beta6_9_runner",
    ROOT / "benchmarks" / "tests" / "test_beta9_review_reconciliation.py",
)
beta5_feedback = _load("beta5_owner_feedback_packet_for_beta6_9_runner", SCRIPTS / "beta5_owner_feedback_packet.py")
module = _load("beta6_9_real_api_review_runner", SCRIPTS / "beta6_9_real_api_review_runner.py")


class _FakeResponse:
    status = 200

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def test_real_api_review_runner_writes_complete_bounded_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = _write_env_file(tmp_path)
    feedback_index = _write_feedback_index(tmp_path)
    pr_review = beta9_fixture._write_ready_pr_review_packet(tmp_path / "pr_review")
    preview_summary = _write_preview_summary(tmp_path / "preview")
    output_root = tmp_path / "run"

    def fake_probe_external_api_from_env(*, agent_card_path: Path, env_file_path: Path, output_path: Path):
        report = {
            "schema_version": "beta6-external-agent-api-probe-report:v1",
            "passed": True,
            "failure_reasons": [],
            "agent_card": str(agent_card_path),
            "env_file": str(env_file_path),
            "api_key_recorded": False,
        }
        output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return report

    monkeypatch.setattr(module, "probe_external_api_from_env", fake_probe_external_api_from_env)
    monkeypatch.setattr(module.urllib.request, "urlopen", _fake_urlopen(_approved_payload()))

    summary = module.run_real_api_review_chain(
        output_root=output_root,
        env_file=env_file,
        feedback_index=feedback_index,
        pr_review_evidence=pr_review,
        preview_summary=preview_summary,
        rollback_evidence_ref="rollback:fixture:clean",
    )

    assert summary["passed"] is True
    assert summary["external_review_verdict"] == "approved"
    assert summary["beta5_authorization_input_ready"] is True
    assert summary["merge_authorized"] is True
    assert summary["merge_performed"] is False
    assert summary["deploy_allowed"] is False
    assert summary["production_runtime_execution_allowed"] is False
    assert summary["production_receipt_write_allowed"] is False
    assert summary["h3_boundary"] == {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}

    expected = {
        "beta6_external_agent_readiness.json",
        "beta6_real_api_registration.json",
        "beta7_real_api_pr_review_task_invitation.json",
        "beta8_real_api_pr_review_response.json",
        "beta9_real_api_pr_review_reconciliation.json",
        "beta5_real_api_post_review_merge_authorization.json",
        "beta6_9_real_api_review_summary.json",
    }
    assert expected.issubset({path.name for path in output_root.iterdir()})
    combined = "\n".join(path.read_text(encoding="utf-8") for path in output_root.glob("*.json"))
    assert "fixture-secret" not in combined
    assert "api_key_recorded" in combined


def test_external_api_empty_content_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = _write_env_file(tmp_path)
    task_invitation = tmp_path / "task_invitation.json"
    task_invitation.write_text('{"task_title":"fixture","expected_output":"review_verdict"}\n', encoding="utf-8")
    task_brief = tmp_path / "brief.md"
    task_brief.write_text("Review fixture.\n", encoding="utf-8")
    pr_review = beta9_fixture._write_ready_pr_review_packet(tmp_path / "pr_review")
    preview_summary = _write_preview_summary(tmp_path / "preview")
    report_path = tmp_path / "api_report.json"
    response_path = tmp_path / "response.md"
    monkeypatch.setattr(module.urllib.request, "urlopen", _fake_urlopen(_empty_payload()))

    report = module.call_external_review_api(
        env_file=env_file,
        task_invitation_path=task_invitation,
        task_brief_path=task_brief,
        pr_review_evidence_path=pr_review,
        preview_summary_path=preview_summary,
        response_file_path=response_path,
        report_path=report_path,
        max_tokens=1200,
        temperature=0.0,
    )

    assert report["passed"] is False
    assert "external Agent API content must be non-empty" in report["failure_reasons"]
    assert report["api_key_present"] is True
    assert report["api_key_recorded"] is False
    assert "fixture-secret" not in report_path.read_text(encoding="utf-8")


def _write_env_file(tmp_path: Path) -> Path:
    path = tmp_path / ".env.beta6.external.local"
    path.write_text(
        "\n".join(
            [
                "BETA6_EXTERNAL_AGENT_PROVIDER=openai_compatible",
                "BETA6_EXTERNAL_AGENT_API_BASE_URL=https://external-agent.example/v1",
                "BETA6_EXTERNAL_AGENT_MODEL=external-reviewer-model",
                "BETA6_EXTERNAL_AGENT_API_KEY=fixture-secret",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _write_feedback_index(tmp_path: Path) -> Path:
    first_summary = _write_preview_summary(tmp_path / "owner_first")
    second_summary = _write_preview_summary(tmp_path / "owner_second")
    first_packet = tmp_path / "owner_first_packet.json"
    second_packet = tmp_path / "owner_second_packet.json"
    beta5_feedback.record_owner_feedback_packet(
        preview_summary_path=first_summary,
        output_path=first_packet,
        owner_id="owner-cc",
        operator_id="operator-cc",
        feedback_verdict="accepted",
        feedback_ref="owner-feedback:first-accepted",
        audit_ref="audit:first",
        external_evidence_ref="external-preview:first",
    )
    beta5_feedback.record_owner_feedback_packet(
        preview_summary_path=second_summary,
        output_path=second_packet,
        owner_id="owner-cc",
        operator_id="operator-cc",
        feedback_verdict="needs_followup",
        feedback_ref="owner-feedback:second-followup",
        audit_ref="audit:second",
        external_evidence_ref="external-preview:second",
    )
    index_path = tmp_path / "feedback_index.json"
    index = beta5_feedback.write_owner_feedback_index(
        packet_paths=[first_packet, second_packet],
        packet_globs=[],
        output_path=index_path,
        min_packets=2,
    )
    assert index["passed"] is True
    return index_path


def _write_preview_summary(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    deploy_receipt = root / "beta5_external_deploy_receipt.json"
    rollback_receipt = root / "beta5_external_deploy_rollback_drill_receipt.json"
    deploy_receipt.write_text('{"receipt":"deploy"}\n', encoding="utf-8")
    rollback_receipt.write_text('{"receipt":"rollback"}\n', encoding="utf-8")
    payload = {
        "schema_version": "beta5-repeatable-preview-nightly-artifact:v1",
        "passed": True,
        "failure_reasons": [],
        "run_root": str(root),
        "deploy_receipt": str(deploy_receipt),
        "deploy_receipt_sha256": beta5_feedback._sha256(deploy_receipt),
        "rollback_receipt": str(rollback_receipt),
        "rollback_receipt_sha256": beta5_feedback._sha256(rollback_receipt),
        "nodes": [
            {"node_id": "vm1", "node_ip": "192.168.56.4"},
            {"node_id": "vm2", "node_ip": "192.168.56.5"},
            {"node_id": "vm3", "node_ip": "192.168.56.6"},
        ],
        "smoke_cycles": 5,
        "smoke_total_checks": 15,
        "latency_ms_median": 8.2,
        "latency_ms_max": 21.3,
        "external_environment_provider": "virtualbox",
        "external_environment_classification": "external_preview",
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    path = root / "beta5_repeatable_preview_summary.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _approved_payload() -> dict[str, Any]:
    content = {
        "verdict": "approved",
        "boundary_preserved": True,
        "h3_remains_blocked": True,
        "production_claim_detected": False,
        "reason": "Evidence is consistent and no production boundary is crossed.",
    }
    return {
        "choices": [
            {
                "message": {"role": "assistant", "content": json.dumps(content, separators=(",", ":"))},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


def _empty_payload() -> dict[str, Any]:
    return {"choices": [{"message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}]}


def _fake_urlopen(payload: dict[str, Any]):
    def run(request, timeout: int):
        assert timeout == 120
        assert request.headers.get("Authorization") == "Bearer fixture-secret"
        body = json.loads(request.data.decode("utf-8"))
        assert body["max_tokens"] == 1200
        assert body["temperature"] == 0.0
        assert body["messages"][0]["role"] == "system"
        return _FakeResponse(payload)

    return run
