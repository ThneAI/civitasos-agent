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
_load("beta1_repo_review_proposal", ROOT / "scripts" / "beta1_repo_review_proposal.py")
_load("beta2_patch_proposal", ROOT / "scripts" / "beta2_patch_proposal.py")
_load("beta2_operator_apply_receipt", ROOT / "scripts" / "beta2_operator_apply_receipt.py")
_load("beta2_patch_review_outcome", ROOT / "scripts" / "beta2_patch_review_outcome.py")
_load("beta3_controlled_apply_candidate", ROOT / "scripts" / "beta3_controlled_apply_candidate.py")
_load("beta3_controlled_apply_sandbox", ROOT / "scripts" / "beta3_controlled_apply_sandbox.py")
_load("beta3_post_sandbox_operator_receipt", ROOT / "scripts" / "beta3_post_sandbox_operator_receipt.py")
_load("beta3_multi_agent_review_packet", ROOT / "scripts" / "beta3_multi_agent_review_packet.py")
packet_tests = _load(
    "beta3_multi_agent_review_packet_fixture_for_real_runner",
    ROOT / "benchmarks" / "tests" / "test_beta3_multi_agent_review_packet.py",
)
module = _load(
    "beta3_real_multi_agent_review_runner",
    ROOT / "scripts" / "beta3_real_multi_agent_review_runner.py",
)


def test_real_multi_agent_runner_records_verdicts_and_packet(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    operator_receipt = packet_tests._write_operator_receipt(tmp_path)

    monkeypatch.setenv("FAKE_LLM_API_KEY", "fixture-key")
    monkeypatch.setattr(module, "call_openai_compatible_verdict_model", _fake_model)

    report = module.run_real_multi_agent_review(
        operator_receipt_path=operator_receipt,
        output_root=tmp_path / "real-review",
        model="openai:deepseek-fixture",
        base_url="https://llm.example/v1",
        api_key_env="FAKE_LLM_API_KEY",
        review_agent_id="review-fixture",
        risk_agent_id="risk-fixture",
        temperature=0.1,
        max_tokens=900,
        max_evidence_chars=40_000,
    )
    packet = json.loads(Path(report["packet_path"]).read_text(encoding="utf-8"))

    assert report["packet_validation_passed"] is True
    assert report["review_agent"]["decision"] == "approved"
    assert report["risk_agent"]["decision"] == "approved"
    assert packet["packet_status"] == "ready_for_source_apply_authorization_review"
    assert report["source_repo_apply_allowed"] is False
    assert (tmp_path / "real-review" / "review_agent_model_response.json").is_file()
    assert (tmp_path / "real-review" / "beta3_review_evidence_context.md").is_file()


def test_parse_verdict_response_rejects_approved_blockers() -> None:
    with pytest.raises(ValueError, match="must not include blocking_findings"):
        module.parse_verdict_response(
            json.dumps({
                "decision": "approved",
                "reason": "looks good",
                "blocking_findings": ["missing rollback boundary"],
                "observations": [],
            }),
            role="risk_agent",
        )


def test_build_evidence_context_truncates_large_patch(tmp_path: Path) -> None:
    operator_receipt = packet_tests._write_operator_receipt(tmp_path)

    context = module.build_evidence_context(operator_receipt, max_chars=900)

    assert context["truncated"] is True
    assert len(context["content"]) == context["chars"]
    assert "evidence context truncated" in context["content"]


def _fake_model(**kwargs):  # noqa: ANN003, ANN201 - test seam mirrors provider call.
    role = kwargs["role"]
    return {
        "schema_version": "beta3-real-multi-agent-review-model-response:v1",
        "role": role,
        "model": "deepseek-fixture",
        "content": json.dumps({
            "decision": "approved",
            "reason": f"{role} evidence is sufficient for authorization review",
            "blocking_findings": [],
            "observations": [f"{role} saw bounded sandbox evidence"],
        }),
        "prompt_chars": len(kwargs["evidence_context"]),
        "non_claims": [],
    }
