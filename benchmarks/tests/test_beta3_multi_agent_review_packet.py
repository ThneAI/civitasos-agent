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
_load("beta1_repo_review_proposal", ROOT / "scripts" / "beta1_repo_review_proposal.py")
_load("beta2_patch_proposal", ROOT / "scripts" / "beta2_patch_proposal.py")
_load("beta2_operator_apply_receipt", ROOT / "scripts" / "beta2_operator_apply_receipt.py")
_load("beta2_patch_review_outcome", ROOT / "scripts" / "beta2_patch_review_outcome.py")
_load("beta3_controlled_apply_candidate", ROOT / "scripts" / "beta3_controlled_apply_candidate.py")
_load("beta3_controlled_apply_sandbox", ROOT / "scripts" / "beta3_controlled_apply_sandbox.py")
receipt = _load("beta3_post_sandbox_operator_receipt", ROOT / "scripts" / "beta3_post_sandbox_operator_receipt.py")
sandbox_tests = _load(
    "beta3_controlled_apply_sandbox_fixture_for_packet",
    ROOT / "benchmarks" / "tests" / "test_beta3_controlled_apply_sandbox.py",
)
receipt_tests = _load(
    "beta3_post_sandbox_operator_receipt_fixture_for_packet",
    ROOT / "benchmarks" / "tests" / "test_beta3_post_sandbox_operator_receipt.py",
)
module = _load("beta3_multi_agent_review_packet", ROOT / "scripts" / "beta3_multi_agent_review_packet.py")


def test_packet_hash_binds_proposal_sandbox_operator_and_agent_verdicts(tmp_path: Path) -> None:
    operator_receipt = _write_operator_receipt(tmp_path)
    review = _write_verdict(tmp_path, operator_receipt, role="review_agent")
    risk = _write_verdict(tmp_path, operator_receipt, role="risk_agent")
    packet_path = tmp_path / "beta3_multi_agent_review_packet.json"

    report = module.build_review_packet(
        operator_receipt_path=operator_receipt,
        review_verdict_path=review,
        risk_verdict_path=risk,
        output_path=packet_path,
    )
    packet = json.loads(packet_path.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is True
    assert packet["passed"] is True
    assert packet["packet_status"] == "ready_for_source_apply_authorization_review"
    assert packet["source_patch_proposal"]["sha256"]
    assert packet["source_sandbox_report"]["sha256"]
    assert packet["source_operator_receipt"]["sha256"]
    assert packet["review_verdict"]["sha256"]
    assert packet["risk_verdict"]["sha256"]
    assert packet["next_gate_source_apply_authorization_review_allowed"] is True
    assert packet["source_repo_apply_allowed"] is False


def test_packet_blocks_deferred_risk_verdict(tmp_path: Path) -> None:
    operator_receipt = _write_operator_receipt(tmp_path)
    review = _write_verdict(tmp_path, operator_receipt, role="review_agent")
    risk = _write_verdict(tmp_path, operator_receipt, role="risk_agent", decision="deferred")
    packet_path = tmp_path / "blocked.json"

    report = module.build_review_packet(
        operator_receipt_path=operator_receipt,
        review_verdict_path=review,
        risk_verdict_path=risk,
        output_path=packet_path,
    )
    packet = json.loads(packet_path.read_text(encoding="utf-8"))

    assert report["validation"]["passed"] is False
    assert packet["passed"] is False
    assert packet["packet_status"] == "blocked"
    assert "risk_agent verdict must be approved" in packet["failure_reasons"]
    assert packet["next_gate_source_apply_authorization_review_allowed"] is False


def test_packet_validation_rejects_drifted_review_verdict(tmp_path: Path) -> None:
    operator_receipt = _write_operator_receipt(tmp_path)
    review = _write_verdict(tmp_path, operator_receipt, role="review_agent")
    risk = _write_verdict(tmp_path, operator_receipt, role="risk_agent")
    packet_path = tmp_path / "packet.json"
    module.build_review_packet(
        operator_receipt_path=operator_receipt,
        review_verdict_path=review,
        risk_verdict_path=risk,
        output_path=packet_path,
    )
    payload = json.loads(review.read_text(encoding="utf-8"))
    payload["reason"] = "mutated after packet build"
    review.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_review_packet(packet_path)

    assert validation["passed"] is False
    assert "review_agent.sha256 does not match file bytes" in validation["failure_reasons"]


def _write_operator_receipt(tmp_path: Path) -> Path:
    sandbox_report = receipt_tests._write_sandbox_report(tmp_path, patch=sandbox_tests._patch_text())
    output = tmp_path / "beta3_post_sandbox_operator_receipt.json"
    receipt.record_post_sandbox_receipt(
        sandbox_report_path=sandbox_report,
        output_path=output,
        decision="approved",
        operator_id="operator-001",
        reason="allow independent Agent review after sandbox evidence",
        audit_output_path=None,
        audit_actor_id="audit-owner-001",
        append=False,
    )
    return output


def _write_verdict(
    tmp_path: Path,
    operator_receipt: Path,
    *,
    role: str,
    decision: str = "approved",
) -> Path:
    output = tmp_path / f"{role}_verdict.json"
    module.record_verdict(
        operator_receipt_path=operator_receipt,
        role=role,
        agent_id=f"{role}-fixture",
        decision=decision,
        reason=f"{role} checked proposal, sandbox diff, tests, and boundary flags",
        blocking_findings=[],
        observations=["fixture evidence chain is hash-bound"],
        output_path=output,
    )
    return output
