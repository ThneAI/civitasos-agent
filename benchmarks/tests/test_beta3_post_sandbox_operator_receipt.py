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
sandbox = _load("beta3_controlled_apply_sandbox", ROOT / "scripts" / "beta3_controlled_apply_sandbox.py")
sandbox_tests = _load(
    "beta3_controlled_apply_sandbox_fixture",
    ROOT / "benchmarks" / "tests" / "test_beta3_controlled_apply_sandbox.py",
)
module = _load("beta3_post_sandbox_operator_receipt", ROOT / "scripts" / "beta3_post_sandbox_operator_receipt.py")


def test_approved_post_sandbox_receipt_hash_binds_report_and_audit(tmp_path: Path) -> None:
    sandbox_report = _write_sandbox_report(tmp_path, patch=sandbox_tests._patch_text())
    output = tmp_path / "beta3_post_sandbox_operator_receipt.json"
    audit = tmp_path / "sinks" / "audit-events.jsonl"

    write_report = module.record_post_sandbox_receipt(
        sandbox_report_path=sandbox_report,
        output_path=output,
        decision="approved",
        operator_id="operator-001",
        reason="sandbox replay is acceptable for next source-apply gate review",
        audit_output_path=audit,
        audit_actor_id="audit-owner-001",
        append=False,
    )
    receipt = json.loads(output.read_text(encoding="utf-8"))
    audit_row = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])

    assert write_report["validation"]["passed"] is True
    assert receipt["decision_scope"] == "sandbox_replay_review_only"
    assert receipt["next_gate_review_allowed"] is True
    assert receipt["source_repo_apply_allowed"] is False
    assert receipt["sandbox_summary"]["worktree_cleaned"] is True
    assert audit_row["audit_ref_kind"] == "beta3_post_sandbox_operator_receipt"
    assert audit_row["next_gate_review_allowed"] is True


def test_approved_receipt_rejects_failed_sandbox_but_rejection_can_record_it(tmp_path: Path) -> None:
    failed = _write_sandbox_report(tmp_path, patch=sandbox_tests._patch_text(context="mismatch"))

    with pytest.raises(ValueError, match="approved receipt requires passed sandbox report"):
        module.record_post_sandbox_receipt(
            sandbox_report_path=failed,
            output_path=tmp_path / "approved.json",
            decision="approved",
            operator_id="operator-001",
            reason="must not approve failed sandbox",
            audit_output_path=None,
            audit_actor_id="audit-owner-001",
            append=False,
        )

    report = module.record_post_sandbox_receipt(
        sandbox_report_path=failed,
        output_path=tmp_path / "rejected.json",
        decision="rejected",
        operator_id="operator-001",
        reason="sandbox apply-check failed",
        audit_output_path=None,
        audit_actor_id="audit-owner-001",
        append=False,
    )

    assert report["validation"]["passed"] is True
    receipt = json.loads((tmp_path / "rejected.json").read_text(encoding="utf-8"))
    assert receipt["next_gate_review_allowed"] is False


def test_validate_post_sandbox_receipt_rejects_source_apply_authorization(tmp_path: Path) -> None:
    sandbox_report = _write_sandbox_report(tmp_path, patch=sandbox_tests._patch_text())
    output = tmp_path / "receipt.json"
    module.record_post_sandbox_receipt(
        sandbox_report_path=sandbox_report,
        output_path=output,
        decision="deferred",
        operator_id="operator-001",
        reason="wait for independent review",
        audit_output_path=None,
        audit_actor_id="audit-owner-001",
        append=False,
    )
    receipt = json.loads(output.read_text(encoding="utf-8"))
    receipt["source_repo_apply_allowed"] = True
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report = module.validate_post_sandbox_receipt(output)

    assert report["passed"] is False
    assert "source_repo_apply_allowed must be false" in report["failure_reasons"]


def _write_sandbox_report(tmp_path: Path, *, patch: str) -> Path:
    _, candidate_report = sandbox_tests._write_candidate(tmp_path, patch=patch)
    output_root = tmp_path / f"sandbox-{len(list(tmp_path.iterdir()))}"
    sandbox.run_sandbox_apply(
        candidate_report_path=candidate_report,
        output_root=output_root,
        test_commands=["test -f README.md"],
    )
    return output_root / "beta3_controlled_apply_sandbox_report.json"
