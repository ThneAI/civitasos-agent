from __future__ import annotations

import importlib.util
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
_load("beta3_post_sandbox_operator_receipt", ROOT / "scripts" / "beta3_post_sandbox_operator_receipt.py")
_load("beta3_multi_agent_review_packet", ROOT / "scripts" / "beta3_multi_agent_review_packet.py")
_load("beta3_source_apply_authorization", ROOT / "scripts" / "beta3_source_apply_authorization.py")
executor = _load("beta3_source_apply_executor", ROOT / "scripts" / "beta3_source_apply_executor.py")
executor_tests = _load(
    "beta3_source_apply_executor_fixture_for_outcome",
    ROOT / "benchmarks" / "tests" / "test_beta3_source_apply_executor.py",
)
module = _load("beta3_source_apply_outcome", ROOT / "scripts" / "beta3_source_apply_outcome.py")


def test_source_apply_outcome_index_observes_success_and_post_apply_test_failure(tmp_path: Path) -> None:
    passed_report = _write_execution_report(
        tmp_path / "passed",
        test_command="grep -q 'beta3 sandbox change' README.md",
    )
    failed_report = _write_execution_report(
        tmp_path / "failed",
        test_command="grep -q 'missing source apply expectation' README.md",
    )

    summary = module.summarize_source_apply_outcomes([passed_report, failed_report])
    indexed = module.index_source_apply_outcomes(
        [passed_report, failed_report],
        summary_output=tmp_path / "index" / "summary.json",
        index_output=tmp_path / "index" / "source_apply_outcomes.jsonl",
        latest_output=tmp_path / "index" / "latest.json",
    )

    assert summary["passed"] is True
    assert summary["outcome_counts"]["applied_tests_passed"] == 1
    assert summary["outcome_counts"]["applied_tests_failed"] == 1
    assert summary["metrics"]["source_repo_apply_performed_ratio"] == 1.0
    assert summary["metrics"]["tested_passed_apply_ratio"] == 0.5
    assert summary["metrics"]["rollback_decision_required_ratio"] == 0.5
    assert indexed["passed"] is True
    assert Path(indexed["summary_path"]).is_file()
    assert Path(indexed["index_path"]).is_file()
    assert Path(indexed["latest_path"]).is_file()


def test_source_apply_outcome_rejects_publication_boundary_escalation(tmp_path: Path) -> None:
    report_path = _write_execution_report(
        tmp_path / "tampered",
        test_command="grep -q 'beta3 sandbox change' README.md",
    )
    payload = module._read_json_object(report_path, [], "execution report")
    payload["commit_allowed"] = True
    module._write_json(report_path, payload)

    report = module.inspect_source_apply_outcome(report_path)

    assert report["passed"] is False
    assert "commit_allowed must be false" in report["failure_reasons"]


def _write_execution_report(tmp_path: Path, *, test_command: str) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    _, authorization_path = executor_tests._write_authorization(tmp_path)
    output = tmp_path / "source-apply"
    executor.run_source_apply(
        authorization_path=authorization_path,
        output_root=output,
        test_commands=[test_command],
    )
    return output / "beta3_source_apply_execution_report.json"
