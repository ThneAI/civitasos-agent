from __future__ import annotations

import importlib.util
import json
import subprocess
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
beta1 = _load("beta1_repo_review_proposal", ROOT / "scripts" / "beta1_repo_review_proposal.py")
beta2_patch = _load("beta2_patch_proposal", ROOT / "scripts" / "beta2_patch_proposal.py")
module = _load("beta2_operator_apply_receipt", ROOT / "scripts" / "beta2_operator_apply_receipt.py")


def test_record_operator_apply_receipt_writes_manual_audit_record(tmp_path: Path) -> None:
    fixture = _write_manual_apply_fixture(tmp_path, proposal_decision="approved")
    output = fixture["run"] / "beta2_operator_apply_receipt.json"
    audit = fixture["run"] / "packet" / "sinks" / "audit-events.jsonl"

    report = module.record_operator_apply_receipt(
        repo=fixture["repo"],
        patch_validation_path=fixture["patch_validation"],
        proposal_receipt_path=fixture["proposal_receipt"],
        applied_diff_path=fixture["applied_diff"],
        output_path=output,
        operator_id="operator-001",
        reason="operator manually applied approved patch",
        tests_status="passed",
        tests_ref="tests:beta2-fixture:passed",
        manual_apply_confirmed=True,
        audit_output_path=audit,
        audit_actor_id="audit-owner-001",
        append=False,
    )

    receipt = json.loads(output.read_text(encoding="utf-8"))
    audit_rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert report["validation"]["passed"] is True
    assert receipt["manual_apply_confirmed"] is True
    assert receipt["applied_diff"]["target_paths"] == ["README.md"]
    assert receipt["auto_apply_performed"] is False
    assert receipt["commit_created_by_tool"] is False
    assert receipt["push_performed_by_tool"] is False
    assert audit_rows[0]["audit_ref_kind"] == "beta2_operator_applied_patch_receipt"
    assert audit_rows[0]["tests"] == {"status": "passed", "ref": "tests:beta2-fixture:passed"}


def test_record_operator_apply_receipt_requires_approved_proposal(tmp_path: Path) -> None:
    fixture = _write_manual_apply_fixture(tmp_path, proposal_decision="deferred")

    with pytest.raises(ValueError, match="decision must be approved"):
        module.record_operator_apply_receipt(
            repo=fixture["repo"],
            patch_validation_path=fixture["patch_validation"],
            proposal_receipt_path=fixture["proposal_receipt"],
            applied_diff_path=fixture["applied_diff"],
            output_path=fixture["run"] / "beta2_operator_apply_receipt.json",
            operator_id="operator-001",
            reason="should fail",
            tests_status="not-run",
            tests_ref="tests:not-run",
            manual_apply_confirmed=True,
            audit_output_path=None,
            audit_actor_id="audit-owner-001",
            append=False,
        )


def test_record_operator_apply_receipt_requires_explicit_manual_confirmation(tmp_path: Path) -> None:
    fixture = _write_manual_apply_fixture(tmp_path, proposal_decision="approved")

    with pytest.raises(ValueError, match="manual-apply-confirmed"):
        module.record_operator_apply_receipt(
            repo=fixture["repo"],
            patch_validation_path=fixture["patch_validation"],
            proposal_receipt_path=fixture["proposal_receipt"],
            applied_diff_path=fixture["applied_diff"],
            output_path=fixture["run"] / "beta2_operator_apply_receipt.json",
            operator_id="operator-001",
            reason="should fail",
            tests_status="passed",
            tests_ref="tests:beta2-fixture:passed",
            manual_apply_confirmed=False,
            audit_output_path=None,
            audit_actor_id="audit-owner-001",
            append=False,
        )


@pytest.mark.parametrize("reason", ["", "   "])
def test_record_operator_apply_receipt_requires_reason(tmp_path: Path, reason: str) -> None:
    fixture = _write_manual_apply_fixture(tmp_path, proposal_decision="approved")

    with pytest.raises(ValueError, match="reason must be a non-empty string"):
        module.record_operator_apply_receipt(
            repo=fixture["repo"],
            patch_validation_path=fixture["patch_validation"],
            proposal_receipt_path=fixture["proposal_receipt"],
            applied_diff_path=fixture["applied_diff"],
            output_path=fixture["run"] / "beta2_operator_apply_receipt.json",
            operator_id="operator-001",
            reason=reason,
            tests_status="passed",
            tests_ref="tests:beta2-fixture:passed",
            manual_apply_confirmed=True,
            audit_output_path=None,
            audit_actor_id="audit-owner-001",
            append=False,
        )


def test_validate_operator_apply_receipt_rejects_blank_reason(tmp_path: Path) -> None:
    fixture = _write_manual_apply_fixture(tmp_path, proposal_decision="approved")
    output = fixture["run"] / "beta2_operator_apply_receipt.json"
    module.record_operator_apply_receipt(
        repo=fixture["repo"],
        patch_validation_path=fixture["patch_validation"],
        proposal_receipt_path=fixture["proposal_receipt"],
        applied_diff_path=fixture["applied_diff"],
        output_path=output,
        operator_id="operator-001",
        reason="operator manually applied approved patch",
        tests_status="passed",
        tests_ref="tests:beta2-fixture:passed",
        manual_apply_confirmed=True,
        audit_output_path=None,
        audit_actor_id="audit-owner-001",
        append=False,
    )
    receipt = json.loads(output.read_text(encoding="utf-8"))
    receipt["reason"] = "  "
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report = module.validate_operator_apply_receipt(output)

    assert report["passed"] is False
    assert "reason must be a non-empty string" in report["failure_reasons"]


def _write_manual_apply_fixture(tmp_path: Path, *, proposal_decision: str) -> dict[str, Path]:
    repo = tmp_path / "repo"
    run = tmp_path / "run"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "README.md").write_text("initial\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "initial")

    prepare = beta1.prepare_request(
        repo=repo,
        output_root=run,
        request_id="beta2-operator-apply-test",
        request_text="Generate a patch proposal only.",
        base_ref=None,
        operator_id="operator-001",
        target_agent="deepseek-patch-proposer",
    )
    patch = run / "patch_proposal.patch"
    patch.write_text(_patch_text(), encoding="utf-8")
    patch_validation = run / "beta2_patch_proposal_validation.json"
    patch_validation.write_text(
        json.dumps(
            beta2_patch.validate_patch_proposal(
                repo=repo,
                patch_path=patch,
                request_path=Path(prepare["request_path"]),
                allow_path_prefixes=["README.md"],
                deny_path_fragments=[],
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    proposal_receipt = run / "operator_decision_receipt.json"
    beta1.write_operator_receipt(
        request_path=Path(prepare["request_path"]),
        proposal_path=patch,
        output_path=proposal_receipt,
        decision=proposal_decision,
        operator_id="operator-001",
        reason="manual apply selection",
        audit_output_path=None,
        audit_actor_id="audit-owner-001",
        append=False,
    )
    _git(repo, "apply", str(patch))
    applied_diff = run / "applied_diff.patch"
    applied_diff.write_text(_git_text(repo, "diff"), encoding="utf-8")
    return {
        "repo": repo,
        "run": run,
        "patch_validation": patch_validation,
        "proposal_receipt": proposal_receipt,
        "applied_diff": applied_diff,
    }


def _patch_text() -> str:
    return "\n".join(
        [
            "diff --git a/README.md b/README.md",
            "index e79c5e8..2a9f8c1 100644",
            "--- a/README.md",
            "+++ b/README.md",
            "@@ -1 +1,2 @@",
            " initial",
            "+proposed manual apply evidence",
            "",
        ]
    )


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _git_text(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
