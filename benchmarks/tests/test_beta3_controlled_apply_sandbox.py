from __future__ import annotations

import importlib.util
import json
import subprocess
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
beta1 = _load("beta1_repo_review_proposal", ROOT / "scripts" / "beta1_repo_review_proposal.py")
beta2_patch = _load("beta2_patch_proposal", ROOT / "scripts" / "beta2_patch_proposal.py")
_load("beta2_operator_apply_receipt", ROOT / "scripts" / "beta2_operator_apply_receipt.py")
_load("beta2_patch_review_outcome", ROOT / "scripts" / "beta2_patch_review_outcome.py")
candidate = _load("beta3_controlled_apply_candidate", ROOT / "scripts" / "beta3_controlled_apply_candidate.py")
module = _load("beta3_controlled_apply_sandbox", ROOT / "scripts" / "beta3_controlled_apply_sandbox.py")


def test_sandbox_applies_candidate_in_clean_worktree_and_preserves_source(tmp_path: Path) -> None:
    repo, candidate_report = _write_candidate(tmp_path, patch=_patch_text())
    before = _git_text(repo, "status", "--short")

    report = module.run_sandbox_apply(
        candidate_report_path=candidate_report,
        output_root=tmp_path / "sandbox",
        test_commands=["test -f README.md && grep -q 'beta3 sandbox change' README.md"],
    )
    diff = (tmp_path / "sandbox" / "sandbox_applied_diff.patch").read_text(encoding="utf-8")

    assert report["passed"] is True
    assert report["sandbox_status"] == "applied_and_cleaned"
    assert report["sandbox_outcome"] == "applied_tests_passed"
    assert report["sandbox"]["test_evidence_status"] == "passed"
    assert report["execution_boundary"]["sandbox_patch_apply_performed"] is True
    assert report["execution_boundary"]["source_repo_patch_apply_performed"] is False
    assert report["sandbox"]["worktree_cleaned"] is True
    assert not (tmp_path / "sandbox" / "sandbox_worktree").exists()
    assert "beta3 sandbox change" in diff
    assert _git_text(repo, "status", "--short") == before


def test_sandbox_records_apply_check_failure_without_source_mutation(tmp_path: Path) -> None:
    repo, candidate_report = _write_candidate(tmp_path, patch=_patch_text(context="different base"))

    report = module.run_sandbox_apply(
        candidate_report_path=candidate_report,
        output_root=tmp_path / "blocked",
    )

    assert report["passed"] is False
    assert report["sandbox_outcome"] == "apply_check_refused"
    assert report["failure_codes"] == ["sandbox_apply_check_refused"]
    assert "sandbox git apply --check failed" in report["failure_reasons"]
    assert report["sandbox"]["apply"] is None
    assert report["source_repo"]["worktree_snapshot_unchanged"] is True
    assert _git_text(repo, "status", "--short") == ""


def test_sandbox_blocks_dirty_request_snapshot(tmp_path: Path) -> None:
    _, candidate_report = _write_candidate(tmp_path, patch=_patch_text(), dirty_request=True)

    report = module.run_sandbox_apply(
        candidate_report_path=candidate_report,
        output_root=tmp_path / "dirty",
    )

    assert report["passed"] is False
    assert "proposal request repo_snapshot.status_short must be clean for sandbox replay" in report["failure_reasons"]
    assert report["failure_codes"] == ["sandbox_input_refused"]
    assert report["sandbox"]["apply_check"] is None


def test_sandbox_classifies_test_failure_before_source_apply_gate(tmp_path: Path) -> None:
    _, candidate_report = _write_candidate(tmp_path, patch=_patch_text())

    report = module.run_sandbox_apply(
        candidate_report_path=candidate_report,
        output_root=tmp_path / "test-failed",
        test_commands=["grep -q 'missing expectation' README.md"],
    )

    assert report["passed"] is False
    assert report["sandbox_outcome"] == "applied_tests_failed"
    assert report["failure_codes"] == ["sandbox_test_failed"]
    assert report["sandbox"]["test_evidence_status"] == "failed"
    assert report["operator_followup"]["required"] is True
    assert report["operator_followup"]["source_apply_must_remain_blocked"] is True
    assert report["operator_followup"]["sandbox_test_failure_requires_operator_review"] is True


def _write_candidate(
    tmp_path: Path,
    *,
    patch: str,
    dirty_request: bool = False,
) -> tuple[Path, Path]:
    repo = tmp_path / f"repo-{len(list(tmp_path.iterdir()))}"
    run = tmp_path / f"run-{len(list(tmp_path.iterdir()))}"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "README.md").write_text("initial\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "initial")
    if dirty_request:
        (repo / "README.md").write_text("initial\nlocal dirty note\n", encoding="utf-8")

    prepare = beta1.prepare_request(
        repo=repo,
        output_root=run,
        request_id="beta3-sandbox-fixture",
        request_text="Generate a patch proposal only.",
        base_ref=None,
        operator_id="operator-001",
        target_agent="deepseek-patch-proposer",
    )
    patch_path = run / "patch_proposal.patch"
    patch_path.write_text(patch, encoding="utf-8")
    validation = beta2_patch.validate_patch_proposal(
        repo=repo,
        patch_path=patch_path,
        request_path=Path(prepare["request_path"]),
        allow_path_prefixes=["README.md"],
        deny_path_fragments=[],
    )
    assert validation["passed"] is True
    (run / "beta2_patch_proposal_validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    beta1.write_operator_receipt(
        request_path=Path(prepare["request_path"]),
        proposal_path=patch_path,
        output_path=run / "operator_decision_receipt.json",
        decision="approved",
        operator_id="operator-001",
        reason="approve fixture for Beta-3 sandbox",
        audit_output_path=None,
        audit_actor_id="audit-owner-001",
        append=False,
    )
    candidate_report = run / "beta3_controlled_apply_candidate.json"
    candidate_report.write_text(
        json.dumps(
            candidate.evaluate_candidate(
                run_root=run,
                operator_selection_reason="select README fixture for sandbox apply",
                operator_id="operator-001",
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return repo, candidate_report


def _patch_text(*, context: str = "initial") -> str:
    return "\n".join(
        [
            "diff --git a/README.md b/README.md",
            "index e79c5e8..2a9f8c1 100644",
            "--- a/README.md",
            "+++ b/README.md",
            "@@ -1 +1,2 @@",
            f" {context}",
            "+beta3 sandbox change",
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
