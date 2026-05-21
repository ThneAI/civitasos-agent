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
beta2_apply = _load("beta2_operator_apply_receipt", ROOT / "scripts" / "beta2_operator_apply_receipt.py")
module = _load("beta2_patch_review_outcome", ROOT / "scripts" / "beta2_patch_review_outcome.py")


def test_inspect_review_outcomes_tracks_deferred_rejected_and_corrected_apply(tmp_path: Path) -> None:
    deferred = _write_run(tmp_path / "deferred", decision="deferred")
    rejected = _write_run(tmp_path / "rejected", decision="rejected")
    corrected = _write_run(tmp_path / "corrected", decision="approved", corrected_apply=True)

    reports = [module.inspect_review_outcome(path) for path in (deferred, rejected, corrected)]
    summary = module.summarize_review_outcomes([deferred, rejected, corrected])

    assert [report["review_outcome"] for report in reports] == ["deferred", "rejected", "corrected_applied"]
    assert all(report["passed"] is True for report in reports)
    assert reports[2]["operator_apply"]["applied_target_paths"] == ["README.md"]
    assert reports[2]["operator_apply"]["applied_diff_exact_patch_match"] is False
    assert summary["passed"] is True
    assert summary["sample_count"] == 3
    assert summary["outcome_counts"]["deferred"] == 1
    assert summary["outcome_counts"]["rejected"] == 1
    assert summary["outcome_counts"]["corrected_applied"] == 1
    assert summary["metrics"]["applied_ratio"] == 1 / 3
    assert summary["metrics"]["tested_apply_ratio"] == 1.0


def test_inspect_review_outcome_fails_when_patch_validation_hash_drifted(tmp_path: Path) -> None:
    run = _write_run(tmp_path / "drifted", decision="deferred")
    (run / "patch_proposal.patch").write_text(_patch_text(extra="+hash drift"), encoding="utf-8")

    report = module.inspect_review_outcome(run)

    assert report["passed"] is False
    assert "patch validation patch_sha256 must match patch bytes" in report["failure_reasons"]


def test_index_review_outcomes_writes_summary_jsonl_and_latest(tmp_path: Path) -> None:
    deferred = _write_run(tmp_path / "deferred", decision="deferred")
    corrected = _write_run(tmp_path / "corrected", decision="approved", corrected_apply=True)

    report = module.index_review_outcomes(
        [deferred, corrected],
        summary_output=tmp_path / "reports" / "summary.json",
        index_output=tmp_path / "reports" / "index.jsonl",
        latest_output=tmp_path / "reports" / "latest.json",
    )
    summary = json.loads((tmp_path / "reports" / "summary.json").read_text(encoding="utf-8"))
    index_rows = [
        json.loads(line)
        for line in (tmp_path / "reports" / "index.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    latest = json.loads((tmp_path / "reports" / "latest.json").read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert summary["sample_count"] == 2
    assert index_rows[0]["schema_version"] == module.INDEX_SCHEMA
    assert index_rows[0]["outcome_counts"]["deferred"] == 1
    assert index_rows[0]["outcome_counts"]["corrected_applied"] == 1
    assert latest == index_rows[0]


def test_index_review_outcomes_does_not_write_outputs_for_invalid_sample(tmp_path: Path) -> None:
    run = _write_run(tmp_path / "drifted", decision="deferred")
    (run / "patch_proposal.patch").write_text(_patch_text(extra="+hash drift"), encoding="utf-8")
    summary = tmp_path / "reports" / "summary.json"
    index = tmp_path / "reports" / "index.jsonl"
    latest = tmp_path / "reports" / "latest.json"

    report = module.index_review_outcomes(
        [run],
        summary_output=summary,
        index_output=index,
        latest_output=latest,
    )

    assert report["passed"] is False
    assert not summary.exists()
    assert not index.exists()
    assert not latest.exists()


def _write_run(tmp_path: Path, *, decision: str, corrected_apply: bool = False) -> Path:
    repo = tmp_path / "repo"
    run = tmp_path / "run"
    repo.mkdir(parents=True)
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "README.md").write_text("initial\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "initial")

    prepare = beta1.prepare_request(
        repo=repo,
        output_root=run,
        request_id=f"beta2-review-outcome-{decision}",
        request_text="Generate a patch proposal only.",
        base_ref=None,
        operator_id="operator-001",
        target_agent="deepseek-patch-proposer",
    )
    patch = run / "patch_proposal.patch"
    patch.write_text(_patch_text(), encoding="utf-8")
    validation = beta2_patch.validate_patch_proposal(
        repo=repo,
        patch_path=patch,
        request_path=Path(prepare["request_path"]),
        allow_path_prefixes=["README.md"],
        deny_path_fragments=[],
    )
    (run / "beta2_patch_proposal_validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    receipt_path = run / "operator_decision_receipt.json"
    beta1.write_operator_receipt(
        request_path=Path(prepare["request_path"]),
        proposal_path=patch,
        output_path=receipt_path,
        decision=decision,
        operator_id="operator-001",
        reason=f"{decision} for review outcome test",
        audit_output_path=None,
        audit_actor_id="audit-owner-001",
        append=False,
    )
    if corrected_apply:
        _git(repo, "apply", str(patch))
        with (repo / "README.md").open("a", encoding="utf-8") as handle:
            handle.write("operator correction\n")
        applied_diff = run / "applied_diff.patch"
        applied_diff.write_text(_git_text(repo, "diff"), encoding="utf-8")
        beta2_apply.record_operator_apply_receipt(
            repo=repo,
            patch_validation_path=run / "beta2_patch_proposal_validation.json",
            proposal_receipt_path=receipt_path,
            applied_diff_path=applied_diff,
            output_path=run / "beta2_operator_apply_receipt.json",
            operator_id="operator-001",
            reason="operator corrected approved proposal",
            tests_status="passed",
            tests_ref="tests:beta2-review-outcome:passed",
            manual_apply_confirmed=True,
            audit_output_path=None,
            audit_actor_id="audit-owner-001",
            append=False,
        )
    return run


def _patch_text(*, extra: str | None = None) -> str:
    rows = [
        "diff --git a/README.md b/README.md",
        "index e79c5e8..2a9f8c1 100644",
        "--- a/README.md",
        "+++ b/README.md",
        "@@ -1 +1,2 @@",
        " initial",
        "+proposed beta2 change",
    ]
    if extra:
        rows.append(extra)
    return "\n".join(rows) + "\n"


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
