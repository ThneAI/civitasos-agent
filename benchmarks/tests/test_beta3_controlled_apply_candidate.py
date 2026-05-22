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
module = _load("beta3_controlled_apply_candidate", ROOT / "scripts" / "beta3_controlled_apply_candidate.py")


def test_candidate_passes_for_approved_pending_docs_patch(tmp_path: Path) -> None:
    run = _write_run(tmp_path, decision="approved", target="README.md")

    report = module.evaluate_candidate(
        run_root=run,
        operator_selection_reason="select low-risk README patch for Beta-3 candidate review",
        operator_id="operator-001",
    )

    assert report["passed"] is True
    assert report["candidate_status"] == "eligible_for_controlled_apply_design"
    assert report["source_beta2_outcome"]["review_outcome"] == "approved_pending_apply"
    assert report["execution_boundary"]["patch_application_allowed_by_this_gate"] is False
    assert report["execution_boundary"]["commit_allowed_by_this_gate"] is False


def test_candidate_blocks_deferred_and_missing_selection_reason(tmp_path: Path) -> None:
    run = _write_run(tmp_path, decision="deferred", target="README.md")

    report = module.evaluate_candidate(
        run_root=run,
        operator_selection_reason=" ",
        operator_id="operator-001",
    )

    assert report["passed"] is False
    assert "operator_selection_reason must be a non-empty string" in report["failure_reasons"]
    assert "candidate requires Beta-2 operator decision approved" in report["failure_reasons"]
    assert "candidate requires Beta-2 review outcome approved_pending_apply" in report["failure_reasons"]


def test_candidate_blocks_non_default_script_target_until_explicit_allowlisted(tmp_path: Path) -> None:
    run = _write_run(tmp_path, decision="approved", target="scripts/helper.py")
    suffix_run = _write_run(tmp_path, decision="approved", target="README.md.bak")

    blocked = module.evaluate_candidate(
        run_root=run,
        operator_selection_reason="script patch needs separate low-risk review",
        operator_id="operator-001",
    )
    allowed = module.evaluate_candidate(
        run_root=run,
        operator_selection_reason="operator explicitly selects fixture script target",
        operator_id="operator-001",
        allow_path_prefixes=["scripts/helper.py"],
    )
    suffix_blocked = module.evaluate_candidate(
        run_root=suffix_run,
        operator_selection_reason="README suffix path is not the exact default allowlisted file",
        operator_id="operator-001",
    )

    assert blocked["passed"] is False
    assert "candidate target path is outside low-risk allowlist: scripts/helper.py" in blocked["failure_reasons"]
    assert allowed["passed"] is True
    assert allowed["low_risk_allow_path_prefixes"] == ["scripts/helper.py"]
    assert suffix_blocked["passed"] is False
    assert "candidate target path is outside low-risk allowlist: README.md.bak" in suffix_blocked["failure_reasons"]


def _write_run(tmp_path: Path, *, decision: str, target: str) -> Path:
    repo = tmp_path / f"repo-{decision}-{target.replace('/', '-')}"
    run = tmp_path / f"run-{decision}-{target.replace('/', '-')}"
    target_path = repo / target
    target_path.parent.mkdir(parents=True, exist_ok=True)
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    target_path.write_text("initial\n", encoding="utf-8")
    _git(repo, "add", target)
    _git(repo, "commit", "-m", "initial")

    prepare = beta1.prepare_request(
        repo=repo,
        output_root=run,
        request_id=f"beta3-candidate-{decision}-{target.replace('/', '-')}",
        request_text="Generate a patch proposal only.",
        base_ref=None,
        operator_id="operator-001",
        target_agent="deepseek-patch-proposer",
    )
    patch = run / "patch_proposal.patch"
    patch.write_text(_patch_text(target), encoding="utf-8")
    validation = beta2_patch.validate_patch_proposal(
        repo=repo,
        patch_path=patch,
        request_path=Path(prepare["request_path"]),
        allow_path_prefixes=[target],
        deny_path_fragments=[],
    )
    assert validation["passed"] is True
    (run / "beta2_patch_proposal_validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    beta1.write_operator_receipt(
        request_path=Path(prepare["request_path"]),
        proposal_path=patch,
        output_path=run / "operator_decision_receipt.json",
        decision=decision,
        operator_id="operator-001",
        reason=f"{decision} for Beta-3 candidate test",
        audit_output_path=None,
        audit_actor_id="audit-owner-001",
        append=False,
    )
    return run


def _patch_text(target: str) -> str:
    return "\n".join(
        [
            f"diff --git a/{target} b/{target}",
            "index e79c5e8..2a9f8c1 100644",
            f"--- a/{target}",
            f"+++ b/{target}",
            "@@ -1 +1,2 @@",
            " initial",
            "+beta3 candidate fixture",
            "",
        ]
    )


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
