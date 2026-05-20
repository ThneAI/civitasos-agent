from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "beta2_patch_proposal.py"
spec = importlib.util.spec_from_file_location("beta2_patch_proposal", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

BETA1_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "beta1_repo_review_proposal.py"
beta1_spec = importlib.util.spec_from_file_location("beta1_repo_review_proposal_for_beta2", BETA1_SCRIPT)
assert beta1_spec and beta1_spec.loader
beta1_module = importlib.util.module_from_spec(beta1_spec)
sys.modules[beta1_spec.name] = beta1_module
beta1_spec.loader.exec_module(beta1_module)


def test_validate_patch_proposal_passes_for_repo_relative_unified_diff(tmp_path: Path) -> None:
    repo = _write_git_repo(tmp_path)
    request = beta1_module.prepare_request(
        repo=repo,
        output_root=tmp_path / "run",
        request_id="beta2-test-001",
        request_text="Generate a patch proposal only.",
        base_ref=None,
        operator_id="operator-001",
        target_agent="deepseek-reviewer",
    )
    patch = _write_patch(tmp_path / "patch_proposal.patch", "README.md")

    report = module.validate_patch_proposal(
        repo=repo,
        patch_path=patch,
        request_path=Path(request["request_path"]),
        allow_path_prefixes=["README.md"],
        deny_path_fragments=[],
    )

    assert report["passed"] is True
    assert report["target_paths"] == ["README.md"]
    assert report["dangerous_actions_allowed"]["apply_patch"] is False
    assert report["dangerous_actions_allowed"]["commit"] is False
    assert report["dangerous_actions_allowed"]["push"] is False


def test_validate_patch_proposal_fails_for_ignored_target(tmp_path: Path) -> None:
    repo = _write_git_repo(tmp_path)
    (repo / ".gitignore").write_text("secret.txt\n", encoding="utf-8")
    patch = _write_patch(tmp_path / "patch_proposal.patch", "secret.txt")

    report = module.validate_patch_proposal(
        repo=repo,
        patch_path=patch,
        request_path=None,
        allow_path_prefixes=[],
        deny_path_fragments=[],
    )

    assert report["passed"] is False
    assert any("git-ignored" in reason for reason in report["failure_reasons"])


def test_validate_patch_proposal_fails_for_denied_path_and_forbidden_claim(tmp_path: Path) -> None:
    repo = _write_git_repo(tmp_path)
    patch = _write_patch(tmp_path / "patch_proposal.patch", "deploy/production.yaml")
    patch.write_text(patch.read_text(encoding="utf-8") + "\n# already deployed\n", encoding="utf-8")

    report = module.validate_patch_proposal(
        repo=repo,
        patch_path=patch,
        request_path=None,
        allow_path_prefixes=[],
        deny_path_fragments=[],
    )

    assert report["passed"] is False
    assert any("denied fragment" in reason for reason in report["failure_reasons"])
    assert any("forbidden claim: already deployed" in reason for reason in report["failure_reasons"])


def _write_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    (repo / "README.md").write_text("initial\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "initial")
    return repo


def _write_patch(path: Path, target: str) -> Path:
    path.write_text(
        "\n".join(
            [
                f"diff --git a/{target} b/{target}",
                "index e79c5e8..2a9f8c1 100644",
                f"--- a/{target}",
                f"+++ b/{target}",
                "@@ -1 +1,2 @@",
                " initial",
                "+proposed beta2 change",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
