from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

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


module = _load("beta_fe5_8_frontend_release_gates", SCRIPTS / "beta_fe5_8_frontend_release_gates.py")


def test_fe5_push_consumes_fe4_receipt_and_pushes_bounded_branch(tmp_path: Path) -> None:
    repo, remote = _frontend_repo_with_remote(tmp_path)
    changed = repo / "src" / "TaskReadAdapter.ts"
    changed.write_text("export const TaskReadAdapter = 1;\n", encoding="utf-8")
    _run(["git", "add", "src/TaskReadAdapter.ts"], repo)
    _run(["git", "commit", "-m", "test adapter"], repo)
    commit_id = _git(repo, "rev-parse", "HEAD")
    fe4 = _write_fe4_receipt(tmp_path / "fe4.json", repo, commit_id)

    report = module.run_fe5_push(
        source_fe4_receipt=fe4,
        frontend_root=repo,
        output_root=tmp_path / "out",
        remote="origin",
        target_branch="beta-fe/test-adapter",
        operator_id="operator",
        operator_authorization="test",
    )

    assert report["passed"] is True
    assert report["schema_version"] == module.FE5_RECEIPT_SCHEMA
    assert report["remote_branch_after_head"] == commit_id
    assert report["boundary"]["push_allowed"] is True
    assert report["boundary"]["merge_allowed"] is False
    assert _git(repo, "ls-remote", "origin", "refs/heads/beta-fe/test-adapter").startswith(commit_id)
    assert not _git(repo, "status", "--short")


def test_local_review_blocks_production_boundary_expansion() -> None:
    diff = '+ const deploy_allowed = "deploy_allowed\\": true";\n'
    review = module._local_review(diff)
    assert review["verdict"] == "changes_requested"
    assert review["findings"]


def test_parse_external_review_json_from_fenced_block() -> None:
    parsed = module._parse_review_json('```json\n{"verdict":"approved","risk_level":"low","findings":[],"summary":"ok"}\n```')
    assert parsed["verdict"] == "approved"


def _frontend_repo_with_remote(tmp_path: Path) -> tuple[Path, Path]:
    remote = tmp_path / "remote.git"
    _run(["git", "init", "--bare", str(remote)], tmp_path)
    repo = tmp_path / "frontend"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "TaskPoolPanel.tsx").write_text("export const TaskPoolPanel = 1;\n", encoding="utf-8")
    _run(["git", "init"], repo)
    _run(["git", "remote", "add", "origin", str(remote)], repo)
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-m", "baseline"], repo)
    _run(["git", "push", "origin", "HEAD:refs/heads/main"], repo)
    return repo, remote


def _write_fe4_receipt(path: Path, repo: Path, commit_id: str) -> Path:
    payload = {
        "schema_version": "beta-fe4-frontend-commit-receipt:v1",
        "passed": True,
        "decision": "beta_fe4_frontend_commit_receipt_passed",
        "commit_id": commit_id,
        "boundary": {
            "frontend_code_modified": True,
            "apply_allowed": True,
            "commit_allowed": True,
            "push_allowed": False,
            "pr_allowed": False,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _run(argv: list[str], cwd: Path) -> None:
    cmd = list(argv)
    if cmd[:2] == ["git", "commit"]:
        cmd = ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *cmd[1:]]
    result = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()
