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


module = _load("beta_fe9_frontend_post_merge_smoke", SCRIPTS / "beta_fe9_frontend_post_merge_smoke.py")


def test_fe9_post_merge_smoke_passes_when_checkout_matches_remote_merge(tmp_path: Path) -> None:
    repo, commit_id = _repo_with_remote_main(tmp_path)
    fe8 = _write_fe8_receipt(tmp_path / "fe8.json", commit_id)

    report = module.run_post_merge_smoke(
        source_fe8_receipt=fe8,
        frontend_root=repo,
        output_root=tmp_path / "out",
        remote="origin",
        base_branch="main",
        verification_commands=["python -c 'print(\"smoke ok\")'"],
        operator_id="operator",
        operator_authorization="test",
    )

    assert report["passed"] is True
    assert report["schema_version"] == module.RECEIPT_SCHEMA
    assert report["remote_head"] == commit_id
    assert report["local_head"] == commit_id
    assert report["boundary"]["post_merge_smoke_allowed"] is True
    assert report["boundary"]["deploy_allowed"] is False
    assert report["verification_commands"][0]["returncode"] == 0


def test_fe9_post_merge_smoke_blocks_local_remote_drift(tmp_path: Path) -> None:
    repo, commit_id = _repo_with_remote_main(tmp_path)
    _write(repo / "drift.txt", "local drift\n")
    _run(["git", "add", "drift.txt"], repo)
    _run(["git", "commit", "-m", "local drift"], repo)
    fe8 = _write_fe8_receipt(tmp_path / "fe8.json", commit_id)

    report = module.run_post_merge_smoke(
        source_fe8_receipt=fe8,
        frontend_root=repo,
        output_root=tmp_path / "out",
        remote="origin",
        base_branch="main",
        verification_commands=["python -c 'print(\"should not run\")'"],
        operator_id="operator",
        operator_authorization="test",
    )

    assert report["passed"] is False
    assert any("local frontend HEAD" in reason for reason in report["failure_reasons"])
    assert report["verification_commands"] == []


def _repo_with_remote_main(tmp_path: Path) -> tuple[Path, str]:
    remote = tmp_path / "remote.git"
    _run(["git", "init", "--bare", str(remote)], tmp_path)
    repo = tmp_path / "frontend"
    repo.mkdir()
    _run(["git", "init"], repo)
    _run(["git", "remote", "add", "origin", str(remote)], repo)
    _write(repo / "package.json", "{\"scripts\":{\"build\":\"echo build\"}}\n")
    _run(["git", "add", "package.json"], repo)
    _run(["git", "commit", "-m", "merged frontend change"], repo)
    commit_id = _git(repo, "rev-parse", "HEAD")
    _run(["git", "push", "origin", "HEAD:refs/heads/main"], repo)
    return repo, commit_id


def _write_fe8_receipt(path: Path, commit_id: str) -> Path:
    payload = {
        "schema_version": "beta-fe8-frontend-merge-receipt:v1",
        "passed": True,
        "decision": "beta_fe8_frontend_merge_receipt_passed",
        "base_branch": "main",
        "base_branch_after_head": commit_id,
        "pr": {"state": "MERGED", "mergeCommit": {"oid": commit_id}},
        "boundary": {
            "merge_allowed": True,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


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
