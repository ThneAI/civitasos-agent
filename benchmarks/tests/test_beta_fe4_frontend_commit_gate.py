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


module = _load("beta_fe4_frontend_commit_gate", SCRIPTS / "beta_fe4_frontend_commit_gate.py")


def test_beta_fe4_commit_gate_creates_local_commit_and_receipt(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    changed_files = _modify_files(frontend, ("src/A.ts", "src/B.ts"))
    fe3 = _write_fe3_receipt(tmp_path / "fe3.json", changed_files)

    report = module.run_commit_gate(
        frontend_root=frontend,
        source_fe3_receipt=fe3,
        output_root=tmp_path / "out",
        commit_message="test frontend adapter slice",
        operator_id="operator",
        operator_authorization="test authorization",
    )

    assert report["passed"] is True
    assert report["decision"] == "beta_fe4_frontend_commit_gate_passed"
    assert report["git_actions_performed"] == {"commit": True, "push": False, "pr": False, "merge": False, "deploy": False}
    assert report["boundary"]["commit_allowed"] is True
    assert report["boundary"]["push_allowed"] is False
    assert report["committed_files"] == changed_files
    assert not _git_lines(frontend, "status", "--short")
    receipt = json.loads(Path(report["commit_receipt"]["path"]).read_text(encoding="utf-8"))
    assert receipt["schema_version"] == module.RECEIPT_SCHEMA
    assert receipt["commit_id"] == report["commit_id"]


def test_beta_fe4_commit_gate_blocks_worktree_drift(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    changed_files = _modify_files(frontend, ("src/A.ts",))
    extra = frontend / "src/extra.ts"
    extra.write_text("export const extra = 1;\n", encoding="utf-8")
    fe3 = _write_fe3_receipt(tmp_path / "fe3.json", changed_files)

    report = module.run_commit_gate(
        frontend_root=frontend,
        source_fe3_receipt=fe3,
        output_root=tmp_path / "out",
        commit_message="test frontend adapter slice",
        operator_id="operator",
        operator_authorization="test authorization",
    )

    assert report["passed"] is False
    assert any("changed files must match" in reason for reason in report["failure_reasons"])
    assert _git_lines(frontend, "status", "--short")


def _frontend_repo(path: Path) -> Path:
    (path / "src").mkdir(parents=True)
    for rel in ("src/A.ts", "src/B.ts"):
        (path / rel).write_text("export const value = 1;\n", encoding="utf-8")
    _run(["git", "init"], path)
    _run(["git", "add", "."], path)
    _run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "baseline"], path)
    return path


def _modify_files(repo: Path, files: tuple[str, ...]) -> list[str]:
    for rel in files:
        target = repo / rel
        target.write_text(target.read_text(encoding="utf-8") + "export const changed = 2;\n", encoding="utf-8")
    return sorted(files)


def _write_fe3_receipt(path: Path, changed_files: list[str]) -> Path:
    payload = {
        "schema_version": "beta-fe3-frontend-apply-receipt:v1",
        "passed": True,
        "decision": "beta_fe3_frontend_apply_receipt_passed",
        "changed_files": changed_files,
        "allowed_changed_files": changed_files,
        "rollback_check": {"exit_code": 0},
        "verification_commands": [{"exit_code": 0}, {"exit_code": 0}],
        "boundary": {
            "frontend_code_modified": True,
            "apply_allowed": True,
            "commit_allowed": False,
            "push_allowed": False,
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
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr


def _git_lines(repo: Path, *args: str) -> list[str]:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]
