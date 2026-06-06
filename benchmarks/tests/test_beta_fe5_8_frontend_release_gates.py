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


def test_fe6_resolves_relative_body_file_before_gh(tmp_path: Path, monkeypatch) -> None:
    repo, _remote = _frontend_repo_with_remote(tmp_path)
    commit_id = _git(repo, "rev-parse", "HEAD")
    _run(["git", "push", "origin", f"{commit_id}:refs/heads/beta-fe/test-adapter"], repo)
    fe5 = tmp_path / "fe5.json"
    fe5.write_text(
        json.dumps({
            "schema_version": module.FE5_RECEIPT_SCHEMA,
            "passed": True,
            "decision": "beta_fe5_frontend_push_receipt_passed",
            "commit_id": commit_id,
            "remote": "origin",
            "target_branch": "beta-fe/test-adapter",
            "remote_branch_after_head": commit_id,
            "boundary": {
                "frontend_code_modified": True,
                "apply_allowed": True,
                "commit_allowed": True,
                "push_allowed": True,
                "pr_allowed": False,
                "review_allowed": False,
                "merge_allowed": False,
                "deploy_allowed": False,
                "production_runtime_execution_allowed": False,
                "production_receipt_write_allowed": False,
            },
            "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
        }),
        encoding="utf-8",
    )
    body = tmp_path / "draft_pr_body.md"
    body.write_text("bounded PR body\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    captured: dict[str, list[str]] = {}

    def fake_gh(_cwd: Path, *args: str):
        captured["args"] = list(args)
        return {
            "argv": ["gh", *args],
            "returncode": 0,
            "stdout": "https://example.test/pr/1\n",
            "stderr": "",
        }

    def fake_gh_json(_cwd: Path, _failures: list[str], *args: str):
        if args[:2] == ("pr", "list"):
            return []
        return {
            "number": 1,
            "url": "https://example.test/pr/1",
            "isDraft": True,
            "state": "OPEN",
            "headRefName": "beta-fe/test-adapter",
            "headRefOid": commit_id,
            "baseRefName": "main",
            "title": "test adapter",
        }

    monkeypatch.setattr(module, "_gh", fake_gh)
    monkeypatch.setattr(module, "_gh_json", fake_gh_json)

    report = module.run_fe6_pr(
        source_fe5_receipt=fe5,
        frontend_root=repo,
        output_root=tmp_path / "out",
        github_repo="example/frontend",
        base_branch="main",
        title="test adapter",
        body_file=Path("draft_pr_body.md"),
        operator_id="operator",
        operator_authorization="test",
    )

    assert report["passed"] is True
    body_arg = captured["args"][captured["args"].index("--body-file") + 1]
    assert body_arg == str(body.resolve())


def test_local_review_blocks_production_boundary_expansion() -> None:
    diff = '+ const deploy_allowed = "deploy_allowed\\": true";\n'
    review = module._local_review(diff)
    assert review["verdict"] == "changes_requested"
    assert review["findings"]


def test_local_review_accepts_task_pool_api_adapter_slice() -> None:
    diff = "\n".join([
        "diff --git a/src/services/apiClient.ts b/src/services/apiClient.ts",
        "+import { createTaskPoolApi } from './taskPoolApi';",
        "+export interface ApiResponse<T> { data?: T }",
        "+export interface PoolTaskPostRequest { task_type: string }",
        "+const apiClient = createTaskPoolApi();",
    ])

    review = module._local_review(diff)

    assert review["verdict"] == "approved"
    assert review["matched_profile"] == "task_pool_api_adapter"


def test_local_review_accepts_task_pool_presentation_slice() -> None:
    diff = "\n".join([
        "diff --git a/src/components/TaskPoolPanel.tsx b/src/components/TaskPoolPanel.tsx",
        "+import { operatorFollowUp, wakeTraceDetail } from './taskPoolPresentation';",
        "diff --git a/src/components/taskPoolPresentation.ts b/src/components/taskPoolPresentation.ts",
        "+export const operatorFollowUp = () => null;",
        "+export const wakeTraceDetail = () => 'not observed';",
        "+const TaskPoolPanel = 'boundary context';",
    ])

    review = module._local_review(diff)

    assert review["verdict"] == "approved"
    assert review["matched_profile"] == "task_pool_presentation"


def test_additional_agent_review_command_spec_records_approved(tmp_path: Path) -> None:
    reviewer = tmp_path / "reviewer.py"
    reviewer.write_text(
        "import json\n"
        "print(json.dumps({'verdict':'approved','risk_level':'low','findings':[],'summary':'ok'}))\n",
        encoding="utf-8",
    )

    reviews = module._additional_agent_reviews(
        specs=[f"claude-cli-agent=command:{sys.executable} {reviewer}"],
        pr={"number": 1, "url": "https://example.test/pr/1"},
        diff="+ taskPoolPresentation\n",
        output_root=tmp_path,
        failures=[],
    )

    assert len(reviews) == 1
    assert reviews[0]["reviewer_id"] == "claude-cli-agent"
    assert reviews[0]["verdict"] == "approved"
    assert (tmp_path / "beta_fe7_claude-cli-agent_agent_review.json").is_file()


def test_additional_agent_review_ollama_native_spec_records_approved(tmp_path: Path, monkeypatch) -> None:
    class FakeResult:
        payload = {
            "verdict": "approved",
            "risk_level": "low",
            "allowed_files_only": True,
            "production_boundary_preserved": True,
            "reviewed_files": [
                "src/App.tsx",
                "src/app/AppShell.tsx",
                "src/app/panelRegistry.test.ts",
                "src/app/panelRegistry.ts",
            ],
            "findings": [],
            "summary": "bounded release",
        }
        report = {"runner_kind": "ollama_native_reviewer", "attempt_count": 1}

    class FakeReviewer:
        def __init__(self, *, model):
            assert model == "qwen3.6:latest"

        def review_release(self, prompt):
            assert "DIFF:" in prompt
            return FakeResult()

    monkeypatch.setattr(module, "OllamaNativeReviewer", FakeReviewer)
    failures = []
    reviews = module._additional_agent_reviews(
        specs=["local-gpu-agent=ollama-native:qwen3.6:latest"],
        pr={"number": 1, "url": "https://example.test/pr/1"},
        diff="+ bounded app shell helper\n",
        output_root=tmp_path,
        failures=failures,
    )

    assert failures == []
    assert reviews[0]["runner_kind"] == "ollama_native_reviewer"
    assert reviews[0]["verdict"] == "approved"
    assert reviews[0]["passed"] is True


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
