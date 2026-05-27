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
merge_tests = _load(
    "beta5_github_merge_executor_fixture_for_local_deploy",
    ROOT / "benchmarks" / "tests" / "test_beta5_github_merge_executor.py",
)
merge_module = sys.modules["beta5_github_merge_executor"]
module = _load(
    "beta5_local_controlled_deploy_executor",
    ROOT / "scripts" / "beta5_local_controlled_deploy_executor.py",
)


def test_local_controlled_deploy_runs_deploy_and_smoke_with_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _init_repo(tmp_path / "repo")
    merge_receipt = _write_merge_receipt(tmp_path, repo, monkeypatch)
    authorization_path = tmp_path / "local_deploy_authorization.json"

    report = module.record_deploy_authorization(
        github_merge_receipt_path=merge_receipt,
        target_repo=repo,
        deploy_target="local-staging-probe",
        deploy_command=f"{sys.executable} -c \"print('deploy-probe')\"",
        smoke_command=f"{sys.executable} -c \"print('smoke-probe')\"",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="run local staging probe after Beta-5 merge receipt",
        rollback_evidence_ref="rollback:revert-merge-c60b72f-or-close-local-staging",
        ack_local_controlled_deploy=True,
    )
    execution = module.run_local_controlled_deploy(
        authorization_path=authorization_path,
        output_root=tmp_path / "deploy-run",
    )

    assert report["validation"]["passed"] is True
    assert execution["passed"] is True
    assert execution["receipt_validation"]["passed"] is True
    assert execution["local_deploy_performed"] is True
    assert execution["smoke_performed"] is True
    receipt = json.loads(Path(execution["deploy_receipt_path"]).read_text(encoding="utf-8"))
    assert receipt["external_deploy_allowed"] is False
    assert receipt["production_deploy_allowed"] is False
    assert receipt["production_runtime_execution_allowed"] is False
    assert receipt["target_repo"]["before"] == receipt["target_repo"]["after"]


def test_local_controlled_deploy_authorization_requires_ack_and_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _init_repo(tmp_path / "repo")
    merge_receipt = _write_merge_receipt(tmp_path, repo, monkeypatch)

    with pytest.raises(ValueError, match="rollback_evidence_ref"):
        module.record_deploy_authorization(
            github_merge_receipt_path=merge_receipt,
            target_repo=repo,
            deploy_target="local-staging-probe",
            deploy_command=f"{sys.executable} -c \"print('deploy')\"",
            smoke_command=f"{sys.executable} -c \"print('smoke')\"",
            output_path=tmp_path / "blocked.json",
            operator_id="operator-001",
            reason="missing rollback evidence fixture",
            rollback_evidence_ref="",
            ack_local_controlled_deploy=False,
        )


def test_local_controlled_deploy_blocks_failed_smoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _init_repo(tmp_path / "repo")
    merge_receipt = _write_merge_receipt(tmp_path, repo, monkeypatch)
    authorization_path = tmp_path / "local_deploy_authorization.json"
    module.record_deploy_authorization(
        github_merge_receipt_path=merge_receipt,
        target_repo=repo,
        deploy_target="local-staging-probe",
        deploy_command=f"{sys.executable} -c \"print('deploy')\"",
        smoke_command=f"{sys.executable} -c \"raise SystemExit(7)\"",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="failed smoke fixture",
        rollback_evidence_ref="rollback:failed-smoke-fixture",
        ack_local_controlled_deploy=True,
    )

    execution = module.run_local_controlled_deploy(
        authorization_path=authorization_path,
        output_root=tmp_path / "deploy-run",
    )

    assert execution["passed"] is False
    assert "local_deploy_smoke_failed" in execution["failure_codes"]
    assert execution["deploy_receipt_path"] is None


def test_local_controlled_deploy_receipt_rejects_production_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _init_repo(tmp_path / "repo")
    merge_receipt = _write_merge_receipt(tmp_path, repo, monkeypatch)
    authorization_path = tmp_path / "local_deploy_authorization.json"
    module.record_deploy_authorization(
        github_merge_receipt_path=merge_receipt,
        target_repo=repo,
        deploy_target="local-staging-probe",
        deploy_command=f"{sys.executable} -c \"print('deploy')\"",
        smoke_command=f"{sys.executable} -c \"print('smoke')\"",
        output_path=authorization_path,
        operator_id="operator-001",
        reason="receipt drift fixture",
        rollback_evidence_ref="rollback:receipt-drift-fixture",
        ack_local_controlled_deploy=True,
    )
    execution = module.run_local_controlled_deploy(
        authorization_path=authorization_path,
        output_root=tmp_path / "deploy-run",
    )
    receipt_path = Path(execution["deploy_receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["production_deploy_allowed"] = True
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_deploy_receipt(receipt_path)

    assert validation["passed"] is False
    assert "production_deploy_allowed must be false" in validation["failure_reasons"]


def _write_merge_receipt(tmp_path: Path, repo: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    authorization_path = merge_tests._write_authorization(tmp_path)
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(merge_module, "_gh", merge_tests._fake_gh(authorization))
    report = merge_module.run_github_merge(
        authorization_path=authorization_path,
        output_root=tmp_path / "merge-run",
        merge_method="merge",
        operator_merge_confirmed=True,
    )
    assert report["receipt_validation"]["passed"] is True
    receipt_path = Path(report["receipt_path"])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["post_merge_pr"]["mergeCommit"] = {"oid": _git(repo, "rev-parse", "HEAD")}
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert merge_module.validate_github_merge_receipt(receipt_path)["passed"] is True
    return receipt_path


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _run(["git", "init", "-b", "main"], path)
    _run(["git", "config", "user.email", "test@example.invalid"], path)
    _run(["git", "config", "user.name", "Test User"], path)
    (path / "README.md").write_text("# local staging fixture\n", encoding="utf-8")
    _run(["git", "add", "README.md"], path)
    _run(["git", "commit", "-m", "initial"], path)
    return path


def _git(repo: Path, *args: str) -> str:
    return _run(["git", *args], repo).stdout.strip()


def _run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(argv, cwd=cwd, check=False, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    return completed
