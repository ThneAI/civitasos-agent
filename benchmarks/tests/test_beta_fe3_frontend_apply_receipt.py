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


module = _load("beta_fe3_frontend_apply_receipt", SCRIPTS / "beta_fe3_frontend_apply_receipt.py")


def test_beta_fe3_apply_receipt_accepts_allowed_frontend_slice(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    _modify_allowed_slice(frontend)
    fe26 = _write_fe26_summary(tmp_path / "fe26.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=fe26,
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
    )

    assert receipt["passed"] is True
    assert receipt["decision"] == "beta_fe3_frontend_apply_receipt_passed"
    assert receipt["boundary"]["frontend_code_modified"] is True
    assert receipt["boundary"]["commit_allowed"] is False
    assert set(receipt["changed_files"]) == module.ALLOWED_CHANGED_FILES
    assert receipt["verification_commands"][0]["exit_code"] == 0


def test_beta_fe3_apply_receipt_counts_untracked_allowed_files(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    untracked = frontend / "src/adapters/TaskReadAdapter.ts"
    _run(["git", "rm", "--quiet", "src/adapters/TaskReadAdapter.ts"], frontend)
    untracked.write_text("// recreated untracked\n", encoding="utf-8")
    for rel in module.ALLOWED_CHANGED_FILES - {"src/adapters/TaskReadAdapter.ts"}:
        target = frontend / rel
        target.write_text(target.read_text(encoding="utf-8") + "// changed\n", encoding="utf-8")
    fe26 = _write_fe26_summary(tmp_path / "fe26.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=fe26,
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
    )

    assert receipt["passed"] is True
    assert "src/adapters/TaskReadAdapter.ts" in receipt["changed_files"]


def test_beta_fe3_apply_receipt_blocks_unexpected_file(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    _modify_allowed_slice(frontend)
    extra = frontend / "src/App.tsx"
    extra.write_text("export default function App() { return null; }\n", encoding="utf-8")
    fe26 = _write_fe26_summary(tmp_path / "fe26.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=fe26,
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
    )

    assert receipt["passed"] is False
    assert any("unexpected changed frontend files" in reason for reason in receipt["failure_reasons"])


def test_beta_fe3_apply_receipt_accepts_custom_slice_allowlist(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    custom = frontend / "src/services/taskPoolApi.ts"
    custom.parent.mkdir(parents=True, exist_ok=True)
    custom.write_text("export const taskPoolApi = true;\n", encoding="utf-8")
    fe26 = _write_fe26_summary(tmp_path / "fe26.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=fe26,
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
        allowed_changed_files=["src/services/taskPoolApi.ts"],
    )

    assert receipt["passed"] is True
    assert receipt["changed_files"] == ["src/services/taskPoolApi.ts"]
    assert receipt["allowed_changed_files"] == ["src/services/taskPoolApi.ts"]


def test_beta_fe3_apply_receipt_blocks_unsafe_custom_allowlist(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    fe26 = _write_fe26_summary(tmp_path / "fe26.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=fe26,
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
        allowed_changed_files=["../outside.ts"],
    )

    assert receipt["passed"] is False
    assert any("repo-relative and safe" in reason for reason in receipt["failure_reasons"])


def _frontend_repo(path: Path) -> Path:
    for rel in module.ALLOWED_CHANGED_FILES | {"src/App.tsx"}:
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("// baseline\n", encoding="utf-8")
    _run(["git", "init"], path)
    _run(["git", "add", "."], path)
    _run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "baseline"], path)
    return path


def _modify_allowed_slice(path: Path) -> None:
    for rel in module.ALLOWED_CHANGED_FILES:
        target = path / rel
        target.write_text(target.read_text(encoding="utf-8") + "// changed\n", encoding="utf-8")


def _write_fe26_summary(path: Path) -> Path:
    payload = {
        "schema_version": "beta-fe26-agent-runner-mediation-summary:v1",
        "passed": True,
        "decision": "beta_fe26_agent_runner_mediation_passed",
        "mediation_level": "civitasos_agent_runner_claim_generate_deliver",
        "generation_after_claim_observed_count": 3,
        "boundary": {"frontend_code_modified": False},
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _run(argv: list[str], cwd: Path) -> None:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
