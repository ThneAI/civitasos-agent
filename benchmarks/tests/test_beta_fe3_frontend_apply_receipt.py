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
auth_module = _load("beta_fe3_bounded_apply_authorization", SCRIPTS / "beta_fe3_bounded_apply_authorization.py")


def test_beta_fe3_apply_receipt_accepts_allowed_frontend_slice(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    _modify_allowed_slice(frontend)
    fe26 = _write_fe26_summary(tmp_path / "fe26.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=fe26,
        single_use_authorization=_write_authorization(tmp_path, fe26, sorted(module.ALLOWED_CHANGED_FILES)),
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
        single_use_authorization=_write_authorization(tmp_path, fe26, sorted(module.ALLOWED_CHANGED_FILES)),
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
        single_use_authorization=_write_authorization(tmp_path, fe26, sorted(module.ALLOWED_CHANGED_FILES)),
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
        single_use_authorization=_write_authorization(tmp_path, fe26, ["src/services/taskPoolApi.ts"]),
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
        allowed_changed_files=["src/services/taskPoolApi.ts"],
    )

    assert receipt["passed"] is True
    assert receipt["changed_files"] == ["src/services/taskPoolApi.ts"]
    assert receipt["allowed_changed_files"] == ["src/services/taskPoolApi.ts"]


def test_beta_fe3_apply_receipt_accepts_fe12_mediation_summary(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    custom = frontend / "src/components/taskPoolPresentation.ts"
    custom.parent.mkdir(parents=True, exist_ok=True)
    custom.write_text("export const statusColor = () => '#fff';\n", encoding="utf-8")
    fe12 = _write_fe12_summary(tmp_path / "fe12.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=fe12,
        single_use_authorization=_write_authorization(tmp_path, fe12, ["src/components/taskPoolPresentation.ts"]),
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
        allowed_changed_files=["src/components/taskPoolPresentation.ts"],
    )

    assert receipt["passed"] is True
    assert receipt["source_mediation_schema"] == "beta-fe12-four-agent-frontend-mediation-summary:v1"


def test_beta_fe3_apply_receipt_accepts_four_agent_orchestration_summary(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    custom = frontend / "src/app/AppShell.tsx"
    custom.parent.mkdir(parents=True, exist_ok=True)
    custom.write_text("export function AppShell() { return null; }\n", encoding="utf-8")
    summary = _write_four_agent_orchestration_summary(tmp_path / "fe13.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=summary,
        single_use_authorization=_write_authorization(tmp_path, summary, ["src/app/AppShell.tsx"]),
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
        allowed_changed_files=["src/app/AppShell.tsx"],
    )

    assert receipt["passed"] is True
    assert receipt["source_mediation_schema"] == "beta-fe-four-agent-frontend-orchestration-summary:v1"


def test_beta_fe3_apply_receipt_accepts_private_beta_closeout_summary(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    custom = frontend / "src/app/useRuntimeData.ts"
    custom.parent.mkdir(parents=True, exist_ok=True)
    custom.write_text("export function useRuntimeData() { return {}; }\n", encoding="utf-8")
    summary = _write_private_beta_closeout_summary(tmp_path / "closeout_summary.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=summary,
        single_use_authorization=_write_authorization(tmp_path, summary, ["src/app/useRuntimeData.ts"]),
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
        allowed_changed_files=["src/app/useRuntimeData.ts"],
    )

    assert receipt["passed"] is True
    assert receipt["source_mediation_schema"] == "private-beta-controlled-proposer-reviewer-closeout-summary:v1"


def test_beta_fe3_apply_receipt_blocks_unsafe_custom_allowlist(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    fe26 = _write_fe26_summary(tmp_path / "fe26.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=fe26,
        single_use_authorization=_write_authorization(tmp_path, fe26, sorted(module.ALLOWED_CHANGED_FILES)),
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
        allowed_changed_files=["../outside.ts"],
    )

    assert receipt["passed"] is False
    assert any("repo-relative and safe" in reason for reason in receipt["failure_reasons"])


def test_beta_fe3_apply_receipt_requires_matching_single_use_authorization(tmp_path: Path) -> None:
    frontend = _frontend_repo(tmp_path / "frontend")
    _modify_allowed_slice(frontend)
    fe26 = _write_fe26_summary(tmp_path / "fe26.json")
    other_fe26 = _write_fe26_summary(tmp_path / "other_fe26.json")

    receipt = module.write_receipt(
        frontend_root=frontend,
        source_fe26_summary=fe26,
        single_use_authorization=_write_authorization(tmp_path, other_fe26, sorted(module.ALLOWED_CHANGED_FILES)),
        output_root=tmp_path / "receipt",
        operator_id="operator",
        operator_authorization="test authorization",
        test_commands=["true"],
    )

    assert receipt["passed"] is False
    assert any("hash-bind the source mediation summary" in reason for reason in receipt["failure_reasons"])


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


def _write_fe12_summary(path: Path) -> Path:
    payload = {
        "schema_version": "beta-fe12-four-agent-frontend-mediation-summary:v1",
        "passed": True,
        "decision": "beta_fe12_four_agent_frontend_mediation_passed",
        "patch_slice_id": "task_pool_presentation_extraction",
        "task_receipt_count": 4,
        "claim_observed_count": 4,
        "generation_after_claim_observed_count": 4,
        "delivery_observed_count": 4,
        "safe_next_step": "prepare_bounded_fe3_apply_for_task_pool_presentation_extraction",
        "selected_plan": {"slice_id": "task_pool_presentation_extraction"},
        "boundary": {"frontend_code_modified": False},
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_four_agent_orchestration_summary(path: Path) -> Path:
    payload = {
        "schema_version": "beta-fe-four-agent-frontend-orchestration-summary:v1",
        "passed": True,
        "decision": "beta_fe_four_agent_orchestration_passed",
        "patch_slice_id": "app_shell_panel_registry_decomposition",
        "task_receipt_count": 4,
        "claim_observed_count": 4,
        "generation_after_claim_observed_count": 4,
        "delivery_observed_count": 4,
        "safe_next_step": "prepare_bounded_fe3_apply_for_app_shell_panel_registry_decomposition",
        "selected_plan": {"slice_id": "app_shell_panel_registry_decomposition"},
        "boundary": {"frontend_code_modified": False},
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_private_beta_closeout_summary(path: Path) -> Path:
    payload = {
        "schema_version": "private-beta-controlled-proposer-reviewer-closeout-summary:v1",
        "passed": True,
        "decision": "controlled_proposer_reviewer_ready_for_bounded_apply_request",
        "readiness": {
            "bounded_apply_authorization_request_ready": True,
            "bounded_apply_authorization_granted": False,
        },
        "scenario_binding": {
            "scenario_id": "fe14-runtime-data-adapter-decomposition",
            "patch_slice_id": "runtime_data_adapter_decomposition",
        },
        "verdict_counts": {"inconclusive": 0, "proceed": 2, "reject": 0, "revise": 1},
        "boundary": {"frontend_code_modified": False},
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_authorization(tmp_path: Path, source_summary: Path, allowed_files: list[str]) -> Path:
    request_root = tmp_path / f"auth_request_{source_summary.stem}_{len(allowed_files)}"
    decision_root = tmp_path / f"auth_decision_{source_summary.stem}_{len(allowed_files)}"
    request = auth_module.write_authorization_request(
        source_mediation_summary=source_summary,
        output_root=request_root,
        operator_id="operator",
        operator_statement="request bounded apply",
        allowed_changed_files=allowed_files,
        ack_authorization_request=True,
    )
    assert request["passed"] is True
    decision = auth_module.write_authorization_decision(
        authorization_request=request_root / "beta_fe3_bounded_apply_authorization_request.json",
        output_root=decision_root,
        operator_id="operator",
        operator_decision="authorize_once",
        operator_statement="authorize bounded apply once",
        ack_authorization_decision=True,
    )
    assert decision["passed"] is True
    return decision_root / "beta_fe3_bounded_apply_authorization.json"


def _run(argv: list[str], cwd: Path) -> None:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
