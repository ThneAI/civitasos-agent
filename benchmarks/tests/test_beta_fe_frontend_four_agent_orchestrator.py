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


module = _load("beta_fe_frontend_four_agent_orchestrator", SCRIPTS / "beta_fe_frontend_four_agent_orchestrator.py")


def test_orchestrator_fe13_packet_targets_app_shell_decomposition(tmp_path: Path) -> None:
    frontend = _frontend(tmp_path / "frontend")
    scenario = module.SCENARIOS["fe13-app-shell-decomposition"]

    packet = module.write_packet(scenario=scenario, frontend_root=frontend, output_root=tmp_path / "run")

    assert packet["schema_version"] == module.PACKET_SCHEMA
    assert packet["scenario_id"] == "fe13-app-shell-decomposition"
    assert packet["patch_slice_id"] == "app_shell_panel_registry_decomposition"
    assert packet["collaboration_boundary"]["apply_allowed"] is False
    assert "src/App.tsx" in packet["frontend_snapshot"]["focus_file_lines"]
    assert Path(packet["brief_ref"]["path"]).is_file()
    local_prompt = Path(packet["agent_prompt_refs"]["local-gpu-agent"]["path"]).read_text(encoding="utf-8")
    claude_prompt = Path(packet["agent_prompt_refs"]["claude-cli-agent"]["path"]).read_text(encoding="utf-8")
    assert "Candidate allowed files:" in local_prompt
    assert "src/app/panelRegistry.ts" in local_prompt
    assert "## src/contexts/AuthContext.tsx" not in local_prompt
    assert "this local reviewer receives no raw implementation excerpts" in local_prompt
    assert "## src/contexts/AuthContext.tsx" not in claude_prompt
    assert "this architecture reviewer receives no raw implementation excerpts" in claude_prompt


def test_orchestrator_fe14_packet_targets_runtime_data_adapter(tmp_path: Path) -> None:
    frontend = _frontend(tmp_path / "frontend")
    scenario = module.SCENARIOS["fe14-runtime-data-adapter-decomposition"]

    packet = module.write_packet(scenario=scenario, frontend_root=frontend, output_root=tmp_path / "run")

    assert packet["scenario_id"] == "fe14-runtime-data-adapter-decomposition"
    assert packet["patch_slice_id"] == "runtime_data_adapter_decomposition"
    assert packet["collaboration_boundary"]["apply_allowed"] is False
    prompt = Path(packet["agent_prompt_refs"]["deepseek-api-agent"]["path"]).read_text(encoding="utf-8")
    assert "runtime data fetching" in prompt
    assert "src/app/useRuntimeData.ts" in prompt
    assert "src/services/websocket.ts" in prompt
    assert "backend API contract" in prompt


def test_orchestrator_fe15_packet_targets_observability_presentation(tmp_path: Path) -> None:
    frontend = _frontend(tmp_path / "frontend")
    scenario = module.SCENARIOS["fe15-observability-presentation-extraction"]

    packet = module.write_packet(scenario=scenario, frontend_root=frontend, output_root=tmp_path / "run")

    assert packet["scenario_id"] == "fe15-observability-presentation-extraction"
    assert packet["patch_slice_id"] == "observability_presentation_extraction"
    assert packet["collaboration_boundary"]["apply_allowed"] is False
    prompt = Path(packet["agent_prompt_refs"]["deepseek-api-agent"]["path"]).read_text(encoding="utf-8")
    assert "ObservabilityPanel metric parsing" in prompt
    assert "src/components/observabilityPresentation.ts" in prompt
    assert "service-token scope policy" in prompt
    local_prompt = Path(packet["agent_prompt_refs"]["local-gpu-agent"]["path"]).read_text(encoding="utf-8")
    assert "## src/services/apiClient.ts" not in local_prompt


def test_orchestrator_reconciliation_records_selected_plan(tmp_path: Path) -> None:
    run = tmp_path / "run"
    mediation = run / "mediation"
    mediation.mkdir(parents=True)
    participants = ["deepseek-api-agent", "claude-cli-agent", "hermes-cli-agent", "local-gpu-agent"]
    for participant_id in participants:
        response = mediation / f"{participant_id}.generation.md"
        response.write_text("Patch proposal verdict: proceed\n", encoding="utf-8")
        receipt = {
            "participant_id": participant_id,
            "task_id": f"task-{participant_id}",
            "runner_kind": "fake",
            "final_task": {"status": "Delivered"},
            "claim_observed": True,
            "generation_observed_after_claim": True,
            "delivery_observed": True,
            "generation_response": module._artifact_ref(response),
        }
        (mediation / f"{participant_id}.task_receipt.json").write_text(json.dumps(receipt), encoding="utf-8")

    scenario = module.SCENARIOS["fe13-app-shell-decomposition"]
    reconciliation = module.write_reconciliation(
        scenario=scenario,
        output_root=run,
        mediation_root=mediation,
        mediation={"passed": True, "runner_participant_ids": participants, "failure_reasons": []},
    )

    assert reconciliation["passed"] is True
    assert reconciliation["selected_plan"]["slice_id"] == "app_shell_panel_registry_decomposition"
    assert reconciliation["safe_next_step"] == "operator_review_before_bounded_fe3_apply_for_app_shell_panel_registry_decomposition"


def test_orchestrator_extracts_camel_case_patch_proposal_verdict() -> None:
    assert module._extract_verdict('{"patchProposalVerdict": "proceed"}') == "proceed"


def _frontend(path: Path) -> Path:
    (path / "src/components").mkdir(parents=True)
    (path / "src/components/TaskPoolPanel.tsx").write_text("export const TaskPoolPanel = () => null;\n", encoding="utf-8")
    (path / "src/components/ObservabilityPanel.tsx").write_text("export const ObservabilityPanel = () => null;\n", encoding="utf-8")
    (path / "src/services").mkdir(parents=True)
    (path / "src/services/taskPoolApi.ts").write_text("export const taskPoolApi = true;\n", encoding="utf-8")
    (path / "src/adapters").mkdir(parents=True)
    (path / "src/adapters/TaskReadAdapter.ts").write_text("export const TaskReadAdapter = true;\n", encoding="utf-8")
    (path / "src/adapters/taskReadModel.ts").write_text("export const taskReadModel = true;\n", encoding="utf-8")
    (path / "src/app").mkdir(parents=True)
    (path / "src/app/AppShell.tsx").write_text("export const AppShell = () => null;\n", encoding="utf-8")
    (path / "src/app/panelRegistry.ts").write_text("export const PANEL_REGISTRY = [];\n", encoding="utf-8")
    (path / "src/services/apiClient.ts").write_text("export const apiClient = true;\n", encoding="utf-8")
    (path / "src/services/websocket.ts").write_text("export const wsService = true;\n", encoding="utf-8")
    (path / "src/contexts").mkdir(parents=True)
    (path / "src/contexts/AuthContext.tsx").write_text("export const AuthContext = null;\n", encoding="utf-8")
    (path / "src/contexts/I18nContext.tsx").write_text("export const I18nContext = null;\n", encoding="utf-8")
    (path / "src/contexts/ThemeContext.tsx").write_text("export const ThemeContext = null;\n", encoding="utf-8")
    (path / "src/App.tsx").write_text("export const App = () => null;\n", encoding="utf-8")
    _git(path, "init")
    _git(path, "add", ".")
    _git(path, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "init")
    return path


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()
