from __future__ import annotations

import importlib.util
import json
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


module = _load("beta_fe12_four_agent_frontend_mediation", SCRIPTS / "beta_fe12_four_agent_frontend_mediation.py")


def test_fe12_write_packet_contains_four_participants_and_refs(tmp_path: Path) -> None:
    frontend = _frontend(tmp_path / "frontend")

    packet = module.write_packet(frontend_root=frontend, output_root=tmp_path / "run")

    assert packet["schema_version"] == module.PACKET_SCHEMA
    assert packet["patch_slice_id"] == module.PATCH_SLICE_ID
    assert [item["participant_id"] for item in packet["participants"]] == [
        "deepseek-api-agent",
        "claude-cli-agent",
        "hermes-cli-agent",
        "local-gpu-agent",
    ]
    for participant_id in [item["participant_id"] for item in packet["participants"]]:
        assert Path(packet["agent_prompt_refs"][participant_id]["path"]).is_file()
    assert packet["collaboration_boundary"]["apply_allowed"] is False


def test_fe12_reconciliation_requires_all_four_and_clear_verdicts(tmp_path: Path) -> None:
    run = tmp_path / "run"
    mediation = run / "mediation"
    mediation.mkdir(parents=True)
    participants = ["deepseek-api-agent", "claude-cli-agent", "hermes-cli-agent", "local-gpu-agent"]
    for participant_id in participants:
        response = mediation / f"{participant_id}.generation.md"
        response.write_text("Patch proposal verdict: proceed\n", encoding="utf-8")
        report = mediation / f"{participant_id}.generation_report.json"
        report.write_text("{}\n", encoding="utf-8")
        receipt = {
            "participant_id": participant_id,
            "task_id": f"task-{participant_id}",
            "runner_kind": "fake",
            "final_task": {"status": "Delivered"},
            "claim_observed": True,
            "generation_observed_after_claim": True,
            "delivery_observed": True,
            "generation_response": module._artifact_ref(response),
            "generation_report": module._artifact_ref(report),
        }
        (mediation / f"{participant_id}.task_receipt.json").write_text(json.dumps(receipt), encoding="utf-8")

    reconciliation = module.write_reconciliation(
        output_root=run,
        mediation_root=mediation,
        mediation={"passed": True, "runner_participant_ids": participants, "failure_reasons": []},
    )

    assert reconciliation["passed"] is True
    assert reconciliation["decision"] == "beta_fe12_reconciliation_ready_for_fe3"
    assert reconciliation["verdict_counts"]["proceed"] == 4


def test_fe12_reconciliation_blocks_missing_participant(tmp_path: Path) -> None:
    run = tmp_path / "run"
    mediation = run / "mediation"
    mediation.mkdir(parents=True)

    reconciliation = module.write_reconciliation(
        output_root=run,
        mediation_root=mediation,
        mediation={"passed": True, "runner_participant_ids": [], "failure_reasons": []},
    )

    assert reconciliation["passed"] is False
    assert any("missing participant receipts" in item for item in reconciliation["failure_reasons"])


def _frontend(path: Path) -> Path:
    (path / "src/components").mkdir(parents=True)
    (path / "src/components/TaskPoolPanel.tsx").write_text("const TaskPoolPanel = () => null;\n", encoding="utf-8")
    (path / "src/services").mkdir(parents=True)
    (path / "src/services/taskPoolApi.ts").write_text("export const taskPoolApi = true;\n", encoding="utf-8")
    (path / "src/adapters").mkdir(parents=True)
    (path / "src/adapters/TaskReadAdapter.ts").write_text("export const TaskReadAdapter = true;\n", encoding="utf-8")
    _git(path, "init")
    _git(path, "add", ".")
    _git(path, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "init")
    return path


def _git(repo: Path, *args: str) -> str:
    import subprocess

    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()
