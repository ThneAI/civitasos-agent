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


module = _load("beta_fe2_frontend_patch_proposal", SCRIPTS / "beta_fe2_frontend_patch_proposal.py")


def test_beta_fe2_packet_records_and_reconciles_three_agents(tmp_path: Path) -> None:
    frontend = _write_frontend_fixture(tmp_path / "frontend")
    fe1 = _write_fe1_reconciliation(tmp_path / "fe1.json", unique_count=3)
    run_root = tmp_path / "run"

    report = module.create_packet(
        frontend_root=frontend,
        fe1_reconciliation_path=fe1,
        output_root=run_root,
    )

    assert report["passed"] is True
    assert report["patch_slice_id"] == "task_read_adapter_extraction"
    packet = run_root / "beta_fe2_packet_summary.json"
    validation = module.validate_packet_summary(packet)
    assert validation["passed"] is True
    summary = json.loads(packet.read_text(encoding="utf-8"))
    assert summary["collaboration_boundary"]["apply_allowed"] is False
    assert summary["h3_boundary"]["h3_remains_blocked"] is True

    records = []
    for participant_id, recommendation in (
        ("deepseek-api-agent", "proceed"),
        ("claude-cli-agent", "revise"),
        ("local-gpu-agent", "proceed"),
    ):
        response = _write_response(run_root / "agent_responses" / f"{participant_id}.md", participant_id)
        record = run_root / "agent_responses" / f"{participant_id}.record.json"
        result = module.record_response(
            packet_summary_path=packet,
            participant_id=participant_id,
            response_file=response,
            recommendation=recommendation,
            observer_actor_id="observer-1",
            output_path=record,
        )
        assert result["passed"] is True
        records.append(record)

    reconciliation = module.reconcile_responses(
        packet_summary_path=packet,
        response_record_paths=records,
        output_path=run_root / "beta_fe2_patch_proposal_reconciliation.json",
        min_responses=3,
    )

    assert reconciliation["passed"] is True
    assert reconciliation["decision"] == "beta_fe2_operator_decision_ready"
    assert reconciliation["operator_decision_required"] is True
    assert reconciliation["recommended_patch_slice"]["backend_api_contract_change_allowed"] is False


def test_beta_fe2_requires_fe1_three_participant_reconciliation(tmp_path: Path) -> None:
    frontend = _write_frontend_fixture(tmp_path / "frontend")
    fe1 = _write_fe1_reconciliation(tmp_path / "fe1.json", unique_count=2)

    try:
        module.create_packet(
            frontend_root=frontend,
            fe1_reconciliation_path=fe1,
            output_root=tmp_path / "run",
        )
    except ValueError as exc:
        assert "FE-1 unique participant count must be >= 3" in str(exc)
    else:
        raise AssertionError("expected FE-2 packet creation to block on weak FE-1 evidence")


def test_beta_fe2_response_validation_blocks_apply_claim(tmp_path: Path) -> None:
    frontend = _write_frontend_fixture(tmp_path / "frontend")
    fe1 = _write_fe1_reconciliation(tmp_path / "fe1.json", unique_count=3)
    run_root = tmp_path / "run"
    module.create_packet(frontend_root=frontend, fe1_reconciliation_path=fe1, output_root=run_root)
    packet = run_root / "beta_fe2_packet_summary.json"
    response = _write_response(run_root / "agent_responses" / "deepseek-api-agent.md", "proposal")
    record = run_root / "agent_responses" / "deepseek-api-agent.record.json"
    module.record_response(
        packet_summary_path=packet,
        participant_id="deepseek-api-agent",
        response_file=response,
        recommendation="proceed",
        observer_actor_id="observer-1",
        output_path=record,
    )
    payload = json.loads(record.read_text(encoding="utf-8"))
    payload["apply_allowed"] = True
    record.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_response_record(record)

    assert validation["passed"] is False
    assert "apply_allowed must be false" in validation["failure_reasons"]


def _write_frontend_fixture(root: Path) -> Path:
    (root / "src/components").mkdir(parents=True)
    (root / "src/services").mkdir(parents=True)
    _write_json(
        root / "package.json",
        {
            "name": "fixture-frontend",
            "version": "0.1.0",
            "scripts": {"build": "react-scripts build", "test": "react-scripts test"},
            "dependencies": {"react": "^18.0.0", "typescript": "^4.9.5"},
        },
    )
    (root / "src/services/apiClient.ts").write_text(
        "\n".join(f"line {idx}" for idx in range(1, 930)) + "\n",
        encoding="utf-8",
    )
    (root / "src/components/TaskPoolPanel.tsx").write_text(
        "\n".join(f"line {idx}" for idx in range(1, 340)) + "\n",
        encoding="utf-8",
    )
    (root / "src/App.tsx").write_text("export default function App() { return null; }\n", encoding="utf-8")
    return root


def _write_fe1_reconciliation(path: Path, *, unique_count: int) -> Path:
    participants = ["deepseek-api-agent", "claude-cli-agent", "local-gpu-agent"][:unique_count]
    payload = {
        "schema_version": "beta-fe1-multi-agent-reconciliation:v1",
        "passed": True,
        "decision": "beta_fe1_operator_decision_ready",
        "unique_participant_count": unique_count,
        "unique_participants": participants,
        "recommendation_counts": {"proceed": 1, "revise": max(0, unique_count - 1)},
        "safe_next_step": "operator_review_before_any_frontend_code_change",
        "collaboration_boundary": {
            "direct_mutation_allowed": False,
            "apply_allowed": False,
            "commit_allowed": False,
            "push_allowed": False,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    _write_json(path, payload)
    return path


def _write_response(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# FE-2 Response\n\n{content}\n", encoding="utf-8")
    return path


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
