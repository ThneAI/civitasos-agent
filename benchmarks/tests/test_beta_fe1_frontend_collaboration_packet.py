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


module = _load("beta_fe1_frontend_collaboration_packet", SCRIPTS / "beta_fe1_frontend_collaboration_packet.py")


def test_beta_fe1_packet_records_and_reconciles_responses(tmp_path: Path) -> None:
    frontend = _write_frontend_fixture(tmp_path / "frontend")
    run_root = tmp_path / "run"

    report = module.create_packet(frontend_root=frontend, output_root=run_root)

    assert report["passed"] is True
    packet = run_root / "beta_fe1_packet_summary.json"
    validation = module.validate_packet_summary(packet)
    assert validation["passed"] is True
    summary = json.loads(packet.read_text(encoding="utf-8"))
    assert summary["collaboration_boundary"]["apply_allowed"] is False
    assert summary["h3_boundary"]["h3_remains_blocked"] is True

    first_response = _write_response(run_root / "agent_responses" / "deepseek-api-agent.md", "Implementation proposal")
    second_response = _write_response(run_root / "agent_responses" / "claude-cli-agent.md", "Architecture review")

    first_record = run_root / "agent_responses" / "deepseek-api-agent.record.json"
    second_record = run_root / "agent_responses" / "claude-cli-agent.record.json"
    first = module.record_response(
        packet_summary_path=packet,
        participant_id="deepseek-api-agent",
        response_file=first_response,
        recommendation="revise",
        observer_actor_id="observer-1",
        output_path=first_record,
    )
    second = module.record_response(
        packet_summary_path=packet,
        participant_id="claude-cli-agent",
        response_file=second_response,
        recommendation="proceed",
        observer_actor_id="observer-1",
        output_path=second_record,
    )

    assert first["passed"] is True
    assert second["passed"] is True

    reconciliation = module.reconcile_responses(
        packet_summary_path=packet,
        response_record_paths=[first_record, second_record],
        output_path=run_root / "beta_fe1_multi_agent_reconciliation.json",
        min_responses=2,
    )

    assert reconciliation["passed"] is True
    assert reconciliation["decision"] == "beta_fe1_operator_decision_ready"
    assert reconciliation["operator_decision_required"] is True
    assert reconciliation["collaboration_boundary"]["deploy_allowed"] is False


def test_beta_fe1_response_validation_blocks_mutation_claim(tmp_path: Path) -> None:
    frontend = _write_frontend_fixture(tmp_path / "frontend")
    run_root = tmp_path / "run"
    module.create_packet(frontend_root=frontend, output_root=run_root)
    packet = run_root / "beta_fe1_packet_summary.json"
    response_file = _write_response(run_root / "agent_responses" / "deepseek-api-agent.md", "Implementation proposal")
    record_path = run_root / "agent_responses" / "deepseek-api-agent.record.json"
    module.record_response(
        packet_summary_path=packet,
        participant_id="deepseek-api-agent",
        response_file=response_file,
        recommendation="proceed",
        observer_actor_id="observer-1",
        output_path=record_path,
    )

    payload = json.loads(record_path.read_text(encoding="utf-8"))
    payload["apply_allowed"] = True
    record_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_response_record(record_path)

    assert validation["passed"] is False
    assert "apply_allowed must be false" in validation["failure_reasons"]


def test_beta_fe1_reconciliation_requires_enough_unique_responses(tmp_path: Path) -> None:
    frontend = _write_frontend_fixture(tmp_path / "frontend")
    run_root = tmp_path / "run"
    module.create_packet(frontend_root=frontend, output_root=run_root)
    packet = run_root / "beta_fe1_packet_summary.json"
    response_file = _write_response(run_root / "agent_responses" / "deepseek-api-agent.md", "Implementation proposal")
    record_path = run_root / "agent_responses" / "deepseek-api-agent.record.json"
    module.record_response(
        packet_summary_path=packet,
        participant_id="deepseek-api-agent",
        response_file=response_file,
        recommendation="proceed",
        observer_actor_id="observer-1",
        output_path=record_path,
    )

    reconciliation = module.reconcile_responses(
        packet_summary_path=packet,
        response_record_paths=[record_path],
        output_path=run_root / "beta_fe1_multi_agent_reconciliation.json",
        min_responses=2,
    )

    assert reconciliation["passed"] is False
    assert "unique response participant count must be >= 2" in reconciliation["failure_reasons"]


def _write_frontend_fixture(root: Path) -> Path:
    (root / "src/components").mkdir(parents=True)
    (root / "src/services").mkdir(parents=True)
    (root / "src/contexts").mkdir(parents=True)
    _write_json(
        root / "package.json",
        {
            "name": "fixture-frontend",
            "version": "0.1.0",
            "scripts": {"build": "react-scripts build", "test": "react-scripts test"},
            "dependencies": {"react": "^18.0.0", "typescript": "^4.9.5"},
            "devDependencies": {"@testing-library/react": "^16.0.0"},
        },
    )
    (root / "src/App.tsx").write_text("export default function App() { return null; }\n", encoding="utf-8")
    (root / "src/components/Panel.tsx").write_text("export const Panel = () => null;\n", encoding="utf-8")
    (root / "src/services/apiClient.ts").write_text("export const apiClient = {};\n", encoding="utf-8")
    (root / "src/contexts/AuthContext.tsx").write_text("export const AuthContext = null;\n", encoding="utf-8")
    return root


def _write_response(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# Response\n\n{content}\n", encoding="utf-8")
    return path


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
