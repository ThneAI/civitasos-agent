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


module = _load("beta_fe3_bounded_apply_authorization", SCRIPTS / "beta_fe3_bounded_apply_authorization.py")


def test_bounded_apply_authorization_request_and_decision(tmp_path: Path) -> None:
    source = _write_four_agent_summary(tmp_path / "source.json")
    request = module.write_authorization_request(
        source_mediation_summary=source,
        output_root=tmp_path / "request",
        operator_id="operator",
        operator_statement="request bounded apply",
        allowed_changed_files=["src/app/AppShell.tsx"],
        ack_authorization_request=True,
    )

    assert request["passed"] is True
    assert request["readiness"]["single_use_authorization_request_ready"] is True
    assert request["boundary"]["apply_allowed"] is False

    decision = module.write_authorization_decision(
        authorization_request=tmp_path / "request" / "beta_fe3_bounded_apply_authorization_request.json",
        output_root=tmp_path / "decision",
        operator_id="operator",
        operator_decision="authorize_once",
        operator_statement="authorize once",
        ack_authorization_decision=True,
    )

    assert decision["passed"] is True
    assert decision["single_use"] is True
    assert decision["consumed"] is False
    assert decision["boundary"]["apply_allowed"] is True
    assert decision["boundary"]["commit_allowed"] is False

    validation = module.validate_authorization(tmp_path / "decision" / "beta_fe3_bounded_apply_authorization.json")
    assert validation["passed"] is True


def test_bounded_apply_authorization_requires_ack(tmp_path: Path) -> None:
    source = _write_four_agent_summary(tmp_path / "source.json")

    request = module.write_authorization_request(
        source_mediation_summary=source,
        output_root=tmp_path / "request",
        operator_id="operator",
        operator_statement="request bounded apply",
        allowed_changed_files=["src/app/AppShell.tsx"],
        ack_authorization_request=False,
    )

    assert request["passed"] is False
    assert any("acknowledgement" in reason for reason in request["failure_reasons"])


def test_bounded_apply_authorization_accepts_private_beta_closeout_summary(tmp_path: Path) -> None:
    source = _write_private_beta_closeout_summary(tmp_path / "closeout_summary.json")

    request = module.write_authorization_request(
        source_mediation_summary=source,
        output_root=tmp_path / "request",
        operator_id="operator",
        operator_statement="request bounded apply from private Beta closeout",
        allowed_changed_files=["src/app/useRuntimeData.ts"],
        ack_authorization_request=True,
    )

    assert request["passed"] is True
    assert request["source_mediation_summary"]["path"] == str(source.resolve())


def _write_four_agent_summary(path: Path) -> Path:
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
