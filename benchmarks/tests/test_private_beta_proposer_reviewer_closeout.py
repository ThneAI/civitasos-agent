from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

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


module = _load("private_beta_proposer_reviewer_closeout", SCRIPTS / "private_beta_proposer_reviewer_closeout.py")


def test_closeout_no_apply_records_operator_reconciliation(tmp_path: Path, monkeypatch: Any) -> None:
    execution = _write_execution_fixture(tmp_path)
    monkeypatch.setattr(module, "_frontend_state", lambda _root: _frontend_state(already_decomposed=True))

    summary = module.run_closeout(
        execution_summary_path=execution,
        frontend_root=tmp_path / "frontend",
        output_root=tmp_path / "closeout",
        operator_id="operator",
        operator_decision="closeout_no_apply",
        operator_statement="Select the architecture reviewer result: the named slice is already complete, so close out without apply.",
        selected_participant="claude-cli-agent",
        allowed_changed_files=[],
        ack_reconciliation=True,
    )

    assert summary["passed"] is True
    assert summary["decision"] == "controlled_proposer_reviewer_closed_without_apply"
    assert summary["operator_decision"] == "closeout_no_apply"
    assert summary["selected_participant"] == "claude-cli-agent"
    assert summary["verdict_counts"] == {"inconclusive": 0, "proceed": 3, "reject": 0, "revise": 1}
    assert summary["readiness"]["bounded_apply_authorization_request_ready"] is False
    assert summary["boundary"]["apply_allowed"] is False

    validation = module.validate_closeout(tmp_path / "closeout" / "private_beta_proposer_reviewer_closeout.json")
    assert validation["passed"] is True


def test_closeout_blocks_bounded_apply_when_revision_constraints_are_missing(tmp_path: Path, monkeypatch: Any) -> None:
    execution = _write_execution_fixture(tmp_path)
    monkeypatch.setattr(module, "_frontend_state", lambda _root: _frontend_state(already_decomposed=False))

    summary = module.run_closeout(
        execution_summary_path=execution,
        frontend_root=tmp_path / "frontend",
        output_root=tmp_path / "closeout",
        operator_id="operator",
        operator_decision="approve_bounded_apply_request",
        operator_statement="Approve bounded apply based only on majority support.",
        selected_participant="deepseek-api-agent",
        allowed_changed_files=["src/App.tsx"],
        ack_reconciliation=True,
    )

    assert summary["passed"] is False
    assert "bounded apply request with revise verdict requires explicit revision constraints in operator_statement" in summary["failure_reasons"]
    assert summary["readiness"]["bounded_apply_authorization_request_ready"] is False


def test_fe14_closeout_allows_conditional_bounded_apply_request(tmp_path: Path, monkeypatch: Any) -> None:
    execution = _write_execution_fixture(
        tmp_path,
        scenario_id="fe14-runtime-data-adapter-decomposition",
        patch_slice_id="runtime_data_adapter_decomposition",
    )
    monkeypatch.setattr(module, "_frontend_state", lambda _root: _frontend_state(already_decomposed=True))

    summary = module.run_closeout(
        execution_summary_path=execution,
        frontend_root=tmp_path / "frontend",
        output_root=tmp_path / "closeout",
        operator_id="operator",
        operator_decision="approve_bounded_apply_request",
        operator_statement=(
            "Approve bounded apply request with revision constraints: preserve existing runtime behavior, "
            "add model/hook tests, and keep the later apply behind separate single-use authorization."
        ),
        selected_participant="deepseek-api-agent",
        allowed_changed_files=[
            "src/App.tsx",
            "src/app/useRuntimeData.ts",
            "src/app/runtimeDataModel.ts",
        ],
        ack_reconciliation=True,
    )

    assert summary["passed"] is True
    assert summary["decision"] == "controlled_proposer_reviewer_ready_for_bounded_apply_request"
    assert summary["scenario_binding"]["patch_slice_id"] == "runtime_data_adapter_decomposition"
    assert summary["readiness"]["bounded_apply_authorization_request_ready"] is True
    assert summary["readiness"]["bounded_apply_authorization_granted"] is False


def test_closeout_requires_ack(tmp_path: Path, monkeypatch: Any) -> None:
    execution = _write_execution_fixture(tmp_path)
    monkeypatch.setattr(module, "_frontend_state", lambda _root: _frontend_state(already_decomposed=True))

    summary = module.run_closeout(
        execution_summary_path=execution,
        frontend_root=tmp_path / "frontend",
        output_root=tmp_path / "closeout",
        operator_id="operator",
        operator_decision="closeout_no_apply",
        operator_statement="Close out without apply.",
        selected_participant="claude-cli-agent",
        allowed_changed_files=[],
        ack_reconciliation=False,
    )

    assert summary["passed"] is False
    assert any("acknowledgement" in reason for reason in summary["failure_reasons"])


def _write_execution_fixture(root: Path, *, scenario_id: str | None = None, patch_slice_id: str | None = None) -> Path:
    mediation_root = root / "mediation"
    mediation_root.mkdir(parents=True)
    receipts = []
    for participant, verdict in (
        ("deepseek-api-agent", "Patch proposal verdict: proceed"),
        ("claude-cli-agent", "Patch proposal verdict: revise"),
        ("hermes-cli-agent", "Patch proposal verdict: proceed"),
        ("local-gpu-agent", "Patch proposal verdict: proceed"),
    ):
        generation = mediation_root / f"{participant}.generation.md"
        generation.write_text(f"{verdict}\n", encoding="utf-8")
        receipt = mediation_root / f"{participant}.task_receipt.json"
        _write_json(
            receipt,
            {
                "schema_version": "beta-fe26-agent-runner-task-receipt:v1",
                "participant_id": participant,
                "runner_kind": "test",
                "task_id": f"task-{participant}",
                "claim_observed": True,
                "generation_observed_after_claim": True,
                "delivery_observed": True,
                "final_task": {"status": "Delivered"},
                "generation_response": _artifact_ref(generation),
            },
        )
        receipts.append(_artifact_ref(receipt))
    mediation = root / "mediation_summary.json"
    _write_json(
        mediation,
        {
            "schema_version": "private-beta-controlled-proposer-reviewer-mediation:v1",
            "passed": True,
            "decision": "controlled_proposer_reviewer_mediation_passed",
            "task_receipt_count": 4,
            "task_receipts": receipts,
            "boundary": _execution_boundary(),
        },
    )
    packet = root / "packet_summary.json"
    _write_json(
        packet,
        {
            "schema_version": "beta-fe2-frontend-patch-proposal-packet:v1",
            "scenario_id": scenario_id,
            "patch_slice_id": patch_slice_id,
            "stage": "test",
            "passed": True,
        },
    )
    execution = root / "execution_summary.json"
    _write_json(
        execution,
        {
            "schema_version": "private-beta-controlled-proposer-reviewer-execution:v1",
            "passed": True,
            "decision": "private_beta_controlled_proposer_reviewer_execution_passed",
            "authorization_id": "private-beta-proposer-reviewer-auth:test",
            "artifacts": {"mediation": _artifact_ref(mediation), "packet": _artifact_ref(packet)},
            "readiness": {"proposer_reviewer_outputs_ready_for_closeout": True},
            "boundary": _execution_boundary(),
        },
    )
    return execution


def _frontend_state(*, already_decomposed: bool) -> dict[str, Any]:
    return {
        "frontend_root": "/tmp/frontend",
        "head_commit": "abc",
        "head_short": "abc",
        "status_short": [],
        "focus_file_lines": {
            "src/App.tsx": 224,
            "src/app/AppShell.tsx": 132 if already_decomposed else 0,
            "src/app/panelRegistry.ts": 291 if already_decomposed else 0,
            "src/app/panelRegistry.test.ts": 49 if already_decomposed else 0,
        },
        "app_shell_present": already_decomposed,
        "panel_registry_present": already_decomposed,
        "panel_registry_test_present": already_decomposed,
        "app_shell_panel_registry_already_decomposed": already_decomposed,
    }


def _execution_boundary() -> dict[str, bool]:
    return {
        "authorization_consumed": True,
        "agent_execution_performed": True,
        "patch_proposal_generated": True,
        "release_review_generated": True,
        "frontend_code_modified": False,
        "apply_allowed": False,
        "commit_allowed": False,
        "push_allowed": False,
        "merge_allowed": False,
        "deploy_allowed": False,
        "external_public_ingress_opened": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
