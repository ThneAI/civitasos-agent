from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "l1_export_operator_repair_probe_byproducts.py"
spec = importlib.util.spec_from_file_location("l1_export_operator_repair_probe_byproducts", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def test_export_operator_repair_probe_byproducts_writes_packet_records(tmp_path) -> None:
    probe_root = _write_probe_fixture(tmp_path)
    audit_output = tmp_path / "packet" / "sinks" / "audit-events.jsonl"
    probe_output = tmp_path / "packet" / "monitoring" / "probe-events.jsonl"

    report = module.export_operator_repair_probe_byproducts(
        probe_root=probe_root,
        audit_output_path=audit_output,
        probe_output_path=probe_output,
        audit_actor_id="audit-owner-001",
        observer_actor_id="observer-001",
        audit_ref_prefix="audit:l1-repair-probe",
        probe_ref_prefix="probe:l1-repair-probe",
    )

    audit_rows = [json.loads(line) for line in audit_output.read_text(encoding="utf-8").splitlines()]
    probe_rows = [json.loads(line) for line in probe_output.read_text(encoding="utf-8").splitlines()]
    assert report["audit_record_count"] == 3
    assert report["probe_record_count"] == 1
    assert report["failed_task_id"] == "failed-task-001"
    assert report["repair_task_id"] == "repair-task-001"
    assert [row["audit_ref_kind"] for row in audit_rows] == [
        "l1_operator_repair_probe_contract_rejection",
        "l1_operator_approved_repair_task",
        "l1_operator_repair_task_read_model",
    ]
    assert audit_rows[0]["task_id"] == "failed-task-001"
    assert audit_rows[0]["violation_reasons"] == [
        "missing required section: 与上游不同之处",
        "output makes a positive H3/production authorization claim",
    ]
    assert audit_rows[1]["operator_approval"]["approved"] is True
    assert audit_rows[2]["repair_task_status"] == "Open"
    assert probe_rows == [{
        "type": "monitoring_green",
        "actor_id": "observer-001",
        "status": "green",
        "live_monitoring_ref": "probe:l1-repair-probe:operator-repair-probe-observed",
        "checked_at": probe_rows[0]["checked_at"],
        "source_evidence_ref": str(probe_root / "summary.json"),
        "failed_task_id": "failed-task-001",
        "repair_task_id": "repair-task-001",
        "observed_byproduct": "operator_approved_repair_probe",
        "non_claims": [
            "probe_observation_is_l1_controlled_pilot_only",
            "probe_observation_does_not_claim_h3_production_readiness",
        ],
    }]


def test_export_operator_repair_probe_byproducts_appends(tmp_path) -> None:
    probe_root = _write_probe_fixture(tmp_path)
    audit_output = tmp_path / "packet" / "sinks" / "audit-events.jsonl"
    probe_output = tmp_path / "packet" / "monitoring" / "probe-events.jsonl"
    audit_output.parent.mkdir(parents=True)
    probe_output.parent.mkdir(parents=True)
    audit_output.write_text('{"type":"audit_event_recorded","actor_id":"audit-owner-001"}\n', encoding="utf-8")
    probe_output.write_text('{"type":"monitoring_green","actor_id":"observer-001"}\n', encoding="utf-8")

    module.export_operator_repair_probe_byproducts(
        probe_root=probe_root,
        audit_output_path=audit_output,
        probe_output_path=probe_output,
        audit_actor_id="audit-owner-001",
        observer_actor_id="observer-001",
        audit_ref_prefix="audit:l1-repair-probe",
        probe_ref_prefix="probe:l1-repair-probe",
        append=True,
    )

    assert len(audit_output.read_text(encoding="utf-8").splitlines()) == 4
    assert len(probe_output.read_text(encoding="utf-8").splitlines()) == 2


def test_export_operator_repair_probe_byproducts_fails_closed_on_unapproved_repair(tmp_path) -> None:
    probe_root = _write_probe_fixture(tmp_path)
    repair_read_model = probe_root / "reports" / "repair_task_read_model.json"
    data = json.loads(repair_read_model.read_text(encoding="utf-8"))
    data["task"]["input"]["operator_approval"]["approved"] = False
    repair_read_model.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="operator approval must be true"):
        module.export_operator_repair_probe_byproducts(
            probe_root=probe_root,
            audit_output_path=tmp_path / "audit-events.jsonl",
            probe_output_path=tmp_path / "probe-events.jsonl",
            audit_actor_id="audit-owner-001",
            observer_actor_id="observer-001",
            audit_ref_prefix="audit:l1-repair-probe",
            probe_ref_prefix="probe:l1-repair-probe",
        )


def _write_probe_fixture(tmp_path: Path) -> Path:
    probe_root = tmp_path / "l1_operator_repair_failure_probe"
    reports = probe_root / "reports"
    reports.mkdir(parents=True)
    summary = {
        "schema_version": "l1-operator-approved-repair-probe-summary:v1",
        "contract_rejection_status": 422,
        "contract_rejection_error": "delivery contract violation",
        "failed_task_id": "failed-task-001",
        "repair_task_id": "repair-task-001",
        "repair_task_status": "Open",
        "repair_source_failed_task_id": "failed-task-001",
        "repair_operator_approval": {
            "schema_version": "l1-operator-approved-repair:v1",
            "approved": True,
            "approved_by": "l1-controlled-pilot-operator",
            "source_failed_task_id": "failed-task-001",
        },
    }
    rejection = {
        "status": 422,
        "body": {
            "success": False,
            "error": "delivery contract violation",
            "task_id": "failed-task-001",
            "delivery_contract_verification": {
                "passed": False,
                "contract": {
                    "active": True,
                    "h3_must_remain_blocked": True,
                    "required_sections": ["变更摘要", "与上游不同之处", "H3"],
                },
                "failure_reasons": [
                    "missing required section: 与上游不同之处",
                    "output makes a positive H3/production authorization claim",
                ],
                "repair_suggestions": [
                    "Add a dedicated section named `与上游不同之处` with task-specific content.",
                    "Replace positive H.3/production claims with an explicit blocked/no-authorization boundary.",
                ],
            },
        },
    }
    post_repair = {"posted_task_id": "repair-task-001"}
    repair_read_model = {
        "task": {
            "id": "repair-task-001",
            "status": "Open",
            "input": {
                "source_failed_task_id": "failed-task-001",
                "operator_approval": {
                    "schema_version": "l1-operator-approved-repair:v1",
                    "approved": True,
                    "approved_by": "l1-controlled-pilot-operator",
                    "source_failed_task_id": "failed-task-001",
                },
            },
        },
    }
    (probe_root / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (reports / "contract_rejection_422.json").write_text(json.dumps(rejection), encoding="utf-8")
    (reports / "post_repair.json").write_text(json.dumps(post_repair), encoding="utf-8")
    (reports / "repair_task_read_model.json").write_text(json.dumps(repair_read_model), encoding="utf-8")
    return probe_root
