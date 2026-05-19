from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "l1_export_contract_audit_refs.py"
spec = importlib.util.spec_from_file_location("l1_export_contract_audit_refs", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def test_export_contract_audit_refs_writes_packet_compatible_jsonl(tmp_path) -> None:
    evidence = tmp_path / "contract_runner_evidence.json"
    evidence.write_text(
        json.dumps({
            "repair_suggestion_audit_refs": {
                "records": [{
                    "source": "beta_task_id",
                    "task_id": "task-beta",
                    "failure_reason": "delivery_contract_violation",
                    "repair_suggestions": ["Add missing H3 section"],
                    "audit_ref_kind": "delivery_contract_repair_suggestions",
                }]
            }
        }),
        encoding="utf-8",
    )
    output = tmp_path / "sinks" / "audit-events.jsonl"

    report = module.export_contract_audit_refs(
        evidence_path=evidence,
        output_path=output,
        actor_id="audit-owner",
        audit_ref_prefix="audit-ref",
    )

    assert report["record_count"] == 1
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert rows == [{
        "type": "audit_event_recorded",
        "actor_id": "audit-owner",
        "status": "recorded",
        "audit_event_ref": "audit-ref:001",
        "recorded_at": rows[0]["recorded_at"],
        "source_evidence_ref": str(evidence),
        "task_id": "task-beta",
        "failure_reason": "delivery_contract_violation",
        "repair_suggestions": ["Add missing H3 section"],
        "audit_ref_kind": "delivery_contract_repair_suggestions",
        "source_record": {
            "source": "beta_task_id",
            "task_id": "task-beta",
            "failure_reason": "delivery_contract_violation",
            "repair_suggestions": ["Add missing H3 section"],
            "audit_ref_kind": "delivery_contract_repair_suggestions",
        },
        "non_claims": [
            "audit_record_is_l1_controlled_pilot_only",
            "repair_suggestions_do_not_authorize_auto_retry",
        ],
    }]


def test_export_contract_audit_refs_fails_closed_when_empty(tmp_path) -> None:
    evidence = tmp_path / "contract_runner_evidence.json"
    evidence.write_text('{"repair_suggestion_audit_refs":{"records":[]}}', encoding="utf-8")

    with pytest.raises(ValueError, match="no repair_suggestion_audit_refs records found"):
        module.export_contract_audit_refs(
            evidence_path=evidence,
            output_path=tmp_path / "audit-events.jsonl",
            actor_id="audit-owner",
            audit_ref_prefix="audit-ref",
        )
