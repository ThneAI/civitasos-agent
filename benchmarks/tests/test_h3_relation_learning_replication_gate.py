from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_relation_learning_replication_gate import run_gate
from civitasos_runtime.models import RelationExpectationVector
from civitasos_runtime.relation_learning import (
    RelationEvidence,
    calculate_relation_update,
    learning_provenance,
)


def test_replication_gate_accepts_two_differentiated_batches(tmp_path: Path) -> None:
    reports = [
        _write_batch(tmp_path, owner_id="owner-a", suffix="a"),
        _write_batch(tmp_path, owner_id="owner-b", suffix="b"),
    ]
    output = tmp_path / "replication.json"

    report = run_gate(evidence_reports=reports, output=output)

    assert report["passed"] is True
    assert report["metrics"]["owner_count"] == 2
    assert report["metrics"]["record_count"] == 6
    assert report["checks"]["owner_negative_control_is_neutral"] is True
    assert report["checks"]["provider_negative_control_is_neutral"] is True
    assert report["readiness"]["replication_evidence_ready_for_h3_review"] is True
    assert report["readiness"]["valid_for_qualification"] is False
    assert output.is_file()


def test_replication_gate_rejects_template_post_states(tmp_path: Path) -> None:
    reports = [
        _write_batch(tmp_path, owner_id="owner-a", suffix="a"),
        _write_batch(tmp_path, owner_id="owner-b", suffix="b"),
    ]
    second = json.loads(reports[1].read_text(encoding="utf-8"))
    template = second["worker_summaries"]["alpha"]["relation_update"]["after"]
    for summary in second["worker_summaries"].values():
        summary["relation_update"]["after"] = template
    reports[1].write_text(json.dumps(second), encoding="utf-8")

    report = run_gate(
        evidence_reports=reports,
        output=tmp_path / "replication.json",
    )

    assert report["passed"] is False
    assert (
        "different_outcomes_produce_different_post_states"
        in report["failure_reasons"]
    )


def _write_batch(tmp_path: Path, *, owner_id: str, suffix: str) -> Path:
    scenarios = {
        "alpha": (
            "settlement_confirmed",
            "accountable_delivery_summary",
            "local-gpu-agent",
            "low",
        ),
        "beta": (
            "post_delivery_dispute",
            "evidence_quality_review",
            "deepseek-api-agent",
            "medium",
        ),
        "gamma": (
            "post_delivery_failure",
            "authorization_boundary_audit",
            "claude-cli-agent",
            "high",
        ),
    }
    workers = {}
    for worker, (outcome, task_kind, provider, risk_class) in scenarios.items():
        before = RelationExpectationVector()
        evidence = RelationEvidence(
            ref=f"source:{suffix}:{worker}",
            outcome_kind=outcome,
            task_kind=task_kind,
            required_capability="general",
            provider=provider,
            owner_id=owner_id,
            risk_class=risk_class,
        )
        learning = calculate_relation_update(before, [evidence])
        provenance = learning_provenance(learning)
        updates = [
            {
                "parameter_name": "expected_trust",
                "local_update_blocked": False,
                "update_params": {"delta_provenance": provenance},
            },
            {
                "parameter_name": "normative_relation",
                "local_update_blocked": True,
            },
        ]
        workers[worker] = {
            "agent_id": f"agent:{suffix}:{worker}",
            "task_id": f"task:{suffix}:{worker}",
            "event_kind": outcome,
            "relation_update": {
                "relation_key": f"relation:{suffix}:{worker}",
                "before": before.__dict__,
                "after": learning.after.__dict__,
                "expectation_updates": updates,
            },
        }
    path = tmp_path / f"batch-{suffix}.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h2-multi-agent-backend-continuity-gate:v1",
                "passed": True,
                "owner_id": owner_id,
                "worker_summaries": workers,
            }
        ),
        encoding="utf-8",
    )
    return path
