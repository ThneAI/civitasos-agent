from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.h3_read_only_goal_proposal_gate import (
    build_h3_read_only_goal_proposal_gate,
)


def test_passed_h2_evidence_builds_only_read_only_proposals(tmp_path: Path) -> None:
    h2_path = _write_h2_report(tmp_path / "h2.json")

    report = build_h3_read_only_goal_proposal_gate(
        h2_evidence_report_path=h2_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["proposal_surface"]["proposal_count"] == 6
    assert report["h3_boundary"]["goal_emission_allowed"] is False
    assert report["h3_boundary"]["runtime_execution_allowed"] is False
    for proposal in report["proposal_surface"]["proposals"]:
        assert proposal["state"] == "read_only_review_required"
        assert proposal["review_policy"]["operator_review_required"] is True
        assert not any(proposal["execution_policy"].values())
        assert proposal["evidence_refs"]
        assert proposal["telos_basis"]
        assert proposal["vmv_alignment"]["human_sovereignty_preserved"] is True


def test_failed_h2_evidence_blocks_without_proposals(tmp_path: Path) -> None:
    h2_path = _write_h2_report(tmp_path / "h2.json", passed=False)

    report = build_h3_read_only_goal_proposal_gate(
        h2_evidence_report_path=h2_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["proposal_surface"]["proposal_count"] == 0
    assert report["checks"]["h2_evidence_passed"] is False


def test_h2_boundary_regression_blocks_proposals(tmp_path: Path) -> None:
    h2_path = _write_h2_report(tmp_path / "h2.json")
    payload = json.loads(h2_path.read_text(encoding="utf-8"))
    payload["boundary"]["goal_emission_allowed"] = True
    h2_path.write_text(json.dumps(payload), encoding="utf-8")

    report = build_h3_read_only_goal_proposal_gate(
        h2_evidence_report_path=h2_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["h2_goal_emission_allowed_false"] is False
    assert report["proposal_surface"]["proposals"] == []


def test_unbound_record_evidence_blocks_proposals(tmp_path: Path) -> None:
    h2_path = _write_h2_report(tmp_path / "h2.json")
    payload = json.loads(h2_path.read_text(encoding="utf-8"))
    payload["records"][0]["source_report_sha256"] = "0" * 64
    h2_path.write_text(json.dumps(payload), encoding="utf-8")

    report = build_h3_read_only_goal_proposal_gate(
        h2_evidence_report_path=h2_path,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["records_bound_to_source_hashes"] is False


def test_proposal_capacity_never_silently_truncates_evidence(tmp_path: Path) -> None:
    h2_path = _write_h2_report(tmp_path / "h2.json")

    report = build_h3_read_only_goal_proposal_gate(
        h2_evidence_report_path=h2_path,
        agent_root=tmp_path,
        max_proposals=5,
    )

    assert report["passed"] is False
    assert report["checks"]["proposal_capacity_sufficient"] is False
    assert report["proposal_surface"]["proposals"] == []


def _write_h2_report(path: Path, *, passed: bool = True) -> Path:
    source_hashes = [hashlib.sha256(f"source-{index}".encode()).hexdigest() for index in range(2)]
    records = []
    event_kinds = (
        "settlement_confirmed",
        "post_delivery_dispute",
        "post_delivery_failure",
    )
    for owner_index, owner_id in enumerate(("owner-a", "owner-b")):
        for worker_index, event_kind in enumerate(event_kinds):
            task_id = f"task-{owner_index}-{worker_index}"
            records.append(
                {
                    "record_id": f"record-{owner_index}-{worker_index}",
                    "source_report_sha256": source_hashes[owner_index],
                    "owner_id": owner_id,
                    "worker": f"worker-{worker_index}",
                    "agent_id": f"did:civ:agent-{owner_index}-{worker_index}",
                    "task_id": task_id,
                    "event_kind": event_kind,
                    "iem_changed": True,
                    "relation_changed": True,
                    "authorization_changed": True,
                    "negative_authorization_strengthened": (
                        event_kind != "settlement_confirmed"
                    ),
                    "evidence_integrity_passed": True,
                }
            )
    report = {
        "schema_version": "h2-delayed-consequence-evidence-check:v1",
        "passed": passed,
        "integrity_passed": True,
        "maturity_passed": passed,
        "failure_class": "none" if passed else "evidence_maturity",
        "metrics": {
            "record_count": 6,
            "owner_count": 2,
            "task_count": 6,
            "observation_day_count": 2,
            "observation_span_seconds": 172800.0,
            "iem_change_ratio": 1.0,
            "relation_change_ratio": 1.0,
            "authorization_change_count": 6,
            "negative_authorization_change_count": 4,
            "normative_local_update_blocked_ratio": 1.0,
        },
        "thresholds": {
            "min_owner_count": 2,
            "min_task_count": 6,
            "min_observation_days": 2,
            "min_observation_span_seconds": 86400.0,
            "min_iem_change_ratio": 1.0,
            "min_relation_change_ratio": 1.0,
            "min_authorization_change_count": 2,
            "min_normative_blocked_ratio": 1.0,
        },
        "h3_readiness": {
            "ready": passed,
            "decision": (
                "ready_for_h3_read_only_goal_proposal_gate"
                if passed
                else "blocked_collecting_h2_delayed_consequence_evidence"
            ),
        },
        "boundary": {
            "artifact_only": True,
            "runtime_mutation_allowed": False,
            "goal_emission_allowed": False,
            "goal_execution_allowed": False,
            "normative_local_mutation_allowed": False,
        },
        "source_reports": [
            {"path": f"/evidence/source-{index}.json", "sha256": source_hash}
            for index, source_hash in enumerate(source_hashes)
        ],
        "records": records,
    }
    path.write_text(json.dumps(report), encoding="utf-8")
    return path
