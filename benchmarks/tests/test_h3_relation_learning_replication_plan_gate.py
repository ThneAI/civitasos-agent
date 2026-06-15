from __future__ import annotations

import hashlib
import json
from pathlib import Path

from benchmarks.h3_bounded_plan_challenge_review_gate import (
    create_challenge_review_packet,
)
from benchmarks.h3_relation_learning_replication_gate import SCHEMA_VERSION
from benchmarks.h3_relation_learning_replication_plan_gate import (
    REQUIRED_REPLICATION_CHECKS,
    build_replication_plan_gate,
)


def test_replication_plan_binds_six_records_and_enters_a4(tmp_path: Path) -> None:
    replication_path = _write_replication_report(tmp_path)
    output = tmp_path / "bounded_plan.json"

    report = build_replication_plan_gate(
        replication_report_path=replication_path,
        output_path=output,
    )

    assert report["passed"] is True
    draft = report["draft_surface"]["drafts"][0]
    assert draft["proposal_kind"] == "validate_relation_learning_replication"
    assert len(draft["source_binding"]["evidence_refs"]) == 6
    assert draft["execution_policy"]["runtime_execution_allowed"] is False
    packet = create_challenge_review_packet(
        bounded_plan_report_path=output,
        output_path=tmp_path / "challenge.json",
        agent_root=tmp_path,
        validation_profile="development",
        development_window_seconds=1,
    )
    assert packet["required_review_count"] == 3


def test_replication_plan_rejects_missing_negative_control(tmp_path: Path) -> None:
    replication_path = _write_replication_report(tmp_path)
    value = json.loads(replication_path.read_text(encoding="utf-8"))
    value["checks"]["duplicate_event_replay_is_blocked"] = False
    replication_path.write_text(json.dumps(value), encoding="utf-8")

    report = build_replication_plan_gate(
        replication_report_path=replication_path,
        output_path=tmp_path / "bounded_plan.json",
    )

    assert report["passed"] is False
    assert report["checks"]["required_replication_checks_passed"] is False


def _write_replication_report(tmp_path: Path) -> Path:
    source_paths = []
    records = []
    outcomes = (
        "settlement_confirmed",
        "post_delivery_dispute",
        "post_delivery_failure",
    )
    for owner_index, owner in enumerate(("owner-a", "owner-b")):
        source = tmp_path / f"{owner}.json"
        source.write_text(json.dumps({"passed": True}), encoding="utf-8")
        source_paths.append(source)
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        for outcome_index, outcome in enumerate(outcomes):
            index = owner_index * 3 + outcome_index
            records.append(
                {
                    "record_id": f"record:{index}",
                    "owner_id": owner,
                    "agent_id": f"did:civ:test:{index}",
                    "task_id": f"task:{index}",
                    "relation_key": f"relation:{index}",
                    "event_kind": outcome,
                    "task_kind": f"task-kind:{outcome_index}",
                    "provider": f"provider:{outcome_index}",
                    "provenance_valid": True,
                    "within_caps": True,
                    "normative_guard_observed": True,
                    "source_report": {
                        "path": str(source),
                        "sha256": source_hash,
                    },
                }
            )
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": True,
        "checks": {name: True for name in REQUIRED_REPLICATION_CHECKS},
        "records": records,
        "negative_controls": {
            "checks": {
                "owner_negative_control_is_neutral": True,
                "provider_negative_control_is_neutral": True,
                "provider_owner_negative_control_is_neutral": True,
                "duplicate_event_replay_is_blocked": True,
                "different_relation_history_changes_delta": True,
                "stress_update_respects_all_caps": True,
            }
        },
        "readiness": {
            "replication_evidence_ready_for_h3_review": True,
            "valid_for_qualification": False,
            "automatic_state_change_allowed": False,
        },
    }
    path = tmp_path / "replication.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path
