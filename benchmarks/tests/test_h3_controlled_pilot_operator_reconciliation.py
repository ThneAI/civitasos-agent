from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.h3_controlled_pilot_operator_reconciliation import (
    BOUNDARY,
    create_operator_review_packet,
    reconcile_operator_review,
)
from benchmarks.h3_controlled_pilot_post_run_review import SCHEMA_VERSION


NOW = datetime.now(timezone.utc)


def test_a9_operator_reconciliation_retains_only_replication_hypotheses(
    tmp_path: Path,
) -> None:
    source = _write_source(tmp_path)
    packet_path = tmp_path / "operator_packet.json"
    create_operator_review_packet(
        post_run_review_path=source,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    _complete_packet(packet_path)

    report = reconcile_operator_review(
        post_run_review_path=source,
        operator_packet_path=packet_path,
        output_path=tmp_path / "a9.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["review_summary"]["retained_for_replication_count"] == 1
    assert report["review_summary"]["need_more_evidence_count"] == 1
    assert report["readiness"]["replication_plan_review_input_ready"] is True
    assert report["readiness"]["qualification_input_ready"] is False
    assert report["readiness"]["automatic_state_change_allowed"] is False
    assert report["boundary"]["controlled_pilot_execution_allowed"] is False
    assert report["boundary"]["trust_mutation_allowed"] is False


def test_a9_rejects_tampered_source_receipt(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    packet_path = tmp_path / "operator_packet.json"
    create_operator_review_packet(
        post_run_review_path=source,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    _complete_packet(packet_path)
    receipt = tmp_path / "receipt.json"
    receipt.write_text('{"tampered":true}\n', encoding="utf-8")

    report = reconcile_operator_review(
        post_run_review_path=source,
        operator_packet_path=packet_path,
        output_path=tmp_path / "a9.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["source_post_run_receipt_hash_valid"] is False
    assert report["readiness"]["replication_plan_review_input_ready"] is False


def test_a9_requires_limitations_acknowledgement(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    packet_path = tmp_path / "operator_packet.json"
    create_operator_review_packet(
        post_run_review_path=source,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    _complete_packet(packet_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["evidence_limitations"]["counterexamples_acknowledged"] = False
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = reconcile_operator_review(
        post_run_review_path=source,
        operator_packet_path=packet_path,
        output_path=tmp_path / "a9.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["counterexamples_acknowledged"] is False


def test_a9_packet_cannot_enable_state_mutation(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    packet_path = tmp_path / "operator_packet.json"
    create_operator_review_packet(
        post_run_review_path=source,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    _complete_packet(packet_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["boundary"]["trust_mutation_allowed"] = True
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = reconcile_operator_review(
        post_run_review_path=source,
        operator_packet_path=packet_path,
        output_path=tmp_path / "a9.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["operator_packet_boundary"] is False
    assert report["boundary"] == BOUNDARY


def test_a9_qualification_reconciliation_remains_non_qualifying(
    tmp_path: Path,
) -> None:
    source = _write_source(tmp_path, profile="qualification")
    packet_path = tmp_path / "operator_packet.json"
    packet = create_operator_review_packet(
        post_run_review_path=source,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    assert packet["validation_profile"] == "qualification"
    assert packet["development_only"] is False
    assert packet["boundary"]["qualification_controlled_only"] is True
    _complete_packet(packet_path, operator_role="qualification_operator")

    report = reconcile_operator_review(
        post_run_review_path=source,
        operator_packet_path=packet_path,
        output_path=tmp_path / "a9.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["validation_profile"] == "qualification"
    assert report["development_only"] is False
    assert report["valid_for_qualification"] is False
    assert report["readiness"]["replication_plan_review_input_ready"] is True
    assert report["readiness"]["qualification_input_ready"] is False
    assert report["boundary"]["qualification_evidence_allowed"] is False


def test_a9_rejects_qualification_packet_marked_development(
    tmp_path: Path,
) -> None:
    source = _write_source(tmp_path, profile="qualification")
    packet_path = tmp_path / "operator_packet.json"
    create_operator_review_packet(
        post_run_review_path=source,
        output_path=packet_path,
        agent_root=tmp_path,
    )
    _complete_packet(packet_path, operator_role="qualification_operator")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["development_only"] = True
    packet_path.write_text(json.dumps(packet), encoding="utf-8")

    report = reconcile_operator_review(
        post_run_review_path=source,
        operator_packet_path=packet_path,
        output_path=tmp_path / "a9.json",
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["operator_packet_development_flag"] is False


def _write_source(
    tmp_path: Path,
    *,
    profile: str = "development",
) -> Path:
    receipt = tmp_path / "receipt.json"
    task = tmp_path / "task.json"
    generation = tmp_path / "generation.json"
    generation.write_text('{"schema_version":"generation:v1"}\n', encoding="utf-8")
    task.write_text('{"schema_version":"task:v1"}\n', encoding="utf-8")
    receipt.write_text(
        json.dumps(
            {
                "schema_version": "receipt:v1",
                "validation_profile": profile,
                "task": _ref(task),
                "generation_reports": [_ref(generation)],
                "side_effects": {
                    "production_state_mutated": False,
                    "iem_state_mutated": False,
                    "relation_state_mutated": False,
                    "authorization_state_mutated": False,
                    "normative_state_mutated": False,
                },
            }
        ),
        encoding="utf-8",
    )
    source = tmp_path / "post_run_review.json"
    source.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "passed": True,
                "validation_profile": profile,
                "development_only": profile == "development",
                "valid_for_qualification": False,
                "source_post_run_receipt": _ref(receipt),
                "source_task": _ref(task),
                "generation_report_count": 1,
                "readiness": {
                    "controlled_pilot_outputs_valid_for_operator_review": True,
                    "automatic_state_change_allowed": False,
                },
                "reconciliation": {
                    "state": "operator_review_required",
                    "automatic_adoption_allowed": False,
                    "trust_or_authorization_change_allowed": False,
                    "candidate_conditions": [
                        {
                            "condition": "settlement receipts correlate with trust",
                            "support_count": 1,
                        },
                        {
                            "condition": "lower stake proves safer cooperation",
                            "support_count": 1,
                        },
                    ],
                    "counterexamples": ["stake changed at the same time"],
                    "unresolved_assumptions": ["causality remains untested"],
                },
            }
        ),
        encoding="utf-8",
    )
    return source


def _complete_packet(
    path: Path,
    *,
    operator_role: str = "development_operator",
) -> None:
    packet = json.loads(path.read_text(encoding="utf-8"))
    for index, review in enumerate(packet["candidate_reviews"]):
        review["decision"] = (
            "retain_for_replication" if index == 0 else "need_more_evidence"
        )
        review["reason"] = "Keep the observation bounded and test it again."
    packet["evidence_limitations"]["counterexamples_acknowledged"] = True
    packet["evidence_limitations"]["unresolved_assumptions_acknowledged"] = True
    packet["operator_synthesis"] = {
        "decision": "retain_bounded_hypotheses_for_replication",
        "provisional_findings": ["Receipts may support relation continuity."],
        "deferred_questions": ["Separate settlement effects from stake changes."],
        "reason": "The observations are useful but insufficient for causal adoption.",
        "operator_id": "operator:test",
        "operator_role": operator_role,
        "reviewed_at": NOW.isoformat(),
    }
    path.write_text(json.dumps(packet), encoding="utf-8")


def _ref(path: Path) -> dict[str, str]:
    import hashlib

    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
