from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h3_relation_learning_replication_gate import run_gate as run_replication
from benchmarks.h3_relation_learning_semantic_qualification_gate import run_gate
from civitasos_runtime.models import RelationExpectationVector
from civitasos_runtime.relation_learning import (
    RelationEvidence,
    calculate_relation_update,
    learning_provenance,
)


def test_semantic_qualification_accepts_bounded_owner_provider_controls(
    tmp_path: Path,
) -> None:
    evidence = [
        _write_source(tmp_path, owner_id="owner-a", suffix="a"),
        _write_source(tmp_path, owner_id="owner-b", suffix="b"),
    ]
    replication_path = tmp_path / "replication.json"
    replication = run_replication(
        evidence_reports=evidence,
        output=replication_path,
    )
    assert replication["passed"] is True
    a9_path = _write_prior_a9(tmp_path)

    report = run_gate(
        evidence_reports=evidence,
        replication_report_path=replication_path,
        prior_a9_reconciliation_path=a9_path,
        output=tmp_path / "qualification.json",
    )

    assert report["passed"] is True
    assert report["valid_for_qualification"] is True
    assert report["metrics"]["real_owner_neutral_pair_count"] == 3
    assert report["metrics"]["authorization_change_count"] == 6
    assert report["readiness"]["i1_entry_inputs_ready"] is True
    assert report["readiness"]["i1_execution_allowed"] is False


def test_semantic_qualification_rejects_unbound_source(tmp_path: Path) -> None:
    evidence = [
        _write_source(tmp_path, owner_id="owner-a", suffix="a"),
        _write_source(tmp_path, owner_id="owner-b", suffix="b"),
    ]
    replication_path = tmp_path / "replication.json"
    run_replication(evidence_reports=evidence, output=replication_path)
    source = json.loads(evidence[1].read_text(encoding="utf-8"))
    source["worker_summaries"]["gamma"]["task_id"] = "tampered-task"
    evidence[1].write_text(json.dumps(source), encoding="utf-8")

    report = run_gate(
        evidence_reports=evidence,
        replication_report_path=replication_path,
        prior_a9_reconciliation_path=_write_prior_a9(tmp_path),
        output=tmp_path / "qualification.json",
    )

    assert report["passed"] is False
    assert report["checks"]["source_reports_hash_bound_to_replication"] is False


def _write_source(tmp_path: Path, *, owner_id: str, suffix: str) -> Path:
    scenarios = {
        "alpha": (
            "settlement_confirmed",
            "accountable_delivery_summary",
            "local-gpu-agent",
            "low",
            {
                "decision": "standard_claim_allowed",
                "direct_match_allowed": True,
                "required_stake_multiplier": 1.188,
                "verification_level": "baseline",
            },
        ),
        "beta": (
            "post_delivery_dispute",
            "evidence_quality_review",
            "deepseek-api-agent",
            "medium",
            {
                "decision": "elevated_verification_required",
                "direct_match_allowed": True,
                "required_stake_multiplier": 1.498,
                "verification_level": "elevated",
            },
        ),
        "gamma": (
            "post_delivery_failure",
            "authorization_boundary_audit",
            "claude-cli-agent",
            "high",
            {
                "decision": "elevated_verification_required",
                "direct_match_allowed": True,
                "required_stake_multiplier": 1.791,
                "verification_level": "elevated",
            },
        ),
    }
    before_authorization = {
        "decision": "standard_claim_allowed",
        "direct_match_allowed": True,
        "required_stake_multiplier": 1.24,
        "verification_level": "baseline",
    }
    workers = {}
    checks = {
        "all_backend_outcomes_exported": True,
        "all_phase1_processes_passed": True,
        "all_phase2_processes_passed": True,
        "all_post_shutdown_outcomes_created": True,
    }
    for worker, (
        outcome,
        task_kind,
        provider,
        risk_class,
        authorization_after,
    ) in scenarios.items():
        before = RelationExpectationVector()
        learning = calculate_relation_update(
            before,
            [
                RelationEvidence(
                    ref=f"source:{suffix}:{worker}",
                    outcome_kind=outcome,
                    task_kind=task_kind,
                    required_capability="general",
                    provider=provider,
                    owner_id=owner_id,
                    risk_class=risk_class,
                )
            ],
        )
        provenance = learning_provenance(learning)
        workers[worker] = {
            "agent_id": f"agent:{suffix}:{worker}",
            "task_id": f"task:{suffix}:{worker}",
            "event_kind": outcome,
            "authorization_change": {
                "before": before_authorization,
                "after": authorization_after,
                "changed": True,
            },
            "iem_update": {"relation_entry_persisted": True},
            "relation_update": {
                "relation_key": f"relation:{suffix}:{worker}",
                "before": before.__dict__,
                "after": learning.after.__dict__,
                "action_bias": {
                    "direct_match_allowed": authorization_after[
                        "direct_match_allowed"
                    ],
                    "required_stake_multiplier": authorization_after[
                        "required_stake_multiplier"
                    ],
                    "verification_level": authorization_after[
                        "verification_level"
                    ],
                },
                "expectation_updates": [
                    {
                        "parameter_name": "expected_trust",
                        "local_update_blocked": False,
                        "update_params": {"delta_provenance": provenance},
                    },
                    {
                        "parameter_name": "normative_relation",
                        "local_update_blocked": True,
                    },
                ],
            },
        }
        for suffix_name in (
            "runtime_identity_continuous",
            "memory_recalled",
            "relation_persisted_in_iem",
            "event_after_shutdown",
            "normative_local_update_blocked",
            "authorization_profile_changed",
            "authorization_matches_action_bias",
        ):
            checks[f"{worker}_{suffix_name}"] = True
    path = tmp_path / f"source-{suffix}.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h2-multi-agent-backend-continuity-gate:v1",
                "passed": True,
                "owner_id": owner_id,
                "checks": checks,
                "worker_summaries": workers,
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_prior_a9(tmp_path: Path) -> Path:
    path = tmp_path / "a9.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": (
                    "h3-controlled-pilot-operator-reconciliation:v1"
                ),
                "passed": True,
                "valid_for_qualification": False,
                "readiness": {"automatic_state_change_allowed": False},
                "boundary": {
                    "authorization_mutation_allowed": False,
                    "controlled_pilot_execution_allowed": False,
                    "iem_mutation_allowed": False,
                    "normative_mutation_allowed": False,
                    "relation_mutation_allowed": False,
                    "trust_mutation_allowed": False,
                },
            }
        ),
        encoding="utf-8",
    )
    return path
