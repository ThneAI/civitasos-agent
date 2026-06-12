from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmarks.h3_controlled_pilot_execution_preflight_gate import (
    BOUNDARY as PREFLIGHT_BOUNDARY,
)
from benchmarks.h3_controlled_pilot_post_run_review import (
    review_post_run_receipt,
)
from benchmarks.h3_controlled_pilot_runner import run_controlled_pilot
from benchmarks.h3_controlled_pilot_runner import _parse_json_response


NOW = datetime(2026, 6, 9, 14, 0, tzinfo=timezone.utc)


def test_parse_json_response_accepts_provider_thinking_wrapper() -> None:
    payload = _parse_json_response(
        '<think>auditing evidence</think>\\n{"verdict":"review required"}\\n'
    )
    assert payload == {"verdict": "review required"}


def test_three_agent_controlled_pilot_consumes_once_and_writes_receipt(
    tmp_path: Path,
) -> None:
    preflight, bounded, evidence = _write_inputs(tmp_path)

    report = run_controlled_pilot(
        preflight_path=preflight,
        bounded_plan_report_path=bounded,
        evidence_report_paths=evidence,
        agent_root=tmp_path,
        model="test-model",
        ack_kill_switch_armed=True,
        current_time=NOW,
        agent_call=_fake_agent_call,
    )

    assert report["passed"] is True
    assert report["generation_report_count"] == 3
    assert report["readiness"]["operator_review_required"] is True
    receipt = json.loads(
        Path(report["post_run_receipt"]["path"]).read_text(encoding="utf-8")
    )
    assert receipt["task_count"] == 1
    assert receipt["agent_count"] == 3
    assert receipt["side_effects"]["authorization_consumed"] is True
    assert receipt["side_effects"]["iem_state_mutated"] is False
    assert receipt["boundary"]["result_requires_operator_review"] is True
    consumption_path = Path(receipt["authorization_consumption"]["path"])
    assert receipt["authorization_consumption"]["sha256"] == _sha256(
        consumption_path
    )
    consumption = json.loads(consumption_path.read_text(encoding="utf-8"))
    assert consumption["immutable"] is True
    assert consumption["state"] == "authorization_consumed"
    review = review_post_run_receipt(
        post_run_receipt_path=Path(report["post_run_receipt"]["path"]),
        output_path=tmp_path / "post_run_review.json",
        agent_root=tmp_path,
    )
    assert review["passed"] is True
    assert review["valid_generation_report_count"] == 3
    assert review["readiness"]["automatic_state_change_allowed"] is False

    replay = run_controlled_pilot(
        preflight_path=preflight,
        bounded_plan_report_path=bounded,
        evidence_report_paths=evidence,
        agent_root=tmp_path,
        model="test-model",
        ack_kill_switch_armed=True,
        current_time=NOW,
        agent_call=_fake_agent_call,
    )
    assert replay["passed"] is False
    assert "post_run_receipt_absent" in replay["failure_reasons"]


def test_kill_switch_blocks_before_authorization_consumption(tmp_path: Path) -> None:
    preflight, bounded, evidence = _write_inputs(tmp_path)
    kill_switch = tmp_path / "stop"
    kill_switch.write_text("stop\n", encoding="utf-8")

    report = run_controlled_pilot(
        preflight_path=preflight,
        bounded_plan_report_path=bounded,
        evidence_report_paths=evidence,
        agent_root=tmp_path,
        model="test-model",
        ack_kill_switch_armed=True,
        kill_switch_file=kill_switch,
        current_time=NOW,
        agent_call=_fake_agent_call,
    )

    assert report["passed"] is False
    assert report["checks"]["kill_switch_not_triggered"] is False
    assert not (tmp_path / "post_run.authorization_consumption.json").exists()


def test_missing_evidence_fails_closed_after_single_use_claim(tmp_path: Path) -> None:
    preflight, bounded, evidence = _write_inputs(tmp_path)

    report = run_controlled_pilot(
        preflight_path=preflight,
        bounded_plan_report_path=bounded,
        evidence_report_paths=evidence[:1],
        agent_root=tmp_path,
        model="test-model",
        ack_kill_switch_armed=True,
        current_time=NOW,
        agent_call=_fake_agent_call,
    )

    assert report["passed"] is False
    assert report["generation_report_count"] == 0
    receipt = json.loads(
        Path(report["post_run_receipt"]["path"]).read_text(encoding="utf-8")
    )
    assert receipt["state"] == "controlled_pilot_failed_closed"
    assert receipt["side_effects"]["authorization_consumed"] is True


def test_labeled_evidence_refs_and_structured_attestation_are_accepted(
    tmp_path: Path,
) -> None:
    preflight, bounded, evidence = _write_inputs(tmp_path)

    def structured_call(role: str, prompt: str) -> tuple[dict, dict]:
        payload, raw = _fake_agent_call(role, prompt)
        payload["evidence_refs"] = [
            "record_id: record:1:task-success-a",
            "source_report_sha256: ignored",
        ]
        payload["boundary_attestation"] = {
            "state_unchanged": True,
            "no_auto_modification": True,
        }
        return payload, raw

    report = run_controlled_pilot(
        preflight_path=preflight,
        bounded_plan_report_path=bounded,
        evidence_report_paths=evidence,
        agent_root=tmp_path,
        model="test-model",
        ack_kill_switch_armed=True,
        current_time=NOW,
        agent_call=structured_call,
    )

    assert report["passed"] is True
    assert report["generation_report_count"] == 3


def test_qualification_runner_preserves_operator_review_boundary(
    tmp_path: Path,
) -> None:
    preflight, bounded, evidence = _write_inputs(
        tmp_path,
        profile="qualification",
    )

    report = run_controlled_pilot(
        preflight_path=preflight,
        bounded_plan_report_path=bounded,
        evidence_report_paths=evidence,
        agent_root=tmp_path,
        model="test-model",
        ack_kill_switch_armed=True,
        current_time=NOW,
        agent_call=_fake_agent_call,
    )

    assert report["passed"] is True
    assert report["validation_profile"] == "qualification"
    assert report["development_only"] is False
    assert report["valid_for_qualification"] is False
    receipt = json.loads(
        Path(report["post_run_receipt"]["path"]).read_text(encoding="utf-8")
    )
    assert receipt["validation_profile"] == "qualification"
    assert receipt["boundary"]["qualification_controlled_only"] is True
    assert receipt["boundary"]["result_valid_for_qualification"] is False
    assert receipt["boundary"]["result_requires_operator_review"] is True


def test_qualification_runner_rejects_development_scope(tmp_path: Path) -> None:
    preflight, bounded, evidence = _write_inputs(
        tmp_path,
        profile="qualification",
    )
    value = json.loads(preflight.read_text(encoding="utf-8"))
    value["authorization_receipt"]["authorized_scope"][
        "environment"
    ] = "development_local_controlled_only"
    preflight.write_text(json.dumps(value), encoding="utf-8")

    report = run_controlled_pilot(
        preflight_path=preflight,
        bounded_plan_report_path=bounded,
        evidence_report_paths=evidence,
        agent_root=tmp_path,
        model="test-model",
        ack_kill_switch_armed=True,
        current_time=NOW,
        agent_call=_fake_agent_call,
    )

    assert report["passed"] is False
    assert report["checks"]["authorized_scope_valid"] is False


def test_relation_learning_replication_task_exposes_delta_provenance(
    tmp_path: Path,
) -> None:
    preflight, bounded, evidence = _write_inputs(tmp_path)
    bounded_value = json.loads(bounded.read_text(encoding="utf-8"))
    draft = bounded_value["draft_surface"]["drafts"][0]
    draft["proposal_kind"] = "validate_relation_learning_replication"
    evidence_value = json.loads(evidence[0].read_text(encoding="utf-8"))
    update = evidence_value["worker_summaries"]["alpha"]["relation_update"][
        "expectation_updates"
    ][0]
    update["update_params"] = {
        "delta_provenance": {
            "schema_version": "relation-learning-provenance:v1",
            "source_event_ids": ["event:1"],
            "raw_deltas": {"expected_trust": 0.1},
            "bounded_deltas": {"expected_trust": 0.08},
            "applied_deltas": {"expected_trust": 0.08},
            "per_step_abs_caps": {"expected_trust": 0.08},
            "components": [
                {
                    "outcome_kind": "settlement_confirmed",
                    "effective_weight": 0.8,
                    "base_deltas": {"expected_trust": 0.1},
                }
            ],
        }
    }
    evidence[0].write_text(json.dumps(evidence_value), encoding="utf-8")
    draft["source_binding"]["evidence_refs"][0]["source_report_sha256"] = _sha256(
        evidence[0]
    )
    bounded.write_text(json.dumps(bounded_value), encoding="utf-8")

    report = run_controlled_pilot(
        preflight_path=preflight,
        bounded_plan_report_path=bounded,
        evidence_report_paths=evidence,
        agent_root=tmp_path,
        model="test-model",
        ack_kill_switch_armed=True,
        current_time=NOW,
        agent_call=_fake_agent_call,
    )

    assert report["passed"] is True
    task = json.loads(Path(report["task"]["path"]).read_text(encoding="utf-8"))
    assert task["task_kind"] == "relation_learning_replication_analysis"
    provenance = task["evidence_snapshots"][0]["record"]["relation_update"][
        "learning_provenance"
    ]
    assert provenance["source_event_count"] == 1
    assert provenance["source_event_id_sha256"] == [_sha256_text("event:1")]
    assert "base_deltas" not in provenance["components"][0]


def test_qualification_runner_repairs_invalid_response_contract(
    tmp_path: Path,
) -> None:
    preflight, bounded, evidence = _write_inputs(
        tmp_path,
        profile="qualification",
    )
    attempts: dict[str, int] = {}

    def repairable_call(role: str, prompt: str) -> tuple[dict, dict]:
        attempts[role] = attempts.get(role, 0) + 1
        if attempts[role] == 1:
            payload, raw = _fake_agent_call(role, prompt)
        else:
            payload, raw = _fake_agent_call(role, "evidence_snapshots")
        if attempts[role] == 1:
            payload["boundary_attestation"] = {"state_unchanged": False}
            payload["evidence_refs"].append("record:unknown")
        return payload, raw

    report = run_controlled_pilot(
        preflight_path=preflight,
        bounded_plan_report_path=bounded,
        evidence_report_paths=evidence,
        agent_root=tmp_path,
        model="test-model",
        ack_kill_switch_armed=True,
        current_time=NOW,
        agent_call=repairable_call,
    )

    assert report["passed"] is True
    assert attempts == {role: 2 for role in (
        "relation_evidence_analyst",
        "counterexample_challenger",
        "audit_verifier",
    )}
    receipt = json.loads(
        Path(report["post_run_receipt"]["path"]).read_text(encoding="utf-8")
    )
    for ref in receipt["generation_reports"]:
        generation = json.loads(Path(ref["path"]).read_text(encoding="utf-8"))
        assert generation["passed"] is True
        assert generation["repair_attempted"] is True
        assert generation["generation_attempt_count"] == 2


def _write_inputs(
    tmp_path: Path,
    *,
    profile: str = "development",
) -> tuple[Path, Path, list[Path]]:
    evidence_refs = []
    evidence_paths = []
    for index, task_id in enumerate(("task-success-a", "task-success-b"), start=1):
        evidence_path = tmp_path / f"evidence-{index}.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "worker_summaries": {
                        "alpha": {
                            "agent_id": f"did:civ:test:{index}",
                            "task_id": task_id,
                            "event_kind": "settlement_confirmed",
                            "observed_at": f"2026-06-0{index}T00:00:00+00:00",
                            "authorization_change": {
                                "before": {"verification_level": "baseline"},
                                "after": {"verification_level": "baseline"},
                                "changed": True,
                            },
                            "relation_update": {
                                "before": {"expected_trust": 0.7},
                                "after": {"expected_trust": 0.75},
                                "action_bias": {"verification_level": "baseline"},
                                "expectation_updates": [
                                    {
                                        "parameter_name": "normative_relation",
                                        "local_update_blocked": True,
                                    }
                                ],
                            },
                            "iem_update": {
                                "before_state_hash": "sha256:before",
                                "after_state_hash": "sha256:after",
                                "relation_entry_persisted": True,
                                "relation_key": f"relation:{index}",
                            },
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        digest = _sha256(evidence_path)
        evidence_refs.append(
            {
                "record_id": f"record:{index}:{task_id}",
                "task_id": task_id,
                "source_report_sha256": digest,
            }
        )
        evidence_paths.append(evidence_path)

    bounded = tmp_path / "bounded.json"
    bounded.write_text(
        json.dumps(
            {
                "draft_surface": {
                    "drafts": [
                        {
                            "draft_id": "draft-success",
                            "proposal_kind": (
                                "review_conditions_for_preserving_successful_relations"
                            ),
                            "title": "Successful relation conditions",
                            "objective": "identify observable conditions",
                            "hypotheses": ["receipts support accountability"],
                            "failure_conditions": ["causal ambiguity"],
                            "success_metrics": ["traceable evidence"],
                            "stop_conditions": ["hash mismatch"],
                            "source_binding": {"evidence_refs": evidence_refs},
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    sink = tmp_path / "post_run.json"
    receipt = {
        "authorization_receipt_id": "receipt:test",
        "authorized_scope": {
            "environment": (
                "development_local_controlled_only"
                if profile == "development"
                else "controlled_pilot_only"
            ),
            "max_tasks": 1 if profile == "development" else 3,
            "max_agents": 3,
            "max_duration_seconds": 1800 if profile == "development" else 3600,
            "production_use_allowed": False,
            "automatic_rollout_allowed": False,
        },
        "single_use": True,
        "consumed": False,
        "valid_from": (NOW - timedelta(minutes=1)).isoformat(),
        "valid_until": (NOW + timedelta(minutes=30)).isoformat(),
        "controls": {
            "post_run_receipt_sink_ref": str(sink),
        },
    }
    boundary = dict(PREFLIGHT_BOUNDARY)
    boundary["controlled_runner_input_ready"] = True
    preflight = tmp_path / "preflight.json"
    preflight.write_text(
        json.dumps(
            {
                "schema_version": "h3-controlled-pilot-execution-preflight-gate:v1",
                "passed": True,
                "validation_profile": profile,
                "development_only": profile == "development",
                "valid_for_qualification": profile == "qualification",
                "authorization_receipt": receipt,
                "readiness": {
                    "controlled_runner_input_ready": True,
                    "controlled_pilot_execution_ready": False,
                },
                "boundary": boundary,
            }
        ),
        encoding="utf-8",
    )
    return preflight, bounded, evidence_paths


def _fake_agent_call(role: str, prompt: str) -> tuple[dict, dict]:
    assert "evidence_snapshots" in prompt
    return (
        {
            "verdict": f"{role}: review required",
            "supported_conditions": ["hash-bound receipts and explicit settlement"],
            "counterexamples": ["two observations do not establish causality"],
            "unresolved_assumptions": ["cross-domain generalization remains untested"],
            "evidence_refs": [
                "record:1:task-success-a",
                "record:2:task-success-b",
            ],
            "boundary_attestation": "no state mutation requested",
        },
        {"provider": "fixture", "model": "test-model"},
    )


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()
