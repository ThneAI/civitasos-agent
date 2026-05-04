from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from benchmarks.f1c_merge import (
    _aggregate_identity_prompt_observability,
    _build_ii2_scorecard,
    _evaluate_g2_gate,
    _evaluate_g3_gate,
    _evaluate_h0_gate,
    _evaluate_h1_gate,
    _evaluate_h2_gate,
    _evaluate_integrity_gate,
    _evaluate_sentinel_gate,
    _inter_agent_jaccard,
)
from benchmarks.task_loader import Manifest, TaskSpec


def _write_raw_ticks(
    run_dir: Path,
    task_id: str,
    actions: list[str],
    *,
    decision_sources: list[str] | None = None,
    identity_states: list[str] | None = None,
    identity_prompt_injected: list[bool] | None = None,
    llm_mode_requests: list[str] | None = None,
    llm_mode_selected: list[bool] | None = None,
    served_intent_layers: list[str] | None = None,
    wait_references_telos: list[bool] | None = None,
    time_window_ids: list[str] | None = None,
    relation_context_ids: list[str] | None = None,
    relation_memory_refs: list[str] | None = None,
    relation_context_sources: list[str] | None = None,
    relation_id_sources: list[str] | None = None,
    relation_pair_present: list[bool] | None = None,
    relation_pair_failure_events_present: list[bool] | None = None,
    relation_pair_failure_ref_present: list[bool] | None = None,
    h0_expectation_trace_present: list[bool] | None = None,
    h0_relation_surprise_present: list[bool] | None = None,
    h0_iem_update_log_present: list[bool] | None = None,
    h0_relation_action_bias_present: list[bool] | None = None,
    h0_normative_local_update_blocked: list[bool] | None = None,
    h0_relation_training_sample_present: list[bool] | None = None,
    h0_relation_negative_fast_learning_present: list[bool] | None = None,
    h0_relation_repair_sample_present: list[bool] | None = None,
    h0_relation_repair_slow_recovery_present: list[bool] | None = None,
    h0_relation_history_preserved_present: list[bool] | None = None,
    h0_survival_surprise_present: list[bool] | None = None,
    h0_economic_surprise_present: list[bool] | None = None,
    h0_reputation_surprise_present: list[bool] | None = None,
    h0_task_surprise_present: list[bool] | None = None,
    h0_governance_surprise_present: list[bool] | None = None,
    h0_identity_action_bias_present: list[bool] | None = None,
    h0_constitutional_surprise_present: list[bool] | None = None,
    h0_normative_governance_trigger_present: list[bool] | None = None,
    h0_governed_revision_present: list[bool] | None = None,
    h0_predicted_update_present: list[bool] | None = None,
    h0_desired_slow_drift_present: list[bool] | None = None,
) -> None:
    raw_dir = run_dir / "raw_ticks"
    raw_dir.mkdir(parents=True, exist_ok=True)
    p = raw_dir / f"{task_id}.csv"
    rows: list[dict[str, str]] = []
    for idx, action in enumerate(actions):
        row = {
            "decision_action": action,
            "decision_source": (
                decision_sources[idx]
                if decision_sources is not None
                else ("llm" if action == "task_execute" else "rules")
            ),
        }
        if identity_states is not None:
            row["identity_state"] = identity_states[idx]
        if identity_prompt_injected is not None:
            row["identity_prompt_injected"] = "true" if identity_prompt_injected[idx] else "false"
        if llm_mode_requests is not None:
            row["llm_mode_request"] = llm_mode_requests[idx]
        if llm_mode_selected is not None:
            row["llm_mode_selected"] = "true" if llm_mode_selected[idx] else "false"
        if served_intent_layers is not None:
            row["served_intent_layer"] = served_intent_layers[idx]
        if wait_references_telos is not None:
            row["wait_references_telos"] = "true" if wait_references_telos[idx] else "false"
        if time_window_ids is not None:
            row["time_window_id"] = time_window_ids[idx]
        if relation_context_ids is not None:
            row["relation_context_id"] = relation_context_ids[idx]
        if relation_memory_refs is not None:
            row["relation_memory_refs"] = relation_memory_refs[idx]
        if relation_context_sources is not None:
            row["relation_context_source"] = relation_context_sources[idx]
        if relation_id_sources is not None:
            row["relation_id_source"] = relation_id_sources[idx]
        if relation_pair_present is not None:
            row["relation_pair_present"] = "true" if relation_pair_present[idx] else "false"
        if relation_pair_failure_events_present is not None:
            row["relation_pair_failure_events_present"] = (
                "true" if relation_pair_failure_events_present[idx] else "false"
            )
        if relation_pair_failure_ref_present is not None:
            row["relation_pair_failure_ref_present"] = (
                "true" if relation_pair_failure_ref_present[idx] else "false"
            )
        if h0_expectation_trace_present is not None:
            row["h0_expectation_trace_present"] = (
                "true" if h0_expectation_trace_present[idx] else "false"
            )
        if h0_relation_surprise_present is not None:
            row["h0_relation_surprise_present"] = (
                "true" if h0_relation_surprise_present[idx] else "false"
            )
        if h0_iem_update_log_present is not None:
            row["h0_iem_update_log_present"] = (
                "true" if h0_iem_update_log_present[idx] else "false"
            )
        if h0_relation_action_bias_present is not None:
            row["h0_relation_action_bias_present"] = (
                "true" if h0_relation_action_bias_present[idx] else "false"
            )
        if h0_normative_local_update_blocked is not None:
            row["h0_normative_local_update_blocked"] = (
                "true" if h0_normative_local_update_blocked[idx] else "false"
            )
        if h0_relation_training_sample_present is not None:
            row["h0_relation_training_sample_present"] = (
                "true" if h0_relation_training_sample_present[idx] else "false"
            )
        if h0_relation_negative_fast_learning_present is not None:
            row["h0_relation_negative_fast_learning_present"] = (
                "true" if h0_relation_negative_fast_learning_present[idx] else "false"
            )
        if h0_relation_repair_sample_present is not None:
            row["h0_relation_repair_sample_present"] = (
                "true" if h0_relation_repair_sample_present[idx] else "false"
            )
        if h0_relation_repair_slow_recovery_present is not None:
            row["h0_relation_repair_slow_recovery_present"] = (
                "true" if h0_relation_repair_slow_recovery_present[idx] else "false"
            )
        if h0_relation_history_preserved_present is not None:
            row["h0_relation_history_preserved_present"] = (
                "true" if h0_relation_history_preserved_present[idx] else "false"
            )
        if h0_survival_surprise_present is not None:
            row["h0_survival_surprise_present"] = (
                "true" if h0_survival_surprise_present[idx] else "false"
            )
        if h0_economic_surprise_present is not None:
            row["h0_economic_surprise_present"] = (
                "true" if h0_economic_surprise_present[idx] else "false"
            )
        if h0_reputation_surprise_present is not None:
            row["h0_reputation_surprise_present"] = (
                "true" if h0_reputation_surprise_present[idx] else "false"
            )
        if h0_task_surprise_present is not None:
            row["h0_task_surprise_present"] = (
                "true" if h0_task_surprise_present[idx] else "false"
            )
        if h0_governance_surprise_present is not None:
            row["h0_governance_surprise_present"] = (
                "true" if h0_governance_surprise_present[idx] else "false"
            )
        if h0_identity_action_bias_present is not None:
            row["h0_identity_action_bias_present"] = (
                "true" if h0_identity_action_bias_present[idx] else "false"
            )
        if h0_constitutional_surprise_present is not None:
            row["h0_constitutional_surprise_present"] = (
                "true" if h0_constitutional_surprise_present[idx] else "false"
            )
        if h0_normative_governance_trigger_present is not None:
            row["h0_normative_governance_trigger_present"] = (
                "true" if h0_normative_governance_trigger_present[idx] else "false"
            )
        if h0_governed_revision_present is not None:
            row["h0_governed_revision_present"] = (
                "true" if h0_governed_revision_present[idx] else "false"
            )
        if h0_predicted_update_present is not None:
            row["h0_predicted_update_present"] = (
                "true" if h0_predicted_update_present[idx] else "false"
            )
        if h0_desired_slow_drift_present is not None:
            row["h0_desired_slow_drift_present"] = (
                "true" if h0_desired_slow_drift_present[idx] else "false"
            )
        rows.append(row)
    fieldnames = list(rows[0].keys()) if rows else ["decision_action"]
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def _task_spec(
    task_id: str,
    *,
    category_id: str = "G03",
    metrics_targeted: list[str] | None = None,
    backend_seed_failures: int = 0,
    variant: str = "happy_path",
) -> TaskSpec:
    return TaskSpec(
        id=task_id,
        category_id=category_id,
        category_name=category_id,
        targets_disease="G",
        variant=variant,
        description="d",
        briefing="b",
        telos="t",
        success_criteria=[{"kind": "regex", "body": "x"}],
        max_ticks=10,
        metrics_targeted=metrics_targeted or ["g3_relation_aware_decision_ratio"],
        backend_seed_failures=backend_seed_failures,
    )


def _manifest_for_tasks(tmp_path: Path, tasks: list[TaskSpec]) -> Manifest:
    return Manifest(
        schema_version="2.0",
        allowed_metric_codes=sorted({metric for task in tasks for metric in task.metrics_targeted}),
        taxonomy=[{"id": task.category_id} for task in tasks],
        tasks=tasks,
        path=tmp_path / "manifest.yaml",
    )


def _json_hash(payload: object) -> str:
    blob = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(blob).hexdigest()}"


def _write_h0e_evidence(
    run_dir: Path,
    task_id: str,
    *,
    authority: str = "governance_council",
    corrupt_proof_hash: bool = False,
    embed_replay: bool = False,
    write_sidecar: bool = True,
    write_runtime_audit: bool = False,
) -> None:
    task_dir = run_dir / "tasks" / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "schema_version": "iem:v1",
        "identity_id": f"benchmark:{task_id}",
        "expectation_vector": {"h0e_constitutional_guard": {"authority": authority}},
        "precision_vector": {"h0e_constitutional_guard": 1.0},
        "desire_vector": {},
        "domain_weight_matrix": {"constitutional": 1.0},
        "drift_parameters": {},
        "relation_expectation_matrix": {},
    }
    update_log = [{"rule": "governed_revision", "authority": authority}]
    anchor = {
        "schema_version": "iem:v1",
        "version_id": "iem:v1:test-anchor",
        "state_hash": _json_hash(state),
        "latest_update_log_hash": _json_hash(update_log),
        "storage_hint": f"civitasos://benchmark/{task_id}/iem/latest",
        "benchmark_task_id": task_id,
    }
    vote_refs = [
        {"voter_id": "did:alpha", "choice": "yes", "stake": 144, "effective_power": 12.0, "voted_at": 1, "delegated": False},
        {"voter_id": "did:beta", "choice": "yes", "stake": 121, "effective_power": 11.0, "voted_at": 2, "delegated": False},
    ]
    proof = {
        "proposal_id": "prop-1",
        "revision_id": "rev-1",
        "status": "approved",
        "authority": authority,
        "vote_count": 2,
        "yes_power": 23.0,
        "no_power": 0.0,
        "abstain_power": 0.0,
        "finalized_at": 3,
        "proposal_hash": "sha256:proposal",
        "votes_hash": _json_hash(vote_refs),
        "vote_refs": vote_refs,
        "iem_anchor_hash": _json_hash(anchor),
    }
    proof["proof_hash"] = "sha256:bad" if corrupt_proof_hash else _json_hash(proof)
    replay = {"state": state, "update_log": update_log, "anchor": anchor}
    if write_sidecar:
        (task_dir / "h0e_iem_anchor_replay.json").write_text(
            json.dumps(replay),
            encoding="utf-8",
        )
    evidence = {
        "revision_id": "rev-1",
        "proposal_id": "prop-1",
        "approved": True,
        "status": "approved",
        "authority": authority,
        "source": "backend_governance_read_model",
        "rule_id": "h0e_constitutional_guard",
        "old_value": "review_required_v1",
        "new_value": "review_required_v2",
        "iem_anchor": anchor,
        "iem_anchor_hash": _json_hash(anchor),
        "decision_proof": proof,
    }
    if embed_replay:
        evidence["iem_anchor_replay"] = replay
    if write_runtime_audit:
        runtime_update_log = [
            {
                "target": "normative_state",
                "parameter_name": "h0e_constitutional_guard",
                "old_value": "review_required_v1",
                "new_value": "review_required_v2",
                "rule": "governed_revision",
                "reason_event": "rev-1",
                "update_params": {"status": "approved"},
                "local_update_blocked": False,
            }
        ]
        runtime_state = {
            **state,
            "identity_id": "did:civ:devnet:worker",
            "normative_state": {"h0e_constitutional_guard": "review_required_v2"},
            "last_tick_id": "tick-1",
        }
        runtime_anchor = {
            "schema_version": "iem:v1",
            "version_id": "iem:v1:runtime",
            "state_hash": _json_hash(runtime_state),
            "latest_update_log_hash": _json_hash(runtime_update_log),
            "storage_hint": "civitasos://identity/did:civ:devnet:worker/iem/latest",
        }
        (task_dir / "h0f_runtime_iem_audit.json").write_text(
            json.dumps({
                "source": "runtime_identity_iem_audit_log",
                "task_id": task_id,
                "tick_id": "tick-1",
                "identity_id": "did:civ:devnet:worker",
                "did_anchor": "did:civ:devnet:worker",
                "identity_iem_state": runtime_state,
                "expectation_update_log": runtime_update_log,
                "identity_iem_anchor": runtime_anchor,
                "governed_revision_updates": runtime_update_log,
            }),
            encoding="utf-8",
        )
    (task_dir / "h0e_governed_revision.json").write_text(
        json.dumps(evidence),
        encoding="utf-8",
    )


def _write_summary(
    run_dir: Path,
    *,
    completed: int,
    total: int,
    tasks: list[dict[str, object]] | None = None,
) -> None:
    payload = {
        "run_id": run_dir.name,
        "tasks_completed": completed,
        "tasks_total": total,
        "tasks": tasks or [],
    }
    (run_dir / "summary.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_final_metrics(path: Path) -> None:
    rows = [
        {
            "agent_alias": "alpha",
            "run_id": "rid-alpha",
            "agent_id": "did:alpha",
            "category_id": "A01",
            "targets_disease": "A",
            "task_count": "2",
            "m1_result_deviation_rate": "0.1",
            "m2_verification_miss_rate": "0.2",
            "m3_aspect_gap_response_rate": "0.5",
            "m4_lessons_impact_rate": "0.3",
            "m5_tick_latency_p50_ms": "1",
            "m5_tick_latency_p95_ms": "2",
            "m5_tick_latency_p99_ms": "3",
            "m5_task_latency_p50_ms": "1000",
            "m5_task_latency_p95_ms": "8000",
            "m6_wait_ratio": "0.1",
            "notes": "",
        },
        {
            "agent_alias": "beta",
            "run_id": "rid-beta",
            "agent_id": "did:beta",
            "category_id": "A01",
            "targets_disease": "A",
            "task_count": "2",
            "m1_result_deviation_rate": "0.3",
            "m2_verification_miss_rate": "0.6",
            "m3_aspect_gap_response_rate": "",
            "m4_lessons_impact_rate": "",
            "m5_tick_latency_p50_ms": "1",
            "m5_tick_latency_p95_ms": "2",
            "m5_tick_latency_p99_ms": "3",
            "m5_task_latency_p50_ms": "1000",
            "m5_task_latency_p95_ms": "18000",
            "m6_wait_ratio": "0.2",
            "notes": "pending H.2",
        },
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def _write_g2_final_metrics(path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = [
        "agent_alias",
        "run_id",
        "agent_id",
        "category_id",
        "targets_disease",
        "task_count",
        "g2_mode_choice_observable_ratio",
        "g3_relation_memory_hit_ratio",
        "g3_relation_aware_decision_ratio",
        "g3_cross_agent_time_consistency_ratio",
        "g3_r2r_relation_id_ratio",
        "g3_relation_pair_context_ratio",
        "g3_relation_pair_failure_ref_ratio",
        "h1_served_intent_layer_coverage_ratio",
        "h1_verifier_before_delivery_ratio",
        "h0_expectation_trace_ratio",
        "h0_hard_domain_trace_ratio",
        "h0_drive_constitution_verdict_ratio",
        "h0_iem_update_log_ratio",
        "h0_relation_action_bias_ratio",
        "h0_normative_guard_ratio",
        "h0_relation_training_sample_ratio",
        "h0_relation_negative_fast_learning_ratio",
        "h0_relation_repair_slow_recovery_ratio",
        "h0_relation_history_preserved_ratio",
        "h0_identity_domain_trace_ratio",
        "h0_reputation_surprise_ratio",
        "h0_task_surprise_ratio",
        "h0_governance_surprise_ratio",
        "h0_expanded_domain_trace_ratio",
        "h0_identity_action_bias_ratio",
        "h0_constitutional_surprise_ratio",
        "h0_normative_governance_trigger_ratio",
        "h0_governed_revision_ratio",
        "h0_predicted_update_ratio",
        "h0_desired_slow_drift_ratio",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def _write_h2_run_root(tmp_path: Path) -> Path:
    runs_root = tmp_path / "runs" / "H2"
    run_dir = runs_root / "baseline-alpha-20260504T000000Z"
    task_id = "A01_adversarial_01"
    task_dir = run_dir / "tasks" / task_id
    raw_dir = run_dir / "raw_ticks"
    task_dir.mkdir(parents=True)
    raw_dir.mkdir(parents=True)
    (run_dir / "summary.json").write_text(
        json.dumps({
            "run_id": run_dir.name,
            "finished_at": "2026-05-04T00:01:00+00:00",
            "tasks": [
                {
                    "task_id": task_id,
                    "agent_self_reported_success": True,
                    "sentinel_kind": "done",
                    "sentinel_reason": "backend status=Delivered",
                    "final_output": "done",
                }
            ],
        }),
        encoding="utf-8",
    )
    (raw_dir / f"{task_id}.csv").write_text(
        "run_id,agent_id,task_id,tick_seq,tick_id,timestamp,decision_action,decision_reasoning\n"
        f"{run_dir.name},did:alpha,{task_id},1,tick-1,2026-05-04T00:00:01+00:00,task_execute,done\n",
        encoding="utf-8",
    )
    (task_dir / "backend_terminal_state.json").write_text(
        json.dumps({
            "task_id": f"backend-{task_id}",
            "status": "Delivered",
            "output": {"answer": "done"},
            "failure_reason": None,
            "challenge_deadline_at": None,
        }),
        encoding="utf-8",
    )
    (task_dir / "backend_task_id.txt").write_text(f"backend-{task_id}\n", encoding="utf-8")
    (runs_root / "h1_llm_judge_report.json").write_text(
        json.dumps({
            "schema_version": "h1-llm-criteria-report:v1",
            "enabled": True,
            "passed": True,
            "total_criteria": 1,
            "judged_criteria": 1,
            "passed_criteria": 1,
            "rows": [
                {
                    "agent_alias": "alpha",
                    "task_id": task_id,
                    "criterion_index": 0,
                    "criterion_desc": "targeted action",
                    "passed": True,
                    "score": 1.0,
                    "model": "judge-test",
                    "prompt_version": "h1-judge-v1",
                    "prompt_hash": "sha256:test",
                }
            ],
        }),
        encoding="utf-8",
    )
    return runs_root


def test_inter_agent_jaccard_uses_weighted_bigrams_as_primary(tmp_path: Path) -> None:
    # Same action vocabulary but different multiplicities:
    # legacy set-Jaccard == 1.0, weighted bigram-Jaccard == 0.5.
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    _write_raw_ticks(alpha, "T01", ["pool_claim", "task_execute", "task_execute"])
    _write_raw_ticks(beta, "T01", ["pool_claim", "task_execute"])

    rows = _inter_agent_jaccard([("alpha", alpha), ("beta", beta)])
    assert len(rows) == 1
    row = rows[0]
    assert row["task_id"] == "T01"
    assert row["jaccard_legacy_set"] == "1.0000"
    assert row["jaccard_weighted_action"] == "0.6667"
    assert row["jaccard_weighted_bigram"] == "0.5000"
    # Primary `jaccard` follows weighted bigrams.
    assert row["jaccard"] == row["jaccard_weighted_bigram"]
    assert row["flagged"] == "0"
    assert row["flagged_legacy_set"] == "1"


def test_inter_agent_jaccard_flags_identical_sequences(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    seq = ["pool_claim", "task_execute", "vote"]
    _write_raw_ticks(alpha, "T02", seq)
    _write_raw_ticks(beta, "T02", seq)

    rows = _inter_agent_jaccard([("alpha", alpha), ("beta", beta)])
    assert len(rows) == 1
    row = rows[0]
    assert row["jaccard"] == "1.0000"
    assert row["flagged"] == "1"
    assert row["flagged_legacy_set"] == "1"


def test_integrity_gate_passes_on_ratio_threshold() -> None:
    rows = [
        {"task_id": "T1", "flagged": "1"},
        {"task_id": "T1", "flagged": "0"},
        {"task_id": "T2", "flagged": "0"},
        {"task_id": "T2", "flagged": "0"},
    ]
    gate = _evaluate_integrity_gate(
        rows,
        max_flagged_pair_ratio=0.25,
        max_flagged_task_ratio=0.50,
        min_common_tasks=2,
    )
    assert gate["passed"] is True
    assert gate["flagged_pair_ratio"] == 0.25
    assert gate["flagged_task_ratio"] == 0.5


def test_integrity_gate_fails_when_common_tasks_too_few() -> None:
    rows = [
        {"task_id": "T1", "flagged": "0"},
        {"task_id": "T1", "flagged": "0"},
    ]
    gate = _evaluate_integrity_gate(
        rows,
        max_flagged_pair_ratio=0.25,
        max_flagged_task_ratio=0.50,
        min_common_tasks=3,
    )
    assert gate["passed"] is False
    reasons = gate["failure_reasons"]
    assert isinstance(reasons, list)
    assert any("insufficient common tasks" in r for r in reasons)


def test_sentinel_gate_passes_without_failed_or_give_up(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    alpha.mkdir()
    beta.mkdir()
    _write_summary(
        alpha,
        completed=2,
        total=2,
        tasks=[
            {"task_id": "T1", "sentinel_kind": "done", "sentinel_reason": "ok"},
            {"task_id": "T2", "sentinel_kind": "done", "sentinel_reason": "ok"},
        ],
    )
    _write_summary(
        beta,
        completed=2,
        total=2,
        tasks=[
            {"task_id": "T1", "sentinel_kind": "done", "sentinel_reason": "ok"},
            {"task_id": "T2", "sentinel_kind": "none", "sentinel_reason": ""},
        ],
    )
    gate = _evaluate_sentinel_gate([("alpha", alpha), ("beta", beta)])
    assert gate["passed"] is True
    assert gate["violation_count"] == 0


def test_sentinel_gate_fails_on_failed_or_give_up(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    alpha.mkdir()
    beta.mkdir()
    _write_summary(
        alpha,
        completed=1,
        total=2,
        tasks=[
            {"task_id": "T1", "sentinel_kind": "done", "sentinel_reason": "ok"},
            {"task_id": "T2", "sentinel_kind": "give_up", "sentinel_reason": "timeout"},
        ],
    )
    _write_summary(
        beta,
        completed=1,
        total=2,
        tasks=[
            {"task_id": "T1", "sentinel_kind": "failed", "sentinel_reason": "tool error"},
            {"task_id": "T2", "sentinel_kind": "done", "sentinel_reason": "ok"},
        ],
    )
    gate = _evaluate_sentinel_gate([("alpha", alpha), ("beta", beta)])
    assert gate["passed"] is False
    assert gate["violation_count"] == 2
    reasons = gate["failure_reasons"]
    assert isinstance(reasons, list)
    assert any("alpha" in r for r in reasons)
    assert any("beta" in r for r in reasons)


def test_g2_gate_passes_when_rows_observable_and_raw_selection_covers_tasks(
    tmp_path: Path,
) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    alpha.mkdir()
    beta.mkdir()
    _write_raw_ticks(
        alpha,
        "T01",
        ["wait", "task_execute"],
        llm_mode_requests=["waiting", ""],
        llm_mode_selected=[True, False],
    )
    _write_raw_ticks(
        alpha,
        "T02",
        ["wait", "task_execute"],
        llm_mode_requests=["deep_think", ""],
        llm_mode_selected=[True, False],
    )
    _write_raw_ticks(
        beta,
        "T01",
        ["wait", "task_execute"],
        llm_mode_requests=["waiting", ""],
        llm_mode_selected=[True, False],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "A01",
                "targets_disease": "A",
                "task_count": "2",
                "g2_mode_choice_observable_ratio": "1.0",
            },
            {
                "agent_alias": "beta",
                "run_id": "rid-beta",
                "agent_id": "did:beta",
                "category_id": "A01",
                "targets_disease": "A",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "0.5",
            },
        ],
    )

    gate = _evaluate_g2_gate(
        runs=[("alpha", alpha), ("beta", beta)],
        final_metrics_csv=final_metrics,
    )

    assert gate["passed"] is True
    assert gate["observable_row_ratio"] == 1.0
    per_agent = {row["agent_alias"]: row for row in gate["per_agent"]}
    assert per_agent["alpha"]["expected_task_count"] == 2
    assert per_agent["alpha"]["llm_mode_selected"] == 2
    assert per_agent["alpha"]["llm_waiting_selected"] == 1
    assert per_agent["alpha"]["llm_deep_think_selected"] == 1


def test_g2_gate_fails_on_blank_ratio_and_missing_raw_selection(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    alpha.mkdir()
    _write_raw_ticks(
        alpha,
        "T01",
        ["wait", "task_execute"],
        llm_mode_requests=["waiting", ""],
        llm_mode_selected=[True, False],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "A01",
                "targets_disease": "A",
                "task_count": "2",
                "g2_mode_choice_observable_ratio": "",
            },
        ],
    )

    gate = _evaluate_g2_gate(
        runs=[("alpha", alpha)],
        final_metrics_csv=final_metrics,
    )

    assert gate["passed"] is False
    reasons = gate["failure_reasons"]
    assert any("g2 observable final_metrics row ratio" in r for r in reasons)
    assert any("raw llm_mode_selected/task_count" in r for r in reasons)
    assert gate["missing_rows_sample"] == [
        {"agent_alias": "alpha", "category_id": "A01", "task_count": "2"},
    ]


def test_h1_gate_passes_with_served_intent_verifier_and_carry_through(
    tmp_path: Path,
) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "V04_h1_verifier_before_delivery_01",
        ["verifier_compare", "task_execute"],
        served_intent_layers=["short", "short"],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "V04",
                "targets_disease": "V",
                "task_count": "1",
                "h1_served_intent_layer_coverage_ratio": "1.0",
                "h1_verifier_before_delivery_ratio": "1.0",
            },
        ],
    )
    manifest = _manifest_for_tasks(
        tmp_path,
        [
            _task_spec(
                "V04_h1_verifier_before_delivery_01",
                category_id="V04",
                metrics_targeted=["h1_verifier_before_delivery_ratio"],
                variant="adversarial",
            ),
        ],
    )
    manifest.tasks[0].verifier_tools = ["verifier_compare"]

    gate = _evaluate_h1_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        manifest=manifest,
        g3_gate={"passed": True},
        h0_gate={"passed": True},
        require_active=True,
    )

    assert gate["passed"] is True
    assert gate["skipped"] is False
    assert gate["raw_h1_served_intent_layer_coverage_ratio"] == 1.0
    assert gate["raw_h1_verifier_before_delivery_ratio"] == 1.0


def test_h1_gate_fails_on_missing_served_intent_and_late_verifier(
    tmp_path: Path,
) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "V04_h1_verifier_before_delivery_01",
        ["task_execute", "verifier_compare"],
        served_intent_layers=["", "short"],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "V04",
                "targets_disease": "V",
                "task_count": "1",
                "h1_served_intent_layer_coverage_ratio": "0.5",
                "h1_verifier_before_delivery_ratio": "0.0",
            },
        ],
    )
    manifest = _manifest_for_tasks(
        tmp_path,
        [
            _task_spec(
                "V04_h1_verifier_before_delivery_01",
                category_id="V04",
                metrics_targeted=["h1_verifier_before_delivery_ratio"],
                variant="adversarial",
            ),
        ],
    )
    manifest.tasks[0].verifier_tools = ["verifier_compare"]

    gate = _evaluate_h1_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        manifest=manifest,
        g3_gate={"passed": False},
        h0_gate={"passed": True},
        require_active=True,
    )

    assert gate["passed"] is False
    reasons = gate["failure_reasons"]
    assert any("h1_served_intent_layer_coverage_ratio" in r for r in reasons)
    assert any("h1_verifier_before_delivery_ratio" in r for r in reasons)
    assert any("G3 carry-through" in r for r in reasons)


def test_h1_gate_fails_closed_on_llm_judge_report_failure(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "R01_happy_01",
        ["task_execute"],
        served_intent_layers=["short"],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "R01",
                "targets_disease": "R",
                "task_count": "1",
                "h1_served_intent_layer_coverage_ratio": "1.0",
                "h1_verifier_before_delivery_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h1_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        g3_gate={"passed": True},
        h0_gate={"passed": True},
        require_active=True,
        llm_judge_report={
            "enabled": True,
            "skipped": False,
            "passed": False,
            "failure_reasons": ["H1 llm_judge pass rate 0.0000 < 1.0000"],
        },
    )

    assert gate["passed"] is False
    assert gate["llm_judge"]["passed"] is False
    assert any("llm_judge success criteria" in r for r in gate["failure_reasons"])


def test_h2_gate_skips_by_default(tmp_path: Path) -> None:
    gate = _evaluate_h2_gate(runs_root=tmp_path, require_active=False)

    assert gate == {
        "passed": True,
        "skipped": True,
        "require_active": False,
        "failure_reasons": [],
    }


def test_h2_gate_builds_report_and_passes(tmp_path: Path) -> None:
    runs_root = _write_h2_run_root(tmp_path)
    report_path = tmp_path / "h2_outcome_report.json"

    gate = _evaluate_h2_gate(
        runs_root=runs_root,
        require_active=True,
        h2_outcome_report_path=report_path,
        g3_gate={"passed": True},
        h0_gate={"passed": True},
        h1_gate={"passed": True},
    )

    assert gate["passed"] is True
    assert gate["skipped"] is False
    assert gate["report_path"] == str(report_path)
    assert report_path.is_file()
    assert gate["outcome_report"]["passed"] is True
    assert gate["outcome_report"]["metrics"]["outcome_record_count"] == 1
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["records"][0]["record_id"] == "alpha:A01_adversarial_01"


def test_h2_gate_fails_closed_on_h1_carry_through_failure(tmp_path: Path) -> None:
    runs_root = _write_h2_run_root(tmp_path)

    gate = _evaluate_h2_gate(
        runs_root=runs_root,
        require_active=True,
        g3_gate={"passed": True},
        h0_gate={"passed": True},
        h1_gate={"passed": False, "failure_reasons": ["H1 failed"]},
    )

    assert gate["passed"] is False
    assert gate["outcome_report"]["passed"] is True
    assert any("H1 carry-through" in reason for reason in gate["failure_reasons"])


def test_g3_gate_skips_when_no_relation_rows(tmp_path: Path) -> None:
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "A01",
                "targets_disease": "A",
                "task_count": "2",
                "g2_mode_choice_observable_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_g3_gate(final_metrics_csv=final_metrics)

    assert gate["passed"] is True
    assert gate["skipped"] is True
    assert gate["relation_rows"] == 0


def test_g3_gate_fails_when_relation_row_below_floor(tmp_path: Path) -> None:
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G3",
                "targets_disease": "G",
                "task_count": "2",
                "g2_mode_choice_observable_ratio": "1.0",
                "g3_relation_memory_hit_ratio": "0.5",
                "g3_relation_aware_decision_ratio": "1.0",
                "g3_cross_agent_time_consistency_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_g3_gate(final_metrics_csv=final_metrics)

    assert gate["passed"] is False
    assert gate["skipped"] is False
    assert gate["relation_rows"] == 1
    assert any("g3_relation_memory_hit_ratio" in r for r in gate["failure_reasons"])


def test_g3_gate_fails_when_raw_time_windows_disagree(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    gamma = tmp_path / "baseline-gamma-20260101T000000Z"
    for run_dir, window_id in (
        (alpha, "tw-shared"),
        (beta, "tw-drifted"),
        (gamma, "tw-shared"),
    ):
        _write_raw_ticks(
            run_dir,
            "G02_happy_01",
            ["wait", "task_execute"],
            time_window_ids=[window_id, ""],
        )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": alias,
                "run_id": f"rid-{alias}",
                "agent_id": f"did:{alias}",
                "category_id": "G02",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "g3_relation_memory_hit_ratio": "1.0",
                "g3_relation_aware_decision_ratio": "1.0",
                "g3_cross_agent_time_consistency_ratio": "1.0",
            }
            for alias in ("alpha", "beta", "gamma")
        ],
    )

    gate = _evaluate_g3_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha), ("beta", beta), ("gamma", gamma)],
    )

    assert gate["passed"] is False
    assert gate["raw_time_window_task_count"] == 1
    assert gate["raw_cross_agent_time_consistency_ratio"] == 0.0
    assert any("raw cross-agent time consistency ratio" in r for r in gate["failure_reasons"])


def test_g3_gate_checks_raw_llm_relation_refs(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    for run_dir, refs in (
        (alpha, ["relation:G01:prior", "relation:G01:prior"]),
        (beta, ["", ""]),
    ):
        _write_raw_ticks(
            run_dir,
            "G01_happy_01",
            ["wait", "task_execute"],
            decision_sources=["llm", "llm"],
            relation_context_ids=["rel-g01", "rel-g01"],
            relation_memory_refs=refs,
            time_window_ids=["tw-g01", "tw-g01"],
        )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": alias,
                "run_id": f"rid-{alias}",
                "agent_id": f"did:{alias}",
                "category_id": "G01",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "g3_relation_memory_hit_ratio": "1.0",
                "g3_relation_aware_decision_ratio": "1.0",
                "g3_cross_agent_time_consistency_ratio": "1.0",
            }
            for alias in ("alpha", "beta")
        ],
    )

    gate = _evaluate_g3_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha), ("beta", beta)],
    )

    assert gate["passed"] is False
    assert gate["raw_llm_relation_trace_rows"] == 4
    assert gate["raw_llm_relation_ref_rows"] == 2
    assert gate["raw_llm_relation_ref_ratio"] == 0.5
    assert any("raw LLM relation ref ratio" in r for r in gate["failure_reasons"])


def test_g3_gate_can_require_backend_relation_context_source(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    for run_dir, source in (
        (alpha, "backend_read_model"),
        (beta, "synthetic_benchmark"),
    ):
        _write_raw_ticks(
            run_dir,
            "G01_happy_01",
            ["task_execute"],
            decision_sources=["llm"],
            relation_context_ids=["rel-g01"],
            relation_memory_refs=["relation:G01:prior"],
            time_window_ids=["tw-g01"],
            relation_context_sources=[source],
        )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": alias,
                "run_id": f"rid-{alias}",
                "agent_id": f"did:{alias}",
                "category_id": "G01",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "g3_relation_memory_hit_ratio": "1.0",
                "g3_relation_aware_decision_ratio": "1.0",
                "g3_cross_agent_time_consistency_ratio": "1.0",
            }
            for alias in ("alpha", "beta")
        ],
    )

    gate = _evaluate_g3_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha), ("beta", beta)],
        min_backend_relation_context_source_ratio=1.0,
    )

    assert gate["passed"] is False
    assert gate["raw_relation_context_source_rows"] == 2
    assert gate["raw_backend_relation_context_source_rows"] == 1
    assert gate["raw_backend_relation_context_source_ratio"] == 0.5
    assert any("raw backend relation context source ratio" in r for r in gate["failure_reasons"])


def test_g3_gate_can_require_relation_provenance(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    for run_dir, relation_id_source, has_pair, has_failure_ref in (
        (alpha, "r2r_registry", True, True),
        (beta, "derived_fallback", False, False),
    ):
        _write_raw_ticks(
            run_dir,
            "G01_happy_01",
            ["task_execute"],
            decision_sources=["llm"],
            relation_context_ids=["rel-g01"],
            relation_memory_refs=["failure:rel-g01:failed-1" if has_failure_ref else "relation:G01:prior"],
            time_window_ids=["tw-g01"],
            relation_context_sources=["backend_read_model"],
            relation_id_sources=[relation_id_source],
            relation_pair_present=[has_pair],
            relation_pair_failure_events_present=[True],
            relation_pair_failure_ref_present=[has_failure_ref],
        )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": alias,
                "run_id": f"rid-{alias}",
                "agent_id": f"did:{alias}",
                "category_id": "G01",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "g3_relation_memory_hit_ratio": "1.0",
                "g3_relation_aware_decision_ratio": "1.0",
                "g3_cross_agent_time_consistency_ratio": "1.0",
                "g3_r2r_relation_id_ratio": "0.5",
                "g3_relation_pair_context_ratio": "0.5",
                "g3_relation_pair_failure_ref_ratio": "0.5",
            }
            for alias in ("alpha", "beta")
        ],
    )

    gate = _evaluate_g3_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha), ("beta", beta)],
        min_r2r_relation_id_ratio=1.0,
        min_relation_pair_context_ratio=1.0,
        min_relation_pair_failure_ref_ratio=1.0,
    )

    assert gate["passed"] is False
    assert gate["raw_g3_r2r_relation_id_ratio"] == 0.5
    assert gate["raw_g3_relation_pair_context_ratio"] == 0.5
    assert gate["raw_g3_relation_pair_failure_ref_ratio"] == 0.5
    assert any("R2R relation id ratio" in r for r in gate["failure_reasons"])
    assert any("relation pair context ratio" in r for r in gate["failure_reasons"])
    assert any("relation-pair failure ref ratio" in r for r in gate["failure_reasons"])


def test_g3_failure_ref_gate_allows_categories_without_failure_events(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G03_happy_01",
        ["task_execute"],
        decision_sources=["llm"],
        relation_context_ids=["rel-g03"],
        relation_memory_refs=["failure:rel-g03:failed-1"],
        time_window_ids=["tw-g03"],
        relation_context_sources=["backend_read_model"],
        relation_id_sources=["r2r_registry"],
        relation_pair_present=[True],
        relation_pair_failure_events_present=[True],
        relation_pair_failure_ref_present=[True],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G01",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "g3_relation_memory_hit_ratio": "1.0",
                "g3_relation_aware_decision_ratio": "1.0",
                "g3_cross_agent_time_consistency_ratio": "1.0",
                "g3_r2r_relation_id_ratio": "1.0",
                "g3_relation_pair_context_ratio": "1.0",
                "g3_relation_pair_failure_ref_ratio": "",
            },
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G03",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "g3_relation_memory_hit_ratio": "1.0",
                "g3_relation_aware_decision_ratio": "1.0",
                "g3_cross_agent_time_consistency_ratio": "1.0",
                "g3_r2r_relation_id_ratio": "1.0",
                "g3_relation_pair_context_ratio": "1.0",
                "g3_relation_pair_failure_ref_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_g3_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        min_r2r_relation_id_ratio=1.0,
        min_relation_pair_context_ratio=1.0,
        min_relation_pair_failure_ref_ratio=1.0,
    )

    assert gate["passed"] is True
    assert gate["raw_g3_relation_pair_failure_ref_ratio"] == 1.0


def test_h0_gate_skips_when_inactive(tmp_path: Path) -> None:
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G01",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(final_metrics_csv=final_metrics)

    assert gate["passed"] is True
    assert gate["skipped"] is True


def test_h0_gate_passes_on_failure_memory_trace(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G03_failure_memory_01",
        ["task_execute", "task_execute"],
        relation_pair_failure_events_present=[True, True],
        h0_expectation_trace_present=[True, True],
        h0_relation_surprise_present=[True, True],
        h0_iem_update_log_present=[True, True],
        h0_relation_action_bias_present=[True, True],
        h0_normative_local_update_blocked=[True, True],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G03",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_relation_action_bias_ratio": "1.0",
                "h0_normative_guard_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
    )

    assert gate["passed"] is True
    assert gate["skipped"] is False
    assert gate["raw_h0_relation_failure_event_rows"] == 2
    assert gate["raw_h0_relation_failure_trace_ratio"] == 1.0
    assert gate["raw_h0_iem_update_log_ratio"] == 1.0
    assert gate["raw_h0_relation_action_bias_ratio"] == 1.0
    assert gate["raw_h0_normative_guard_ratio"] == 1.0


def test_h0_gate_passes_on_relation_training_invariants(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G03_relation_training_01",
        ["task_execute", "task_execute"],
        relation_pair_failure_events_present=[True, True],
        h0_expectation_trace_present=[True, True],
        h0_relation_surprise_present=[True, True],
        h0_iem_update_log_present=[True, True],
        h0_relation_action_bias_present=[True, True],
        h0_normative_local_update_blocked=[True, True],
        h0_relation_training_sample_present=[True, True],
        h0_relation_negative_fast_learning_present=[True, False],
        h0_relation_repair_sample_present=[True, False],
        h0_relation_repair_slow_recovery_present=[True, False],
        h0_relation_history_preserved_present=[True, True],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G03",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_relation_action_bias_ratio": "1.0",
                "h0_normative_guard_ratio": "1.0",
                "h0_relation_training_sample_ratio": "1.0",
                "h0_relation_negative_fast_learning_ratio": "1.0",
                "h0_relation_repair_slow_recovery_ratio": "0.5",
                "h0_relation_history_preserved_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
        min_relation_training_sample_ratio=1.0,
        min_relation_negative_fast_learning_ratio=1.0,
        min_relation_repair_slow_recovery_ratio=1.0,
        min_relation_history_preserved_ratio=1.0,
    )

    assert gate["passed"] is True
    assert gate["raw_h0_relation_training_sample_ratio"] == 1.0
    assert gate["raw_h0_relation_negative_fast_learning_ratio"] == 1.0
    assert gate["raw_h0_relation_negative_fast_learning_tick_ratio"] == 0.5
    assert gate["raw_h0_relation_negative_fast_learning_task_count"] == 1
    assert gate["raw_h0_relation_repair_sample_rows"] == 1
    assert gate["raw_h0_relation_repair_slow_recovery_ratio"] == 1.0
    assert gate["raw_h0_relation_history_preserved_ratio"] == 1.0


def test_h0_gate_excludes_generic_relation_context_from_negative_training_denominator(
    tmp_path: Path,
) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G03_seeded_failure_01",
        ["task_execute"],
        relation_pair_failure_events_present=[True],
        h0_expectation_trace_present=[True],
        h0_relation_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_relation_action_bias_present=[True],
        h0_normative_local_update_blocked=[True],
        h0_relation_training_sample_present=[True],
        h0_relation_negative_fast_learning_present=[True],
        h0_relation_history_preserved_present=[True],
    )
    _write_raw_ticks(
        alpha,
        "G02_context_only_01",
        ["task_execute"],
        relation_pair_failure_events_present=[True],
        h0_expectation_trace_present=[True],
        h0_relation_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_relation_action_bias_present=[True],
        h0_normative_local_update_blocked=[True],
        h0_relation_training_sample_present=[True],
        h0_relation_negative_fast_learning_present=[False],
        h0_relation_history_preserved_present=[True],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G03",
                "targets_disease": "G",
                "task_count": "2",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_relation_action_bias_ratio": "1.0",
                "h0_normative_guard_ratio": "1.0",
                "h0_relation_training_sample_ratio": "1.0",
                "h0_relation_negative_fast_learning_ratio": "1.0",
                "h0_relation_history_preserved_ratio": "1.0",
            },
        ],
    )
    manifest = _manifest_for_tasks(
        tmp_path,
        [
            _task_spec("G03_seeded_failure_01", backend_seed_failures=1),
            _task_spec("G02_context_only_01", category_id="G02"),
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        manifest=manifest,
        require_active=True,
        min_relation_training_sample_ratio=1.0,
        min_relation_negative_fast_learning_ratio=1.0,
        min_relation_history_preserved_ratio=1.0,
    )

    assert gate["passed"] is True
    assert gate["raw_h0_relation_failure_task_count"] == 2
    assert gate["raw_h0_relation_negative_fast_learning_required_task_count"] == 1
    assert gate["raw_h0_relation_negative_fast_learning_task_count"] == 1
    assert gate["raw_h0_relation_negative_fast_learning_ratio"] == 1.0
    assert gate["raw_h0_relation_negative_fast_learning_tick_ratio"] == 0.5


def test_h0_gate_fails_when_relation_training_negative_learning_missing(
    tmp_path: Path,
) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G03_relation_training_01",
        ["task_execute", "task_execute"],
        relation_pair_failure_events_present=[True, True],
        h0_expectation_trace_present=[True, True],
        h0_relation_surprise_present=[True, True],
        h0_iem_update_log_present=[True, True],
        h0_relation_action_bias_present=[True, True],
        h0_normative_local_update_blocked=[True, True],
        h0_relation_training_sample_present=[True, True],
        h0_relation_negative_fast_learning_present=[False, False],
        h0_relation_history_preserved_present=[True, True],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G03",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_relation_action_bias_ratio": "1.0",
                "h0_normative_guard_ratio": "1.0",
                "h0_relation_training_sample_ratio": "1.0",
                "h0_relation_negative_fast_learning_ratio": "0.0",
                "h0_relation_history_preserved_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        manifest=_manifest_for_tasks(
            tmp_path,
            [
                _task_spec(
                    "G03_relation_training_01",
                    metrics_targeted=[
                        "g3_relation_aware_decision_ratio",
                        "h0_relation_negative_fast_learning_ratio",
                    ],
                ),
            ],
        ),
        require_active=True,
        min_relation_training_sample_ratio=1.0,
        min_relation_negative_fast_learning_ratio=1.0,
        min_relation_history_preserved_ratio=1.0,
    )

    assert gate["passed"] is False
    assert gate["raw_h0_relation_negative_fast_learning_ratio"] == 0.0
    assert gate["raw_h0_relation_negative_fast_learning_tick_ratio"] == 0.0
    assert any(
        "raw_h0_relation_negative_fast_learning_ratio" in reason
        for reason in gate["failure_reasons"]
    )


def test_h0_gate_fails_when_relation_repair_required_without_samples(
    tmp_path: Path,
) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G03_relation_training_01",
        ["task_execute"],
        relation_pair_failure_events_present=[True],
        h0_expectation_trace_present=[True],
        h0_relation_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_relation_action_bias_present=[True],
        h0_normative_local_update_blocked=[True],
        h0_relation_training_sample_present=[True],
        h0_relation_negative_fast_learning_present=[True],
        h0_relation_history_preserved_present=[True],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G03",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_relation_action_bias_ratio": "1.0",
                "h0_normative_guard_ratio": "1.0",
                "h0_relation_training_sample_ratio": "1.0",
                "h0_relation_negative_fast_learning_ratio": "1.0",
                "h0_relation_history_preserved_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
        min_relation_training_sample_ratio=1.0,
        min_relation_negative_fast_learning_ratio=1.0,
        min_relation_repair_slow_recovery_ratio=1.0,
        min_relation_history_preserved_ratio=1.0,
    )

    assert gate["passed"] is False
    assert gate["raw_h0_relation_repair_sample_rows"] == 0
    assert any(
        "no repair sample rows" in reason
        for reason in gate["failure_reasons"]
    )


def test_h0_gate_passes_on_identity_evolution_trace_without_relation_failure(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G01_h0c_identity_01",
        ["task_execute", "task_execute"],
        h0_expectation_trace_present=[True, True],
        h0_survival_surprise_present=[True, True],
        h0_economic_surprise_present=[True, True],
        h0_iem_update_log_present=[True, True],
        h0_identity_action_bias_present=[True, True],
        h0_predicted_update_present=[True, True],
        h0_constitutional_surprise_present=[False, True],
        h0_normative_governance_trigger_present=[False, True],
        h0_normative_local_update_blocked=[False, True],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G01",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_constitutional_surprise_ratio": "0.5",
                "h0_normative_governance_trigger_ratio": "0.5",
                "h0_predicted_update_ratio": "1.0",
                "h0_desired_slow_drift_ratio": "0.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
    )

    assert gate["passed"] is True
    assert gate["raw_h0_relation_failure_event_rows"] == 0
    assert gate["raw_h0_identity_event_rows"] == 2
    assert gate["raw_h0_identity_domain_trace_ratio"] == 1.0
    assert gate["raw_h0_identity_action_bias_ratio"] == 1.0
    assert gate["raw_h0_predicted_update_ratio"] == 1.0
    assert gate["raw_h0_normative_governance_trigger_ratio"] == 1.0


def test_h0_gate_passes_on_expanded_identity_domains(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G07_h0d_expanded_01",
        ["task_execute", "task_execute"],
        h0_expectation_trace_present=[True, True],
        h0_survival_surprise_present=[True, True],
        h0_economic_surprise_present=[True, True],
        h0_reputation_surprise_present=[True, True],
        h0_task_surprise_present=[True, True],
        h0_governance_surprise_present=[True, True],
        h0_iem_update_log_present=[True, True],
        h0_identity_action_bias_present=[True, True],
        h0_predicted_update_present=[True, True],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G07",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_reputation_surprise_ratio": "1.0",
                "h0_task_surprise_ratio": "1.0",
                "h0_governance_surprise_ratio": "1.0",
                "h0_expanded_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_predicted_update_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
    )

    assert gate["passed"] is True
    assert gate["raw_h0_expanded_domain_event_rows"] == 2
    assert gate["raw_h0_reputation_surprise_rows"] == 2
    assert gate["raw_h0_task_surprise_rows"] == 2
    assert gate["raw_h0_governance_surprise_rows"] == 2
    assert gate["raw_h0_expanded_domain_trace_ratio"] == 1.0


def test_h0_gate_passes_on_governed_revision_trace(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G08_h0e_governed_revision_01",
        ["task_execute", "task_execute"],
        h0_expectation_trace_present=[True, True],
        h0_survival_surprise_present=[True, True],
        h0_economic_surprise_present=[True, True],
        h0_iem_update_log_present=[True, True],
        h0_identity_action_bias_present=[True, True],
        h0_predicted_update_present=[True, True],
        h0_governed_revision_present=[True, True],
    )
    _write_h0e_evidence(alpha, "G08_h0e_governed_revision_01")
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G08",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_predicted_update_ratio": "1.0",
                "h0_governed_revision_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
    )

    assert gate["passed"] is True
    assert gate["raw_h0_governed_revision_event_rows"] == 2
    assert gate["raw_h0_governed_revision_rows"] == 2
    assert gate["raw_h0_governed_revision_tick_ratio"] == 1.0
    assert gate["raw_h0_governed_revision_expected_task_count"] == 1
    assert gate["raw_h0_governed_revision_task_count"] == 1
    assert gate["raw_h0_governed_revision_ratio"] == 1.0
    assert gate["raw_h0_decision_proof_hash_valid_ratio"] == 1.0
    assert gate["raw_h0_iem_anchor_replay_valid_ratio"] == 1.0
    assert gate["raw_h0_iem_anchor_replay_embedded_ratio"] == 0.0
    assert gate["raw_h0_iem_anchor_replay_legacy_sidecar_files"] == 1
    assert gate["raw_h0_iem_anchor_replay_legacy_sidecar_ratio"] == 1.0
    assert gate["raw_h0_vote_refs_present_ratio"] == 1.0
    assert gate["raw_h0_governed_revision_authority_kinds"] == ["governance"]


def test_h0_gate_uses_governed_revision_task_coverage(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G08_h0e_governed_revision_01",
        ["wait", "task_execute"],
        h0_expectation_trace_present=[True, True],
        h0_survival_surprise_present=[True, True],
        h0_economic_surprise_present=[True, True],
        h0_iem_update_log_present=[True, True],
        h0_identity_action_bias_present=[True, True],
        h0_predicted_update_present=[True, True],
        h0_governed_revision_present=[False, True],
    )
    _write_h0e_evidence(alpha, "G08_h0e_governed_revision_01")
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G08",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_predicted_update_ratio": "1.0",
                "h0_governed_revision_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
        min_governed_revision_ratio=1.0,
    )

    assert gate["passed"] is True
    assert gate["raw_h0_governed_revision_event_rows"] == 2
    assert gate["raw_h0_governed_revision_rows"] == 1
    assert gate["raw_h0_governed_revision_tick_ratio"] == 0.5
    assert gate["raw_h0_governed_revision_expected_task_count"] == 1
    assert gate["raw_h0_governed_revision_task_count"] == 1
    assert gate["raw_h0_governed_revision_ratio"] == 1.0


def test_h0_gate_excludes_unapproved_local_revision_from_governed_denominator(
    tmp_path: Path,
) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G08_h0e_governed_revision_01",
        ["task_execute"],
        h0_expectation_trace_present=[True],
        h0_survival_surprise_present=[True],
        h0_economic_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_identity_action_bias_present=[True],
        h0_predicted_update_present=[True],
        h0_governed_revision_present=[True],
    )
    _write_raw_ticks(
        alpha,
        "G08_h0e_unapproved_local_revision_01",
        ["task_execute"],
        h0_expectation_trace_present=[True],
        h0_survival_surprise_present=[True],
        h0_economic_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_identity_action_bias_present=[True],
        h0_predicted_update_present=[True],
        h0_governed_revision_present=[False],
    )
    _write_h0e_evidence(alpha, "G08_h0e_governed_revision_01")
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G08",
                "targets_disease": "G",
                "task_count": "2",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_predicted_update_ratio": "1.0",
                "h0_governed_revision_ratio": "1.0",
            },
        ],
    )
    manifest = _manifest_for_tasks(
        tmp_path,
        [
            _task_spec(
                "G08_h0e_governed_revision_01",
                category_id="G08",
                metrics_targeted=["h0_governed_revision_ratio"],
            ),
            _task_spec(
                "G08_h0e_unapproved_local_revision_01",
                category_id="G08",
                metrics_targeted=["h0_governed_revision_ratio"],
                variant="adversarial",
            ),
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        manifest=manifest,
        require_active=True,
    )

    assert gate["passed"] is True
    assert gate["raw_h0_governed_revision_event_rows"] == 1
    assert gate["raw_h0_governed_revision_rows"] == 1
    assert gate["raw_h0_governed_revision_expected_task_count"] == 1
    assert gate["raw_h0_governed_revision_task_count"] == 1
    assert gate["raw_h0_governed_revision_ratio"] == 1.0


def test_h0_gate_passes_on_backend_embedded_replay_without_sidecar(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G08_h0e_governed_revision_01",
        ["task_execute"],
        h0_expectation_trace_present=[True],
        h0_survival_surprise_present=[True],
        h0_economic_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_identity_action_bias_present=[True],
        h0_predicted_update_present=[True],
        h0_governed_revision_present=[True],
    )
    _write_h0e_evidence(
        alpha,
        "G08_h0e_governed_revision_01",
        embed_replay=True,
        write_sidecar=False,
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G08",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_predicted_update_ratio": "1.0",
                "h0_governed_revision_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
        min_iem_anchor_replay_embedded_ratio=1.0,
    )

    assert gate["passed"] is True
    assert gate["raw_h0_iem_anchor_replay_valid_ratio"] == 1.0
    assert gate["raw_h0_iem_anchor_replay_embedded_files"] == 1
    assert gate["raw_h0_iem_anchor_replay_embedded_ratio"] == 1.0
    assert gate["raw_h0_iem_anchor_replay_legacy_sidecar_files"] == 0
    assert gate["raw_h0_iem_anchor_replay_legacy_sidecar_ratio"] == 0.0


def test_h0_gate_fails_when_legacy_sidecar_fallback_is_disallowed(
    tmp_path: Path,
) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G08_h0e_governed_revision_01",
        ["task_execute"],
        h0_expectation_trace_present=[True],
        h0_survival_surprise_present=[True],
        h0_economic_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_identity_action_bias_present=[True],
        h0_predicted_update_present=[True],
        h0_governed_revision_present=[True],
    )
    _write_h0e_evidence(alpha, "G08_h0e_governed_revision_01")
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G08",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_predicted_update_ratio": "1.0",
                "h0_governed_revision_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
        max_iem_anchor_replay_legacy_sidecar_ratio=0.0,
    )

    assert gate["passed"] is False
    assert gate["raw_h0_iem_anchor_replay_valid_ratio"] == 1.0
    assert gate["raw_h0_iem_anchor_replay_legacy_sidecar_ratio"] == 1.0
    assert any(
        "raw_h0_iem_anchor_replay_legacy_sidecar_ratio" in reason
        for reason in gate["failure_reasons"]
    )


def test_h0_gate_passes_on_runtime_iem_audit_artifact(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G08_h0e_governed_revision_01",
        ["task_execute"],
        h0_expectation_trace_present=[True],
        h0_survival_surprise_present=[True],
        h0_economic_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_identity_action_bias_present=[True],
        h0_predicted_update_present=[True],
        h0_governed_revision_present=[True],
    )
    _write_h0e_evidence(
        alpha,
        "G08_h0e_governed_revision_01",
        embed_replay=True,
        write_runtime_audit=True,
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G08",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_predicted_update_ratio": "1.0",
                "h0_governed_revision_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
        min_iem_anchor_replay_embedded_ratio=1.0,
        min_runtime_iem_audit_ratio=1.0,
    )

    assert gate["passed"] is True
    assert gate["raw_h0_runtime_iem_audit_valid_files"] == 1
    assert gate["raw_h0_runtime_iem_audit_valid_ratio"] == 1.0


def test_h0_gate_fails_when_runtime_iem_audit_required_but_missing(
    tmp_path: Path,
) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G08_h0e_governed_revision_01",
        ["task_execute"],
        h0_expectation_trace_present=[True],
        h0_survival_surprise_present=[True],
        h0_economic_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_identity_action_bias_present=[True],
        h0_predicted_update_present=[True],
        h0_governed_revision_present=[True],
    )
    _write_h0e_evidence(
        alpha,
        "G08_h0e_governed_revision_01",
        embed_replay=True,
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G08",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_predicted_update_ratio": "1.0",
                "h0_governed_revision_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
        min_iem_anchor_replay_embedded_ratio=1.0,
        min_runtime_iem_audit_ratio=1.0,
    )

    assert gate["passed"] is False
    assert gate["raw_h0_runtime_iem_audit_valid_ratio"] == 0.0
    assert any(
        "raw_h0_runtime_iem_audit_valid_ratio" in reason
        for reason in gate["failure_reasons"]
    )


def test_h0_gate_fails_when_embedded_replay_required_but_only_sidecar_exists(
    tmp_path: Path,
) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G08_h0e_governed_revision_01",
        ["task_execute"],
        h0_expectation_trace_present=[True],
        h0_survival_surprise_present=[True],
        h0_economic_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_identity_action_bias_present=[True],
        h0_predicted_update_present=[True],
        h0_governed_revision_present=[True],
    )
    _write_h0e_evidence(alpha, "G08_h0e_governed_revision_01")
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G08",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_predicted_update_ratio": "1.0",
                "h0_governed_revision_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
        min_iem_anchor_replay_embedded_ratio=1.0,
    )

    assert gate["passed"] is False
    assert gate["raw_h0_iem_anchor_replay_valid_ratio"] == 1.0
    assert gate["raw_h0_iem_anchor_replay_embedded_ratio"] == 0.0
    assert any(
        "raw_h0_iem_anchor_replay_embedded_ratio" in reason
        for reason in gate["failure_reasons"]
    )


def test_h0_gate_fails_on_invalid_governed_revision_proof_hash(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G08_h0e_governed_revision_01",
        ["task_execute"],
        h0_expectation_trace_present=[True],
        h0_survival_surprise_present=[True],
        h0_economic_surprise_present=[True],
        h0_iem_update_log_present=[True],
        h0_identity_action_bias_present=[True],
        h0_predicted_update_present=[True],
        h0_governed_revision_present=[True],
    )
    _write_h0e_evidence(
        alpha,
        "G08_h0e_governed_revision_01",
        corrupt_proof_hash=True,
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G08",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_identity_domain_trace_ratio": "1.0",
                "h0_identity_action_bias_ratio": "1.0",
                "h0_predicted_update_ratio": "1.0",
                "h0_governed_revision_ratio": "1.0",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
    )

    assert gate["passed"] is False
    assert gate["raw_h0_decision_proof_hash_valid_ratio"] == 0.0
    assert any(
        "raw_h0_decision_proof_hash_valid_ratio" in reason
        for reason in gate["failure_reasons"]
    )


def test_h0_gate_fails_when_required_trace_missing(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    _write_raw_ticks(
        alpha,
        "G03_failure_memory_01",
        ["task_execute", "task_execute"],
        relation_pair_failure_events_present=[True, True],
        h0_expectation_trace_present=[True, True],
        h0_relation_surprise_present=[True, False],
        h0_iem_update_log_present=[True, True],
        h0_relation_action_bias_present=[True, False],
        h0_normative_local_update_blocked=[True, False],
    )
    final_metrics = tmp_path / "final_metrics.csv"
    _write_g2_final_metrics(
        final_metrics,
        [
            {
                "agent_alias": "alpha",
                "run_id": "rid-alpha",
                "agent_id": "did:alpha",
                "category_id": "G03",
                "targets_disease": "G",
                "task_count": "1",
                "g2_mode_choice_observable_ratio": "1.0",
                "h0_expectation_trace_ratio": "1.0",
                "h0_iem_update_log_ratio": "1.0",
                "h0_relation_action_bias_ratio": "0.5",
                "h0_normative_guard_ratio": "0.5",
            },
        ],
    )

    gate = _evaluate_h0_gate(
        final_metrics_csv=final_metrics,
        runs=[("alpha", alpha)],
        require_active=True,
    )

    assert gate["passed"] is False
    assert gate["raw_h0_relation_failure_trace_ratio"] == 0.5
    assert gate["raw_h0_relation_action_bias_ratio"] == 0.5
    assert any("raw_h0_relation_failure_trace_ratio" in r for r in gate["failure_reasons"])
    assert any("raw_h0_relation_action_bias_ratio" in r for r in gate["failure_reasons"])


def test_ii2_scorecard_builds_four_dimension_scores(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    alpha.mkdir()
    beta.mkdir()
    _write_summary(alpha, completed=60, total=60)
    _write_summary(beta, completed=54, total=60)

    final_metrics = tmp_path / "final_metrics.csv"
    _write_final_metrics(final_metrics)
    jaccard_rows = [
        {"task_id": "T1", "agent_a": "alpha", "agent_b": "beta", "flagged": "0"},
        {"task_id": "T2", "agent_a": "alpha", "agent_b": "beta", "flagged": "1"},
    ]

    scorecard = _build_ii2_scorecard(
        runs=[("alpha", alpha), ("beta", beta)],
        final_metrics_csv=final_metrics,
        jaccard_rows=jaccard_rows,
    )

    assert scorecard["schema_version"] == "ii2_scorecard.v1"
    assert "weights" in scorecard
    agents = scorecard["agents"]
    assert len(agents) == 2
    alpha_row = next(r for r in agents if r["agent_alias"] == "alpha")
    beta_row = next(r for r in agents if r["agent_alias"] == "beta")
    assert alpha_row["completion_rate"] == 1.0
    assert beta_row["completion_rate"] == 0.9
    assert alpha_row["identity_score"] > beta_row["identity_score"]
    assert alpha_row["passed"] is True
    assert beta_row["passed"] is False
    gate = scorecard["gate"]
    assert gate["passed"] is False
    assert isinstance(gate["failure_reasons"], list)


def test_ii2_scorecard_recognizes_generic_m2_observation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED", raising=False)
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    alpha.mkdir()
    beta.mkdir()
    _write_summary(alpha, completed=60, total=60)
    _write_summary(beta, completed=60, total=60)

    # Generic verification action should count as observable for M2.
    _write_raw_ticks(alpha, "T_adv_01", ["pool_claim", "query_reputation", "task_execute"])
    _write_raw_ticks(beta, "T_adv_01", ["pool_claim", "query_reputation", "task_execute"])

    final_metrics = tmp_path / "final_metrics.csv"
    _write_final_metrics(final_metrics)
    jaccard_rows = [
        {"task_id": "T_adv_01", "agent_a": "alpha", "agent_b": "beta", "flagged": "0"},
    ]
    manifest = Manifest(
        schema_version="1.1",
        allowed_metric_codes=["M2"],
        taxonomy=[{"id": "A01"}],
        tasks=[
            TaskSpec(
                id="T_adv_01",
                category_id="A01",
                category_name="A",
                targets_disease="A",
                variant="adversarial",
                description="d",
                briefing="b",
                telos="t",
                success_criteria=[{"kind": "regex", "body": "x"}],
                max_ticks=10,
                metrics_targeted=["M2"],
                verifier_tools=["manual_check"],
            ),
        ],
        path=tmp_path / "manifest.yaml",
    )

    scorecard = _build_ii2_scorecard(
        runs=[("alpha", alpha), ("beta", beta)],
        final_metrics_csv=final_metrics,
        jaccard_rows=jaccard_rows,
        manifest=manifest,
    )
    gate = scorecard["gate"]
    assert gate["observability_warnings"] == []


def test_identity_prompt_observability_aggregates_per_agent(tmp_path: Path) -> None:
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    alpha.mkdir()
    beta.mkdir()
    _write_raw_ticks(
        alpha,
        "T01",
        ["pool_claim", "task_execute"],
        identity_states=["PROVISIONAL", "PROVISIONAL"],
        identity_prompt_injected=[True, True],
    )
    _write_raw_ticks(
        beta,
        "T01",
        ["pool_claim", "task_execute"],
        identity_states=["PROVISIONAL", "PROVISIONAL"],
        identity_prompt_injected=[False, False],
    )

    summary = _aggregate_identity_prompt_observability([("alpha", alpha), ("beta", beta)])
    assert summary["tasks_with_ticks"] == 2
    assert summary["observable_schema_task_ratio"] == 1.0
    assert summary["identity_state_task_ratio"] == 1.0
    assert summary["identity_prompt_task_ratio"] == 0.5
    assert summary["identity_prompt_tick_ratio"] == 0.5
    assert summary["identity_prompt_llm_task_ratio"] == 0.5
    assert summary["identity_prompt_llm_tick_ratio"] == 0.5


def test_ii2_scorecard_records_identity_prompt_coverage(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED", "true")
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    beta = tmp_path / "baseline-beta-20260101T000000Z"
    alpha.mkdir()
    beta.mkdir()
    _write_summary(alpha, completed=60, total=60)
    _write_summary(beta, completed=60, total=60)
    _write_raw_ticks(
        alpha,
        "T01",
        ["pool_claim", "task_execute"],
        identity_states=["PROVISIONAL", "PROVISIONAL"],
        identity_prompt_injected=[True, True],
    )
    _write_raw_ticks(
        beta,
        "T01",
        ["pool_claim", "task_execute"],
        identity_states=["PROVISIONAL", "PROVISIONAL"],
        identity_prompt_injected=[True, True],
    )

    final_metrics = tmp_path / "final_metrics.csv"
    _write_final_metrics(final_metrics)
    jaccard_rows = [
        {"task_id": "T01", "agent_a": "alpha", "agent_b": "beta", "flagged": "0"},
    ]

    scorecard = _build_ii2_scorecard(
        runs=[("alpha", alpha), ("beta", beta)],
        final_metrics_csv=final_metrics,
        jaccard_rows=jaccard_rows,
    )
    alpha_row = next(r for r in scorecard["agents"] if r["agent_alias"] == "alpha")
    observed = alpha_row["metrics_observed"]
    assert observed["identity_observable_schema_task_ratio"] == 1.0
    assert observed["identity_state_task_ratio"] == 1.0
    assert observed["identity_prompt_task_ratio"] == 1.0
    assert observed["identity_prompt_tick_ratio"] == 1.0
    assert observed["identity_prompt_llm_task_ratio"] == 1.0
    assert observed["identity_prompt_llm_tick_ratio"] == 1.0
    gate = scorecard["gate"]
    assert gate["observability_warnings"] == []


def test_ii2_scorecard_excludes_rules_only_tasks_from_identity_prompt_floor(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("CIVITASOS_INSTITUTIONAL_IDENTITY_ENABLED", "true")
    alpha = tmp_path / "baseline-alpha-20260101T000000Z"
    alpha.mkdir()
    _write_summary(alpha, completed=60, total=60)
    _write_raw_ticks(
        alpha,
        "T_rules_only",
        ["pool_claim", "report_blocked"],
        decision_sources=["rules", "rules"],
        identity_states=["PROVISIONAL", "PROVISIONAL"],
        identity_prompt_injected=[False, False],
    )

    final_metrics = tmp_path / "final_metrics.csv"
    _write_final_metrics(final_metrics)

    scorecard = _build_ii2_scorecard(
        runs=[("alpha", alpha)],
        final_metrics_csv=final_metrics,
        jaccard_rows=[],
    )

    observed = scorecard["agents"][0]["metrics_observed"]
    assert observed["identity_prompt_task_ratio"] == 0.0
    assert observed["identity_prompt_llm_task_ratio"] is None
    gate = scorecard["gate"]
    assert gate["observability_warnings"] == []
