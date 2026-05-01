from __future__ import annotations

import csv
import json
from pathlib import Path

from benchmarks.f1c_merge import (
    _aggregate_identity_prompt_observability,
    _build_ii2_scorecard,
    _evaluate_g2_gate,
    _evaluate_g3_gate,
    _evaluate_h0_gate,
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
        rows.append(row)
    fieldnames = list(rows[0].keys()) if rows else ["decision_action"]
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


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
        "h0_expectation_trace_ratio",
        "h0_hard_domain_trace_ratio",
        "h0_drive_constitution_verdict_ratio",
        "h0_iem_update_log_ratio",
        "h0_relation_action_bias_ratio",
        "h0_normative_guard_ratio",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


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
