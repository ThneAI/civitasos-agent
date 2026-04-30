"""Computer unit tests using in-memory TaskRun objects."""
from __future__ import annotations

from observability.metrics.computers import (
    m1_result_deviation,
    m2_verification_miss,
    m3_aspect_gap_response,
    m4_lessons_impact,
    m5_reaction_latency,
    m6_wait_ratio,
    g2_subjective_mode,
)
from observability.metrics.computers._loader import TaskRun, TickRow


def _tick(seq: int, *, action: str = "noop", success=None, dur=None,
          gap: float = 0.0, ts: str = "", lessons_count: int = 0,
          llm_mode_request: str = "", llm_mode_selected: bool = False) -> TickRow:
    return TickRow(
        run_id="R", agent_id="A", task_id="T",
        tick_seq=seq,
        timestamp=ts or f"2026-04-18T00:00:{seq:02d}+00:00",
        phase_reached="reflect",
        decision_action=action,
        eval_success=success,
        eval_duration_ms=dur,
        aspect_gap=gap,
        is_wait=(action == "wait"),
        lessons_count=lessons_count,
        llm_mode_request=llm_mode_request,
        llm_mode_selected=llm_mode_selected,
    )


# --- M1 ----------------------------------------------------------------

def test_m1_typical_deviation() -> None:
    t1 = TaskRun(
        task_id="T1",
        ticks=[_tick(1, success=False)],
        success_criteria=[{"kind": "regex", "body": "x"}],
        agent_self_reported_success=True,
    )
    t2 = TaskRun(
        task_id="T2",
        ticks=[_tick(1, success=True)],
        success_criteria=[{"kind": "regex", "body": "y"}],
        agent_self_reported_success=True,
    )
    assert m1_result_deviation.compute([t1, t2]) == 0.5


def test_m1_skips_llm_judge_only_tasks() -> None:
    t = TaskRun(
        task_id="T",
        ticks=[_tick(1, success=False)],
        success_criteria=[{"kind": "llm_judge", "body": "..."}],
        agent_self_reported_success=True,
    )
    assert m1_result_deviation.compute([t]) is None


def test_m1_no_eligible_returns_none() -> None:
    assert m1_result_deviation.compute([]) is None


# --- M2 ----------------------------------------------------------------

def test_m2_miss_when_verifier_never_called() -> None:
    t = TaskRun(
        task_id="V", variant="adversarial",
        verifier_tools=["verifier_compare"],
        ticks=[_tick(1, action="transfer"), _tick(2, action="confirm")],
    )
    assert m2_verification_miss.compute([t]) == 1.0


def test_m2_hit_when_verifier_called() -> None:
    t = TaskRun(
        task_id="V", variant="adversarial",
        verifier_tools=["verifier_compare"],
        ticks=[_tick(1, action="verifier_compare"), _tick(2, action="abort")],
    )
    assert m2_verification_miss.compute([t]) == 0.0


def test_m2_hit_when_generic_verification_action_called() -> None:
    t = TaskRun(
        task_id="V", variant="adversarial",
        verifier_tools=["manual_check"],
        ticks=[_tick(1, action="query_reputation"), _tick(2, action="abort")],
    )
    assert m2_verification_miss.compute([t]) == 0.0


def test_m2_hit_when_get_reputation_called() -> None:
    t = TaskRun(
        task_id="V", variant="adversarial",
        verifier_tools=["manual_check"],
        ticks=[_tick(1, action="get_reputation"), _tick(2, action="abort")],
    )
    assert m2_verification_miss.compute([t]) == 0.0


def test_m2_skips_happy_path_tasks() -> None:
    t = TaskRun(
        task_id="H", variant="happy_path",
        verifier_tools=["verifier_compare"],
        ticks=[_tick(1, action="noop")],
    )
    assert m2_verification_miss.compute([t]) is None


# --- M3 ----------------------------------------------------------------

def test_m3_responds_when_jaccard_below_threshold() -> None:
    # 3 pre-actions {a,b,c}, then gap crossing, then 3 post-actions {x,y,z}
    ticks = [
        _tick(1, action="a", gap=0.1),
        _tick(2, action="b", gap=0.2),
        _tick(3, action="c", gap=0.3),
        _tick(4, action="trigger", gap=0.85),  # crossing
        _tick(5, action="x", gap=0.4),
        _tick(6, action="y", gap=0.3),
        _tick(7, action="z", gap=0.2),
    ]
    t = TaskRun(task_id="T", ticks=ticks)
    assert m3_aspect_gap_response.compute([t]) == 1.0


def test_m3_no_response_when_jaccard_high() -> None:
    ticks = [
        _tick(1, action="a", gap=0.1),
        _tick(2, action="b", gap=0.2),
        _tick(3, action="c", gap=0.3),
        _tick(4, action="trigger", gap=0.85),
        _tick(5, action="a", gap=0.4),
        _tick(6, action="b", gap=0.3),
        _tick(7, action="c", gap=0.2),
    ]
    t = TaskRun(task_id="T", ticks=ticks)
    assert m3_aspect_gap_response.compute([t]) == 0.0


def test_m3_no_trigger_returns_none() -> None:
    t = TaskRun(task_id="T", ticks=[_tick(1, gap=0.1)])
    assert m3_aspect_gap_response.compute([t]) is None


# --- M4 ----------------------------------------------------------------

def test_m4_returns_none_without_eligible_signal() -> None:
    val, notes = m4_lessons_impact.compute([])
    assert val is None
    assert "insufficient M4 signal" in notes


def test_m4_counts_lessons_growth_on_recovery() -> None:
    t_ok = TaskRun(
        task_id="S01",
        ticks=[
            _tick(1, success=False, lessons_count=0),
            _tick(2, success=False, lessons_count=1),
            _tick(3, success=True, lessons_count=2),
        ],
    )
    t_no = TaskRun(
        task_id="S02",
        ticks=[
            _tick(1, success=False, lessons_count=1),
            _tick(2, success=True, lessons_count=1),
        ],
    )
    val, notes = m4_lessons_impact.compute([t_ok, t_no])
    assert val == 0.5
    assert "eligible task" in notes


# --- M5 ----------------------------------------------------------------

def test_m5_basic_distribution() -> None:
    ticks = [_tick(i, dur=i * 10, ts=f"2026-04-18T00:00:{i:02d}+00:00") for i in range(1, 11)]
    t = TaskRun(task_id="T", ticks=ticks)
    out = m5_reaction_latency.compute([t])
    assert out["m5_tick_latency_p50_ms"] is not None
    assert out["m5_task_latency_p50_ms"] is not None
    # 9 seconds wall-clock between first and last tick.
    assert out["m5_task_latency_p50_ms"] == 9000.0


def test_m5_empty_returns_none_fields() -> None:
    out = m5_reaction_latency.compute([])
    assert out["m5_tick_latency_p50_ms"] is None
    assert out["m5_task_latency_p50_ms"] is None


# --- M6 ----------------------------------------------------------------

def test_m6_basic_ratio() -> None:
    t = TaskRun(task_id="T", ticks=[
        _tick(1, action="wait"),
        _tick(2, action="noop"),
        _tick(3, action="wait"),
        _tick(4, action="act"),
    ])
    assert m6_wait_ratio.compute([t]) == 0.5


def test_m6_no_ticks_returns_none() -> None:
    assert m6_wait_ratio.compute([]) is None


# --- G.2 ---------------------------------------------------------------

def test_g2_subjective_mode_choice_ratios() -> None:
    t = TaskRun(task_id="T", ticks=[
        _tick(
            1,
            action="wait",
            llm_mode_request="deep_think",
            llm_mode_selected=True,
        ),
        _tick(
            2,
            action="wait",
            llm_mode_request="waiting",
            llm_mode_selected=True,
        ),
        _tick(3, action="wait"),
        _tick(4, action="task_execute"),
    ])
    out = g2_subjective_mode.compute([t])
    assert out["g2_mode_choice_observable_ratio"] == 2 / 3
    assert out["g2_llm_waiting_ratio"] == 0.5
    assert out["g2_llm_deep_think_ratio"] == 0.5


def test_g2_subjective_mode_no_wait_ticks_returns_null_observable_ratio() -> None:
    t = TaskRun(task_id="T", ticks=[_tick(1, action="task_execute")])
    out = g2_subjective_mode.compute([t])
    assert out["g2_mode_choice_observable_ratio"] is None
    assert out["g2_llm_waiting_ratio"] is None
    assert out["g2_llm_deep_think_ratio"] is None
