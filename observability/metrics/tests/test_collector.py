"""CollectorAdapter tests using fake TickContext / EnergyState shaped objects."""
from __future__ import annotations

import csv
from pathlib import Path
from types import SimpleNamespace

from civitasos_runtime.models import ExpectationUpdate, ExpectationUpdateRule

from observability.metrics.collector import CollectorAdapter
from observability.metrics.schema import RAW_COLUMNS
from observability.metrics.writer import RawWriter


def _make_loop(
    *,
    aspect_gap: float = 0.2,
    peer_trust_avg: float = 0.5,
    balance: float = 100.0,
    lessons_count: int = 0,
    mode: str = "active",
):
    state = SimpleNamespace(
        aspect_gap=aspect_gap, peer_trust_avg=peer_trust_avg, balance=balance,
    )
    energy = SimpleNamespace(state=state)
    lessons = [{} for _ in range(lessons_count)]
    memory = SimpleNamespace(recall=lambda key: lessons if key == "lessons_learned" else None)
    return SimpleNamespace(_energy=energy, _memory=memory, mode=SimpleNamespace(value=mode))


def _make_ctx(
    action: str = "noop",
    success: bool = True,
    duration_ms: int = 42,
    *,
    gap: float = 0.0,
    briefing: dict | None = None,
):
    return SimpleNamespace(
        tick_id="tick-abc",
        timestamp="2026-04-18T15:30:22+00:00",
        phase=SimpleNamespace(value="reflect"),
        briefing=briefing or {},
        decision=SimpleNamespace(
            action=action,
            source=SimpleNamespace(value="rules"),
            reasoning="hello\nworld",
        ),
        conscience_verdict=SimpleNamespace(allowed=True, reason="ok"),
        evaluation=SimpleNamespace(success=success, cost=0.001, duration_ms=duration_ms),
    )


def test_writes_one_row_per_tick(tmp_path: Path) -> None:
    csv_path = tmp_path / "T.csv"
    with RawWriter(csv_path) as writer:
        adapter = CollectorAdapter(
            run_id="R", agent_id="A", loop=_make_loop(), writer=writer,
        )
        adapter.bind_task("R01_happy_01")
        adapter(_make_ctx(action="noop"))
        adapter(_make_ctx(action="wait"))

    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert len(rows) == 2
    assert rows[0]["task_id"] == "R01_happy_01"
    assert rows[0]["tick_seq"] == "1"
    assert rows[0]["decision_action"] == "noop"
    assert rows[0]["is_wait"] == "false"
    assert rows[1]["tick_seq"] == "2"
    assert rows[1]["is_wait"] == "true"
    # Header order = RAW_COLUMNS
    header = csv_path.open(encoding="utf-8").readline().rstrip("\n")
    assert header.split(",") == list(RAW_COLUMNS)


def test_skip_when_unbound(tmp_path: Path) -> None:
    csv_path = tmp_path / "T.csv"
    with RawWriter(csv_path) as writer:
        adapter = CollectorAdapter(
            run_id="R", agent_id="A", loop=_make_loop(), writer=writer,
        )
        adapter(_make_ctx())  # no bind_task → skipped
    # Only the header row exists.
    assert csv_path.read_text(encoding="utf-8").count("\n") == 1


def test_reasoning_escaped_and_truncated(tmp_path: Path) -> None:
    csv_path = tmp_path / "T.csv"
    big = "X" * 600 + "\n" + "Y" * 50
    with RawWriter(csv_path) as writer:
        adapter = CollectorAdapter(
            run_id="R", agent_id="A", loop=_make_loop(), writer=writer,
        )
        adapter.bind_task("R01_happy_01")
        ctx = _make_ctx()
        ctx.decision.reasoning = big
        adapter(ctx)
    row = next(csv.DictReader(csv_path.open(encoding="utf-8")))
    val = row["decision_reasoning"]
    assert "\n" not in val
    assert len(val) <= 500


def test_failure_does_not_propagate(tmp_path: Path) -> None:
    """Even if the writer explodes, adapter must swallow the exception."""

    class ExplodingWriter:
        def write(self, row):  # noqa: ARG002
            raise RuntimeError("disk full")

    adapter = CollectorAdapter(
        run_id="R", agent_id="A", loop=_make_loop(), writer=ExplodingWriter(),
    )
    adapter.bind_task("T")
    adapter(_make_ctx())  # must not raise


def test_energy_snapshot_used(tmp_path: Path) -> None:
    csv_path = tmp_path / "T.csv"
    loop = _make_loop(
        aspect_gap=0.85,
        peer_trust_avg=0.42,
        balance=12.5,
        lessons_count=3,
    )
    with RawWriter(csv_path) as writer:
        adapter = CollectorAdapter(run_id="R", agent_id="A", loop=loop, writer=writer)
        adapter.bind_task("T")
        adapter(_make_ctx())
    row = next(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert row["aspect_gap"] == "0.85"
    assert row["peer_trust_avg"] == "0.42"
    assert row["balance"] == "12.5"
    assert row["lessons_count"] == "3"


def test_identity_snapshot_used(tmp_path: Path) -> None:
    csv_path = tmp_path / "T.csv"
    identity_briefing = {
        "identity": {
            "state": "PROVISIONAL",
            "remaining_epochs": 2,
        },
        "_identity_prompt_injected": True,
    }
    with RawWriter(csv_path) as writer:
        adapter = CollectorAdapter(run_id="R", agent_id="A", loop=_make_loop(), writer=writer)
        adapter.bind_task("T")
        adapter(_make_ctx(briefing=identity_briefing))
    row = next(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert row["identity_state"] == "PROVISIONAL"
    assert row["identity_remaining_epochs"] == "2"
    assert row["identity_prompt_injected"] == "true"


def test_subjective_time_snapshot_used(tmp_path: Path) -> None:
    csv_path = tmp_path / "T.csv"
    briefing = {
        "subjective_time": {
            "lifecycle_stage": "mature",
            "recommended_mode": "deep_think",
            "llm_mode_request": "deep_think",
            "llm_mode_selected": True,
        }
    }
    with RawWriter(csv_path) as writer:
        adapter = CollectorAdapter(
            run_id="R",
            agent_id="A",
            loop=_make_loop(mode="deep_think"),
            writer=writer,
        )
        adapter.bind_task("T")
        adapter(_make_ctx(action="wait", briefing=briefing))
    row = next(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert row["mode"] == "deep_think"
    assert row["subjective_lifecycle_stage"] == "mature"
    assert row["subjective_recommended_mode"] == "deep_think"
    assert row["llm_mode_request"] == "deep_think"
    assert row["llm_mode_selected"] == "true"


def test_relation_time_snapshot_used(tmp_path: Path) -> None:
    csv_path = tmp_path / "T.csv"
    briefing = {
        "relation_context": {
            "id": "relctx-1",
            "relation_id": "rel:r:w",
            "relation_id_source": "r2r_registry",
            "relation_pair": {"requester": "r", "worker": "w"},
            "relation_pair_failure_source": "backend_relation_pair_read_model",
            "recent_failures": [{"task_id": "failed-1"}],
            "memory_refs": ["failure:rel:r:w:failed-1", "challenge:2"],
            "source": "backend_read_model",
        },
        "time_window": {
            "id": "tw-1",
            "challenge_deadline_bucket": "2026-05-01T00:00:00Z/5s",
        },
    }
    with RawWriter(csv_path) as writer:
        adapter = CollectorAdapter(
            run_id="R",
            agent_id="A",
            loop=_make_loop(),
            writer=writer,
        )
        adapter.bind_task("T")
        adapter(_make_ctx(briefing=briefing))
    row = next(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert row["relation_context_id"] == "relctx-1"
    assert row["relation_memory_refs"] == "failure:rel:r:w:failed-1;challenge:2"
    assert row["time_window_id"] == "tw-1"
    assert row["challenge_deadline_bucket"] == "2026-05-01T00:00:00Z/5s"
    assert row["relation_context_source"] == "backend_read_model"
    assert row["relation_id_source"] == "r2r_registry"
    assert row["relation_pair_present"] == "true"
    assert row["relation_pair_failure_source"] == "backend_relation_pair_read_model"
    assert row["relation_pair_failure_events_present"] == "true"
    assert row["relation_pair_failure_ref_present"] == "true"


def test_h0_expectation_snapshot_used(tmp_path: Path) -> None:
    csv_path = tmp_path / "T.csv"
    ctx = _make_ctx()
    ctx.expectations = {"survival": {"expected_value": 0.9}}
    ctx.surprise = {
        "survival": {"surprise_score": -0.2},
        "economic": {"surprise_score": -0.1},
        "reputation": {"surprise_score": -0.4},
        "task": {"surprise_score": -0.5},
        "governance": {"surprise_score": -0.3},
        "relation": {"surprise_score": -0.3},
    }
    ctx.drive = {
        "relation": {"constitution_verdict": "allowed"},
        "survival": {"survival_probability": {"constitution_verdict": "allowed"}},
        "constitutional": {"challenge_window": {"action_bias": "governance_trigger"}},
    }
    ctx.action_bias = {
        "relation": {"verification_level": "high"},
        "survival": {"survival_probability": "reduce_action_intensity"},
        "economic": {"economic_balance_ratio": "conserve_energy"},
        "reputation": {"reputation_score": "repair_reputation"},
        "task": {"task_success_probability": "reduce_task_risk"},
        "governance": {"governance_participation": "increase_governance_attention"},
        "normative": {"challenge_window": "governance_trigger"},
    }
    ctx.expectation_updates = [
        ExpectationUpdate(
            target="identity_expectation_vector",
            parameter_name="survival_probability",
            rule=ExpectationUpdateRule.PRECISION_WEIGHTED_DELTA,
        ),
        ExpectationUpdate(
            target="identity_desire_vector",
            parameter_name="risk_aversion",
            rule=ExpectationUpdateRule.SLOW_TRAIT_DRIFT,
        ),
        ExpectationUpdate(
            target="normative_state",
            parameter_name="challenge_window",
            rule=ExpectationUpdateRule.GOVERNANCE_TRIGGER,
            local_update_blocked=True,
        ),
    ]
    with RawWriter(csv_path) as writer:
        adapter = CollectorAdapter(
            run_id="R",
            agent_id="A",
            loop=_make_loop(),
            writer=writer,
        )
        adapter.bind_task("T")
        adapter(ctx)
    row = next(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert row["h0_expectation_trace_present"] == "true"
    assert row["h0_survival_surprise_present"] == "true"
    assert row["h0_economic_surprise_present"] == "true"
    assert row["h0_reputation_surprise_present"] == "true"
    assert row["h0_task_surprise_present"] == "true"
    assert row["h0_governance_surprise_present"] == "true"
    assert row["h0_relation_surprise_present"] == "true"
    assert row["h0_drive_constitution_verdict_present"] == "true"
    assert row["h0_iem_update_log_present"] == "true"
    assert row["h0_relation_action_bias_present"] == "true"
    assert row["h0_normative_local_update_blocked"] == "true"
    assert row["h0_identity_action_bias_present"] == "true"
    assert row["h0_constitutional_surprise_present"] == "false"
    assert row["h0_normative_governance_trigger_present"] == "true"
    assert row["h0_predicted_update_present"] == "true"
    assert row["h0_desired_slow_drift_present"] == "true"
