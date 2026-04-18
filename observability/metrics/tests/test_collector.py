"""CollectorAdapter tests using fake TickContext / EnergyState shaped objects."""
from __future__ import annotations

import csv
from pathlib import Path
from types import SimpleNamespace

from observability.metrics.collector import CollectorAdapter
from observability.metrics.schema import RAW_COLUMNS
from observability.metrics.writer import RawWriter


def _make_loop(*, aspect_gap: float = 0.2, peer_trust_avg: float = 0.5, balance: float = 100.0):
    state = SimpleNamespace(
        aspect_gap=aspect_gap, peer_trust_avg=peer_trust_avg, balance=balance,
    )
    energy = SimpleNamespace(state=state)
    return SimpleNamespace(_energy=energy)


def _make_ctx(action: str = "noop", success: bool = True, duration_ms: int = 42, *, gap: float = 0.0):
    return SimpleNamespace(
        tick_id="tick-abc",
        timestamp="2026-04-18T15:30:22+00:00",
        phase=SimpleNamespace(value="reflect"),
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
    loop = _make_loop(aspect_gap=0.85, peer_trust_avg=0.42, balance=12.5)
    with RawWriter(csv_path) as writer:
        adapter = CollectorAdapter(run_id="R", agent_id="A", loop=loop, writer=writer)
        adapter.bind_task("T")
        adapter(_make_ctx())
    row = next(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert row["aspect_gap"] == "0.85"
    assert row["peer_trust_avg"] == "0.42"
    assert row["balance"] == "12.5"
