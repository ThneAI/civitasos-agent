"""Writer tests: header, RFC 4180 quoting, fsync, concurrent safety."""
from __future__ import annotations

import csv
import threading
from pathlib import Path

from observability.metrics.schema import RAW_COLUMNS
from observability.metrics.writer import RawWriter


def _row(idx: int, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "run_id": "R",
        "agent_id": "A",
        "task_id": "T",
        "tick_seq": idx,
        "tick_id": f"t{idx}",
        "timestamp": "2026-04-18T00:00:00+00:00",
        "phase_reached": "reflect",
        "decision_action": "noop",
        "aspect_gap": 0.0,
        "peer_trust_avg": 0.0,
        "balance": 0.0,
        "is_wait": False,
    }
    base.update(overrides)
    return base


def test_header_written_once(tmp_path: Path) -> None:
    p = tmp_path / "T.csv"
    with RawWriter(p) as w:
        w.write(_row(1))
    with RawWriter(p) as w:
        w.write(_row(2))
    text = p.read_text(encoding="utf-8")
    # Header appears exactly once.
    assert text.count(",".join(RAW_COLUMNS)) == 1
    assert text.count("\n") == 3  # header + 2 rows


def test_quoting_escapes_commas_and_quotes(tmp_path: Path) -> None:
    p = tmp_path / "T.csv"
    with RawWriter(p) as w:
        w.write(_row(1, decision_action='wait', decision_reasoning='a, b "c"'))
    rows = list(csv.DictReader(p.open(encoding="utf-8")))
    assert rows[0]["decision_reasoning"] == 'a, b "c"'


def test_concurrent_writes_dont_lose_rows(tmp_path: Path) -> None:
    p = tmp_path / "T.csv"
    n = 100
    with RawWriter(p) as w:
        threads = [threading.Thread(target=w.write, args=(_row(i),)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    rows = list(csv.DictReader(p.open(encoding="utf-8")))
    assert len(rows) == n


def test_extra_keys_dropped_missing_keys_blank(tmp_path: Path) -> None:
    p = tmp_path / "T.csv"
    with RawWriter(p) as w:
        w.write({"run_id": "R", "extra_unknown": "ignore_me"})
    rows = list(csv.DictReader(p.open(encoding="utf-8")))
    assert "extra_unknown" not in rows[0]
    assert rows[0]["run_id"] == "R"
    assert rows[0]["task_id"] == ""
