from __future__ import annotations

import csv
from pathlib import Path

from benchmarks.f1c_merge import _evaluate_integrity_gate, _inter_agent_jaccard


def _write_raw_ticks(run_dir: Path, task_id: str, actions: list[str]) -> None:
    raw_dir = run_dir / "raw_ticks"
    raw_dir.mkdir(parents=True, exist_ok=True)
    p = raw_dir / f"{task_id}.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["decision_action"])
        w.writeheader()
        for a in actions:
            w.writerow({"decision_action": a})


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
