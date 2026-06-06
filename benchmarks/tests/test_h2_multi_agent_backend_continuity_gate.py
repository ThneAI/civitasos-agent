from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.h2_multi_agent_backend_continuity_gate import (
    SCHEMA_VERSION,
    WORKER_CASES,
    run_gate,
)


BACKEND_BINARY = (
    Path(__file__).resolve().parents[3]
    / "civitasos-backend"
    / "target"
    / "debug"
    / "api_only"
)


@pytest.mark.skipif(not BACKEND_BINARY.is_file(), reason="backend debug binary not built")
def test_h2_multi_agent_backend_continuity_gate(tmp_path: Path) -> None:
    report = run_gate(
        run_root=tmp_path / "h2-multi-agent",
        backend_binary=BACKEND_BINARY,
    )

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["passed"] is True
    assert report["failure_reasons"] == []
    assert all(report["checks"].values())
    assert {
        worker: summary["event_kind"]
        for worker, summary in report["worker_summaries"].items()
    } == WORKER_CASES
    assert report["worker_summaries"]["alpha"]["relation_update"]["after"][
        "expected_trust"
    ] > report["worker_summaries"]["alpha"]["relation_update"]["before"][
        "expected_trust"
    ]
    for worker in ("beta", "gamma"):
        update = report["worker_summaries"][worker]["relation_update"]
        assert update["after"]["expected_trust"] < update["before"]["expected_trust"]
        assert update["action_bias"]["verification_level"] in {"elevated", "strict"}


def test_h2_multi_agent_backend_continuity_gate_refuses_overwrite(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "h2-multi-agent"
    run_root.mkdir()
    (run_root / "keep.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError):
        run_gate(run_root=run_root, backend_binary=BACKEND_BINARY)
