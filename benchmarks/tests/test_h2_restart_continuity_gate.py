from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.h2_restart_continuity_gate import (
    SCHEMA_VERSION,
    _did_from_public_key,
    run_gate,
)


def test_did_derivation_matches_did_civ_shape() -> None:
    did = _did_from_public_key("11" * 32)
    assert did.startswith("did:civ:devnet:z6Mk")


def test_h2_restart_continuity_gate_runs_two_processes(tmp_path: Path) -> None:
    run_root = tmp_path / "continuity"
    report = run_gate(run_root=run_root)

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["passed"] is True
    assert report["failure_reasons"] == []
    assert all(report["checks"].values())
    assert report["checks"]["separate_processes"] is True
    assert report["checks"]["runtime_identity_continuous"] is True
    assert report["checks"]["delayed_event_after_shutdown"] is True
    assert report["checks"]["future_behavior_biased"] is True
    assert report["checks"]["normative_local_update_blocked"] is True

    phase1 = json.loads((run_root / "phase1.json").read_text(encoding="utf-8"))
    phase2 = json.loads((run_root / "phase2.json").read_text(encoding="utf-8"))
    assert phase1["pid"] != phase2["pid"]
    assert phase1["agent_id"] == phase2["agent_id"]
    assert phase1["public_key_hex"] == phase2["public_key_hex"]


def test_h2_restart_continuity_gate_refuses_implicit_overwrite(tmp_path: Path) -> None:
    run_root = tmp_path / "continuity"
    run_root.mkdir()
    (run_root / "existing.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError):
        run_gate(run_root=run_root)
