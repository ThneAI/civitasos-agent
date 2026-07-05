from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.post_h3_minimal_production_task_chain import run_gate as run_minimal_chain
from benchmarks.post_h3_observer_mode_readiness_gate import run_gate as run_post_h3ac
from benchmarks.post_h3_readiness_index import build_index
from benchmarks.tests.test_post_h3_observer_mode_readiness_gate import _write_post_h3ab_fixture


def test_post_h3_readiness_index_accepts_ac_only(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3ac = _write_post_h3ac_fixture(tmp_path, monkeypatch)

    report = build_index(
        post_h3ac_summary_path=post_h3ac,
        output=tmp_path / "post_h3_readiness_index.json",
    )

    assert report["passed"] is True
    assert report["status"] == "post_h3_observer_ready_waiting_minimal_production_task_chain_blueprint"
    assert report["readiness"]["post_h3_observer_mode_ready"] is True
    assert report["readiness"]["minimal_production_task_chain_blueprint_ready"] is False
    assert report["readiness"]["production_task_execution_allowed"] is False


def test_post_h3_readiness_index_accepts_ac_and_minimal_chain(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3ac = _write_post_h3ac_fixture(tmp_path, monkeypatch)
    minimal = _write_minimal_chain_fixture(tmp_path, post_h3ac)

    report = build_index(
        post_h3ac_summary_path=post_h3ac,
        minimal_chain_summary_path=minimal,
        output=tmp_path / "post_h3_readiness_index.json",
    )

    assert report["passed"] is True
    assert report["status"] == "post_h3_observer_ready_minimal_production_task_chain_blueprint_ready"
    assert report["readiness"]["minimal_production_task_chain_blueprint_ready"] is True
    assert report["boundary"]["runtime_execution_allowed"] is False


def test_post_h3_readiness_index_rejects_minimal_chain_execution_claim(tmp_path: Path, monkeypatch: Any) -> None:
    post_h3ac = _write_post_h3ac_fixture(tmp_path, monkeypatch)
    minimal = _write_minimal_chain_fixture(tmp_path, post_h3ac)
    payload = json.loads(minimal.read_text(encoding="utf-8"))
    payload["readiness"]["production_task_execution_allowed"] = True
    minimal.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report = build_index(
        post_h3ac_summary_path=post_h3ac,
        minimal_chain_summary_path=minimal,
        output=tmp_path / "post_h3_readiness_index.json",
    )

    assert report["passed"] is False
    assert "minimal_chain_no_execution_allowed" in report["failure_reasons"]
    assert report["readiness"]["production_task_execution_allowed"] is False


def _write_post_h3ac_fixture(tmp_path: Path, monkeypatch: Any) -> Path:
    post_h3ab = _write_post_h3ab_fixture(tmp_path, monkeypatch)
    post_h3ac_root = tmp_path / "post_h3ac"
    run_post_h3ac(
        post_h3ab_summary_path=post_h3ab,
        output_root=post_h3ac_root,
        ack_observer_readiness=True,
    )
    return post_h3ac_root / "post_h3ac_observer_mode_readiness_summary.json"


def _write_minimal_chain_fixture(tmp_path: Path, post_h3ac: Path) -> Path:
    root = tmp_path / "minimal_chain"
    run_minimal_chain(post_h3ac_summary_path=post_h3ac, output_root=root)
    return root / "post_h3_minimal_production_task_chain_summary.json"
