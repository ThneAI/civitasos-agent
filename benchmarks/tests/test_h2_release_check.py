from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h2_release_check import check_h2_release


def test_h2_release_check_passes_for_complete_evidence(tmp_path: Path) -> None:
    run_root = _write_h2_release_payloads(tmp_path)

    report = _run_check(run_root, tmp_path)

    assert report["passed"] is True
    assert report["checks"]["h2_gate_not_skipped"] is True
    assert report["checks"]["outcome_report_passed"] is True
    assert report["checks"]["backend_outcome_events_valid"] is True


def test_h2_release_check_fails_closed_when_h2_gate_skipped(tmp_path: Path) -> None:
    run_root = _write_h2_release_payloads(tmp_path)
    summary = _read_json(run_root / "merge_summary.json")
    summary["h2_gate"]["skipped"] = True
    summary["h2_gate"]["require_active"] = False
    _write_json(run_root / "merge_summary.json", summary)

    report = _run_check(run_root, tmp_path)

    assert report["passed"] is False
    assert report["checks"]["h2_gate_not_skipped"] is False
    assert report["checks"]["h2_gate_require_active"] is False


def test_h2_release_check_fails_closed_on_outcome_report_regression(tmp_path: Path) -> None:
    run_root = _write_h2_release_payloads(tmp_path)
    outcome_report = _read_json(run_root / "h2_outcome_report.json")
    outcome_report["passed"] = False
    outcome_report["metrics"]["h1_evidence_ref_ratio"] = 0.5
    outcome_report["checks"]["h1_evidence_ref_ratio"] = False
    _write_json(run_root / "h2_outcome_report.json", outcome_report)

    report = _run_check(run_root, tmp_path)

    assert report["passed"] is False
    assert report["checks"]["outcome_report_passed"] is False
    assert report["checks"]["h1_evidence_ref_ratio"] is False


def test_h2_release_check_fails_when_backend_artifact_required_but_missing(tmp_path: Path) -> None:
    run_root = _write_h2_release_payloads(tmp_path, include_backend=False)

    report = _run_check(run_root, tmp_path, require_backend=True)

    assert report["passed"] is False
    assert report["checks"]["backend_outcome_events_present"] is False


def test_h2_release_check_rejects_truncated_backend_artifact(tmp_path: Path) -> None:
    run_root = _write_h2_release_payloads(tmp_path)
    backend_artifact = _read_json(run_root / "backend_outcome_events.json")
    backend_artifact["total"] = 2
    backend_artifact["returned"] = 1
    _write_json(run_root / "backend_outcome_events.json", backend_artifact)

    report = _run_check(run_root, tmp_path)

    assert report["passed"] is False
    assert report["checks"]["backend_outcome_events_valid"] is False
    assert any("truncated" in reason for reason in report["failure_reasons"])


def _run_check(
    run_root: Path,
    agent_root: Path,
    *,
    require_backend: bool = True,
) -> dict:
    return check_h2_release(
        run_root=run_root,
        outcome_report_path=None,
        backend_outcome_events_path=None,
        agent_root=agent_root,
        min_outcome_record_count=1,
        min_delayed_event_count=1,
        min_outcome_ledger_coverage_ratio=1.0,
        min_h1_evidence_ref_ratio=1.0,
        min_normative_local_update_blocked_ratio=1.0,
        min_delayed_verifier_coverage_ratio=1.0,
        require_backend_outcome_events=require_backend,
        allow_truncated_backend_outcome_events=False,
    )


def _write_h2_release_payloads(tmp_path: Path, *, include_backend: bool = True) -> Path:
    run_root = tmp_path / "runs" / "h2"
    backend_path = run_root / "backend_outcome_events.json"
    report_backend_path = str(backend_path) if include_backend else None
    _write_json(
        run_root / "merge_summary.json",
        {
            "integrity_gate": {"passed": True},
            "sentinel_gate": {"passed": True},
            "ii2_gate": {"passed": True},
            "g2_gate": {"passed": True},
            "g3_gate": {"passed": True},
            "h0_gate": {"passed": True},
            "h1_gate": {"passed": True},
            "h2_gate": {
                "passed": True,
                "skipped": False,
                "require_active": True,
                "report_path": str(run_root / "h2_outcome_report.json"),
                "g3_carry_through_passed": True,
                "h0_carry_through_passed": True,
                "h1_carry_through_passed": True,
                "outcome_report": {
                    "passed": True,
                    "backend_outcome_events_path": report_backend_path,
                },
            },
        },
    )
    _write_json(
        run_root / "h2_outcome_report.json",
        {
            "schema_version": "h2-outcome-report:v1",
            "passed": True,
            "failure_reasons": [],
            "run_root": str(run_root),
            "judge_report_path": str(run_root / "h1_llm_judge_report.json"),
            "delayed_outcomes_path": None,
            "backend_outcome_events_path": report_backend_path,
            "checks": {
                "outcome_ledger_coverage_ratio": True,
                "h1_evidence_ref_ratio": True,
                "normative_local_update_blocked_ratio": True,
                "delayed_verifier_coverage_ratio": True,
            },
            "metrics": {
                "expected_task_count": 1,
                "outcome_record_count": 1,
                "outcome_ledger_coverage_ratio": 1.0,
                "h1_evidence_ref_ratio": 1.0,
                "normative_local_update_blocked_ratio": 1.0,
                "delayed_event_count": 1,
                "delayed_event_record_count": 1,
                "delayed_verifier_coverage_ratio": 1.0,
            },
            "records": [{"record_id": "alpha:A01"}],
        },
    )
    if include_backend:
        _write_json(
            backend_path,
            {
                "schema_version": "h2-delayed-outcome-events:v1",
                "source": "backend_task_pool_read_model",
                "events": [_backend_event("backend-A01")],
                "total": 1,
                "returned": 1,
                "limit": 500,
                "filters": {},
            },
        )
    return run_root


def _backend_event(task_id: str) -> dict:
    return {
        "event_id": f"backend-task-outcome:{task_id}:completed",
        "agent_alias": "did:alpha",
        "agent_id": "did:alpha",
        "task_id": task_id,
        "event_kind": "settlement_confirmed",
        "observed_at": "2026-05-04T02:00:00+00:00",
        "source": "backend_task_pool_read_model",
        "subject": "did:alpha",
        "evidence_ref": {
            "ref_id": f"task_pool:{task_id}:completed",
            "source": "backend_task_pool_read_model",
            "task_status": "Completed",
        },
        "verifier_or_settlement_read": True,
        "outcome_status": "completed",
    }


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))