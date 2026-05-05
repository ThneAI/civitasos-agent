from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h2_value_calibration_report import build_h2_value_calibration_report


def test_h2_value_calibration_report_builds_boundary_metrics(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [
            _record(
                "alpha:A01",
                agent_alias="alpha",
                candidates=[
                    {"state": "Predicted", "update_kind": "post_delivery_telos_observation"},
                    {
                        "state": "Desired",
                        "update_kind": "delayed_repeated_pattern_slow_drift_candidate",
                        "event_kind": "post_delivery_dispute",
                        "pattern_count": 2,
                        "requires_repeated_pattern": True,
                        "local_mutation_allowed": False,
                    },
                    {
                        "state": "Normative",
                        "update_kind": "governance_trace_only",
                        "local_mutation_allowed": False,
                        "blocked_or_governed": True,
                    },
                ],
                delayed_events=[{"event_kind": "post_delivery_dispute", "source": "benchmark_seed"}],
                normative_status={
                    "required": True,
                    "local_mutation_allowed": False,
                    "blocked_or_governed": True,
                },
            ),
            _record(
                "alpha:A02",
                agent_alias="alpha",
                candidates=[{"state": "Predicted", "update_kind": "post_delivery_terminal_observation"}],
            ),
        ],
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
    )

    assert report["passed"] is True
    assert report["checks"]["repeated_outcome_pattern_count"] is True
    assert report["checks"]["normative_local_mutation_forbidden"] is True
    assert report["checks"]["desired_slow_drift_requires_repeated_pattern"] is True
    assert report["metrics"]["outcome_record_count"] == 2
    assert report["metrics"]["value_calibration_trace_coverage_ratio"] == 1.0
    assert report["metrics"]["predicted_update_candidate_count"] == 2
    assert report["metrics"]["desired_slow_drift_candidate_count"] == 1
    assert report["metrics"]["repeated_outcome_pattern_count"] == 1
    assert report["metrics"]["backend_sourced_repeated_outcome_pattern_count"] == 0
    assert report["metrics"]["repeated_outcome_pattern_source_counts"] == {"benchmark_seed": 1}
    assert report["metrics"]["repeated_outcome_event_kinds"] == ["post_delivery_dispute"]
    assert report["metrics"]["repeated_outcome_patterns"] == [
        {
            "identity": "alpha",
            "event_kind": "post_delivery_dispute",
            "max_pattern_count": 2,
            "candidate_count": 1,
            "record_ids": ["alpha:A01"],
            "sources": ["benchmark_seed"],
        }
    ]
    assert report["metrics"]["normative_mutation_blocked_count"] == 1


def test_h2_value_calibration_report_can_require_repeated_patterns(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [_record("alpha:A01", candidates=[{"state": "Predicted", "update_kind": "post_delivery"}])],
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
        min_repeated_outcome_pattern_count=1,
    )

    assert report["passed"] is False
    assert report["checks"]["repeated_outcome_pattern_count"] is False
    assert report["metrics"]["repeated_outcome_pattern_count"] == 0


def test_h2_value_calibration_report_can_require_repeated_event_kinds(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [
            _record(
                "alpha:A01",
                candidates=[
                    {
                        "state": "Desired",
                        "update_kind": "delayed_repeated_pattern_slow_drift_candidate",
                        "event_kind": "post_delivery_dispute",
                        "pattern_count": 2,
                        "requires_repeated_pattern": True,
                    }
                ],
            )
        ],
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
        required_repeated_outcome_event_kinds=["post_delivery_dispute", "economic_deviation"],
    )

    assert report["passed"] is False
    assert report["checks"]["required_repeated_outcome_event_kinds"] is False
    assert report["metrics"]["repeated_outcome_event_kinds"] == ["post_delivery_dispute"]
    assert any("economic_deviation" in reason for reason in report["failure_reasons"])


def test_h2_value_calibration_report_can_require_backend_sourced_repeated_patterns(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [
            _record(
                "alpha:A01",
                candidates=[
                    {
                        "state": "Desired",
                        "update_kind": "delayed_repeated_pattern_slow_drift_candidate",
                        "event_kind": "post_delivery_dispute",
                        "pattern_count": 2,
                        "requires_repeated_pattern": True,
                    }
                ],
                delayed_events=[{"event_kind": "post_delivery_dispute", "source": "benchmark_seed"}],
            )
        ],
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
        min_backend_sourced_repeated_outcome_pattern_count=1,
    )

    assert report["passed"] is False
    assert report["checks"]["backend_sourced_repeated_outcome_pattern_count"] is False
    assert report["metrics"]["backend_sourced_repeated_outcome_pattern_count"] == 0
    assert report["metrics"]["repeated_outcome_pattern_source_counts"] == {"benchmark_seed": 1}


def test_h2_value_calibration_report_counts_backend_sourced_repeated_patterns(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [
            _record(
                "alpha:A01",
                candidates=[
                    {
                        "state": "Desired",
                        "update_kind": "delayed_repeated_pattern_slow_drift_candidate",
                        "event_kind": "post_delivery_dispute",
                        "pattern_count": 2,
                        "requires_repeated_pattern": True,
                    }
                ],
                delayed_events=[{"event_kind": "post_delivery_dispute", "source": "backend_task_pool_read_model"}],
            )
        ],
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
        min_backend_sourced_repeated_outcome_pattern_count=1,
    )

    assert report["passed"] is True
    assert report["metrics"]["backend_sourced_repeated_outcome_pattern_count"] == 1
    assert report["metrics"]["repeated_outcome_pattern_source_counts"] == {"backend_task_pool_read_model": 1}


def test_h2_value_calibration_report_counts_protocol_backend_source(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [
            _record(
                "protocol_governance:upgrade-1.0.0-to-1.1.0",
                agent_alias="protocol_governance",
                candidates=[
                    {
                        "state": "Desired",
                        "update_kind": "delayed_repeated_pattern_slow_drift_candidate",
                        "event_kind": "governance_rollback",
                        "pattern_count": 2,
                        "requires_repeated_pattern": True,
                    }
                ],
                delayed_events=[{"event_kind": "governance_rollback", "source": "backend_protocol_upgrade_read_model"}],
            )
        ],
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
        min_backend_sourced_repeated_outcome_pattern_count=1,
        required_repeated_outcome_event_kinds=["governance_rollback"],
    )

    assert report["passed"] is True
    assert report["metrics"]["backend_sourced_repeated_outcome_pattern_count"] == 1
    assert report["metrics"]["repeated_outcome_pattern_source_counts"] == {
        "backend_protocol_upgrade_read_model": 1
    }


def test_h2_value_calibration_report_counts_economic_backend_source(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [
            _record(
                "worker-1:economic-1",
                agent_alias="worker-1",
                candidates=[
                    {
                        "state": "Desired",
                        "update_kind": "delayed_repeated_pattern_slow_drift_candidate",
                        "event_kind": "economic_deviation",
                        "pattern_count": 2,
                        "requires_repeated_pattern": True,
                    }
                ],
                delayed_events=[{"event_kind": "economic_deviation", "source": "backend_economic_read_model"}],
            )
        ],
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
        min_backend_sourced_repeated_outcome_pattern_count=1,
        required_repeated_outcome_event_kinds=["economic_deviation"],
    )

    assert report["passed"] is True
    assert report["metrics"]["backend_sourced_repeated_outcome_pattern_count"] == 1
    assert report["metrics"]["repeated_outcome_pattern_source_counts"] == {
        "backend_economic_read_model": 1
    }


def test_h2_value_calibration_report_groups_repeated_pattern_records(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [
            _record(
                "alpha:A01",
                agent_alias="alpha",
                candidates=[
                    {
                        "state": "Desired",
                        "update_kind": "delayed_repeated_pattern_slow_drift_candidate",
                        "event_kind": "post_delivery_dispute",
                        "pattern_count": 2,
                        "requires_repeated_pattern": True,
                    }
                ],
            ),
            _record(
                "alpha:A02",
                agent_alias="alpha",
                candidates=[
                    {
                        "state": "Desired",
                        "update_kind": "delayed_repeated_pattern_slow_drift_candidate",
                        "event_kind": "post_delivery_dispute",
                        "pattern_count": 2,
                        "requires_repeated_pattern": True,
                    }
                ],
            ),
        ],
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
        min_repeated_outcome_pattern_count=1,
    )

    assert report["passed"] is True
    assert report["metrics"]["repeated_outcome_patterns"] == [
        {
            "identity": "alpha",
            "event_kind": "post_delivery_dispute",
            "max_pattern_count": 2,
            "candidate_count": 2,
            "record_ids": ["alpha:A01", "alpha:A02"],
            "sources": [],
        }
    ]


def test_h2_value_calibration_report_fails_when_desired_drift_lacks_repeated_pattern(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [
            _record(
                "alpha:A01",
                candidates=[
                    {"state": "Predicted", "update_kind": "post_delivery_telos_observation"},
                    {"state": "Desired", "update_kind": "slow_drift_candidate"},
                ],
            ),
        ],
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["desired_slow_drift_requires_repeated_pattern"] is False
    assert report["metrics"]["desired_slow_drift_without_repeated_pattern_count"] == 1


def test_h2_value_calibration_report_fails_when_normative_mutation_is_allowed(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [
            _record(
                "alpha:A01",
                candidates=[
                    {"state": "Predicted", "update_kind": "post_delivery_telos_observation"},
                    {
                        "state": "Normative",
                        "update_kind": "governance_trace_only",
                        "local_mutation_allowed": True,
                        "blocked_or_governed": False,
                    },
                ],
                normative_status={
                    "required": True,
                    "local_mutation_allowed": True,
                    "blocked_or_governed": False,
                },
            ),
        ],
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["normative_local_mutation_forbidden"] is False
    assert report["metrics"]["normative_local_mutation_violation_count"] == 2


def test_h2_value_calibration_report_fails_on_failed_outcome_report(tmp_path: Path) -> None:
    outcome_report = _write_outcome_report(
        tmp_path,
        [_record("alpha:A01", candidates=[{"state": "Predicted", "update_kind": "post_delivery"}])],
        passed=False,
    )

    report = build_h2_value_calibration_report(
        outcome_report_path=outcome_report,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["outcome_report_passed"] is False


def _write_outcome_report(tmp_path: Path, records: list[dict], *, passed: bool = True) -> Path:
    path = tmp_path / "h2_outcome_report.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h2-outcome-report:v1",
                "passed": passed,
                "records": records,
            }
        ),
        encoding="utf-8",
    )
    return path


def _record(
    record_id: str,
    *,
    agent_alias: str = "alpha",
    candidates: list[dict] | None = None,
    delayed_events: list[dict] | None = None,
    normative_status: dict | None = None,
) -> dict:
    return {
        "record_id": record_id,
        "task_id": record_id.split(":", 1)[-1],
        "agent_alias": agent_alias,
        "iem_update_candidates": candidates or [],
        "delayed_events": delayed_events or [],
        "normative_update_blocked_or_governed": normative_status
        or {"required": False, "local_mutation_allowed": False},
    }
