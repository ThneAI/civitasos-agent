from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h2_value_calibration_closure import (
    BACKEND_REPEATED_PATTERN_SOURCE,
    BACKEND_REPEATED_PATTERN_SOURCES,
    build_h2_value_calibration_closure,
)


def test_h2_value_calibration_closure_passes_for_backend_sourced_evidence(tmp_path: Path) -> None:
    value_report = _write_value_report(
        tmp_path,
        repeated_patterns=[_pattern("post_delivery_dispute", sources=[BACKEND_REPEATED_PATTERN_SOURCE])],
    )

    report = build_h2_value_calibration_closure(
        value_report_path=value_report,
        agent_root=tmp_path,
        min_repeated_outcome_pattern_count=1,
        min_backend_sourced_repeated_outcome_pattern_count=1,
        required_backend_sourced_repeated_outcome_event_kinds=["post_delivery_dispute"],
    )

    assert report["passed"] is True
    assert report["h3_goal_generator_readiness"]["ready"] is True
    assert report["h3_goal_generator_readiness"]["decision"] == "ready_for_h3_goal_generator_skeleton"
    assert report["checks"]["backend_sourced_repeated_outcome_pattern_count"] is True
    assert report["evidence"]["backend_sourced_repeated_outcome_event_kinds"] == ["post_delivery_dispute"]
    assert report["closure_boundary"]["seed_patterns_count_as_h3_backend_readiness"] is False


def test_h2_value_calibration_closure_blocks_seed_only_patterns(tmp_path: Path) -> None:
    value_report = _write_value_report(
        tmp_path,
        repeated_patterns=[_pattern("post_delivery_dispute", sources=["benchmark_seed"])],
    )

    report = build_h2_value_calibration_closure(
        value_report_path=value_report,
        agent_root=tmp_path,
        min_backend_sourced_repeated_outcome_pattern_count=1,
    )

    assert report["passed"] is False
    assert report["h3_goal_generator_readiness"]["ready"] is False
    assert report["h3_goal_generator_readiness"]["decision"] == "blocked_before_h3"
    assert report["checks"]["backend_sourced_repeated_outcome_pattern_count"] is False
    assert any("backend_sourced_repeated_outcome_pattern_count" in reason for reason in report["failure_reasons"])


def test_h2_value_calibration_closure_can_require_backend_sourced_event_kinds(tmp_path: Path) -> None:
    value_report = _write_value_report(
        tmp_path,
        repeated_patterns=[
            _pattern("post_delivery_dispute", sources=[BACKEND_REPEATED_PATTERN_SOURCE]),
            _pattern("economic_deviation", sources=["benchmark_seed"]),
        ],
    )

    report = build_h2_value_calibration_closure(
        value_report_path=value_report,
        agent_root=tmp_path,
        min_backend_sourced_repeated_outcome_pattern_count=1,
        required_repeated_outcome_event_kinds=["post_delivery_dispute", "economic_deviation"],
        required_backend_sourced_repeated_outcome_event_kinds=["post_delivery_dispute", "economic_deviation"],
    )

    assert report["passed"] is False
    assert report["checks"]["required_repeated_outcome_event_kinds"] is True
    assert report["checks"]["required_backend_sourced_repeated_outcome_event_kinds"] is False
    assert report["evidence"]["missing_backend_sourced_repeated_outcome_event_kinds"] == ["economic_deviation"]


def test_h2_value_calibration_closure_counts_protocol_backend_source(tmp_path: Path) -> None:
    assert "backend_protocol_upgrade_read_model" in BACKEND_REPEATED_PATTERN_SOURCES
    value_report = _write_value_report(
        tmp_path,
        repeated_patterns=[_pattern("governance_rollback", sources=["backend_protocol_upgrade_read_model"])],
        metrics={"backend_sourced_repeated_outcome_pattern_count": 1},
    )

    report = build_h2_value_calibration_closure(
        value_report_path=value_report,
        agent_root=tmp_path,
        min_backend_sourced_repeated_outcome_pattern_count=1,
        required_backend_sourced_repeated_outcome_event_kinds=["governance_rollback"],
    )

    assert report["passed"] is True
    assert report["evidence"]["backend_sourced_repeated_outcome_event_kinds"] == ["governance_rollback"]


def test_h2_value_calibration_closure_counts_economic_backend_source(tmp_path: Path) -> None:
    assert "backend_economic_read_model" in BACKEND_REPEATED_PATTERN_SOURCES
    value_report = _write_value_report(
        tmp_path,
        repeated_patterns=[_pattern("economic_deviation", sources=["backend_economic_read_model"])],
        metrics={"backend_sourced_repeated_outcome_pattern_count": 1},
    )

    report = build_h2_value_calibration_closure(
        value_report_path=value_report,
        agent_root=tmp_path,
        min_backend_sourced_repeated_outcome_pattern_count=1,
        required_backend_sourced_repeated_outcome_event_kinds=["economic_deviation"],
    )

    assert report["passed"] is True
    assert report["evidence"]["backend_sourced_repeated_outcome_event_kinds"] == ["economic_deviation"]


def test_h2_value_calibration_closure_fails_on_boundary_regression(tmp_path: Path) -> None:
    value_report = _write_value_report(
        tmp_path,
        passed=False,
        checks={"normative_local_mutation_forbidden": False},
        metrics={"normative_local_mutation_violation_count": 1},
        repeated_patterns=[_pattern("post_delivery_dispute", sources=[BACKEND_REPEATED_PATTERN_SOURCE])],
    )

    report = build_h2_value_calibration_closure(
        value_report_path=value_report,
        agent_root=tmp_path,
    )

    assert report["passed"] is False
    assert report["checks"]["value_report_passed"] is False
    assert report["checks"]["value_report_check_normative_local_mutation_forbidden"] is False
    assert report["checks"]["normative_local_mutation_forbidden"] is False


def _write_value_report(
    tmp_path: Path,
    *,
    repeated_patterns: list[dict],
    passed: bool = True,
    checks: dict | None = None,
    metrics: dict | None = None,
) -> Path:
    default_checks = {
        "outcome_report_passed": True,
        "outcome_report_schema_version": True,
        "value_calibration_trace_coverage_ratio": True,
        "repeated_outcome_pattern_count": True,
        "backend_sourced_repeated_outcome_pattern_count": True,
        "normative_local_mutation_forbidden": True,
        "desired_slow_drift_requires_repeated_pattern": True,
        "required_repeated_outcome_event_kinds": True,
    }
    default_checks.update(checks or {})
    event_kinds = sorted({pattern["event_kind"] for pattern in repeated_patterns})
    source_counts: dict[str, int] = {}
    for pattern in repeated_patterns:
        sources = pattern.get("sources") or ["unknown"]
        for source in set(sources):
            source_counts[source] = source_counts.get(source, 0) + 1
    default_metrics = {
        "outcome_record_count": 1,
        "value_calibration_trace_record_count": 1,
        "value_calibration_trace_coverage_ratio": 1.0,
        "repeated_outcome_pattern_count": len(repeated_patterns),
        "backend_sourced_repeated_outcome_pattern_count": sum(
            1
            for pattern in repeated_patterns
            if any(source in BACKEND_REPEATED_PATTERN_SOURCES for source in pattern.get("sources", []))
        ),
        "repeated_outcome_pattern_source_counts": source_counts,
        "repeated_outcome_event_kinds": event_kinds,
        "repeated_outcome_patterns": repeated_patterns,
        "desired_slow_drift_without_repeated_pattern_count": 0,
        "normative_local_mutation_violation_count": 0,
    }
    default_metrics.update(metrics or {})
    path = tmp_path / "h2_value_calibration_report.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "h2-value-calibration-report:v1",
                "passed": passed,
                "failure_reasons": [] if passed else ["fixture boundary regression"],
                "outcome_report_path": str(tmp_path / "h2_outcome_report.json"),
                "thresholds": {},
                "checks": default_checks,
                "metrics": default_metrics,
            }
        ),
        encoding="utf-8",
    )
    return path


def _pattern(event_kind: str, *, sources: list[str]) -> dict:
    return {
        "identity": "alpha",
        "event_kind": event_kind,
        "max_pattern_count": 2,
        "candidate_count": 2,
        "record_ids": ["alpha:A01", "alpha:A02"],
        "sources": sources,
    }
