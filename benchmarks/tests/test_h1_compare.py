from __future__ import annotations

import json
from pathlib import Path

from benchmarks.h1_compare import compare_runs


def _write_payloads(
    runs_root: Path,
    *,
    jaccard_ratio: float,
    sentinel_violations: int,
    ii2_passed: bool,
    identity_score: float,
    m1: float | None = None,
    m2: float | None = None,
) -> None:
    runs_root.mkdir(parents=True, exist_ok=True)
    ii2 = {
        "overall_identity_score": identity_score,
        "agents": [
            {"agent_alias": "alpha", "identity_score": identity_score},
            {"agent_alias": "beta", "identity_score": identity_score},
            {"agent_alias": "gamma", "identity_score": identity_score},
        ],
    }
    (runs_root / "ii2_scorecard.json").write_text(
        json.dumps(ii2),
        encoding="utf-8",
    )
    merge = {
        "jaccard_flagged_ratio": jaccard_ratio,
        "integrity_gate": {"passed": True},
        "sentinel_gate": {"passed": sentinel_violations == 0, "violation_count": sentinel_violations},
        "ii2_gate": {"passed": ii2_passed},
        "ii2_scorecard_json": str(runs_root / "ii2_scorecard.json"),
    }
    (runs_root / "merge_summary.json").write_text(
        json.dumps(merge),
        encoding="utf-8",
    )
    if m1 is not None or m2 is not None:
        (runs_root / "final_metrics.csv").write_text(
            "run_id,agent_id,category_id,targets_disease,task_count,"
            "m1_result_deviation_rate,m2_verification_miss_rate\n"
            f"r,agent,R01,R,1,{'' if m1 is None else m1},{'' if m2 is None else m2}\n",
            encoding="utf-8",
        )


def test_compare_runs_passes_for_non_regression(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    _write_payloads(
        baseline,
        jaccard_ratio=0.20,
        sentinel_violations=0,
        ii2_passed=True,
        identity_score=0.61,
    )
    _write_payloads(
        candidate,
        jaccard_ratio=0.18,
        sentinel_violations=0,
        ii2_passed=True,
        identity_score=0.64,
    )

    report = compare_runs(
        baseline_runs_root=baseline,
        candidate_runs_root=candidate,
        max_jaccard_regression=0.02,
        min_identity_delta=-0.01,
        min_result_deviation_reduction=-1.0,
        min_verification_miss_reduction=-1.0,
        require_sentinel_zero=True,
    )
    assert report["passed"] is True


def test_compare_runs_fails_when_candidate_has_sentinel_violations(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    _write_payloads(
        baseline,
        jaccard_ratio=0.20,
        sentinel_violations=0,
        ii2_passed=True,
        identity_score=0.61,
    )
    _write_payloads(
        candidate,
        jaccard_ratio=0.19,
        sentinel_violations=2,
        ii2_passed=True,
        identity_score=0.63,
    )

    report = compare_runs(
        baseline_runs_root=baseline,
        candidate_runs_root=candidate,
        max_jaccard_regression=0.02,
        min_identity_delta=-0.01,
        min_result_deviation_reduction=-1.0,
        min_verification_miss_reduction=-1.0,
        require_sentinel_zero=True,
    )
    assert report["passed"] is False
    assert report["checks"]["candidate_sentinel_zero"] is False


def test_compare_runs_reports_h1_quality_reductions(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    _write_payloads(
        baseline,
        jaccard_ratio=0.20,
        sentinel_violations=0,
        ii2_passed=True,
        identity_score=0.61,
        m1=0.40,
        m2=0.50,
    )
    _write_payloads(
        candidate,
        jaccard_ratio=0.18,
        sentinel_violations=0,
        ii2_passed=True,
        identity_score=0.64,
        m1=0.18,
        m2=0.20,
    )

    report = compare_runs(
        baseline_runs_root=baseline,
        candidate_runs_root=candidate,
        max_jaccard_regression=0.02,
        min_identity_delta=-0.01,
        min_result_deviation_reduction=0.50,
        min_verification_miss_reduction=0.50,
        require_sentinel_zero=True,
    )
    assert report["passed"] is True
    assert report["checks"]["result_deviation_reduction_ok"] is True
    assert report["checks"]["verification_miss_reduction_ok"] is True


def test_compare_runs_fails_when_result_deviation_reduction_is_too_small(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    _write_payloads(
        baseline,
        jaccard_ratio=0.20,
        sentinel_violations=0,
        ii2_passed=True,
        identity_score=0.61,
        m1=0.40,
        m2=0.50,
    )
    _write_payloads(
        candidate,
        jaccard_ratio=0.18,
        sentinel_violations=0,
        ii2_passed=True,
        identity_score=0.64,
        m1=0.30,
        m2=0.20,
    )

    report = compare_runs(
        baseline_runs_root=baseline,
        candidate_runs_root=candidate,
        max_jaccard_regression=0.02,
        min_identity_delta=-0.01,
        min_result_deviation_reduction=0.50,
        min_verification_miss_reduction=0.50,
        require_sentinel_zero=True,
    )
    assert report["passed"] is False
    assert report["checks"]["result_deviation_reduction_ok"] is False
