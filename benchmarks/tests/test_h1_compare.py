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
        require_sentinel_zero=True,
    )
    assert report["passed"] is False
    assert report["checks"]["candidate_sentinel_zero"] is False
