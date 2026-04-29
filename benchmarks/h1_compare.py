"""H.1 baseline compare scaffold.

Compares two benchmark run roots (both must already have merge output) and
emits a compact regression report suitable for CI/nightly checks.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path}")
    return payload


def _load_merge_summary(runs_root: Path) -> dict[str, Any]:
    path = runs_root / "merge_summary.json"
    if not path.exists():
        raise FileNotFoundError(f"missing merge_summary.json under {runs_root}")
    return _read_json(path)


def _load_ii2_scorecard(runs_root: Path, summary: dict[str, Any]) -> dict[str, Any]:
    from_summary = summary.get("ii2_scorecard_json")
    if isinstance(from_summary, str) and from_summary.strip():
        p = Path(from_summary)
        if not p.exists():
            p = runs_root / from_summary
        if p.exists():
            return _read_json(p)
    fallback = runs_root / "ii2_scorecard.json"
    if not fallback.exists():
        raise FileNotFoundError(f"missing ii2_scorecard.json under {runs_root}")
    return _read_json(fallback)


def _agent_identity(scorecard: dict[str, Any]) -> dict[str, float]:
    agents = scorecard.get("agents")
    if not isinstance(agents, list):
        return {}
    out: dict[str, float] = {}
    for row in agents:
        if not isinstance(row, dict):
            continue
        alias = str(row.get("agent_alias", "")).strip()
        if not alias:
            continue
        try:
            out[alias] = float(row.get("identity_score", 0.0))
        except (TypeError, ValueError):
            out[alias] = 0.0
    return out


def compare_runs(
    *,
    baseline_runs_root: Path,
    candidate_runs_root: Path,
    max_jaccard_regression: float,
    min_identity_delta: float,
    require_sentinel_zero: bool,
) -> dict[str, Any]:
    baseline_summary = _load_merge_summary(baseline_runs_root)
    candidate_summary = _load_merge_summary(candidate_runs_root)
    baseline_ii2 = _load_ii2_scorecard(baseline_runs_root, baseline_summary)
    candidate_ii2 = _load_ii2_scorecard(candidate_runs_root, candidate_summary)

    baseline_jaccard = float(baseline_summary.get("jaccard_flagged_ratio", 0.0) or 0.0)
    candidate_jaccard = float(candidate_summary.get("jaccard_flagged_ratio", 0.0) or 0.0)
    baseline_identity = float(baseline_ii2.get("overall_identity_score", 0.0) or 0.0)
    candidate_identity = float(candidate_ii2.get("overall_identity_score", 0.0) or 0.0)
    baseline_sentinel = int(
        baseline_summary.get("sentinel_gate", {}).get("violation_count", 0) or 0,
    )
    candidate_sentinel = int(
        candidate_summary.get("sentinel_gate", {}).get("violation_count", 0) or 0,
    )

    baseline_agents = _agent_identity(baseline_ii2)
    candidate_agents = _agent_identity(candidate_ii2)
    aliases = sorted(set(baseline_agents) | set(candidate_agents))
    per_agent = [
        {
            "agent_alias": alias,
            "baseline_identity_score": baseline_agents.get(alias),
            "candidate_identity_score": candidate_agents.get(alias),
            "delta": (
                candidate_agents.get(alias, 0.0) - baseline_agents.get(alias, 0.0)
            ),
        }
        for alias in aliases
    ]

    checks = {
        "jaccard_non_regression": candidate_jaccard <= baseline_jaccard + max_jaccard_regression,
        "identity_delta_ok": (candidate_identity - baseline_identity) >= min_identity_delta,
        "candidate_integrity_gate": bool(candidate_summary.get("integrity_gate", {}).get("passed", False)),
        "candidate_sentinel_gate": bool(candidate_summary.get("sentinel_gate", {}).get("passed", False)),
        "candidate_ii2_gate": bool(candidate_summary.get("ii2_gate", {}).get("passed", False)),
    }
    if require_sentinel_zero:
        checks["candidate_sentinel_zero"] = candidate_sentinel == 0

    return {
        "baseline_runs_root": str(baseline_runs_root),
        "candidate_runs_root": str(candidate_runs_root),
        "thresholds": {
            "max_jaccard_regression": max_jaccard_regression,
            "min_identity_delta": min_identity_delta,
            "require_sentinel_zero": require_sentinel_zero,
        },
        "baseline": {
            "jaccard_flagged_ratio": baseline_jaccard,
            "overall_identity_score": baseline_identity,
            "sentinel_violation_count": baseline_sentinel,
        },
        "candidate": {
            "jaccard_flagged_ratio": candidate_jaccard,
            "overall_identity_score": candidate_identity,
            "sentinel_violation_count": candidate_sentinel,
        },
        "delta": {
            "jaccard_flagged_ratio": candidate_jaccard - baseline_jaccard,
            "overall_identity_score": candidate_identity - baseline_identity,
            "sentinel_violation_count": candidate_sentinel - baseline_sentinel,
        },
        "per_agent": per_agent,
        "checks": checks,
        "passed": all(checks.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-runs-root", required=True)
    parser.add_argument("--candidate-runs-root", required=True)
    parser.add_argument("--max-jaccard-regression", type=float, default=0.02)
    parser.add_argument("--min-identity-delta", type=float, default=-0.01)
    parser.add_argument("--allow-sentinel-violations", action="store_true")
    args = parser.parse_args()

    report = compare_runs(
        baseline_runs_root=Path(args.baseline_runs_root),
        candidate_runs_root=Path(args.candidate_runs_root),
        max_jaccard_regression=args.max_jaccard_regression,
        min_identity_delta=args.min_identity_delta,
        require_sentinel_zero=not args.allow_sentinel_violations,
    )
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
