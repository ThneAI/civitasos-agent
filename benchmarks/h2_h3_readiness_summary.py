"""Summarize H.2 maturity and H.3 read-only proposal readiness.

The summary is informational and artifact-only. A blocked H.2 report is a valid
input and produces an actionable list of remaining evidence requirements
without failing the summary process itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h2-h3-readiness-summary:v1"
H2_SCHEMA_VERSION = "h2-delayed-consequence-evidence-check:v1"
H3_SCHEMA_VERSION = "h3-read-only-goal-proposal-gate:v1"


def build_h2_h3_readiness_summary(
    *,
    h2_evidence_report_path: Path,
    agent_root: Path,
    h3_proposal_report_path: Path | None = None,
) -> dict[str, Any]:
    h2_path = _resolve(h2_evidence_report_path, agent_root)
    failures: list[str] = []
    h2 = _read_json(h2_path, failures)
    if h2 is not None and h2.get("schema_version") != H2_SCHEMA_VERSION:
        failures.append(f"unexpected H2 schema: {h2.get('schema_version')!r}")

    h3_path = _resolve(h3_proposal_report_path, agent_root) if h3_proposal_report_path else None
    h3: dict[str, Any] | None = None
    if h3_path is not None:
        h3 = _read_json(h3_path, failures)
        if h3 is not None and h3.get("schema_version") != H3_SCHEMA_VERSION:
            failures.append(f"unexpected H3 schema: {h3.get('schema_version')!r}")

    metrics = _object(h2.get("metrics")) if h2 else {}
    thresholds = _object(h2.get("thresholds")) if h2 else {}
    h2_checks = _object(h2.get("checks")) if h2 else {}
    missing_requirements = _missing_requirements(metrics, thresholds, h2_checks)
    h2_ready = bool(
        h2
        and h2.get("passed") is True
        and _object(h2.get("h3_readiness")).get("ready") is True
    )
    h3_ready = bool(
        h3
        and h3.get("passed") is True
        and _object(h3.get("readiness")).get("read_only_proposal_surface_ready") is True
    )

    structurally_valid = not failures and h2 is not None
    if h3_ready:
        status = "h3_read_only_goal_proposals_ready_for_review"
    elif h2_ready:
        status = "ready_to_run_h3_read_only_goal_proposal_gate"
    else:
        status = "blocked_collecting_h2_delayed_consequence_evidence"

    return {
        "schema_version": SCHEMA_VERSION,
        "passed": structurally_valid,
        "failure_reasons": failures,
        "status": status,
        "h2": {
            "report": _artifact_ref(h2_path),
            "ready": h2_ready,
            "decision": _object(h2.get("h3_readiness")).get("decision") if h2 else None,
            "metrics": metrics,
            "thresholds": thresholds,
            "missing_requirements": missing_requirements,
        },
        "h3_read_only_proposal": {
            "report": _artifact_ref(h3_path) if h3_path else None,
            "ready": h3_ready,
            "decision": (
                _object(h3.get("readiness")).get("decision")
                if h3
                else "not_run"
            ),
            "proposal_count": (
                _object(h3.get("proposal_surface")).get("proposal_count", 0)
                if h3
                else 0
            ),
        },
        "next_action": (
            "review read-only proposals; do not emit or execute goals"
            if h3_ready
            else (
                "run h3_read_only_goal_proposal_gate"
                if h2_ready
                else "collect only the missing H.2 evidence listed in this summary"
            )
        ),
        "boundary": {
            "artifact_only": True,
            "runtime_mutation_allowed": False,
            "goal_emission_allowed": False,
            "goal_execution_allowed": False,
            "normative_local_mutation_allowed": False,
            "production_transition_allowed": False,
        },
    }


def _missing_requirements(
    metrics: dict[str, Any],
    thresholds: dict[str, Any],
    checks: dict[str, Any],
) -> list[dict[str, Any]]:
    missing: list[dict[str, Any]] = []
    for metric_name, threshold_name in (
        ("owner_count", "min_owner_count"),
        ("task_count", "min_task_count"),
        ("observation_day_count", "min_observation_days"),
        ("observation_span_seconds", "min_observation_span_seconds"),
        ("iem_change_ratio", "min_iem_change_ratio"),
        ("relation_change_ratio", "min_relation_change_ratio"),
        ("authorization_change_count", "min_authorization_change_count"),
        ("negative_authorization_change_count", "min_authorization_change_count"),
        ("normative_local_update_blocked_ratio", "min_normative_blocked_ratio"),
    ):
        current = _number(metrics.get(metric_name))
        required = _number(thresholds.get(threshold_name))
        if current is None or required is None or current < required:
            missing.append(
                {
                    "kind": "threshold",
                    "metric": metric_name,
                    "current": current,
                    "required": required,
                    "remaining": (
                        max(0.0, required - current)
                        if current is not None and required is not None
                        else None
                    ),
                }
            )
    for check_name, passed in sorted(checks.items()):
        if passed is not True and check_name not in {
            "minimum_owner_count",
            "minimum_task_count",
            "minimum_observation_days",
            "minimum_observation_span_seconds",
            "minimum_iem_change_ratio",
            "minimum_relation_change_ratio",
            "minimum_authorization_change_count",
            "negative_outcomes_change_authorization",
            "minimum_normative_blocked_ratio",
        }:
            missing.append(
                {
                    "kind": "integrity_check",
                    "check": check_name,
                    "current": False,
                    "required": True,
                }
            )
    return missing


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"missing report: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"invalid report {path}: {exc}")
        return None
    if not isinstance(value, dict):
        failures.append(f"expected JSON object: {path}")
        return None
    return value


def _artifact_ref(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
    }


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _resolve(path: Path, root: Path) -> Path:
    return path if path.is_absolute() else (root / path).resolve()


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--h2-evidence-report", type=Path, required=True)
    parser.add_argument("--h3-proposal-report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report = build_h2_h3_readiness_summary(
        h2_evidence_report_path=args.h2_evidence_report,
        h3_proposal_report_path=args.h3_proposal_report,
        agent_root=agent_root,
    )
    output = _resolve(args.output, agent_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
