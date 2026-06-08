"""Build non-executable H.3 goal proposals from qualified H.2 evidence.

This gate is deliberately read-only. It consumes a passed cross-day H.2
delayed-consequence report and writes review proposals bound to its evidence.
It never calls an LLM, emits a goal, creates an executable plan, or mutates
runtime, IEM, relation, authorization, or normative state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h3-read-only-goal-proposal-gate:v1"
H2_SCHEMA_VERSION = "h2-delayed-consequence-evidence-check:v1"
H2_READY_DECISION = "ready_for_h3_read_only_goal_proposal_gate"
NEGATIVE_EVENT_KINDS = {
    "post_delivery_dispute",
    "post_delivery_failure",
}
ALLOWED_EVENT_KINDS = NEGATIVE_EVENT_KINDS | {"settlement_confirmed"}


def build_h3_read_only_goal_proposal_gate(
    *,
    h2_evidence_report_path: Path,
    agent_root: Path,
    max_proposals: int = 20,
) -> dict[str, Any]:
    path = _resolve(h2_evidence_report_path, agent_root)
    failures: list[str] = []
    checks: dict[str, bool] = {}
    h2_report = _read_json(path, failures)

    records: list[dict[str, Any]] = []
    source_reports: list[dict[str, Any]] = []
    if h2_report is None:
        _require(checks, failures, "h2_evidence_report_present", False)
    else:
        checks["h2_evidence_report_present"] = True
        _require_equal(
            checks,
            failures,
            "h2_schema_version",
            h2_report.get("schema_version"),
            H2_SCHEMA_VERSION,
        )
        _require(checks, failures, "h2_evidence_passed", h2_report.get("passed") is True)
        _require(
            checks,
            failures,
            "h2_integrity_passed",
            h2_report.get("integrity_passed") is True,
        )
        _require(
            checks,
            failures,
            "h2_maturity_passed",
            h2_report.get("maturity_passed") is True,
        )
        _require_equal(
            checks,
            failures,
            "h2_failure_class",
            h2_report.get("failure_class"),
            "none",
        )
        readiness = _object(h2_report.get("h3_readiness"))
        _require(checks, failures, "h2_h3_readiness_ready", readiness.get("ready") is True)
        _require_equal(
            checks,
            failures,
            "h2_h3_readiness_decision",
            readiness.get("decision"),
            H2_READY_DECISION,
        )
        _require_read_only_boundary(
            _object(h2_report.get("boundary")),
            checks=checks,
            failures=failures,
        )
        records = _objects(h2_report.get("records"))
        source_reports = _objects(h2_report.get("source_reports"))
        _require(checks, failures, "h2_records_present", bool(records))
        _require(checks, failures, "h2_source_reports_present", bool(source_reports))
        _validate_h2_records(records, source_reports, checks=checks, failures=failures)
        _validate_h2_metrics(h2_report, records, checks=checks, failures=failures)

    _require(checks, failures, "max_proposals_positive", max_proposals > 0)
    proposal_group_count = _proposal_group_count(records)
    _require(
        checks,
        failures,
        "proposal_capacity_sufficient",
        proposal_group_count <= max_proposals,
    )
    proposals: list[dict[str, Any]] = []
    if not failures and all(checks.values()):
        proposals = _build_proposals(records, max_proposals=max_proposals)
    _require(checks, failures, "read_only_proposals_present", bool(proposals))

    passed = not failures and all(checks.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "h2_evidence_report": {
            "path": str(path),
            "sha256": _sha256(path) if path.is_file() else None,
        },
        "checks": checks,
        "readiness": {
            "read_only_proposal_surface_ready": passed,
            "decision": (
                "h3_read_only_goal_proposals_ready_for_review"
                if passed
                else "blocked_before_h3_read_only_goal_proposals"
            ),
            "allowed_scope": (
                "artifact-only proposal review"
                if passed
                else "continue H.2 evidence collection or repair invalid evidence"
            ),
        },
        "proposal_surface": {
            "mode": "read_only",
            "proposal_count": len(proposals),
            "proposals": proposals,
        },
        "h3_boundary": {
            "artifact_only": True,
            "proposal_review_allowed": passed,
            "goal_emission_allowed": False,
            "executable_plan_allowed": False,
            "runtime_execution_allowed": False,
            "llm_planning_allowed": False,
            "iem_mutation_allowed": False,
            "relation_mutation_allowed": False,
            "authorization_mutation_allowed": False,
            "normative_local_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "evidence_summary": {
            "source_report_count": len(source_reports),
            "record_count": len(records),
            "owner_ids": sorted({str(record.get("owner_id") or "") for record in records}),
            "task_ids": sorted({str(record.get("task_id") or "") for record in records}),
        },
        "non_claims": [
            "does_not_emit_goals",
            "does_not_generate_executable_plans",
            "does_not_call_llms",
            "does_not_start_agents_or_runtime",
            "does_not_mutate_iem_relation_authorization_or_normative_state",
            "does_not_authorize_production_transition",
        ],
    }


def _validate_h2_records(
    records: list[dict[str, Any]],
    source_reports: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    source_hashes = {
        str(ref.get("sha256") or "")
        for ref in source_reports
        if _valid_sha256(ref.get("sha256"))
    }
    record_ids = [str(record.get("record_id") or "") for record in records]
    task_ids = [str(record.get("task_id") or "") for record in records]
    _require(
        checks,
        failures,
        "source_report_hashes_valid",
        len(source_hashes) == len(source_reports),
    )
    _require(
        checks,
        failures,
        "source_report_paths_present",
        all(str(ref.get("path") or "").strip() for ref in source_reports),
    )
    _require(
        checks,
        failures,
        "record_ids_unique_and_present",
        all(record_ids) and len(record_ids) == len(set(record_ids)),
    )
    _require(
        checks,
        failures,
        "task_ids_unique_and_present",
        all(task_ids) and len(task_ids) == len(set(task_ids)),
    )
    _require(
        checks,
        failures,
        "records_bound_to_source_hashes",
        all(str(record.get("source_report_sha256") or "") in source_hashes for record in records),
    )
    _require(
        checks,
        failures,
        "record_integrity_passed",
        all(record.get("evidence_integrity_passed") is True for record in records),
    )
    _require(
        checks,
        failures,
        "record_event_kinds_allowed",
        all(str(record.get("event_kind") or "") in ALLOWED_EVENT_KINDS for record in records),
    )
    _require(
        checks,
        failures,
        "record_changes_observable",
        all(
            record.get("iem_changed") is True
            and record.get("relation_changed") is True
            and record.get("authorization_changed") is True
            for record in records
        ),
    )
    negative_records = [
        record
        for record in records
        if str(record.get("event_kind") or "") in NEGATIVE_EVENT_KINDS
    ]
    _require(
        checks,
        failures,
        "negative_authorization_strengthened",
        bool(negative_records)
        and all(
            record.get("negative_authorization_strengthened") is True
            for record in negative_records
        ),
    )


def _validate_h2_metrics(
    h2_report: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    metrics = _object(h2_report.get("metrics"))
    thresholds = _object(h2_report.get("thresholds"))
    owner_count = len({str(record.get("owner_id") or "") for record in records})
    task_count = len({str(record.get("task_id") or "") for record in records})
    _require_equal(checks, failures, "record_count_consistent", metrics.get("record_count"), len(records))
    _require_equal(checks, failures, "owner_count_consistent", metrics.get("owner_count"), owner_count)
    _require_equal(checks, failures, "task_count_consistent", metrics.get("task_count"), task_count)
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
        metric = _number(metrics.get(metric_name))
        threshold = _number(thresholds.get(threshold_name))
        _require(
            checks,
            failures,
            f"{metric_name}_meets_h2_threshold",
            metric is not None and threshold is not None and metric >= threshold,
        )


def _build_proposals(
    records: list[dict[str, Any]],
    *,
    max_proposals: int,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in records:
        event_kind = str(record.get("event_kind") or "")
        category = "risk_review" if event_kind in NEGATIVE_EVENT_KINDS else "successful_pattern_review"
        grouped.setdefault((str(record.get("agent_id") or ""), category), []).append(record)

    proposals: list[dict[str, Any]] = []
    for (agent_id, category), evidence in sorted(grouped.items()):
        evidence = sorted(evidence, key=lambda item: str(item.get("record_id") or ""))
        record_ids = [str(item.get("record_id") or "") for item in evidence]
        event_kinds = sorted({str(item.get("event_kind") or "") for item in evidence})
        proposal_kind = (
            "review_relation_risk_and_verification_policy"
            if category == "risk_review"
            else "review_conditions_for_preserving_successful_relations"
        )
        rationale = (
            "Observed negative consequences changed relation expectations and later authorization constraints."
            if category == "risk_review"
            else "Observed successful settlement changed relation expectations and later authorization constraints."
        )
        digest = hashlib.sha256(
            json.dumps(
                {
                    "agent_id": agent_id,
                    "proposal_kind": proposal_kind,
                    "record_ids": record_ids,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:20]
        proposals.append(
            {
                "proposal_id": f"h3-read-only:{digest}",
                "state": "read_only_review_required",
                "proposal_kind": proposal_kind,
                "subject_agent_id": agent_id,
                "rationale": rationale,
                "telos_basis": (
                    "reduce repeated relationship risk without erasing accountability"
                    if category == "risk_review"
                    else "preserve conditions that made accountable cooperation succeed"
                ),
                "vmv_alignment": {
                    "mission": "make previously impossible accountable Agent relationships possible",
                    "human_sovereignty_preserved": True,
                    "verifiable_truth_required": True,
                    "accountability_must_not_disappear": True,
                    "safety_over_efficiency": True,
                    "normative_change_requires_governance": True,
                },
                "trigger_event_kinds": event_kinds,
                "owner_ids": sorted({str(item.get("owner_id") or "") for item in evidence}),
                "evidence_refs": [
                    {
                        "record_id": str(item.get("record_id") or ""),
                        "task_id": str(item.get("task_id") or ""),
                        "source_report_sha256": str(item.get("source_report_sha256") or ""),
                    }
                    for item in evidence
                ],
                "observed_effects": {
                    "iem_changed": all(item.get("iem_changed") is True for item in evidence),
                    "relation_changed": all(item.get("relation_changed") is True for item in evidence),
                    "authorization_changed": all(
                        item.get("authorization_changed") is True for item in evidence
                    ),
                },
                "review_policy": {
                    "operator_review_required": True,
                    "governance_review_required_for_normative_change": True,
                    "automatic_approval_allowed": False,
                },
                "execution_policy": {
                    "goal_emission_allowed": False,
                    "executable_plan_allowed": False,
                    "runtime_execution_allowed": False,
                    "iem_mutation_allowed": False,
                    "normative_local_mutation_allowed": False,
                },
            }
        )
    return proposals[:max_proposals]


def _proposal_group_count(records: list[dict[str, Any]]) -> int:
    return len(
        {
            (
                str(record.get("agent_id") or ""),
                (
                    "risk_review"
                    if str(record.get("event_kind") or "") in NEGATIVE_EVENT_KINDS
                    else "successful_pattern_review"
                ),
            )
            for record in records
        }
    )


def _require_read_only_boundary(
    boundary: dict[str, Any],
    *,
    checks: dict[str, bool],
    failures: list[str],
) -> None:
    _require(checks, failures, "h2_artifact_only", boundary.get("artifact_only") is True)
    for field in (
        "runtime_mutation_allowed",
        "goal_emission_allowed",
        "goal_execution_allowed",
        "normative_local_mutation_allowed",
    ):
        _require(checks, failures, f"h2_{field}_false", boundary.get(field) is False)


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"missing H2 evidence report: {path}")
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"invalid H2 evidence report {path}: {exc}")
        return None
    if not isinstance(value, dict):
        failures.append(f"expected JSON object in H2 evidence report: {path}")
        return None
    return value


def _require(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    passed: bool,
) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def _require_equal(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    actual: Any,
    expected: Any,
) -> None:
    passed = actual == expected
    checks[name] = passed
    if not passed:
        failures.append(f"{name} expected {expected!r}, got {actual!r}")


def _objects(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _valid_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _resolve(path: Path, root: Path) -> Path:
    return path if path.is_absolute() else (root / path).resolve()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--h2-evidence-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-proposals", type=int, default=20)
    args = parser.parse_args()

    report = build_h3_read_only_goal_proposal_gate(
        h2_evidence_report_path=args.h2_evidence_report,
        agent_root=agent_root,
        max_proposals=args.max_proposals,
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
