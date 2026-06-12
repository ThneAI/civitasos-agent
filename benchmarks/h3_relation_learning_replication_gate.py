"""Validate differentiated, bounded relation learning across H.2 evidence batches."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from civitasos_runtime.models import RelationExpectationVector
from civitasos_runtime.relation_learning import (
    MAX_ABS_DELTA,
    RelationEvidence,
    calculate_relation_update,
    learning_provenance,
)

SCHEMA_VERSION = "h3-relation-learning-replication-gate:v1"
EXPECTED_OUTCOMES = {
    "settlement_confirmed",
    "post_delivery_dispute",
    "post_delivery_failure",
}


def run_gate(
    *,
    evidence_reports: list[Path],
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    sources: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for path in evidence_reports:
        report = _read_json(path)
        sources.append(
            {
                "path": str(path),
                "sha256": _sha256(path),
                "schema_version": report.get("schema_version"),
                "owner_id": report.get("owner_id"),
                "passed": report.get("passed"),
            }
        )
        owner_id = str(report.get("owner_id") or "")
        for worker, summary in _object(report.get("worker_summaries")).items():
            if not isinstance(summary, dict):
                continue
            records.append(
                _replication_record(
                    owner_id=owner_id,
                    worker=str(worker),
                    summary=summary,
                    source_path=path,
                )
            )

    owners = {record["owner_id"] for record in records if record["owner_id"]}
    task_ids = {record["task_id"] for record in records if record["task_id"]}
    relation_keys = {
        record["relation_key"] for record in records if record["relation_key"]
    }
    outcomes = {
        record["event_kind"] for record in records if record["event_kind"]
    }
    task_kinds = {
        record["task_kind"] for record in records if record["task_kind"]
    }
    providers = {
        record["provider"] for record in records if record["provider"]
    }
    _check(
        checks,
        failures,
        "at_least_two_passing_source_reports",
        len(sources) >= 2 and all(item["passed"] is True for item in sources),
    )
    _check(checks, failures, "at_least_two_distinct_owners", len(owners) >= 2)
    _check(checks, failures, "at_least_six_distinct_tasks", len(task_ids) >= 6)
    _check(
        checks,
        failures,
        "at_least_six_distinct_relation_pairs",
        len(relation_keys) >= 6,
    )
    _check(
        checks,
        failures,
        "success_dispute_failure_covered",
        EXPECTED_OUTCOMES.issubset(outcomes),
    )
    _check(checks, failures, "at_least_three_task_kinds", len(task_kinds) >= 3)
    _check(checks, failures, "at_least_three_agent_providers", len(providers) >= 3)
    _check(
        checks,
        failures,
        "all_records_have_explainable_provenance",
        bool(records) and all(record["provenance_valid"] for record in records),
    )
    _check(
        checks,
        failures,
        "all_deltas_within_caps",
        bool(records) and all(record["within_caps"] for record in records),
    )
    _check(
        checks,
        failures,
        "all_normative_updates_blocked",
        bool(records) and all(record["normative_guard_observed"] for record in records),
    )
    _check(
        checks,
        failures,
        "different_outcomes_produce_different_post_states",
        _different_outcomes_are_distinct(records),
    )
    _check(
        checks,
        failures,
        "negative_outcome_severity_is_ordered",
        _severity_is_ordered(records),
    )

    controls = _run_negative_controls()
    for name, passed in controls["checks"].items():
        _check(checks, failures, name, passed)

    passed = bool(checks) and all(checks.values())
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_reports": sources,
        "metrics": {
            "source_report_count": len(sources),
            "record_count": len(records),
            "owner_count": len(owners),
            "task_count": len(task_ids),
            "relation_pair_count": len(relation_keys),
            "outcome_count": len(outcomes),
            "task_kind_count": len(task_kinds),
            "provider_count": len(providers),
        },
        "dimensions": {
            "owners": sorted(owners),
            "outcomes": sorted(outcomes),
            "task_kinds": sorted(task_kinds),
            "providers": sorted(providers),
        },
        "records": records,
        "negative_controls": controls,
        "readiness": {
            "status": (
                "h3_relation_learning_replication_ready_for_review"
                if passed
                else "blocked_h3_relation_learning_replication"
            ),
            "replication_evidence_ready_for_h3_review": passed,
            "valid_for_qualification": False,
            "automatic_state_change_allowed": False,
        },
        "non_claims": [
            "replication_gate_does_not_prove_open_world_causality",
            "replication_gate_does_not_authorize_another_pilot",
            "replication_gate_does_not_mutate_iem_relation_or_authorization_state",
            "replication_gate_does_not_unlock_production_or_external_agent_command",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _replication_record(
    *,
    owner_id: str,
    worker: str,
    summary: dict[str, Any],
    source_path: Path,
) -> dict[str, Any]:
    relation = _object(summary.get("relation_update"))
    updates = [
        item
        for item in relation.get("expectation_updates", [])
        if isinstance(item, dict)
    ]
    provenance = {}
    for update in updates:
        candidate = _object(_object(update.get("update_params")).get("delta_provenance"))
        if candidate:
            provenance = candidate
            break
    components = [
        item for item in provenance.get("components", []) if isinstance(item, dict)
    ]
    component = components[0] if len(components) == 1 else {}
    applied = _object(provenance.get("applied_deltas"))
    caps = _object(provenance.get("per_step_abs_caps"))
    within_caps = bool(applied) and all(
        abs(_float(value)) <= _float(caps.get(parameter)) + 1e-9
        for parameter, value in applied.items()
        if parameter in caps
    )
    provenance_valid = (
        provenance.get("schema_version") == "relation-learning-provenance:v1"
        and len(components) == 1
        and bool(provenance.get("source_event_ids"))
        and bool(provenance.get("raw_deltas"))
        and bool(provenance.get("bounded_deltas"))
        and bool(applied)
        and set(MAX_ABS_DELTA).issubset(caps)
    )
    normative_guard = any(
        update.get("parameter_name") == "normative_relation"
        and update.get("local_update_blocked") is True
        for update in updates
    )
    return {
        "record_id": (
            f"h3-replication:{owner_id}:{worker}:{summary.get('task_id')}"
        ),
        "owner_id": owner_id,
        "worker": worker,
        "agent_id": summary.get("agent_id"),
        "task_id": str(summary.get("task_id") or ""),
        "relation_key": str(relation.get("relation_key") or ""),
        "event_kind": str(summary.get("event_kind") or ""),
        "task_kind": str(component.get("task_kind") or ""),
        "provider": str(component.get("provider") or ""),
        "risk_class": str(component.get("risk_class") or ""),
        "before": relation.get("before"),
        "after": relation.get("after"),
        "applied_deltas": applied,
        "source_event_ids": provenance.get("source_event_ids"),
        "provenance_valid": provenance_valid,
        "within_caps": within_caps,
        "normative_guard_observed": normative_guard,
        "source_report": {
            "path": str(source_path),
            "sha256": _sha256(source_path),
        },
    }


def _different_outcomes_are_distinct(records: list[dict[str, Any]]) -> bool:
    states: dict[str, set[str]] = {}
    for record in records:
        event_kind = record["event_kind"]
        if event_kind not in EXPECTED_OUTCOMES:
            continue
        states.setdefault(event_kind, set()).add(_canonical(record.get("after")))
    if not EXPECTED_OUTCOMES.issubset(states):
        return False
    ordered = sorted(EXPECTED_OUTCOMES)
    return all(
        states[left].isdisjoint(states[right])
        for index, left in enumerate(ordered)
        for right in ordered[index + 1 :]
    )


def _severity_is_ordered(records: list[dict[str, Any]]) -> bool:
    trust_deltas: dict[str, list[float]] = {}
    for record in records:
        trust_deltas.setdefault(record["event_kind"], []).append(
            _float(_object(record.get("applied_deltas")).get("expected_trust"))
        )
    if not EXPECTED_OUTCOMES.issubset(trust_deltas):
        return False
    success = sum(trust_deltas["settlement_confirmed"]) / len(
        trust_deltas["settlement_confirmed"]
    )
    dispute = sum(trust_deltas["post_delivery_dispute"]) / len(
        trust_deltas["post_delivery_dispute"]
    )
    failure = sum(trust_deltas["post_delivery_failure"]) / len(
        trust_deltas["post_delivery_failure"]
    )
    return failure < dispute < 0.0 < success


def _run_negative_controls() -> dict[str, Any]:
    before = RelationExpectationVector()
    left = calculate_relation_update(
        before,
        [
            RelationEvidence(
                ref="negative-control:left",
                outcome_kind="post_delivery_dispute",
                task_kind="same-task",
                provider="deepseek-api-agent",
                owner_id="owner-a",
            )
        ],
    )
    right = calculate_relation_update(
        before,
        [
            RelationEvidence(
                ref="negative-control:right",
                outcome_kind="post_delivery_dispute",
                task_kind="same-task",
                provider="local-gpu-agent",
                owner_id="owner-b",
            )
        ],
    )
    replay = calculate_relation_update(
        before,
        [
            RelationEvidence(
                ref="negative-control:replay",
                outcome_kind="post_delivery_failure",
            )
        ],
        prior_source_event_ids=["negative-control:replay"],
        prior_sample_count=5,
    )
    low_precision = calculate_relation_update(
        RelationExpectationVector(precision=0.20),
        [
            RelationEvidence(
                ref="history-control:low",
                outcome_kind="post_delivery_failure",
            )
        ],
    )
    high_precision = calculate_relation_update(
        RelationExpectationVector(precision=0.80),
        [
            RelationEvidence(
                ref="history-control:high",
                outcome_kind="post_delivery_failure",
            )
        ],
    )
    stress = calculate_relation_update(
        before,
        [
            RelationEvidence(
                ref=f"cap-control:{index}",
                outcome_kind="relation_repair_relapse",
                risk_class="critical",
            )
            for index in range(10)
        ],
    )
    return {
        "checks": {
            "provider_owner_negative_control_is_neutral": (
                left.applied_deltas == right.applied_deltas
                and asdict(left.after) == asdict(right.after)
            ),
            "duplicate_event_replay_is_blocked": (
                not replay.novel_evidence
                and replay.sample_count == 5
                and asdict(replay.after) == asdict(before)
            ),
            "different_relation_history_changes_delta": (
                low_precision.applied_deltas["expected_trust"]
                != high_precision.applied_deltas["expected_trust"]
            ),
            "stress_update_respects_all_caps": all(
                abs(stress.bounded_deltas[parameter]) <= cap
                for parameter, cap in MAX_ABS_DELTA.items()
            ),
        },
        "provider_owner_neutral_left": learning_provenance(left),
        "provider_owner_neutral_right": learning_provenance(right),
        "duplicate_replay": learning_provenance(replay),
        "history_low_precision": learning_provenance(low_precision),
        "history_high_precision": learning_provenance(high_precision),
        "cap_stress": learning_provenance(stress),
    }


def _check(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    passed: bool,
) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-report", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = run_gate(
        evidence_reports=[Path(path).resolve() for path in args.evidence_report],
        output=Path(args.output).resolve(),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
