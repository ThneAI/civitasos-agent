"""Qualify bounded H.3 relation learning semantics without mutating runtime state."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from benchmarks.h3_evidence import artifact_ref, object_value, read_required_json_object, sha256_file
from benchmarks.h3_relation_learning_replication_gate import (
    EXPECTED_OUTCOMES,
    SCHEMA_VERSION as REPLICATION_SCHEMA_VERSION,
)

SCHEMA_VERSION = "h3-relation-learning-semantic-qualification:v1"
REQUIRED_REPLICATION_CHECKS = {
    "all_deltas_within_caps",
    "all_normative_updates_blocked",
    "all_records_have_explainable_provenance",
    "different_outcomes_produce_different_post_states",
    "different_relation_history_changes_delta",
    "duplicate_event_replay_is_blocked",
    "negative_outcome_severity_is_ordered",
    "owner_negative_control_is_neutral",
    "provider_negative_control_is_neutral",
    "stress_update_respects_all_caps",
}


def run_gate(
    *,
    evidence_reports: list[Path],
    replication_report_path: Path,
    prior_a9_reconciliation_path: Path,
    output: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    source_reports = [read_required_json_object(path) for path in evidence_reports]
    replication = read_required_json_object(replication_report_path)
    prior_a9 = read_required_json_object(prior_a9_reconciliation_path)
    records = _semantic_records(evidence_reports, source_reports)

    _check(
        checks,
        failures,
        "replication_report_passed",
        replication.get("schema_version") == REPLICATION_SCHEMA_VERSION
        and replication.get("passed") is True,
    )
    replication_checks = object_value(replication.get("checks"))
    _check(
        checks,
        failures,
        "required_replication_controls_passed",
        REQUIRED_REPLICATION_CHECKS.issubset(replication_checks)
        and all(
            replication_checks.get(name) is True
            for name in REQUIRED_REPLICATION_CHECKS
        ),
    )
    _check(
        checks,
        failures,
        "source_reports_hash_bound_to_replication",
        _sources_match_replication(evidence_reports, replication),
    )
    _check(
        checks,
        failures,
        "two_owners_six_tasks_three_outcomes_present",
        len({record["owner_id"] for record in records}) >= 2
        and len({record["task_id"] for record in records}) >= 6
        and EXPECTED_OUTCOMES.issubset(
            {record["event_kind"] for record in records}
        ),
    )
    owner_pair_count = _owner_neutral_pair_count(records)
    _check(
        checks,
        failures,
        "real_owner_pairs_are_semantically_neutral",
        owner_pair_count >= 3,
    )
    _check(
        checks,
        failures,
        "provider_isolated_control_is_neutral",
        replication_checks.get("provider_negative_control_is_neutral") is True,
    )
    _check(
        checks,
        failures,
        "different_history_changes_bounded_delta",
        replication_checks.get("different_relation_history_changes_delta")
        is True,
    )
    _check(
        checks,
        failures,
        "all_authorization_profiles_changed",
        len(records) >= 6
        and all(record["authorization_changed"] for record in records),
    )
    _check(
        checks,
        failures,
        "authorization_profiles_match_action_bias",
        bool(records)
        and all(record["authorization_matches_action_bias"] for record in records),
    )
    _check(
        checks,
        failures,
        "authorization_behavior_is_outcome_specific",
        _authorization_behavior_is_outcome_specific(records),
    )
    _check(
        checks,
        failures,
        "iem_relation_and_runtime_continuity_proven",
        bool(records)
        and all(record["continuity_checks_passed"] for record in records),
    )
    _check(
        checks,
        failures,
        "prior_a9_is_safe_review_not_reused_authorization",
        prior_a9.get("schema_version")
        == "h3-controlled-pilot-operator-reconciliation:v1"
        and prior_a9.get("passed") is True
        and prior_a9.get("valid_for_qualification") is False
        and object_value(prior_a9.get("readiness")).get(
            "automatic_state_change_allowed"
        )
        is False
        and all(
            object_value(prior_a9.get("boundary")).get(name) is False
            for name in (
                "authorization_mutation_allowed",
                "controlled_pilot_execution_allowed",
                "iem_mutation_allowed",
                "normative_mutation_allowed",
                "relation_mutation_allowed",
                "trust_mutation_allowed",
            )
        ),
    )

    passed = bool(checks) and all(checks.values())
    report = {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
        "valid_for_qualification": passed,
        "failure_reasons": failures,
        "checks": checks,
        "source_artifacts": {
            "evidence_reports": [artifact_ref(path) for path in evidence_reports],
            "replication_report": artifact_ref(replication_report_path),
            "prior_a9_reconciliation": artifact_ref(
                prior_a9_reconciliation_path
            ),
        },
        "metrics": {
            "record_count": len(records),
            "owner_count": len({record["owner_id"] for record in records}),
            "task_count": len({record["task_id"] for record in records}),
            "outcome_count": len(
                {record["event_kind"] for record in records}
            ),
            "real_owner_neutral_pair_count": owner_pair_count,
            "authorization_change_count": sum(
                record["authorization_changed"] for record in records
            ),
        },
        "semantic_findings": {
            "owner_dimension": (
                "neutral_in_three_real_owner-paired_control_samples"
            ),
            "provider_dimension": (
                "neutral_in_isolated_deterministic_control; "
                "open-world provider neutrality remains unclaimed"
            ),
            "history_dimension": (
                "same outcome produces different bounded deltas when prior "
                "relation precision differs"
            ),
            "authorization_changed_semantics": (
                "a derived before/after authorization policy profile changed "
                "to match relation action_bias; this qualification gate did "
                "not issue an authorization or mutate authorization state"
            ),
        },
        "readiness": {
            "status": (
                "h3_relation_learning_semantically_qualified"
                if passed
                else "blocked_h3_relation_learning_semantic_qualification"
            ),
            "h3_relation_learning_qualified": passed,
            "i1_entry_inputs_ready": passed,
            "i1_execution_allowed": False,
        },
        "boundary": {
            "qualification_is_bounded_to_supplied_evidence": True,
            "runtime_execution_allowed": False,
            "iem_mutation_allowed": False,
            "relation_mutation_allowed": False,
            "authorization_mutation_allowed": False,
            "normative_mutation_allowed": False,
            "production_transition_allowed": False,
        },
        "non_claims": [
            "qualification_does_not_prove_open_world_provider_neutrality",
            "qualification_does_not_reuse_prior_a6_authorization",
            "qualification_does_not_dispatch_i1_verifiers",
            "qualification_does_not_mutate_iem_relation_or_authorization_state",
            "qualification_does_not_unlock_production",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _semantic_records(
    paths: list[Path],
    reports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path, report in zip(paths, reports, strict=True):
        owner_id = str(report.get("owner_id") or "")
        source_checks = object_value(report.get("checks"))
        for worker, summary_value in object_value(
            report.get("worker_summaries")
        ).items():
            summary = object_value(summary_value)
            relation = object_value(summary.get("relation_update"))
            authorization = object_value(summary.get("authorization_change"))
            action_bias = object_value(relation.get("action_bias"))
            provenance = _first_provenance(relation)
            component = next(
                (
                    item
                    for item in provenance.get("components", [])
                    if isinstance(item, dict)
                ),
                {},
            )
            auth_after = object_value(authorization.get("after"))
            continuity_names = (
                f"{worker}_runtime_identity_continuous",
                f"{worker}_memory_recalled",
                f"{worker}_relation_persisted_in_iem",
                f"{worker}_event_after_shutdown",
                f"{worker}_normative_local_update_blocked",
                f"{worker}_authorization_profile_changed",
                f"{worker}_authorization_matches_action_bias",
            )
            records.append(
                {
                    "source_path": str(path),
                    "owner_id": owner_id,
                    "worker": str(worker),
                    "task_id": str(summary.get("task_id") or ""),
                    "event_kind": str(summary.get("event_kind") or ""),
                    "task_kind": str(component.get("task_kind") or ""),
                    "provider": str(component.get("provider") or ""),
                    "risk_class": str(component.get("risk_class") or ""),
                    "relation_before": relation.get("before"),
                    "relation_after": relation.get("after"),
                    "applied_deltas": provenance.get("applied_deltas"),
                    "authorization_before": authorization.get("before"),
                    "authorization_after": auth_after,
                    "authorization_changed": (
                        authorization.get("changed") is True
                        and authorization.get("before")
                        != authorization.get("after")
                    ),
                    "authorization_matches_action_bias": (
                        auth_after.get("direct_match_allowed")
                        == action_bias.get("direct_match_allowed")
                        and auth_after.get("required_stake_multiplier")
                        == action_bias.get("required_stake_multiplier")
                        and auth_after.get("verification_level")
                        == action_bias.get("verification_level")
                    ),
                    "continuity_checks_passed": all(
                        source_checks.get(name) is True
                        for name in continuity_names
                    ),
                }
            )
    return records


def _first_provenance(relation: dict[str, Any]) -> dict[str, Any]:
    for update in relation.get("expectation_updates", []):
        if not isinstance(update, dict):
            continue
        provenance = object_value(
            object_value(update.get("update_params")).get("delta_provenance")
        )
        if provenance:
            return provenance
    return {}


def _owner_neutral_pair_count(records: list[dict[str, Any]]) -> int:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = (
            record["worker"],
            record["event_kind"],
            record["task_kind"],
            record["provider"],
            record["risk_class"],
        )
        groups[key].append(record)
    count = 0
    for group in groups.values():
        if len({item["owner_id"] for item in group}) < 2:
            continue
        baseline = group[0]
        fields = (
            "relation_before",
            "relation_after",
            "applied_deltas",
            "authorization_before",
            "authorization_after",
        )
        if all(
            all(item[field] == baseline[field] for field in fields)
            for item in group[1:]
        ):
            count += 1
    return count


def _authorization_behavior_is_outcome_specific(
    records: list[dict[str, Any]],
) -> bool:
    profiles: dict[str, set[str]] = defaultdict(set)
    stakes: dict[str, list[float]] = defaultdict(list)
    for record in records:
        outcome = record["event_kind"]
        profile = object_value(record.get("authorization_after"))
        profiles[outcome].add(_canonical(profile))
        stakes[outcome].append(float(profile.get("required_stake_multiplier", 0)))
    if not EXPECTED_OUTCOMES.issubset(profiles):
        return False
    if any(len(profiles[outcome]) != 1 for outcome in EXPECTED_OUTCOMES):
        return False
    success = sum(stakes["settlement_confirmed"]) / len(
        stakes["settlement_confirmed"]
    )
    dispute = sum(stakes["post_delivery_dispute"]) / len(
        stakes["post_delivery_dispute"]
    )
    failure = sum(stakes["post_delivery_failure"]) / len(
        stakes["post_delivery_failure"]
    )
    return success < dispute < failure


def _sources_match_replication(
    evidence_reports: list[Path],
    replication: dict[str, Any],
) -> bool:
    expected = {
        (str(path), sha256_file(path))
        for path in evidence_reports
    }
    observed = {
        (str(item.get("path") or ""), str(item.get("sha256") or ""))
        for item in replication.get("source_reports", [])
        if isinstance(item, dict)
    }
    return expected == observed


def _check(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    passed: bool,
) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-report", action="append", required=True)
    parser.add_argument("--replication-report", required=True)
    parser.add_argument("--prior-a9-reconciliation", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = run_gate(
        evidence_reports=[Path(path).resolve() for path in args.evidence_report],
        replication_report_path=Path(args.replication_report).resolve(),
        prior_a9_reconciliation_path=Path(
            args.prior_a9_reconciliation
        ).resolve(),
        output=Path(args.output).resolve(),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 2)


if __name__ == "__main__":
    main()
