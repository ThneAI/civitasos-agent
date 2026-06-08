"""Aggregate cross-day H.2 delayed-consequence evidence.

The checker consumes completed multi-Agent continuity reports. It does not
create outcomes or mutate runtime state. Its purpose is to prove that observed
consequences changed IEM, directed relation expectations, and later
authorization constraints across distinct tasks and owners.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h2-delayed-consequence-evidence-check:v1"
SOURCE_SCHEMA_VERSION = "h2-multi-agent-backend-continuity-gate:v1"
SOURCE_EVIDENCE_CLASS = "controlled_pilot_backend"
ALLOWED_EVENT_KINDS = {
    "settlement_confirmed",
    "post_delivery_dispute",
    "post_delivery_failure",
}
NEGATIVE_EVENT_KINDS = {
    "post_delivery_dispute",
    "post_delivery_failure",
}
VERIFICATION_LEVEL_RANK = {
    "baseline": 0,
    "elevated": 1,
    "strict": 2,
}
MATURITY_CHECKS = {
    "minimum_owner_count",
    "minimum_task_count",
    "minimum_observation_days",
    "minimum_observation_span_seconds",
    "minimum_iem_change_ratio",
    "minimum_relation_change_ratio",
    "minimum_authorization_change_count",
    "negative_outcomes_change_authorization",
    "minimum_normative_blocked_ratio",
}


def check_delayed_consequence_evidence(
    *,
    source_reports: list[Path],
    agent_root: Path,
    min_owner_count: int = 2,
    min_task_count: int = 6,
    min_observation_days: int = 2,
    min_observation_span_seconds: float = 86400.0,
    min_iem_change_ratio: float = 1.0,
    min_relation_change_ratio: float = 1.0,
    min_authorization_change_count: int = 2,
    min_normative_blocked_ratio: float = 1.0,
    max_future_skew_seconds: float = 300.0,
    checked_at: datetime | None = None,
) -> dict[str, Any]:
    checked_at = _as_utc(checked_at or datetime.now(timezone.utc))
    failures: list[str] = []
    checks: dict[str, bool] = {}
    records: list[dict[str, Any]] = []
    report_refs: list[dict[str, Any]] = []
    resolved_paths = [_resolve(path, agent_root) for path in source_reports]
    _require(
        checks,
        failures,
        "source_report_paths_unique",
        len(resolved_paths) == len(set(resolved_paths)),
    )
    source_owner_ids: list[str] = []
    for source_path in source_reports:
        path = _resolve(source_path, agent_root)
        report = _read_json(path, failures)
        if report is None:
            continue
        report_sha256 = _sha256(path)
        report_refs.append({"path": str(path), "sha256": report_sha256})
        if report.get("schema_version") != SOURCE_SCHEMA_VERSION:
            failures.append(f"unexpected source schema: {path}")
            continue
        if report.get("passed") is not True:
            failures.append(f"source report did not pass: {path}")
            continue
        if report.get("evidence_class") != SOURCE_EVIDENCE_CLASS:
            failures.append(f"unexpected source evidence_class: {path}")
            continue
        owner_id = str(report.get("owner_id") or "").strip()
        if not owner_id:
            failures.append(f"source report missing owner_id: {path}")
            continue
        source_owner_ids.append(owner_id)
        records.extend(
            _records_from_report(
                report,
                path=path,
                report_sha256=report_sha256,
                owner_id=owner_id,
                checked_at=checked_at,
                max_future_skew_seconds=max_future_skew_seconds,
                failures=failures,
            )
        )

    owners = sorted({record["owner_id"] for record in records})
    tasks = sorted({record["task_id"] for record in records if record["task_id"]})
    observed_at = sorted(
        timestamp
        for record in records
        if (timestamp := _timestamp(record.get("observed_at"))) is not None
    )
    observation_days = sorted({timestamp.date().isoformat() for timestamp in observed_at})
    span_seconds = (
        (observed_at[-1] - observed_at[0]).total_seconds()
        if len(observed_at) >= 2
        else 0.0
    )
    iem_change_count = sum(record["iem_changed"] for record in records)
    relation_change_count = sum(record["relation_changed"] for record in records)
    authorization_change_count = sum(record["authorization_changed"] for record in records)
    negative_authorization_change_count = sum(record["negative_authorization_strengthened"] for record in records)
    normative_blocked_count = sum(record["normative_local_update_blocked"] for record in records)
    record_ids = [record["record_id"] for record in records]
    task_ids = [record["task_id"] for record in records if record["task_id"]]
    source_hashes = [ref["sha256"] for ref in report_refs]

    metrics = {
        "source_report_count": len(report_refs),
        "record_count": len(records),
        "owner_count": len(owners),
        "task_count": len(tasks),
        "observation_day_count": len(observation_days),
        "observation_span_seconds": span_seconds,
        "iem_change_count": iem_change_count,
        "iem_change_ratio": _ratio(iem_change_count, len(records)),
        "relation_change_count": relation_change_count,
        "relation_change_ratio": _ratio(relation_change_count, len(records)),
        "authorization_change_count": authorization_change_count,
        "negative_authorization_change_count": negative_authorization_change_count,
        "normative_local_update_blocked_count": normative_blocked_count,
        "normative_local_update_blocked_ratio": _ratio(
            normative_blocked_count,
            len(records),
        ),
        "record_integrity_pass_count": sum(record["evidence_integrity_passed"] for record in records),
        "record_integrity_pass_ratio": _ratio(
            sum(record["evidence_integrity_passed"] for record in records),
            len(records),
        ),
    }
    _require(checks, failures, "source_reports_present", bool(report_refs))
    _require(
        checks,
        failures,
        "source_report_hashes_unique",
        len(source_hashes) == len(set(source_hashes)),
    )
    _require(
        checks,
        failures,
        "source_owner_ids_unique",
        len(source_owner_ids) == len(set(source_owner_ids)),
    )
    _require(checks, failures, "records_present", bool(records))
    _require(checks, failures, "record_ids_unique", len(record_ids) == len(set(record_ids)))
    _require(checks, failures, "task_ids_unique", len(task_ids) == len(set(task_ids)))
    _require(
        checks,
        failures,
        "record_evidence_integrity",
        bool(records) and all(record["evidence_integrity_passed"] for record in records),
    )
    _require(checks, failures, "minimum_owner_count", len(owners) >= min_owner_count)
    _require(checks, failures, "minimum_task_count", len(tasks) >= min_task_count)
    _require(
        checks,
        failures,
        "minimum_observation_days",
        len(observation_days) >= min_observation_days,
    )
    _require(
        checks,
        failures,
        "minimum_observation_span_seconds",
        span_seconds >= min_observation_span_seconds,
    )
    _require(
        checks,
        failures,
        "minimum_iem_change_ratio",
        metrics["iem_change_ratio"] >= min_iem_change_ratio,
    )
    _require(
        checks,
        failures,
        "minimum_relation_change_ratio",
        metrics["relation_change_ratio"] >= min_relation_change_ratio,
    )
    _require(
        checks,
        failures,
        "minimum_authorization_change_count",
        authorization_change_count >= min_authorization_change_count,
    )
    _require(
        checks,
        failures,
        "negative_outcomes_change_authorization",
        negative_authorization_change_count >= min_authorization_change_count,
    )
    _require(
        checks,
        failures,
        "minimum_normative_blocked_ratio",
        metrics["normative_local_update_blocked_ratio"]
        >= min_normative_blocked_ratio,
    )

    maturity_failures = [failure for failure in failures if failure in MATURITY_CHECKS]
    integrity_failures = [failure for failure in failures if failure not in MATURITY_CHECKS]
    integrity_passed = not integrity_failures
    maturity_passed = not maturity_failures
    passed = integrity_passed and maturity_passed and all(checks.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "checked_at": checked_at.isoformat(),
        "passed": passed,
        "integrity_passed": integrity_passed,
        "maturity_passed": maturity_passed,
        "failure_class": (
            "none"
            if passed
            else ("evidence_integrity" if not integrity_passed else "evidence_maturity")
        ),
        "failure_reasons": failures,
        "thresholds": {
            "min_owner_count": min_owner_count,
            "min_task_count": min_task_count,
            "min_observation_days": min_observation_days,
            "min_observation_span_seconds": min_observation_span_seconds,
            "min_iem_change_ratio": min_iem_change_ratio,
            "min_relation_change_ratio": min_relation_change_ratio,
            "min_authorization_change_count": min_authorization_change_count,
            "min_normative_blocked_ratio": min_normative_blocked_ratio,
            "max_future_skew_seconds": max_future_skew_seconds,
        },
        "checks": checks,
        "metrics": metrics,
        "owners": owners,
        "tasks": tasks,
        "observation_days": observation_days,
        "source_reports": report_refs,
        "records": records,
        "h3_readiness": {
            "ready": passed,
            "decision": (
                "ready_for_h3_read_only_goal_proposal_gate"
                if passed
                else "blocked_collecting_h2_delayed_consequence_evidence"
            ),
            "allowed_scope": (
                "artifact-only read-only goal proposal; no goal emission or execution"
                if passed
                else "continue controlled-pilot evidence collection"
            ),
        },
        "boundary": {
            "artifact_only": True,
            "runtime_mutation_allowed": False,
            "goal_emission_allowed": False,
            "goal_execution_allowed": False,
            "normative_local_mutation_allowed": False,
        },
    }


def _records_from_report(
    report: dict[str, Any],
    *,
    path: Path,
    report_sha256: str,
    owner_id: str,
    checked_at: datetime,
    max_future_skew_seconds: float,
    failures: list[str],
) -> list[dict[str, Any]]:
    checks = _object(report.get("checks"))
    records: list[dict[str, Any]] = []
    for worker, raw_summary in _object(report.get("worker_summaries")).items():
        summary = _object(raw_summary)
        relation = _object(summary.get("relation_update"))
        before = _object(relation.get("before"))
        after = _object(relation.get("after"))
        iem = _object(summary.get("iem_update"))
        authorization = _object(summary.get("authorization_change"))
        authorization_before = _object(authorization.get("before"))
        authorization_after = _object(authorization.get("after"))
        action_bias = _object(relation.get("action_bias"))
        task_id = str(summary.get("task_id") or "").strip()
        agent_id = str(summary.get("agent_id") or "").strip()
        event_kind = str(summary.get("event_kind") or "").strip()
        observed_at = _timestamp(summary.get("observed_at"))
        shutdown_at = _timestamp(summary.get("shutdown_at"))
        required_checks = {
            name: checks.get(f"{worker}_{name}") is True
            for name in (
                "event_after_shutdown",
                "event_from_backend",
                "event_matches_task",
                "expected_event_kind",
                "iem_anchor_matches_state",
                "iem_state_changed",
                "relation_persisted_in_iem",
                "authorization_profile_changed",
                "authorization_matches_action_bias",
                "normative_local_update_blocked",
            )
        }
        relation_changed = before != after and bool(before) and bool(after)
        iem_changed = (
            bool(iem.get("before_state_hash"))
            and iem.get("before_state_hash") != iem.get("after_state_hash")
            and iem.get("relation_entry_persisted") is True
            and _object(iem.get("anchor")).get("state_hash") == iem.get("after_state_hash")
        )
        authorization_changed = (
            authorization.get("changed") is True
            and bool(authorization_before)
            and bool(authorization_after)
            and authorization_before != authorization_after
        )
        authorization_matches_action_bias = _authorization_matches_action_bias(
            authorization_after,
            action_bias,
        )
        negative_authorization_strengthened = (
            event_kind in NEGATIVE_EVENT_KINDS
            and authorization_changed
            and _authorization_strengthened(authorization_before, authorization_after)
        )
        timestamp_complete = observed_at is not None and shutdown_at is not None
        event_after_shutdown = bool(
            timestamp_complete and observed_at is not None and shutdown_at is not None and observed_at > shutdown_at
        )
        timestamp_not_future = bool(
            observed_at is not None
            and observed_at <= checked_at + timedelta(seconds=max_future_skew_seconds)
        )
        integrity = {
            "agent_id_present": bool(agent_id),
            "task_id_present": bool(task_id),
            "event_kind_allowed": event_kind in ALLOWED_EVENT_KINDS,
            "timestamps_complete": timestamp_complete,
            "event_after_shutdown": event_after_shutdown,
            "observed_at_not_future": timestamp_not_future,
            "relation_key_present": bool(relation.get("relation_key")),
            "relation_changed": relation_changed,
            "iem_changed_and_anchored": iem_changed,
            "authorization_changed": authorization_changed,
            "authorization_matches_action_bias": authorization_matches_action_bias,
            "negative_authorization_strengthened": (
                negative_authorization_strengthened
                if event_kind in NEGATIVE_EVENT_KINDS
                else True
            ),
            "source_worker_checks_passed": all(required_checks.values()),
            "reports_present": summary.get("reports_present") is True,
        }
        evidence_integrity_passed = all(integrity.values())
        if not evidence_integrity_passed:
            failed_integrity = sorted(name for name, passed in integrity.items() if not passed)
            failures.append(
                f"source record integrity failed {path}:{worker}: {','.join(failed_integrity)}"
            )
        records.append(
            {
                "record_id": f"{report_sha256[:16]}:{worker}:{task_id}",
                "source_report": str(path),
                "source_report_sha256": report_sha256,
                "owner_id": owner_id,
                "worker": worker,
                "agent_id": agent_id,
                "task_id": task_id,
                "event_kind": event_kind,
                "observed_at": summary.get("observed_at"),
                "shutdown_at": summary.get("shutdown_at"),
                "relation_key": relation.get("relation_key"),
                "relation_changed": relation_changed,
                "iem_changed": iem_changed,
                "authorization_before": authorization_before,
                "authorization_after": authorization_after,
                "authorization_changed": authorization_changed,
                "negative_authorization_strengthened": negative_authorization_strengthened,
                "authorization_matches_action_bias": authorization_matches_action_bias,
                "normative_local_update_blocked": checks.get(
                    f"{worker}_normative_local_update_blocked"
                )
                is True,
                "required_source_checks": required_checks,
                "integrity_checks": integrity,
                "evidence_integrity_passed": evidence_integrity_passed,
            }
        )
    return records


def _read_json(path: Path, failures: list[str]) -> dict[str, Any] | None:
    if not path.is_file():
        failures.append(f"missing source report: {path}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"invalid source report {path}: {exc}")
        return None
    return payload if isinstance(payload, dict) else None


def _timestamp(value: Any) -> datetime | None:
    text = str(value or "").replace("Z", "+00:00")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _authorization_matches_action_bias(
    authorization_after: dict[str, Any],
    action_bias: dict[str, Any],
) -> bool:
    if not authorization_after or not action_bias:
        return False
    return all(
        authorization_after.get(field) == action_bias.get(field)
        for field in (
            "verification_level",
            "required_stake_multiplier",
            "direct_match_allowed",
        )
    )


def _authorization_strengthened(
    before: dict[str, Any],
    after: dict[str, Any],
) -> bool:
    before_level = VERIFICATION_LEVEL_RANK.get(str(before.get("verification_level") or ""), -1)
    after_level = VERIFICATION_LEVEL_RANK.get(str(after.get("verification_level") or ""), -1)
    before_stake = _float(before.get("required_stake_multiplier"))
    after_stake = _float(after.get("required_stake_multiplier"))
    direct_match_restricted = (
        before.get("direct_match_allowed") is True
        and after.get("direct_match_allowed") is False
    )
    return (
        after_level > before_level
        or (before_stake is not None and after_stake is not None and after_stake > before_stake)
        or direct_match_restricted
    )


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _require(
    checks: dict[str, bool],
    failures: list[str],
    name: str,
    passed: bool,
) -> None:
    checks[name] = bool(passed)
    if not passed:
        failures.append(name)


def _resolve(path: Path, root: Path) -> Path:
    return path if path.is_absolute() else (root / path).resolve()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    agent_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-report", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--min-owner-count", type=int, default=2)
    parser.add_argument("--min-task-count", type=int, default=6)
    parser.add_argument("--min-observation-days", type=int, default=2)
    parser.add_argument("--min-observation-span-seconds", type=float, default=86400)
    args = parser.parse_args()
    report = check_delayed_consequence_evidence(
        source_reports=args.source_report,
        agent_root=agent_root,
        min_owner_count=args.min_owner_count,
        min_task_count=args.min_task_count,
        min_observation_days=args.min_observation_days,
        min_observation_span_seconds=args.min_observation_span_seconds,
    )
    output = _resolve(args.output, agent_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    if report["passed"]:
        return 0
    return 3 if report["failure_class"] == "evidence_integrity" else 2


if __name__ == "__main__":
    sys.exit(main())
