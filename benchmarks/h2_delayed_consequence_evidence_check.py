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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "h2-delayed-consequence-evidence-check:v1"
SOURCE_SCHEMA_VERSION = "h2-multi-agent-backend-continuity-gate:v1"


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
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    records: list[dict[str, Any]] = []
    report_refs: list[dict[str, Any]] = []
    for source_path in source_reports:
        path = _resolve(source_path, agent_root)
        report = _read_json(path, failures)
        if report is None:
            continue
        report_refs.append({"path": str(path), "sha256": _sha256(path)})
        if report.get("schema_version") != SOURCE_SCHEMA_VERSION:
            failures.append(f"unexpected source schema: {path}")
            continue
        if report.get("passed") is not True:
            failures.append(f"source report did not pass: {path}")
            continue
        owner_id = str(report.get("owner_id") or "").strip()
        if not owner_id:
            failures.append(f"source report missing owner_id: {path}")
            continue
        records.extend(_records_from_report(report, path=path, owner_id=owner_id))

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
    negative_authorization_change_count = sum(
        record["authorization_changed"]
        for record in records
        if record["event_kind"] in {"post_delivery_dispute", "post_delivery_failure"}
    )
    normative_blocked_count = sum(record["normative_local_update_blocked"] for record in records)

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
    }
    _require(checks, failures, "source_reports_present", bool(report_refs))
    _require(checks, failures, "records_present", bool(records))
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

    passed = not failures and all(checks.values())
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed,
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
    owner_id: str,
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
        records.append(
            {
                "record_id": f"{path.name}:{worker}:{summary.get('task_id')}",
                "source_report": str(path),
                "owner_id": owner_id,
                "worker": worker,
                "agent_id": str(summary.get("agent_id") or ""),
                "task_id": str(summary.get("task_id") or ""),
                "event_kind": str(summary.get("event_kind") or ""),
                "observed_at": summary.get("observed_at"),
                "relation_key": relation.get("relation_key"),
                "relation_changed": before != after and bool(before) and bool(after),
                "iem_changed": (
                    bool(iem.get("before_state_hash"))
                    and iem.get("before_state_hash") != iem.get("after_state_hash")
                    and iem.get("relation_entry_persisted") is True
                    and _object(iem.get("anchor")).get("state_hash")
                    == iem.get("after_state_hash")
                ),
                "authorization_before": authorization.get("before"),
                "authorization_after": authorization.get("after"),
                "authorization_changed": authorization.get("changed") is True,
                "normative_local_update_blocked": checks.get(
                    f"{worker}_normative_local_update_blocked"
                )
                is True,
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
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
