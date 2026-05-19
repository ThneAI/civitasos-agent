#!/usr/bin/env python3
"""Export L1 contract runner repair suggestions as packet audit records."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_EVIDENCE = "contract_runner_evidence.json"
DEFAULT_ACTOR_ID = "audit_owner"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence",
        default=os.getenv("L1_CONTRACT_RUNNER_EVIDENCE", DEFAULT_EVIDENCE),
        help="Path to contract_runner_evidence.json.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write packet-compatible sinks/audit-events.jsonl records.",
    )
    parser.add_argument(
        "--actor-id",
        default=os.getenv("L1_AUDIT_OWNER_ACTOR_ID", DEFAULT_ACTOR_ID),
        help="Audit owner actor_id. Must match the L1 packet operator registry.",
    )
    parser.add_argument(
        "--audit-ref-prefix",
        default=os.getenv("L1_AUDIT_REF_PREFIX", "l1-contract-repair"),
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to an existing audit-events.jsonl instead of replacing it.",
    )
    parser.add_argument("--allow-empty", action="store_true")
    args = parser.parse_args(argv)

    report = export_contract_audit_refs(
        evidence_path=Path(args.evidence),
        output_path=Path(args.output),
        actor_id=str(args.actor_id),
        audit_ref_prefix=str(args.audit_ref_prefix),
        append=bool(args.append),
        allow_empty=bool(args.allow_empty),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def export_contract_audit_refs(
    *,
    evidence_path: Path,
    output_path: Path,
    actor_id: str,
    audit_ref_prefix: str,
    append: bool = False,
    allow_empty: bool = False,
) -> dict[str, Any]:
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    records = _repair_audit_source_records(evidence)
    if not isinstance(records, list):
        records = []
    if not records and not allow_empty:
        raise ValueError(
            "no repair_suggestion_audit_refs records found; use --allow-empty only "
            "when this run intentionally has no repair hints"
        )

    output_records = [
        _audit_event_record(
            source_record=record,
            actor_id=actor_id,
            audit_event_ref=f"{audit_ref_prefix}:{index:03d}",
            evidence_path=evidence_path,
        )
        for index, record in enumerate(records, start=1)
        if isinstance(record, dict)
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_text = "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in output_records)
    if append and output_path.exists():
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(output_text)
    else:
        output_path.write_text(output_text, encoding="utf-8")
    return {
        "schema_version": "l1-contract-audit-ref-export-report:v1",
        "evidence_path": str(evidence_path),
        "output_path": str(output_path),
        "actor_id": actor_id,
        "record_count": len(output_records),
        "append": append,
        "packet_record_type": "audit_event_recorded",
        "non_claims": [
            "exported_audit_refs_do_not_auto_retry_failed_tasks",
            "exported_audit_refs_do_not_authorize_production_runtime_execution",
            "exported_audit_refs_require_packet_operator_registry_actor_alignment",
        ],
    }


def _repair_audit_source_records(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    current = evidence.get("repair_suggestion_audit_refs")
    records = current.get("records") if isinstance(current, dict) else None
    if isinstance(records, list) and records:
        return [record for record in records if isinstance(record, dict)]

    # Backfill older contract runner evidence written before
    # repair_suggestion_audit_refs existed.
    legacy_records: list[dict[str, Any]] = []
    tasks = evidence.get("tasks") if isinstance(evidence.get("tasks"), dict) else {}
    failed_tasks = evidence.get("failed_tasks") if isinstance(evidence.get("failed_tasks"), list) else []
    contract_hits = evidence.get("contract_log_hits") if isinstance(evidence.get("contract_log_hits"), list) else []
    for source, task in [
        *[(str(key), value) for key, value in tasks.items() if isinstance(value, dict)],
        *[(f"failed_{index}", value) for index, value in enumerate(failed_tasks, start=1) if isinstance(value, dict)],
    ]:
        suggestions = task.get("repair_suggestions")
        if not isinstance(suggestions, list) or not suggestions:
            suggestions = [_fallback_repair_suggestion(task)]
        legacy_records.append({
            "source": source,
            "task_id": task.get("id"),
            "failure_reason": task.get("failure_reason"),
            "repair_suggestions": suggestions,
            "audit_ref_kind": "legacy_delivery_contract_repair_suggestions",
        })
    for index, hit in enumerate(contract_hits, start=1):
        if not isinstance(hit, dict):
            continue
        legacy_records.append({
            "source": f"contract_log_hit_{index}",
            "task_id": _task_id_from_log_line(str(hit.get("line") or "")),
            "failure_reason": "delivery_contract_blocked",
            "repair_suggestions": [
                "Inspect delivery contract violation and create an operator-approved repair task when needed."
            ],
            "audit_ref_kind": "legacy_delivery_contract_block_log",
            "log": hit.get("log"),
            "line": hit.get("line"),
        })
    return legacy_records


def _fallback_repair_suggestion(task: dict[str, Any]) -> str:
    reason = str(task.get("failure_reason") or "").strip()
    task_id = str(task.get("id") or "").strip()
    if reason:
        return f"Inspect task {task_id or '<unknown>'} failure_reason={reason} and create an operator-approved repair task if needed."
    return f"Inspect task {task_id or '<unknown>'} contract evidence and create an operator-approved repair task if needed."


def _task_id_from_log_line(line: str) -> str | None:
    marker = "for "
    if marker not in line:
        return None
    tail = line.split(marker, 1)[1]
    task_id = tail.split(":", 1)[0].strip()
    return task_id or None


def _audit_event_record(
    *,
    source_record: dict[str, Any],
    actor_id: str,
    audit_event_ref: str,
    evidence_path: Path,
) -> dict[str, Any]:
    return {
        "type": "audit_event_recorded",
        "actor_id": actor_id,
        "status": "recorded",
        "audit_event_ref": audit_event_ref,
        "recorded_at": _now(),
        "source_evidence_ref": str(evidence_path),
        "task_id": source_record.get("task_id"),
        "failure_reason": source_record.get("failure_reason"),
        "repair_suggestions": source_record.get("repair_suggestions") or [],
        "audit_ref_kind": source_record.get("audit_ref_kind"),
        "source_record": source_record,
        "non_claims": [
            "audit_record_is_l1_controlled_pilot_only",
            "repair_suggestions_do_not_authorize_auto_retry",
        ],
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
