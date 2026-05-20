#!/usr/bin/env python3
"""Export L1 operator-approved repair probe byproducts as packet records."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_AUDIT_ACTOR_ID = "audit-owner-001"
DEFAULT_OBSERVER_ACTOR_ID = "observer-001"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probe-root",
        default=os.getenv("L1_OPERATOR_REPAIR_PROBE_ROOT"),
        required=os.getenv("L1_OPERATOR_REPAIR_PROBE_ROOT") is None,
        help="Path to an l1_operator_repair_failure_probe_* run root.",
    )
    parser.add_argument(
        "--audit-output",
        required=True,
        help="Path to write or append packet-compatible sinks/audit-events.jsonl records.",
    )
    parser.add_argument(
        "--probe-output",
        required=True,
        help="Path to write or append packet-compatible monitoring/probe-events.jsonl records.",
    )
    parser.add_argument(
        "--audit-actor-id",
        default=os.getenv("L1_AUDIT_OWNER_ACTOR_ID", DEFAULT_AUDIT_ACTOR_ID),
        help="Audit owner actor_id. Must match the L1 packet operator registry.",
    )
    parser.add_argument(
        "--observer-actor-id",
        default=os.getenv("L1_OBSERVABILITY_OWNER_ACTOR_ID", DEFAULT_OBSERVER_ACTOR_ID),
        help="Observability owner actor_id. Must match the L1 packet operator registry.",
    )
    parser.add_argument(
        "--audit-ref-prefix",
        default=os.getenv("L1_OPERATOR_REPAIR_PROBE_AUDIT_REF_PREFIX", "l1-operator-repair-probe"),
    )
    parser.add_argument(
        "--probe-ref-prefix",
        default=os.getenv("L1_OPERATOR_REPAIR_PROBE_REF_PREFIX", "l1-operator-repair-probe"),
    )
    parser.add_argument("--append", action="store_true")
    args = parser.parse_args(argv)

    report = export_operator_repair_probe_byproducts(
        probe_root=Path(args.probe_root),
        audit_output_path=Path(args.audit_output),
        probe_output_path=Path(args.probe_output),
        audit_actor_id=str(args.audit_actor_id),
        observer_actor_id=str(args.observer_actor_id),
        audit_ref_prefix=str(args.audit_ref_prefix),
        probe_ref_prefix=str(args.probe_ref_prefix),
        append=bool(args.append),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def export_operator_repair_probe_byproducts(
    *,
    probe_root: Path,
    audit_output_path: Path,
    probe_output_path: Path,
    audit_actor_id: str,
    observer_actor_id: str,
    audit_ref_prefix: str,
    probe_ref_prefix: str,
    append: bool = False,
) -> dict[str, Any]:
    source = _load_probe_source(probe_root)
    facts = _validate_probe_source(source)

    recorded_at = _now()
    audit_records = _audit_records(
        source=source,
        facts=facts,
        actor_id=audit_actor_id,
        audit_ref_prefix=audit_ref_prefix,
        recorded_at=recorded_at,
    )
    probe_records = _probe_records(
        source=source,
        facts=facts,
        actor_id=observer_actor_id,
        probe_ref_prefix=probe_ref_prefix,
        recorded_at=recorded_at,
    )
    _write_jsonl(audit_output_path, audit_records, append=append)
    _write_jsonl(probe_output_path, probe_records, append=append)

    return {
        "schema_version": "l1-operator-repair-probe-byproduct-export-report:v1",
        "probe_root": str(probe_root),
        "audit_output_path": str(audit_output_path),
        "probe_output_path": str(probe_output_path),
        "audit_actor_id": audit_actor_id,
        "observer_actor_id": observer_actor_id,
        "audit_record_count": len(audit_records),
        "probe_record_count": len(probe_records),
        "failed_task_id": facts["failed_task_id"],
        "repair_task_id": facts["repair_task_id"],
        "append": append,
        "packet_record_types": ["audit_event_recorded", "monitoring_green"],
        "non_claims": [
            "operator_repair_probe_byproducts_are_l1_controlled_pilot_only",
            "operator_approval_does_not_authorize_production_runtime_execution",
            "operator_repair_probe_export_does_not_write_production_receipts",
        ],
    }


def _load_probe_source(probe_root: Path) -> dict[str, Any]:
    reports = probe_root / "reports"
    paths = {
        "summary": probe_root / "summary.json",
        "contract_rejection": reports / "contract_rejection_422.json",
        "post_repair": reports / "post_repair.json",
        "repair_task_read_model": reports / "repair_task_read_model.json",
    }
    optional_paths = {
        "failed_task_read_model": reports / "failed_task_read_model.json",
        "operator_read_model_after_repair": reports / "operator_read_model_after_repair.json",
        "mark_failed": reports / "mark_failed.json",
    }
    source: dict[str, Any] = {"probe_root": str(probe_root), "paths": {key: str(path) for key, path in paths.items()}}
    for key, path in paths.items():
        source[key] = _read_json(path)
    for key, path in optional_paths.items():
        if path.exists():
            source[key] = _read_json(path)
            source["paths"][key] = str(path)
    return source


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"missing required probe byproduct: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_probe_source(source: dict[str, Any]) -> dict[str, Any]:
    summary = _as_dict(source.get("summary"), "summary")
    rejection = _as_dict(source.get("contract_rejection"), "contract_rejection")
    post_repair = _as_dict(source.get("post_repair"), "post_repair")
    repair_read_model = _as_dict(source.get("repair_task_read_model"), "repair_task_read_model")

    failed_task_id = _required_str(summary.get("failed_task_id"), "summary.failed_task_id")
    repair_task_id = _required_str(summary.get("repair_task_id"), "summary.repair_task_id")
    source_failed_task_id = _required_str(
        summary.get("repair_source_failed_task_id"),
        "summary.repair_source_failed_task_id",
    )
    if source_failed_task_id != failed_task_id:
        raise ValueError("summary repair_source_failed_task_id does not match failed_task_id")

    if int(summary.get("contract_rejection_status") or 0) != 422:
        raise ValueError("summary.contract_rejection_status must be 422")

    rejection_status = int(rejection.get("status") or 0)
    rejection_body = _as_dict(rejection.get("body"), "contract_rejection.body")
    if rejection_status != 422:
        raise ValueError("contract_rejection.status must be 422")
    if rejection_body.get("error") != "delivery contract violation":
        raise ValueError("contract_rejection.body.error must be 'delivery contract violation'")
    if rejection_body.get("task_id") != failed_task_id:
        raise ValueError("contract_rejection.body.task_id does not match failed_task_id")

    verification = _as_dict(
        rejection_body.get("delivery_contract_verification"),
        "contract_rejection.body.delivery_contract_verification",
    )
    if verification.get("passed") is not False:
        raise ValueError("delivery_contract_verification.passed must be false")
    failure_reasons = verification.get("failure_reasons")
    if not isinstance(failure_reasons, list) or not failure_reasons:
        raise ValueError("delivery_contract_verification.failure_reasons must be non-empty")
    repair_suggestions = verification.get("repair_suggestions")
    if not isinstance(repair_suggestions, list) or not repair_suggestions:
        raise ValueError("delivery_contract_verification.repair_suggestions must be non-empty")

    if post_repair.get("posted_task_id") != repair_task_id:
        raise ValueError("post_repair.posted_task_id does not match repair_task_id")

    task = _as_dict(repair_read_model.get("task"), "repair_task_read_model.task")
    if task.get("id") != repair_task_id:
        raise ValueError("repair_task_read_model.task.id does not match repair_task_id")
    task_input = _as_dict(task.get("input"), "repair_task_read_model.task.input")
    operator_approval = _as_dict(task_input.get("operator_approval"), "repair_task_read_model.task.input.operator_approval")
    if operator_approval.get("approved") is not True:
        raise ValueError("repair task operator approval must be true")
    if operator_approval.get("source_failed_task_id") != failed_task_id:
        raise ValueError("repair task operator approval source_failed_task_id does not match failed_task_id")
    if task_input.get("source_failed_task_id") != failed_task_id:
        raise ValueError("repair task source_failed_task_id does not match failed_task_id")

    summary_approval = _as_dict(summary.get("repair_operator_approval"), "summary.repair_operator_approval")
    if summary_approval.get("approved") is not True:
        raise ValueError("summary repair_operator_approval.approved must be true")

    return {
        "failed_task_id": failed_task_id,
        "repair_task_id": repair_task_id,
        "repair_task_status": summary.get("repair_task_status") or task.get("status"),
        "failure_reasons": failure_reasons,
        "repair_suggestions": repair_suggestions,
        "operator_approval": operator_approval,
        "contract": verification.get("contract") or {},
    }


def _audit_records(
    *,
    source: dict[str, Any],
    facts: dict[str, Any],
    actor_id: str,
    audit_ref_prefix: str,
    recorded_at: str,
) -> list[dict[str, Any]]:
    return [
        {
            "type": "audit_event_recorded",
            "actor_id": actor_id,
            "status": "recorded",
            "audit_event_ref": f"{audit_ref_prefix}:contract-rejection",
            "recorded_at": recorded_at,
            "source_evidence_ref": source["paths"]["contract_rejection"],
            "task_id": facts["failed_task_id"],
            "failure_reason": "delivery_contract_violation",
            "violation_reasons": facts["failure_reasons"],
            "repair_suggestions": facts["repair_suggestions"],
            "audit_ref_kind": "l1_operator_repair_probe_contract_rejection",
            "non_claims": _non_claims(),
        },
        {
            "type": "audit_event_recorded",
            "actor_id": actor_id,
            "status": "recorded",
            "audit_event_ref": f"{audit_ref_prefix}:operator-approval",
            "recorded_at": recorded_at,
            "source_evidence_ref": source["paths"]["summary"],
            "task_id": facts["repair_task_id"],
            "source_failed_task_id": facts["failed_task_id"],
            "operator_approval": facts["operator_approval"],
            "audit_ref_kind": "l1_operator_approved_repair_task",
            "non_claims": _non_claims(),
        },
        {
            "type": "audit_event_recorded",
            "actor_id": actor_id,
            "status": "recorded",
            "audit_event_ref": f"{audit_ref_prefix}:repair-task-posted",
            "recorded_at": recorded_at,
            "source_evidence_ref": source["paths"]["repair_task_read_model"],
            "task_id": facts["repair_task_id"],
            "source_failed_task_id": facts["failed_task_id"],
            "repair_task_status": facts["repair_task_status"],
            "audit_ref_kind": "l1_operator_repair_task_read_model",
            "non_claims": _non_claims(),
        },
    ]


def _probe_records(
    *,
    source: dict[str, Any],
    facts: dict[str, Any],
    actor_id: str,
    probe_ref_prefix: str,
    recorded_at: str,
) -> list[dict[str, Any]]:
    return [
        {
            "type": "monitoring_green",
            "actor_id": actor_id,
            "status": "green",
            "live_monitoring_ref": f"{probe_ref_prefix}:operator-repair-probe-observed",
            "checked_at": recorded_at,
            "source_evidence_ref": source["paths"]["summary"],
            "failed_task_id": facts["failed_task_id"],
            "repair_task_id": facts["repair_task_id"],
            "observed_byproduct": "operator_approved_repair_probe",
            "non_claims": [
                "probe_observation_is_l1_controlled_pilot_only",
                "probe_observation_does_not_claim_h3_production_readiness",
            ],
        }
    ]


def _write_jsonl(path: Path, records: list[dict[str, Any]], *, append: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records)
    if append and path.exists():
        with path.open("a", encoding="utf-8") as handle:
            handle.write(text)
    else:
        path.write_text(text, encoding="utf-8")


def _as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _required_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _non_claims() -> list[str]:
    return [
        "audit_record_is_l1_controlled_pilot_only",
        "operator_approval_does_not_authorize_auto_retry",
        "operator_approval_does_not_authorize_production_runtime_execution",
    ]


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
