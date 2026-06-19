"""H.3 controlled-pilot authorization consumption and post-run receipts."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.h3_evidence import artifact_ref, sha256_file, write_json_object

CONSUMPTION_SCHEMA_VERSION = "h3-controlled-pilot-authorization-consumption:v1"
AUTHORIZATION_RECEIPT_SCHEMA_VERSION = "h3-one-time-authorization-receipt:v1"
ROLLBACK_SCHEMA_VERSION = "h3-controlled-pilot-rollback-checkpoint:v1"
POST_RUN_RECEIPT_SCHEMA_VERSION = "h3-controlled-pilot-post-run-receipt:v1"


def build_authorization_receipt(
    *,
    decision: dict[str, Any],
    decision_packet_path: Path,
) -> dict[str, Any]:
    """Build the immutable one-time authorization receipt for an approved A6 decision."""
    seed = {
        "request_id": decision["request_id"],
        "request_sha256": decision["request_sha256"],
        "decision_packet_sha256": sha256_file(decision_packet_path),
        "decided_at": decision["decided_at"],
    }
    return {
        "schema_version": AUTHORIZATION_RECEIPT_SCHEMA_VERSION,
        "authorization_receipt_id": (
            f"h3-one-time-authorization:{_canonical_sha256(seed)[:20]}"
        ),
        "state": "one_time_authorization_granted_pending_execution_preflight",
        "request_id": decision["request_id"],
        "request_sha256": decision["request_sha256"],
        "decision_packet_sha256": sha256_file(decision_packet_path),
        "authorized_scope": decision["requested_scope"],
        "operator_id": decision["operator_id"],
        "monitoring_owner_id": decision["monitoring_owner_id"],
        "audit_owner_id": decision["audit_owner_id"],
        "valid_from": decision["valid_from"],
        "valid_until": decision["valid_until"],
        "controls": decision["controls"],
        "single_use": True,
        "consumed": False,
        "controlled_pilot_execution_allowed": False,
    }


def claim_authorization(
    *,
    path: Path,
    receipt: dict[str, Any],
    preflight_file: Path,
    started_at: datetime,
    profile: str,
) -> dict[str, Any]:
    value = {
        "schema_version": CONSUMPTION_SCHEMA_VERSION,
        "state": "authorization_consumed",
        "authorization_receipt_id": receipt["authorization_receipt_id"],
        "authorization_receipt_sha256": _canonical_sha256(receipt),
        "source_preflight": artifact_ref(preflight_file),
        "consumed_at": started_at.isoformat(),
        "single_use": True,
        "immutable": True,
        "validation_profile": profile,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RuntimeError(f"single-use authorization already claimed: {path}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return value


def write_rollback_checkpoint(
    *,
    path: Path,
    receipt: dict[str, Any],
    authorization_reconciliation_path: Path,
    created_at: datetime,
    profile: str,
) -> dict[str, Any]:
    checkpoint = {
        "schema_version": ROLLBACK_SCHEMA_VERSION,
        "state": "baseline_captured_before_controlled_runner",
        "created_at": created_at.isoformat(),
        "authorization_receipt_id": receipt["authorization_receipt_id"],
        "authorization_receipt_sha256": _canonical_sha256(receipt),
        "source_authorization_reconciliation": artifact_ref(
            authorization_reconciliation_path
        ),
        "baseline": {
            "controlled_runner_started": False,
            "production_state_mutated": False,
            "iem_state_mutated": False,
            "relation_state_mutated": False,
            "authorization_state_mutated": False,
            "normative_state_mutated": False,
        },
        "rollback_actions": [
            f"stop the {profile} controlled runner through the operator kill switch",
            "discard transient pilot outputs while retaining audit evidence",
            "restore the preflight baseline without changing production state",
        ],
    }
    write_json_object(path, checkpoint)
    return checkpoint


def write_post_run_receipt(
    *,
    path: Path,
    passed: bool,
    failures: list[str],
    profile: str,
    receipt: dict[str, Any],
    consumption_path: Path,
    preflight_file: Path,
    bounded_file: Path,
    task_path: Path,
    generation_reports: list[dict[str, Any]],
    started_at: datetime,
    completed_at: datetime,
    duration_seconds: float,
    model: str,
    agent_roles: list[str],
    reconciliation: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema_version": POST_RUN_RECEIPT_SCHEMA_VERSION,
        "passed": passed,
        "state": (
            "controlled_pilot_completed"
            if passed
            else "controlled_pilot_failed_closed"
        ),
        "failure_reasons": failures,
        "validation_profile": profile,
        "development_only": profile == "development",
        "valid_for_qualification": False,
        "authorization_receipt_id": receipt["authorization_receipt_id"],
        "authorization_receipt_sha256": _canonical_sha256(receipt),
        "authorization_consumption": artifact_ref(consumption_path),
        "source_preflight": artifact_ref(preflight_file),
        "source_bounded_plan_report": artifact_ref(bounded_file),
        "task": artifact_ref(task_path),
        "generation_reports": [
            artifact_ref(Path(item["report_path"])) for item in generation_reports
        ],
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "duration_seconds": duration_seconds,
        "model": model,
        "agent_roles": agent_roles,
        "task_count": 1,
        "agent_count": len(generation_reports),
        "reconciliation": reconciliation,
        "side_effects": {
            "authorization_consumed": True,
            "post_run_receipt_written": True,
            "production_state_mutated": False,
            "iem_state_mutated": False,
            "relation_state_mutated": False,
            "authorization_state_mutated": False,
            "normative_state_mutated": False,
            "external_system_mutations": 0,
        },
        "boundary": {
            "development_only": profile == "development",
            "qualification_controlled_only": profile == "qualification",
            "result_valid_for_qualification": False,
            "production_use_allowed": False,
            "automatic_rollout_allowed": False,
            "result_requires_operator_review": True,
            "result_may_directly_change_trust": False,
            "result_may_directly_change_authorization": False,
            "result_may_directly_change_normative_state": False,
        },
    }
    write_json_object(path, value)
    return value


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
