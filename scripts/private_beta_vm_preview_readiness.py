#!/usr/bin/env python3
"""Build a read-only readiness index from private Beta VM preview receipts.

This command only validates existing artifacts. It never contacts preview VMs,
executes deploy or rollback commands, mutates source/Git, opens public ingress,
executes production runtime, or writes production receipts.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from beta_evidence import artifact_ref, read_json_or_empty, validate_ref_bytes, write_json
except ModuleNotFoundError:
    from scripts.beta_evidence import artifact_ref, read_json_or_empty, validate_ref_bytes, write_json

try:
    from civitasos_contracts.artifacts import build_artifact_envelope, validate_artifact_envelope
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import build_artifact_envelope, validate_artifact_envelope


SUMMARY_SCHEMA = "private-beta-vm-preview-chain-summary:v1"
EXECUTION_SCHEMA = "private-beta-vm-preview-execution-receipt:v1"
ROLLBACK_SCHEMA = "private-beta-vm-preview-rollback-receipt:v1"
MONITORING_SCHEMA = "private-beta-vm-preview-monitoring-receipt:v1"
INDEX_SCHEMA = "private-beta-vm-preview-readiness-index:v1"
EXPECTED_VM_TARGETS = ["vm1", "vm2", "vm3"]
REQUIRED_READY = (
    "authorization_consumed",
    "deploy_executed",
    "smoke_passed",
    "rollback_executed",
    "rollback_health_passed",
    "monitoring_receipt_written",
    "private_beta_vm_preview_complete",
)
REQUIRED_BOUNDARY_TRUE = (
    "authorization_consumed",
    "vm_contact_performed",
    "private_preview_deploy_executed",
    "rollback_executed",
    "monitoring_receipt_written",
)
REQUIRED_BOUNDARY_FALSE = (
    "public_ingress_allowed",
    "production_runtime_execution_allowed",
    "production_receipt_write_allowed",
    "source_or_git_mutation_allowed",
    "h3_production_readiness_claimed",
)
NON_CLAIMS = (
    "private_beta_vm_preview_readiness_is_artifact_only",
    "private_beta_vm_preview_readiness_does_not_contact_vms",
    "private_beta_vm_preview_readiness_does_not_authorize_deploy",
    "private_beta_vm_preview_readiness_does_not_open_public_ingress",
    "private_beta_vm_preview_readiness_does_not_execute_production_runtime",
    "private_beta_vm_preview_readiness_does_not_write_production_receipts",
    "private_beta_vm_preview_readiness_does_not_claim_h3_production_readiness",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--min-previews", type=int, default=1)
    args = parser.parse_args(argv)

    report = build_readiness_index(
        summary_paths=[Path(path) for path in args.summary],
        output_path=Path(args.output),
        min_previews=args.min_previews,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def build_readiness_index(
    *,
    summary_paths: list[Path],
    output_path: Path,
    min_previews: int,
) -> dict[str, Any]:
    failures: list[str] = []
    if min_previews < 1:
        failures.append("min_previews must be >= 1")

    records: list[dict[str, Any]] = []
    seen_authorizations: set[str] = set()
    for path in sorted({item.resolve() for item in summary_paths}):
        summary = read_json_or_empty(path, failures, "private Beta VM preview summary")
        if not summary:
            continue
        record = _validate_summary(summary, path, failures)
        authorization_id = str(summary.get("authorization_id") or "").strip()
        if authorization_id in seen_authorizations:
            failures.append(f"duplicate authorization_id: {authorization_id}")
            continue
        seen_authorizations.add(authorization_id)
        records.append(record)

    if len(records) < min_previews:
        failures.append(f"validated preview count {len(records)} below min_previews {min_previews}")

    report = _build_index(records, failures, min_previews)
    write_json(output_path, report)
    return report


def _validate_summary(
    summary: dict[str, Any],
    summary_path: Path,
    failures: list[str],
) -> dict[str, Any]:
    label = summary_path.name
    if summary.get("schema_version") != SUMMARY_SCHEMA:
        failures.append(f"{label} schema_version must be {SUMMARY_SCHEMA}")
    if summary.get("passed") is not True:
        failures.append(f"{label} must be passed")
    if summary.get("decision") != "private_beta_vm_preview_passed":
        failures.append(f"{label} decision must be private_beta_vm_preview_passed")

    envelope = summary.get("artifact_envelope")
    if envelope is not None:
        failures.extend(
            f"{label} artifact_envelope: {failure}"
            for failure in validate_artifact_envelope(envelope)
        )

    authorization_id = str(summary.get("authorization_id") or "").strip()
    if not authorization_id:
        failures.append(f"{label} authorization_id must be non-empty")
    if sorted(str(item) for item in summary.get("vm_target_ids") or []) != EXPECTED_VM_TARGETS:
        failures.append(f"{label} must target exactly vm1/vm2/vm3")

    readiness = summary.get("readiness") if isinstance(summary.get("readiness"), dict) else {}
    for key in REQUIRED_READY:
        if readiness.get(key) is not True:
            failures.append(f"{label} readiness.{key} must be true")
    if readiness.get("production_transition_allowed") is not False:
        failures.append(f"{label} readiness.production_transition_allowed must be false")

    boundary = summary.get("boundary") if isinstance(summary.get("boundary"), dict) else {}
    for key in REQUIRED_BOUNDARY_TRUE:
        if boundary.get(key) is not True:
            failures.append(f"{label} boundary.{key} must be true")
    for key in REQUIRED_BOUNDARY_FALSE:
        if boundary.get(key) is not False:
            failures.append(f"{label} boundary.{key} must be false")

    artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
    execution = _validate_receipt_ref(
        artifacts.get("execution_receipt"), EXECUTION_SCHEMA, authorization_id, failures, f"{label} execution receipt"
    )
    rollback = _validate_receipt_ref(
        artifacts.get("rollback_receipt"), ROLLBACK_SCHEMA, authorization_id, failures, f"{label} rollback receipt"
    )
    monitoring = _validate_receipt_ref(
        artifacts.get("monitoring_receipt"), MONITORING_SCHEMA, authorization_id, failures, f"{label} monitoring receipt"
    )
    latency = monitoring.get("latency_summary") if isinstance(monitoring.get("latency_summary"), dict) else {}
    return {
        "authorization_id": authorization_id,
        "summary": artifact_ref(summary_path),
        "checked_at": summary.get("checked_at"),
        "vm_target_ids": list(EXPECTED_VM_TARGETS),
        "total_checks": int(latency.get("total_checks") or 0),
        "latency_ms_median": latency.get("latency_ms_median"),
        "execution_passed": execution.get("passed") is True,
        "rollback_passed": rollback.get("passed") is True,
        "monitoring_passed": monitoring.get("passed") is True,
    }


def _validate_receipt_ref(
    value: Any,
    expected_schema: str,
    authorization_id: str,
    failures: list[str],
    label: str,
) -> dict[str, Any]:
    path = validate_ref_bytes(value, failures, label)
    if path is None:
        return {}
    receipt = read_json_or_empty(path, failures, label)
    if receipt.get("schema_version") != expected_schema:
        failures.append(f"{label} schema_version must be {expected_schema}")
    if receipt.get("passed") is not True:
        failures.append(f"{label} must be passed")
    receipt_authorization_id = receipt.get("authorization_id")
    if receipt_authorization_id is not None and receipt_authorization_id != authorization_id:
        failures.append(f"{label} authorization_id must match summary")
    return receipt


def _build_index(
    records: list[dict[str, Any]],
    failures: list[str],
    min_previews: int,
) -> dict[str, Any]:
    source_refs = [record["summary"] for record in records]
    passed = not failures
    return {
        "schema_version": INDEX_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="runtime",
            schema_version=INDEX_SCHEMA,
            artifact_id=f"private-beta-vm-preview-readiness-index:{len(records)}",
            subject_id="private-beta-vm-preview-readiness",
            producer="private_beta_vm_preview_readiness",
            source_refs=source_refs,
            scope="artifact_only_private_beta_vm_preview_readiness",
        ),
        "indexed_at": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "decision": "private_beta_vm_preview_readiness_index_passed" if passed else "blocked",
        "failure_reasons": failures,
        "preview_count": len(records),
        "min_previews": min_previews,
        "authorization_ids": [record["authorization_id"] for record in records],
        "total_checks": sum(record["total_checks"] for record in records),
        "records": records,
        "readiness": {
            "private_beta_vm_preview_evidence_ready": passed,
            "production_transition_allowed": False,
        },
        "boundary": {
            "artifact_only": True,
            "vm_contact_performed": False,
            "deploy_allowed": False,
            "public_ingress_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
            "source_or_git_mutation_allowed": False,
            "h3_production_readiness_claimed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }


if __name__ == "__main__":
    raise SystemExit(main())
