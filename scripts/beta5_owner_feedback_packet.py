#!/usr/bin/env python3
"""Record owner feedback, audit refs, and external evidence refs for Beta-5 preview.

This packet consumes a passed Beta-5 repeatable preview nightly artifact and
records human/operator observed feedback references. It does not authorize
production deploy, production runtime execution, or production receipt writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from glob import glob
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PACKET_SCHEMA = "beta5-owner-feedback-evidence-packet:v1"
VALIDATION_SCHEMA = "beta5-owner-feedback-evidence-packet-validation:v1"
WRITE_REPORT_SCHEMA = "beta5-owner-feedback-evidence-packet-write-report:v1"
INDEX_SCHEMA = "beta5-owner-feedback-evidence-index:v1"
SUMMARY_SCHEMA = "beta5-repeatable-preview-nightly-artifact:v1"
VERDICTS = ("accepted", "needs_followup", "rejected")
NON_CLAIMS = (
    "beta5_owner_feedback_packet_is_l1_controlled_pilot_evidence_only",
    "owner_feedback_does_not_authorize_production_deploy",
    "owner_feedback_does_not_authorize_production_runtime_execution",
    "owner_feedback_does_not_write_production_receipts",
    "owner_feedback_does_not_claim_h3_production_readiness",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record owner feedback packet")
    record.add_argument("--preview-summary", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--owner-id", required=True)
    record.add_argument("--operator-id", default="local-operator-cc")
    record.add_argument("--feedback-verdict", choices=VERDICTS, required=True)
    record.add_argument("--feedback-ref", required=True)
    record.add_argument("--audit-ref", required=True)
    record.add_argument("--external-evidence-ref", required=True)
    record.add_argument("--notes", default="")

    validate = subparsers.add_parser("validate", help="validate owner feedback packet")
    validate.add_argument("--packet", required=True)
    validate.add_argument("--output")

    index = subparsers.add_parser("index", help="write cumulative owner feedback evidence index")
    index.add_argument("--packet", action="append", default=[])
    index.add_argument("--packet-glob", action="append", default=[])
    index.add_argument("--output", required=True)
    index.add_argument("--min-packets", type=int, default=1)

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_owner_feedback_packet(
            preview_summary_path=Path(args.preview_summary),
            output_path=Path(args.output),
            owner_id=args.owner_id,
            operator_id=args.operator_id,
            feedback_verdict=args.feedback_verdict,
            feedback_ref=args.feedback_ref,
            audit_ref=args.audit_ref,
            external_evidence_ref=args.external_evidence_ref,
            notes=args.notes,
        )
    elif args.command == "validate":
        report = validate_owner_feedback_packet(Path(args.packet))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "index":
        report = write_owner_feedback_index(
            packet_paths=[Path(path) for path in args.packet],
            packet_globs=list(args.packet_glob),
            output_path=Path(args.output),
            min_packets=args.min_packets,
        )
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    validation = report.get("validation") or report
    return 0 if validation.get("passed") else 1


def write_owner_feedback_index(
    *,
    packet_paths: list[Path],
    packet_globs: list[str],
    output_path: Path,
    min_packets: int = 1,
) -> dict[str, Any]:
    paths = _collect_packet_paths(packet_paths, packet_globs)
    failures: list[str] = []
    if min_packets < 1:
        failures.append("min_packets must be >= 1")
    if not paths:
        failures.append("at least one owner feedback packet path is required")

    records: list[dict[str, Any]] = []
    verdict_counts = {verdict: 0 for verdict in VERDICTS}
    for path in paths:
        validation = validate_owner_feedback_packet(path)
        if validation["passed"] is not True:
            failures.append(f"{path}: {validation['failure_reasons']}")
            continue
        packet = json.loads(path.read_text(encoding="utf-8"))
        observation = packet["preview_observation"]
        verdict = packet["feedback_verdict"]
        verdict_counts[verdict] += 1
        records.append(
            {
                "packet_path": str(path.resolve()),
                "packet_sha256": validation["packet_sha256"],
                "recorded_at": packet["recorded_at"],
                "owner_id": packet["owner_id"],
                "operator_id": packet["operator_id"],
                "feedback_verdict": verdict,
                "feedback_ref": packet["feedback_ref"],
                "audit_ref": packet["audit_ref"],
                "external_evidence_ref": packet["external_evidence_ref"],
                "source_preview_summary": packet["source_preview_summary"],
                "source_preview_run_root": packet["source_preview_run_root"],
                "source_deploy_receipt_sha256": packet["source_deploy_receipt_sha256"],
                "source_rollback_receipt_sha256": packet["source_rollback_receipt_sha256"],
                "nodes": observation["nodes"],
                "smoke_cycles": observation["smoke_cycles"],
                "smoke_total_checks": observation["smoke_total_checks"],
                "latency_ms_median": observation["latency_ms_median"],
                "latency_ms_max": observation["latency_ms_max"],
                "external_environment_provider": observation["external_environment_provider"],
                "external_environment_classification": observation["external_environment_classification"],
            }
        )

    records.sort(key=lambda item: (item["recorded_at"], item["packet_path"]))
    if len(records) < min_packets:
        failures.append(f"validated packet count {len(records)} below min_packets {min_packets}")

    providers = sorted({record["external_environment_provider"] for record in records})
    classifications = sorted({record["external_environment_classification"] for record in records})
    if providers and providers != ["virtualbox"]:
        failures.append("owner feedback index currently only supports virtualbox provider")
    if classifications and classifications != ["external_preview"]:
        failures.append("owner feedback index currently only supports external_preview classification")

    total_smoke_checks = sum(record["smoke_total_checks"] for record in records)
    max_latency = max((record["latency_ms_max"] for record in records), default=None)
    accepted_count = verdict_counts["accepted"]
    index = {
        "schema_version": INDEX_SCHEMA,
        "indexed_at": _now(),
        "passed": not failures,
        "failure_reasons": failures,
        "packet_count": len(records),
        "min_packets": min_packets,
        "verdict_counts": verdict_counts,
        "accepted_ratio": accepted_count / len(records) if records else 0.0,
        "total_smoke_checks": total_smoke_checks,
        "max_latency_ms_max": max_latency,
        "external_environment_providers": providers,
        "external_environment_classifications": classifications,
        "records": records,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
        "h3_boundary": {
            "h3_remains_blocked": True,
            "h3_production_readiness_claimed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, index)
    return index


def record_owner_feedback_packet(
    *,
    preview_summary_path: Path,
    output_path: Path,
    owner_id: str,
    operator_id: str,
    feedback_verdict: str,
    feedback_ref: str,
    audit_ref: str,
    external_evidence_ref: str,
    notes: str = "",
) -> dict[str, Any]:
    failures: list[str] = []
    summary = _load_preview_summary(preview_summary_path, failures)
    owner_id = _required_text(owner_id, failures, "owner_id")
    operator_id = _required_text(operator_id, failures, "operator_id")
    feedback_ref = _required_text(feedback_ref, failures, "feedback_ref")
    audit_ref = _required_text(audit_ref, failures, "audit_ref")
    external_evidence_ref = _required_text(external_evidence_ref, failures, "external_evidence_ref")
    if feedback_verdict not in VERDICTS:
        failures.append(f"feedback_verdict must be one of {list(VERDICTS)}")
    if failures:
        raise ValueError(f"owner feedback packet blocked: {failures}")

    packet = {
        "schema_version": PACKET_SCHEMA,
        "recorded_at": _now(),
        "owner_id": owner_id,
        "operator_id": operator_id,
        "feedback_verdict": feedback_verdict,
        "feedback_ref": feedback_ref,
        "audit_ref": audit_ref,
        "external_evidence_ref": external_evidence_ref,
        "notes": notes.strip(),
        "source_preview_summary": _artifact_ref(preview_summary_path),
        "source_preview_run_root": summary["run_root"],
        "source_deploy_receipt": summary["deploy_receipt"],
        "source_deploy_receipt_sha256": summary["deploy_receipt_sha256"],
        "source_rollback_receipt": summary["rollback_receipt"],
        "source_rollback_receipt_sha256": summary["rollback_receipt_sha256"],
        "preview_observation": {
            "nodes": summary["nodes"],
            "smoke_cycles": summary["smoke_cycles"],
            "smoke_total_checks": summary["smoke_total_checks"],
            "latency_ms_median": summary["latency_ms_median"],
            "latency_ms_max": summary["latency_ms_max"],
            "external_environment_provider": summary["external_environment_provider"],
            "external_environment_classification": summary["external_environment_classification"],
        },
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
        "h3_boundary": {
            "h3_remains_blocked": True,
            "h3_production_readiness_claimed": False,
        },
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, packet)
    validation = validate_owner_feedback_packet(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written owner feedback packet failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": WRITE_REPORT_SCHEMA,
        "packet_written": True,
        "packet_path": str(output_path.resolve()),
        "packet_sha256": _sha256(output_path),
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_owner_feedback_packet(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    packet = _safe_read_json(path, failures, "owner feedback packet")
    if not isinstance(packet, dict):
        return _validation_report(path, failures or ["packet must be a JSON object"])
    if packet.get("schema_version") != PACKET_SCHEMA:
        failures.append(f"schema_version must be {PACKET_SCHEMA}")
    for field in ("owner_id", "operator_id", "feedback_ref", "audit_ref", "external_evidence_ref"):
        if not _text(packet.get(field)):
            failures.append(f"{field} must be a non-empty string")
    if packet.get("feedback_verdict") not in VERDICTS:
        failures.append(f"feedback_verdict must be one of {list(VERDICTS)}")
    summary_ref = _as_artifact_ref(packet.get("source_preview_summary"), failures, "source_preview_summary")
    summary_path = _validate_ref_bytes(summary_ref, failures, "source_preview_summary")
    summary = _load_preview_summary(summary_path, failures) if summary_path else {}
    if summary:
        expected_pairs = {
            "source_preview_run_root": summary.get("run_root"),
            "source_deploy_receipt": summary.get("deploy_receipt"),
            "source_deploy_receipt_sha256": summary.get("deploy_receipt_sha256"),
            "source_rollback_receipt": summary.get("rollback_receipt"),
            "source_rollback_receipt_sha256": summary.get("rollback_receipt_sha256"),
        }
        for field, expected in expected_pairs.items():
            if packet.get(field) != expected:
                failures.append(f"{field} must match source preview summary")
    observation = packet.get("preview_observation")
    if not isinstance(observation, dict):
        failures.append("preview_observation must be an object")
    else:
        if observation.get("external_environment_provider") != "virtualbox":
            failures.append("preview_observation.external_environment_provider must be virtualbox")
        if observation.get("external_environment_classification") != "external_preview":
            failures.append("preview_observation.external_environment_classification must be external_preview")
        if not isinstance(observation.get("nodes"), list) or not observation.get("nodes"):
            failures.append("preview_observation.nodes must be a non-empty list")
        if observation.get("smoke_total_checks", 0) < 1:
            failures.append("preview_observation.smoke_total_checks must be positive")
    for flag in (
        "production_deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
        "h3_production_readiness_claimed",
    ):
        if packet.get(flag) is not False:
            failures.append(f"{flag} must be false")
    h3 = packet.get("h3_boundary")
    if not isinstance(h3, dict) or h3.get("h3_remains_blocked") is not True or h3.get("h3_production_readiness_claimed") is not False:
        failures.append("h3_boundary must keep H.3 blocked and not claim readiness")
    if packet.get("non_claims") != list(NON_CLAIMS):
        failures.append("non_claims must match Beta-5 owner feedback non-claims")
    return _validation_report(path, failures)


def _load_preview_summary(path: Path | None, failures: list[str]) -> dict[str, Any]:
    summary = _safe_read_json(path, failures, "preview summary")
    if not isinstance(summary, dict):
        failures.append("preview summary must be a JSON object")
        return {}
    if summary.get("schema_version") != SUMMARY_SCHEMA:
        failures.append(f"preview summary schema_version must be {SUMMARY_SCHEMA}")
    if summary.get("passed") is not True:
        failures.append("preview summary must have passed=true")
    for field in (
        "run_root",
        "deploy_receipt",
        "deploy_receipt_sha256",
        "rollback_receipt",
        "rollback_receipt_sha256",
        "external_environment_provider",
        "external_environment_classification",
    ):
        if not _text(summary.get(field)):
            failures.append(f"preview summary {field} must be a non-empty string")
    if summary.get("external_environment_provider") != "virtualbox":
        failures.append("preview summary provider must be virtualbox")
    if summary.get("external_environment_classification") != "external_preview":
        failures.append("preview summary classification must be external_preview")
    _validate_summary_artifact(
        summary,
        path_field="deploy_receipt",
        sha_field="deploy_receipt_sha256",
        failures=failures,
    )
    _validate_summary_artifact(
        summary,
        path_field="rollback_receipt",
        sha_field="rollback_receipt_sha256",
        failures=failures,
    )
    if not isinstance(summary.get("nodes"), list) or not summary.get("nodes"):
        failures.append("preview summary nodes must be a non-empty list")
    if not isinstance(summary.get("smoke_cycles"), int) or summary.get("smoke_cycles", 0) < 1:
        failures.append("preview summary smoke_cycles must be a positive integer")
    if not isinstance(summary.get("smoke_total_checks"), int) or summary.get("smoke_total_checks", 0) < 1:
        failures.append("preview summary smoke_total_checks must be a positive integer")
    for field in ("latency_ms_median", "latency_ms_max"):
        value = summary.get(field)
        if not isinstance(value, int | float) or value < 0:
            failures.append(f"preview summary {field} must be a non-negative number")
    for flag in (
        "production_deploy_allowed",
        "production_runtime_execution_allowed",
        "production_receipt_write_allowed",
        "h3_production_readiness_claimed",
    ):
        if summary.get(flag) is not False:
            failures.append(f"preview summary {flag} must be false")
    return summary


def _validate_summary_artifact(
    summary: dict[str, Any],
    *,
    path_field: str,
    sha_field: str,
    failures: list[str],
) -> None:
    path_text = summary.get(path_field)
    expected_sha = summary.get(sha_field)
    if not _text(path_text) or not _text(expected_sha):
        return
    path = Path(str(path_text))
    if not path.is_file():
        failures.append(f"preview summary {path_field} does not exist: {path}")
        return
    if _sha256(path) != expected_sha:
        failures.append(f"preview summary {sha_field} does not match {path_field}")


def _collect_packet_paths(packet_paths: list[Path], packet_globs: list[str]) -> list[Path]:
    collected: list[Path] = []
    for path in packet_paths:
        collected.append(path)
    for pattern in packet_globs:
        collected.extend(Path(path) for path in glob(pattern))
    seen: set[str] = set()
    unique: list[Path] = []
    for path in collected:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return sorted(unique, key=lambda path: str(path))


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _as_artifact_ref(value: Any, failures: list[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an artifact ref object")
        return {}
    if not _text(value.get("path")):
        failures.append(f"{label}.path must be a non-empty string")
    if not _text(value.get("sha256")):
        failures.append(f"{label}.sha256 must be a non-empty string")
    return value


def _validate_ref_bytes(ref: dict[str, Any], failures: list[str], label: str) -> Path | None:
    path_text = ref.get("path") if isinstance(ref, dict) else None
    if not _text(path_text):
        return None
    path = Path(str(path_text))
    if not path.is_file():
        failures.append(f"{label}.path does not exist: {path}")
        return None
    expected = ref.get("sha256")
    actual = _sha256(path)
    if expected != actual:
        failures.append(f"{label}.sha256 mismatch")
    return path


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        failures.append(f"{label} path is missing")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
    return None


def _required_text(value: str, failures: list[str], label: str) -> str:
    text = str(value).strip()
    if not text:
        failures.append(f"{label} must be a non-empty string")
    return text


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": VALIDATION_SCHEMA,
        "checked_at": _now(),
        "packet_path": str(path.resolve()),
        "packet_sha256": _sha256(path) if path.is_file() else None,
        "passed": not failures,
        "failure_reasons": failures,
        "non_claims": list(NON_CLAIMS),
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
