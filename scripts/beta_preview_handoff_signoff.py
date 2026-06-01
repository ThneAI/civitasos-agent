#!/usr/bin/env python3
"""Record and index Beta preview handoff owner signoffs.

This tool consumes a passed Beta preview operator handoff and records explicit
monitoring/audit owner signoff packets. It never executes merge, deploy,
provider calls, production runtime execution, or production receipt writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from glob import glob
from pathlib import Path
from typing import Any

HANDOFF_SCHEMA = "beta-preview-operator-handoff:v1"
SIGNOFF_SCHEMA = "beta-preview-handoff-signoff:v1"
SIGNOFF_WRITE_REPORT_SCHEMA = "beta-preview-handoff-signoff-write-report:v1"
SIGNOFF_VALIDATION_SCHEMA = "beta-preview-handoff-signoff-validation:v1"
INDEX_SCHEMA = "beta-preview-cumulative-evidence-index:v1"
ROLES = ("monitoring_owner", "audit_owner")
VERDICTS = ("accepted", "needs_followup", "rejected")
NON_CLAIMS = (
    "beta_preview_handoff_signoff_is_l1_controlled_preview_evidence_only",
    "beta_preview_handoff_signoff_does_not_execute_merge",
    "beta_preview_handoff_signoff_does_not_execute_deploy",
    "beta_preview_handoff_signoff_does_not_authorize_production_runtime_execution",
    "beta_preview_handoff_signoff_does_not_write_production_receipts",
    "beta_preview_handoff_signoff_does_not_claim_h3_production_readiness",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record", help="record a handoff signoff packet")
    record.add_argument("--handoff", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--role", choices=ROLES, required=True)
    record.add_argument("--actor-id", required=True)
    record.add_argument("--verdict", choices=VERDICTS, required=True)
    record.add_argument("--evidence-ref", required=True)
    record.add_argument("--notes", default="")

    validate = subparsers.add_parser("validate", help="validate a handoff signoff packet")
    validate.add_argument("--packet", required=True)
    validate.add_argument("--output")

    index = subparsers.add_parser("index", help="write cumulative Beta preview evidence index")
    index.add_argument("--handoff", action="append", default=[])
    index.add_argument("--handoff-glob", action="append", default=[])
    index.add_argument("--signoff", action="append", default=[])
    index.add_argument("--signoff-glob", action="append", default=[])
    index.add_argument("--output", required=True)
    index.add_argument("--min-handoffs", type=int, default=1)
    index.add_argument("--require-monitoring-signoff", action="store_true")
    index.add_argument("--require-audit-signoff", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "record":
        report = record_handoff_signoff(
            handoff_path=Path(args.handoff),
            output_path=Path(args.output),
            role=args.role,
            actor_id=args.actor_id,
            verdict=args.verdict,
            evidence_ref=args.evidence_ref,
            notes=args.notes,
        )
    elif args.command == "validate":
        report = validate_handoff_signoff(Path(args.packet))
        if args.output:
            _write_json(Path(args.output), report)
    elif args.command == "index":
        report = write_beta_preview_evidence_index(
            handoff_paths=[Path(path) for path in args.handoff],
            handoff_globs=list(args.handoff_glob),
            signoff_paths=[Path(path) for path in args.signoff],
            signoff_globs=list(args.signoff_glob),
            output_path=Path(args.output),
            min_handoffs=args.min_handoffs,
            require_monitoring_signoff=bool(args.require_monitoring_signoff),
            require_audit_signoff=bool(args.require_audit_signoff),
        )
    else:
        raise AssertionError(f"unknown command: {args.command}")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    validation = report.get("validation") or report
    return 0 if validation.get("passed") else 1


def record_handoff_signoff(
    *,
    handoff_path: Path,
    output_path: Path,
    role: str,
    actor_id: str,
    verdict: str,
    evidence_ref: str,
    notes: str = "",
) -> dict[str, Any]:
    failures: list[str] = []
    handoff = _load_valid_handoff(handoff_path, failures)
    role = _required_choice(role, ROLES, failures, "role")
    actor_id = _required_text(actor_id, failures, "actor_id")
    verdict = _required_choice(verdict, VERDICTS, failures, "verdict")
    evidence_ref = _required_text(evidence_ref, failures, "evidence_ref")
    if failures:
        raise ValueError(f"handoff signoff blocked: {failures}")

    metrics = handoff.get("handoff_metrics") if isinstance(handoff.get("handoff_metrics"), dict) else {}
    packet = {
        "schema_version": SIGNOFF_SCHEMA,
        "recorded_at": _now(),
        "role": role,
        "actor_id": actor_id,
        "verdict": verdict,
        "evidence_ref": evidence_ref,
        "notes": notes.strip(),
        "source_handoff": _artifact_ref(handoff_path),
        "source_chain_summary": handoff.get("chain_summary"),
        "observed_metrics": {
            "readiness_decision": metrics.get("readiness_decision"),
            "provider_identity_count": metrics.get("provider_identity_count"),
            "external_agent_review_count": metrics.get("external_agent_review_count"),
            "preview_smoke_total_checks": metrics.get("preview_smoke_total_checks"),
            "owner_feedback_packet_count": metrics.get("owner_feedback_packet_count"),
            "owner_feedback_accepted_ratio": metrics.get("owner_feedback_accepted_ratio"),
            "rollback_receipt": metrics.get("rollback_receipt"),
        },
        "signoff_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, packet)
    validation = validate_handoff_signoff(output_path)
    if validation["passed"] is not True:
        raise ValueError(f"written handoff signoff failed validation: {validation['failure_reasons']}")
    return {
        "schema_version": SIGNOFF_WRITE_REPORT_SCHEMA,
        "packet_written": True,
        "packet_path": str(output_path.resolve()),
        "packet_sha256": _sha256(output_path),
        "validation": validation,
        "non_claims": list(NON_CLAIMS),
    }


def validate_handoff_signoff(path: Path) -> dict[str, Any]:
    failures: list[str] = []
    packet = _safe_read_json(path, failures, "handoff signoff packet")
    if not isinstance(packet, dict):
        return _validation_report(path, failures or ["packet must be a JSON object"])
    if packet.get("schema_version") != SIGNOFF_SCHEMA:
        failures.append(f"schema_version must be {SIGNOFF_SCHEMA}")
    if packet.get("role") not in ROLES:
        failures.append(f"role must be one of {list(ROLES)}")
    if packet.get("verdict") not in VERDICTS:
        failures.append(f"verdict must be one of {list(VERDICTS)}")
    for field in ("actor_id", "evidence_ref"):
        if not _text(packet.get(field)):
            failures.append(f"{field} must be a non-empty string")
    handoff_ref = _as_artifact_ref(packet.get("source_handoff"), failures, "source_handoff")
    handoff_path = _validate_ref_bytes(handoff_ref, failures, "source_handoff")
    handoff = _load_valid_handoff(handoff_path, failures) if handoff_path else {}
    chain_ref = packet.get("source_chain_summary")
    if not isinstance(chain_ref, dict):
        failures.append("source_chain_summary must be an artifact ref object")
    elif handoff and chain_ref != handoff.get("chain_summary"):
        failures.append("source_chain_summary must match source handoff chain_summary")
    metrics = packet.get("observed_metrics") if isinstance(packet.get("observed_metrics"), dict) else {}
    handoff_metrics = handoff.get("handoff_metrics") if isinstance(handoff.get("handoff_metrics"), dict) else {}
    for field in (
        "readiness_decision",
        "provider_identity_count",
        "external_agent_review_count",
        "preview_smoke_total_checks",
        "owner_feedback_packet_count",
        "owner_feedback_accepted_ratio",
        "rollback_receipt",
    ):
        if handoff and metrics.get(field) != handoff_metrics.get(field):
            failures.append(f"observed_metrics.{field} must match source handoff")
    _validate_boundary(packet.get("signoff_boundary"), failures, "signoff_boundary")
    _validate_h3(packet.get("h3_boundary"), failures, "h3_boundary")
    if packet.get("non_claims") != list(NON_CLAIMS):
        failures.append("non_claims must match handoff signoff non-claims")
    return _validation_report(path, failures)


def write_beta_preview_evidence_index(
    *,
    handoff_paths: list[Path],
    handoff_globs: list[str],
    signoff_paths: list[Path],
    signoff_globs: list[str],
    output_path: Path,
    min_handoffs: int = 1,
    require_monitoring_signoff: bool = False,
    require_audit_signoff: bool = False,
) -> dict[str, Any]:
    failures: list[str] = []
    handoffs = _collect_paths(handoff_paths, handoff_globs)
    signoffs = _collect_paths(signoff_paths, signoff_globs)
    if min_handoffs < 1:
        failures.append("min_handoffs must be >= 1")
    if not handoffs:
        failures.append("at least one handoff path is required")

    handoff_records: list[dict[str, Any]] = []
    for path in handoffs:
        handoff = _load_valid_handoff(path, failures)
        if not handoff:
            continue
        metrics = handoff.get("handoff_metrics") if isinstance(handoff.get("handoff_metrics"), dict) else {}
        handoff_records.append(
            {
                "handoff_path": str(path.resolve()),
                "handoff_sha256": _sha256(path),
                "chain_summary": handoff.get("chain_summary"),
                "checked_at": handoff.get("checked_at"),
                "decision": handoff.get("decision"),
                "provider_identity_count": int(metrics.get("provider_identity_count") or 0),
                "external_agent_review_count": int(metrics.get("external_agent_review_count") or 0),
                "preview_smoke_total_checks": int(metrics.get("preview_smoke_total_checks") or 0),
                "owner_feedback_packet_count": int(metrics.get("owner_feedback_packet_count") or 0),
                "owner_feedback_accepted_ratio": float(metrics.get("owner_feedback_accepted_ratio") or 0.0),
                "owner_feedback_verdict_counts": metrics.get("owner_feedback_verdict_counts") if isinstance(metrics.get("owner_feedback_verdict_counts"), dict) else {},
            }
        )
    if len(handoff_records) < min_handoffs:
        failures.append(f"validated handoff count {len(handoff_records)} below min_handoffs {min_handoffs}")

    signoff_records: list[dict[str, Any]] = []
    signoffs_by_handoff: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for path in signoffs:
        validation = validate_handoff_signoff(path)
        if validation["passed"] is not True:
            failures.append(f"{path}: {validation['failure_reasons']}")
            continue
        packet = json.loads(path.read_text(encoding="utf-8"))
        handoff_sha = packet["source_handoff"]["sha256"]
        role = packet["role"]
        record = {
            "packet_path": str(path.resolve()),
            "packet_sha256": validation["packet_sha256"],
            "recorded_at": packet["recorded_at"],
            "source_handoff_sha256": handoff_sha,
            "role": role,
            "actor_id": packet["actor_id"],
            "verdict": packet["verdict"],
            "evidence_ref": packet["evidence_ref"],
        }
        signoff_records.append(record)
        signoffs_by_handoff.setdefault(handoff_sha, {}).setdefault(role, []).append(record)

    required_roles = []
    if require_monitoring_signoff:
        required_roles.append("monitoring_owner")
    if require_audit_signoff:
        required_roles.append("audit_owner")
    for handoff in handoff_records:
        role_map = signoffs_by_handoff.get(handoff["handoff_sha256"], {})
        for role in required_roles:
            accepted = [item for item in role_map.get(role, []) if item["verdict"] == "accepted"]
            if not accepted:
                failures.append(f"handoff {handoff['handoff_sha256']} missing accepted {role} signoff")

    accepted_signoff_count = sum(1 for item in signoff_records if item["verdict"] == "accepted")
    index = {
        "schema_version": INDEX_SCHEMA,
        "indexed_at": _now(),
        "passed": not failures,
        "decision": "beta_preview_evidence_index_ready" if not failures else "blocked",
        "failure_reasons": failures,
        "handoff_count": len(handoff_records),
        "min_handoffs": min_handoffs,
        "signoff_count": len(signoff_records),
        "accepted_signoff_count": accepted_signoff_count,
        "required_signoff_roles": required_roles,
        "total_preview_smoke_checks": sum(item["preview_smoke_total_checks"] for item in handoff_records),
        "min_owner_feedback_accepted_ratio": min((item["owner_feedback_accepted_ratio"] for item in handoff_records), default=0.0),
        "min_provider_identity_count": min((item["provider_identity_count"] for item in handoff_records), default=0),
        "min_external_agent_review_count": min((item["external_agent_review_count"] for item in handoff_records), default=0),
        "handoffs": handoff_records,
        "signoffs": signoff_records,
        "index_boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_path, index)
    return index


def _load_valid_handoff(path: Path | None, failures: list[str]) -> dict[str, Any]:
    if path is None:
        failures.append("handoff path is required")
        return {}
    handoff = _safe_read_json(path, failures, "operator handoff")
    if not isinstance(handoff, dict):
        failures.append("operator handoff must be a JSON object")
        return {}
    if handoff.get("schema_version") != HANDOFF_SCHEMA:
        failures.append(f"operator handoff schema_version must be {HANDOFF_SCHEMA}")
    if handoff.get("passed") is not True:
        failures.append("operator handoff passed must be true")
    if handoff.get("decision") != "beta_preview_operator_handoff_ready":
        failures.append("operator handoff decision must be beta_preview_operator_handoff_ready")
    _validate_boundary(handoff.get("handoff_boundary"), failures, "handoff_boundary")
    _validate_h3(handoff.get("h3_boundary"), failures, "handoff.h3_boundary")
    if not isinstance(handoff.get("chain_summary"), dict):
        failures.append("operator handoff chain_summary must be an artifact ref object")
    metrics = handoff.get("handoff_metrics") if isinstance(handoff.get("handoff_metrics"), dict) else {}
    if int(metrics.get("provider_identity_count") or 0) < 1:
        failures.append("operator handoff provider_identity_count must be >= 1")
    if int(metrics.get("external_agent_review_count") or 0) < 1:
        failures.append("operator handoff external_agent_review_count must be >= 1")
    if int(metrics.get("preview_smoke_total_checks") or 0) < 1:
        failures.append("operator handoff preview_smoke_total_checks must be >= 1")
    verdict_counts = metrics.get("owner_feedback_verdict_counts") if isinstance(metrics.get("owner_feedback_verdict_counts"), dict) else {}
    if int(verdict_counts.get("rejected") or 0) != 0:
        failures.append("operator handoff owner feedback rejected count must be 0")
    return handoff


def _boundary() -> dict[str, bool]:
    return {
        "l1_beta_controlled_preview_only": True,
        "merge_allowed": False,
        "deploy_allowed": False,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
    }


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _validate_boundary(value: Any, failures: list[str], label: str) -> None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return
    expected = _boundary()
    for key, expected_value in expected.items():
        if value.get(key) is not expected_value:
            failures.append(f"{label}.{key} must be {str(expected_value).lower()}")


def _validate_h3(value: Any, failures: list[str], label: str) -> None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return
    if value.get("h3_remains_blocked") is not True:
        failures.append(f"{label}.h3_remains_blocked must be true")
    if value.get("h3_production_readiness_claimed") is not False:
        failures.append(f"{label}.h3_production_readiness_claimed must be false")


def _required_text(value: Any, failures: list[str], field: str) -> str:
    text = _text(value)
    if not text:
        failures.append(f"{field} must be a non-empty string")
    return text


def _required_choice(value: Any, choices: tuple[str, ...], failures: list[str], field: str) -> str:
    text = _required_text(value, failures, field)
    if text and text not in choices:
        failures.append(f"{field} must be one of {list(choices)}")
    return text


def _collect_paths(paths: list[Path], patterns: list[str]) -> list[Path]:
    collected = list(paths)
    for pattern in patterns:
        collected.extend(Path(path) for path in glob(pattern))
    seen: set[str] = set()
    unique: list[Path] = []
    for path in collected:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return sorted(unique, key=lambda item: str(item))


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
    if expected != _sha256(path):
        failures.append(f"{label}.sha256 mismatch")
    return path


def _safe_read_json(path: Path | None, failures: list[str], label: str) -> Any:
    if path is None:
        failures.append(f"missing {label}: <none>")
        return None
    if not path.is_file():
        failures.append(f"missing {label}: {path}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - operator-facing report preserves parser error.
        failures.append(f"invalid {label} JSON: {exc}")
        return None


def _validation_report(path: Path, failures: list[str]) -> dict[str, Any]:
    return {
        "schema_version": SIGNOFF_VALIDATION_SCHEMA,
        "validated_at": _now(),
        "packet_path": str(path.resolve()),
        "packet_sha256": _sha256(path) if path.is_file() else None,
        "passed": not failures,
        "failure_reasons": failures,
        "production_deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
