#!/usr/bin/env python3
"""Export a Beta-1 repo-review run as an L1 controlled pilot packet.

The packet is importable by civitasos-evidence-ledger after its
packet_manifest.json is refreshed. This script only writes local packet files;
it does not run the ledger, call an LLM, mutate the reviewed repository, or
write production receipts.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from beta1_repo_review_proposal import DANGEROUS_FLAGS, NON_CLAIMS, validate_receipt


PACKET_SCHEMA = "beta1-l1-packet-export-report:v1"
DEFAULT_OPERATOR_ID = "l1-controlled-pilot-operator"
DEFAULT_OBSERVER_ID = "observer-001"
DEFAULT_REGISTRAR_ID = "agent-registrar-001"
DEFAULT_AGENT_OBSERVER_ID = "agent-observer-001"
DEFAULT_AUDIT_OWNER_ID = "audit-owner-001"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True, help="Beta-1 run root containing request/proposal/receipt files.")
    parser.add_argument("--packet-root", required=True, help="Output L1 packet root.")
    parser.add_argument("--operator-id", default=DEFAULT_OPERATOR_ID)
    parser.add_argument("--observer-actor-id", default=DEFAULT_OBSERVER_ID)
    parser.add_argument("--registrar-actor-id", default=DEFAULT_REGISTRAR_ID)
    parser.add_argument("--agent-observer-actor-id", default=DEFAULT_AGENT_OBSERVER_ID)
    parser.add_argument("--audit-actor-id", default=DEFAULT_AUDIT_OWNER_ID)
    parser.add_argument("--external-agent-id", help="External agent id. Defaults to request target_agent.")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)

    report = export_beta1_l1_packet(
        run_root=Path(args.run_root),
        packet_root=Path(args.packet_root),
        operator_id=args.operator_id,
        observer_actor_id=args.observer_actor_id,
        registrar_actor_id=args.registrar_actor_id,
        agent_observer_actor_id=args.agent_observer_actor_id,
        audit_actor_id=args.audit_actor_id,
        external_agent_id=args.external_agent_id,
        overwrite=args.overwrite,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def export_beta1_l1_packet(
    *,
    run_root: Path,
    packet_root: Path,
    operator_id: str,
    observer_actor_id: str,
    registrar_actor_id: str,
    agent_observer_actor_id: str,
    audit_actor_id: str,
    external_agent_id: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    run_root = run_root.resolve()
    packet_root = packet_root.resolve()
    if not run_root.is_dir():
        raise FileNotFoundError(f"Beta-1 run root not found: {run_root}")
    if packet_root.exists() and any(packet_root.iterdir()) and not overwrite:
        raise FileExistsError(f"Refusing to overwrite non-empty packet root: {packet_root}")
    if packet_root.exists() and overwrite:
        shutil.rmtree(packet_root)

    request_path = run_root / "beta1_repo_review_proposal_request.json"
    receipt_path = run_root / "operator_decision_receipt.json"
    validation_path = run_root / "operator_decision_receipt_validation.json"
    summary_path = run_root / "external_model_summary.json"

    request = _read_json(request_path)
    receipt = _read_json(receipt_path)
    proposal_path = _receipt_artifact_path(receipt)
    validation = validate_receipt(receipt_path=receipt_path, request_path=request_path, proposal_path=proposal_path)
    if validation.get("passed") is not True:
        raise ValueError(f"Beta-1 receipt validation failed: {validation.get('failure_reasons')}")
    if validation_path.exists():
        existing_validation = _read_json(validation_path)
        if existing_validation.get("passed") is not True:
            raise ValueError(f"Existing receipt validation is not passed: {validation_path}")
    for flag in DANGEROUS_FLAGS:
        if receipt.get(flag) is not False:
            raise ValueError(f"Unsafe receipt flag: {flag}={receipt.get(flag)!r}")

    external_agent_id = external_agent_id or str(request.get("target_agent") or "external-model-reviewer")
    now = _now()
    _write_packet_files(
        packet_root=packet_root,
        run_root=run_root,
        request=request,
        receipt=receipt,
        validation=validation,
        summary=_read_json(summary_path) if summary_path.exists() else {},
        operator_id=operator_id,
        observer_actor_id=observer_actor_id,
        registrar_actor_id=registrar_actor_id,
        agent_observer_actor_id=agent_observer_actor_id,
        audit_actor_id=audit_actor_id,
        external_agent_id=external_agent_id,
        recorded_at=now,
    )

    return {
        "schema_version": PACKET_SCHEMA,
        "exported": True,
        "run_root": str(run_root),
        "packet_root": str(packet_root),
        "request_id": receipt.get("request_id"),
        "decision": receipt.get("decision"),
        "external_agent_id": external_agent_id,
        "packet_files": [
            "identities/operator_registry.json",
            "identities/external_agent_registry.json",
            "monitoring/probe-events.jsonl",
            "sinks/external-agent-events.jsonl",
            "sinks/audit-events.jsonl",
            "sinks/receipt-events.jsonl",
        ],
        "requires_packet_manifest_refresh": True,
        "manifest_command": (
            "civitasos-evidence-ledger write-l1-pilot-packet-manifest "
            f"--input-root {packet_root} --packet-id beta1-{receipt.get('request_id')} "
            f"--prepared-by-actor-id {audit_actor_id} --prepared-at {now} "
            f"--collection-window-started-at {now} --collection-window-ended-at {now} "
            f"--operator-attestation-ref beta1-operator-decision:{receipt.get('request_id')} --overwrite"
        ),
        "non_claims": list(NON_CLAIMS),
    }


def _write_packet_files(
    *,
    packet_root: Path,
    run_root: Path,
    request: dict[str, Any],
    receipt: dict[str, Any],
    validation: dict[str, Any],
    summary: dict[str, Any],
    operator_id: str,
    observer_actor_id: str,
    registrar_actor_id: str,
    agent_observer_actor_id: str,
    audit_actor_id: str,
    external_agent_id: str,
    recorded_at: str,
) -> None:
    (packet_root / "identities").mkdir(parents=True, exist_ok=True)
    (packet_root / "monitoring").mkdir(parents=True, exist_ok=True)
    (packet_root / "sinks").mkdir(parents=True, exist_ok=True)

    _write_json(packet_root / "identities" / "operator_registry.json", _operator_registry(
        operator_id=operator_id,
        observer_actor_id=observer_actor_id,
        registrar_actor_id=registrar_actor_id,
        agent_observer_actor_id=agent_observer_actor_id,
        audit_actor_id=audit_actor_id,
    ))
    _write_json(packet_root / "identities" / "external_agent_registry.json", [
        {
            "agent_id": external_agent_id,
            "agent_role": "external_model_reviewer",
            "registration_ref": f"agent-reg:beta1:{receipt['request_id']}",
        }
    ])
    _write_jsonl(packet_root / "monitoring" / "probe-events.jsonl", [
        {
            "type": "monitoring_green",
            "actor_id": observer_actor_id,
            "status": "green",
            "live_monitoring_ref": f"lm:beta1:{receipt['request_id']}",
            "checked_at": recorded_at,
            "source_evidence_ref": str(run_root / "external_model_summary.json"),
            "non_claims": [
                "beta1_monitoring_observation_is_l1_controlled_pilot_only",
                "beta1_monitoring_observation_does_not_claim_h3_production_readiness",
            ],
        },
        {
            "type": "backend_health_probe_green",
            "actor_id": observer_actor_id,
            "status": "green",
            "backend_health_ref": f"backend-health:beta1:{receipt['request_id']}",
            "checked_at": recorded_at,
            "source_evidence_ref": str(run_root),
            "non_claims": [
                "beta1_packet_export_does_not_start_backend",
                "beta1_backend_health_ref_is_packet_scope_only",
            ],
        },
    ])
    _write_jsonl(packet_root / "sinks" / "external-agent-events.jsonl", [
        {
            "type": "external_agent_registered",
            "actor_id": registrar_actor_id,
            "status": "registered",
            "agent_id": external_agent_id,
            "agent_role": "external_model_reviewer",
            "registration_ref": f"agent-reg:beta1:{receipt['request_id']}",
            "registered_at": recorded_at,
            "provider_model": summary.get("model"),
            "non_claims": [
                "external_agent_registration_is_l1_controlled_pilot_only",
                "external_agent_registration_does_not_authorize_production_runtime_execution",
            ],
        },
        {
            "type": "external_agent_message_observed",
            "actor_id": agent_observer_actor_id,
            "status": "observed",
            "agent_id": external_agent_id,
            "message_ref": f"proposal:beta1:{receipt['request_id']}:{receipt['proposal_artifact']['sha256']}",
            "observed_at": recorded_at,
            "source_evidence_ref": receipt["proposal_artifact"]["path"],
            "request_id": receipt["request_id"],
            "non_claims": [
                "external_agent_message_is_proposal_only",
                "external_agent_message_does_not_authorize_merge_push_or_deploy",
            ],
        },
    ])
    _write_jsonl(packet_root / "sinks" / "audit-events.jsonl", [
        {
            "type": "audit_event_recorded",
            "actor_id": audit_actor_id,
            "status": "recorded",
            "audit_event_ref": f"beta1-operator-decision:{receipt['request_id']}",
            "recorded_at": recorded_at,
            "source_evidence_ref": receipt["proposal_request"]["path"],
            "audit_ref_kind": "beta1_repo_review_proposal_request",
            "request_id": receipt["request_id"],
            "decision": receipt["decision"],
            "non_claims": list(NON_CLAIMS),
        },
        {
            "type": "audit_event_recorded",
            "actor_id": audit_actor_id,
            "status": "recorded",
            "audit_event_ref": f"beta1-receipt-validation:{receipt['request_id']}",
            "recorded_at": recorded_at,
            "source_evidence_ref": validation["receipt_path"],
            "audit_ref_kind": "beta1_operator_decision_receipt_validation",
            "request_id": receipt["request_id"],
            "validation_passed": validation["passed"],
            "merge_allowed": receipt["merge_allowed"],
            "push_allowed": receipt["push_allowed"],
            "deploy_allowed": receipt["deploy_allowed"],
            "production_runtime_execution_allowed": receipt["production_runtime_execution_allowed"],
            "production_receipt_write_allowed": receipt["production_receipt_write_allowed"],
            "non_claims": list(NON_CLAIMS),
        },
    ])
    _write_jsonl(packet_root / "sinks" / "receipt-events.jsonl", [
        {
            "type": "receipt_sink_ready",
            "actor_id": audit_actor_id,
            "status": "ready",
            "receipt_sink_ref": f"receipt-sink:beta1:{receipt['request_id']}",
            "ready_at": recorded_at,
            "source_evidence_ref": str(run_root / "operator_decision_receipt.json"),
            "non_claims": [
                "receipt_sink_ready_is_l1_controlled_pilot_only",
                "receipt_sink_ready_does_not_write_production_receipts",
            ],
        }
    ])


def _operator_registry(
    *,
    operator_id: str,
    observer_actor_id: str,
    registrar_actor_id: str,
    agent_observer_actor_id: str,
    audit_actor_id: str,
) -> list[dict[str, Any]]:
    return [
        _actor(observer_actor_id, "observability_owner", "L1 Observability Owner"),
        _actor(registrar_actor_id, "external_agent_registrar", "L1 External Agent Registrar"),
        _actor(agent_observer_actor_id, "external_agent_observer", "L1 External Agent Observer"),
        _actor(audit_actor_id, "audit_owner", "L1 Audit Owner"),
        _actor(operator_id, "audit_owner", "L1 Controlled Pilot Operator"),
    ]


def _actor(actor_id: str, role: str, display_name: str) -> dict[str, Any]:
    return {
        "actor_id": actor_id,
        "actor_role": role,
        "display_name": display_name,
        "signature_ref": f"sigref:{actor_id}:beta1",
        "accountability_ref": f"accountability:{actor_id}:beta1",
    }


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"missing required Beta-1 artifact: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _receipt_artifact_path(receipt: dict[str, Any]) -> Path:
    proposal_artifact = receipt.get("proposal_artifact")
    if not isinstance(proposal_artifact, dict):
        raise ValueError("operator decision receipt missing proposal_artifact object")
    raw_path = proposal_artifact.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("operator decision receipt missing proposal_artifact.path")
    return Path(raw_path)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    sys.exit(main())
