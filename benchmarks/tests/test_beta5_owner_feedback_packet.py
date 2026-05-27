from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load("beta5_owner_feedback_packet", SCRIPTS / "beta5_owner_feedback_packet.py")


def _write_preview_summary(tmp_path: Path, *, provider: str = "virtualbox", production_flag: bool = False) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    deploy_receipt = tmp_path / "beta5_external_deploy_receipt.json"
    rollback_receipt = tmp_path / "beta5_external_deploy_rollback_drill_receipt.json"
    deploy_receipt.write_text('{"receipt":"deploy"}\n', encoding="utf-8")
    rollback_receipt.write_text('{"receipt":"rollback"}\n', encoding="utf-8")
    summary = {
        "schema_version": module.SUMMARY_SCHEMA,
        "passed": True,
        "run_root": str(tmp_path),
        "deploy_receipt": str(deploy_receipt),
        "deploy_receipt_sha256": module._sha256(deploy_receipt),
        "rollback_receipt": str(rollback_receipt),
        "rollback_receipt_sha256": module._sha256(rollback_receipt),
        "nodes": [
            {"node_id": "vm1", "node_ip": "192.168.56.4"},
            {"node_id": "vm2", "node_ip": "192.168.56.5"},
            {"node_id": "vm3", "node_ip": "192.168.56.6"},
        ],
        "smoke_cycles": 5,
        "smoke_total_checks": 15,
        "latency_ms_median": 8.2,
        "latency_ms_max": 21.3,
        "external_environment_provider": provider,
        "external_environment_classification": "external_preview",
        "production_deploy_allowed": production_flag,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
        "h3_production_readiness_claimed": False,
    }
    path = tmp_path / "beta5_repeatable_preview_summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def test_record_and_validate_owner_feedback_packet(tmp_path: Path) -> None:
    preview_summary = _write_preview_summary(tmp_path)
    packet_path = tmp_path / "beta5_owner_feedback_packet.json"

    report = module.record_owner_feedback_packet(
        preview_summary_path=preview_summary,
        output_path=packet_path,
        owner_id="owner-cc",
        operator_id="operator-cc",
        feedback_verdict="accepted",
        feedback_ref="owner-feedback:accepted",
        audit_ref="audit:rollback-clean",
        external_evidence_ref="external-preview:virtualbox-vm1-vm2-vm3",
        notes="owner observed preview and rollback receipts",
    )

    assert report["packet_written"] is True
    assert report["validation"]["passed"] is True
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    assert packet["schema_version"] == module.PACKET_SCHEMA
    assert packet["feedback_verdict"] == "accepted"
    assert packet["preview_observation"]["external_environment_provider"] == "virtualbox"
    assert packet["production_deploy_allowed"] is False
    assert packet["production_runtime_execution_allowed"] is False
    assert packet["production_receipt_write_allowed"] is False
    assert packet["h3_boundary"]["h3_remains_blocked"] is True


def test_validate_rejects_tampered_source_preview_summary(tmp_path: Path) -> None:
    preview_summary = _write_preview_summary(tmp_path)
    packet_path = tmp_path / "beta5_owner_feedback_packet.json"
    module.record_owner_feedback_packet(
        preview_summary_path=preview_summary,
        output_path=packet_path,
        owner_id="owner-cc",
        operator_id="operator-cc",
        feedback_verdict="accepted",
        feedback_ref="owner-feedback:accepted",
        audit_ref="audit:rollback-clean",
        external_evidence_ref="external-preview:virtualbox-vm1-vm2-vm3",
    )

    summary = json.loads(preview_summary.read_text(encoding="utf-8"))
    summary["smoke_total_checks"] = 16
    preview_summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = module.validate_owner_feedback_packet(packet_path)

    assert validation["passed"] is False
    assert "source_preview_summary.sha256 mismatch" in validation["failure_reasons"]


def test_record_rejects_non_virtualbox_or_production_summary(tmp_path: Path) -> None:
    invalid_provider = _write_preview_summary(tmp_path / "provider", provider="manual-host")
    try:
        module.record_owner_feedback_packet(
            preview_summary_path=invalid_provider,
            output_path=tmp_path / "provider_packet.json",
            owner_id="owner-cc",
            operator_id="operator-cc",
            feedback_verdict="accepted",
            feedback_ref="owner-feedback:accepted",
            audit_ref="audit:rollback-clean",
            external_evidence_ref="external-preview:manual-host",
        )
    except ValueError as exc:
        assert "preview summary provider must be virtualbox" in str(exc)
    else:
        raise AssertionError("non-VirtualBox preview summary must be rejected")

    production_summary = _write_preview_summary(tmp_path / "production", production_flag=True)
    try:
        module.record_owner_feedback_packet(
            preview_summary_path=production_summary,
            output_path=tmp_path / "production_packet.json",
            owner_id="owner-cc",
            operator_id="operator-cc",
            feedback_verdict="accepted",
            feedback_ref="owner-feedback:accepted",
            audit_ref="audit:rollback-clean",
            external_evidence_ref="external-preview:virtualbox-vm1-vm2-vm3",
        )
    except ValueError as exc:
        assert "preview summary production_deploy_allowed must be false" in str(exc)
    else:
        raise AssertionError("production preview summary must be rejected")


def test_record_rejects_preview_summary_receipt_hash_mismatch(tmp_path: Path) -> None:
    preview_summary = _write_preview_summary(tmp_path)
    summary = json.loads(preview_summary.read_text(encoding="utf-8"))
    summary["deploy_receipt_sha256"] = "0" * 64
    preview_summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    try:
        module.record_owner_feedback_packet(
            preview_summary_path=preview_summary,
            output_path=tmp_path / "packet.json",
            owner_id="owner-cc",
            operator_id="operator-cc",
            feedback_verdict="accepted",
            feedback_ref="owner-feedback:accepted",
            audit_ref="audit:rollback-clean",
            external_evidence_ref="external-preview:virtualbox-vm1-vm2-vm3",
        )
    except ValueError as exc:
        assert "preview summary deploy_receipt_sha256 does not match deploy_receipt" in str(exc)
    else:
        raise AssertionError("preview summary receipt hash mismatch must be rejected")
