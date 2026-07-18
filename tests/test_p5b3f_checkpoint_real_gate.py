import json
import socket
from pathlib import Path

import pytest

from scripts.p5b3f_checkpoint_real_gate import (
    _case_evidence,
    _rejection_evidence,
    validate_real_resources,
)


def test_real_gate_refuses_p4_ports(tmp_path: Path) -> None:
    for port in (18443, 18444):
        with pytest.raises(ValueError, match="must not overlap P4"):
            validate_real_resources(tmp_path / str(port), port)


def test_real_gate_refuses_active_listener(tmp_path: Path) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    try:
        port = listener.getsockname()[1]
        with pytest.raises(ValueError, match="is unavailable"):
            validate_real_resources(tmp_path / "active-listener", port)
    finally:
        listener.close()


def test_real_gate_accepts_empty_isolated_root(tmp_path: Path) -> None:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    run_root = tmp_path / "p5b3f-real"
    assert validate_real_resources(run_root, port) == run_root.resolve()


def test_real_evidence_readers_enforce_boundaries(tmp_path: Path) -> None:
    positive = tmp_path / "cases" / "runtime_intent_durable"
    positive.mkdir(parents=True)
    (positive / "result.json").write_text(
        json.dumps(
            {
                "real_tls_executed": True,
                "backend_sled_executed": True,
                "runtime_sqlite_executed": True,
                "fact_integrity_valid": True,
                "tick_probe_only": True,
                "externally_verified": False,
                "production_evidence": False,
                "receipt_hash": "receipt",
                "evidence_manifest_hash": "manifest",
            }
        )
    )
    assert _case_evidence(tmp_path, "runtime_intent_durable")[
        "fact_integrity_valid"
    ] is True

    rejection = tmp_path / "rejections" / "credential_revoked"
    rejection.mkdir(parents=True)
    result_path = rejection / "result.json"
    result = {
        "real_tls_executed": True,
        "backend_sled_executed": True,
        "runtime_sqlite_executed": True,
        "fact_integrity_valid": True,
        "activation_receipt_status": 404,
        "externally_verified": False,
        "production_evidence": False,
        "failure_audit_source": "local_gate:backend_preflight",
        "failure_audit_boundary": "local_gate_only",
    }
    result_path.write_text(json.dumps(result))
    assert _rejection_evidence(tmp_path, "credential_revoked")[
        "activation_receipt_status"
    ] == 404

    result["production_evidence"] = True
    result_path.write_text(json.dumps(result))
    with pytest.raises(ValueError, match="lacks real evidence"):
        _rejection_evidence(tmp_path, "credential_revoked")
