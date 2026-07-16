import argparse
import json
import subprocess
from pathlib import Path

import pytest

import scripts.p4ef_multivm_tls_drill as drill
from scripts.p4ef_multivm_tls_drill import (
    authorize,
    prepare_materials,
    validate_authorization,
    wait_for_settled_receipt,
)


def assets(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    frontend = tmp_path / "frontend"
    materials = tmp_path / "materials"
    baseline.write_bytes(b"baseline")
    candidate.write_bytes(b"candidate")
    frontend.mkdir()
    (frontend / "index.html").write_text("ready")
    prepare_materials(argparse.Namespace(output_dir=str(materials), node=[]))
    return baseline, candidate, frontend, materials


def authorization_args(
    baseline: Path,
    candidate: Path,
    frontend: Path,
    materials: Path,
    output: Path,
    *,
    acknowledged: bool = True,
) -> argparse.Namespace:
    return argparse.Namespace(
        baseline_bin=str(baseline),
        candidate_bin=str(candidate),
        frontend_build_dir=str(frontend),
        materials_dir=str(materials),
        output=str(output),
        operator_id="test-operator",
        remote_root="/tmp/civitasos-p4ef-test",
        backend_port=18444,
        frontend_port=18443,
        ttl_seconds=3600,
        node=[],
        ack_private_beta_tls_drill=acknowledged,
    )


def test_authorization_binds_tls_release_and_nonproduction_boundaries(tmp_path: Path) -> None:
    baseline, candidate, frontend, materials = assets(tmp_path)
    output = tmp_path / "authorization.json"
    args = authorization_args(baseline, candidate, frontend, materials, output)

    assert authorize(args) == 0
    authorization = json.loads(output.read_text())
    assert authorization["single_use"] is True
    assert authorization["nodes"] == ["vm1", "vm2", "vm3"]
    assert authorization["baseline_sha256"] != authorization["candidate_sha256"]
    assert authorization["material_manifest_sha256"]
    assert authorization["material_file_sha256"]["vm1.key"]
    assert authorization["public_ingress_allowed"] is False
    assert authorization["production_data_allowed"] is False
    validate_authorization(authorization, args)
    subprocess.run(
        [
            "openssl",
            "verify",
            "-x509_strict",
            "-CAfile",
            str(materials / "ca.crt"),
            str(materials / "vm1.crt"),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def test_authorization_rejects_missing_ack_and_material_tampering(tmp_path: Path) -> None:
    baseline, candidate, frontend, materials = assets(tmp_path)
    output = tmp_path / "authorization.json"
    with pytest.raises(SystemExit, match="explicit"):
        authorize(
            authorization_args(
                baseline,
                candidate,
                frontend,
                materials,
                output,
                acknowledged=False,
            )
        )

    args = authorization_args(baseline, candidate, frontend, materials, output)
    authorize(args)
    authorization = json.loads(output.read_text())
    with (materials / "vm1.service").open("a") as handle:
        handle.write("tampered\n")
    with pytest.raises(SystemExit, match="material hash mismatch"):
        validate_authorization(authorization, args)


def test_wait_for_settled_receipt_handles_projection_lag(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        {
            "data": {
                "complete": False,
                "fact_count": 4,
                "missing_event_types": ["settlement.completed"],
                "lifecycle": {"settled": False},
            }
        },
        {
            "data": {
                "complete": True,
                "fact_count": 5,
                "missing_event_types": [],
                "lifecycle": {"settled": True},
                "receipt_hash": "settled-hash",
            }
        },
    ]

    def fake_api_request(*_args, **_kwargs):
        return 200, responses.pop(0)

    monkeypatch.setattr(drill, "api_request", fake_api_request)
    node = argparse.Namespace(node_id="vm1")
    receipt, attempts, _elapsed = wait_for_settled_receipt(
        node, 18443, "task-1", "token", timeout_seconds=1, poll_seconds=0
    )

    assert attempts == 2
    assert receipt["fact_count"] == 5
    assert receipt["receipt_hash"] == "settled-hash"
