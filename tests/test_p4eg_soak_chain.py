import argparse
import json
from pathlib import Path

import pytest

from scripts.p4ef_multivm_tls_drill import prepare_materials
from scripts.p4eg_soak_chain import authorize, read_passed_stage, validate_chain_authorization
from scripts.p4eg_tls_soak import SUMMARY_SCHEMA


def args(tmp_path: Path, *, acknowledged: bool = True) -> argparse.Namespace:
    candidate = tmp_path / "candidate"
    frontend = tmp_path / "frontend"
    materials = tmp_path / "materials"
    candidate.write_bytes(b"candidate")
    frontend.mkdir()
    (frontend / "index.html").write_text("ready")
    prepare_materials(argparse.Namespace(output_dir=str(materials), node=[], valid_days=7))
    return argparse.Namespace(
        candidate_bin=str(candidate),
        frontend_build_dir=str(frontend),
        materials_dir=str(materials),
        remote_root="/tmp/civitasos-p4eg-test",
        backend_port=18444,
        frontend_port=18443,
        round_interval_seconds=60.0,
        browser_every_rounds=15,
        restart_every_rounds=15,
        output=str(tmp_path / "chain-authorization.json"),
        operator_id="test-operator",
        ack_private_beta_soak_chain=acknowledged,
    )


def test_chain_authorization_binds_all_stages_and_assets(tmp_path: Path) -> None:
    values = args(tmp_path)
    assert authorize(values) == 0
    auth = json.loads(Path(values.output).read_text())
    assert auth["stages_hours"] == [1, 8, 24]
    assert auth["public_ingress_allowed"] is False
    validate_chain_authorization(auth, values)

    Path(values.candidate_bin).write_bytes(b"changed")
    with pytest.raises(SystemExit, match="candidate"):
        validate_chain_authorization(auth, values)


def test_chain_requires_ack_and_stops_on_failed_stage(tmp_path: Path) -> None:
    values = args(tmp_path, acknowledged=False)
    with pytest.raises(SystemExit, match="explicit"):
        authorize(values)

    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(
            {
                "schema_version": SUMMARY_SCHEMA,
                "passed": False,
                "status": "failed",
                "tier_hours": 1,
                "cleanup": {"passed": True},
            }
        )
    )
    with pytest.raises(SystemExit, match="will not advance"):
        read_passed_stage(summary, 1)
