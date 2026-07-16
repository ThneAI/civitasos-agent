import argparse
import json
from pathlib import Path

import pytest

from scripts.p4ef_multivm_tls_drill import prepare_materials, sha256
from scripts.p4eg_tls_soak import (
    ROUND_SCHEMA,
    SUMMARY_SCHEMA,
    append_jsonl,
    authorize,
    journal_payload_sha256,
    load_rounds,
)


def assets(tmp_path: Path) -> tuple[Path, Path, Path]:
    candidate = tmp_path / "candidate"
    frontend = tmp_path / "frontend"
    materials = tmp_path / "materials"
    candidate.write_bytes(b"candidate")
    frontend.mkdir()
    (frontend / "index.html").write_text("ready")
    prepare_materials(
        argparse.Namespace(output_dir=str(materials), node=[], valid_days=7)
    )
    return candidate, frontend, materials


def auth_args(
    candidate: Path,
    frontend: Path,
    materials: Path,
    output: Path,
    *,
    hours: int = 1,
    previous_summary: Path | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        hours=hours,
        candidate_bin=str(candidate),
        frontend_build_dir=str(frontend),
        materials_dir=str(materials),
        previous_summary=str(previous_summary) if previous_summary else None,
        output=str(output),
        operator_id="test-operator",
        remote_root="/tmp/civitasos-p4eg-test",
        backend_port=18444,
        frontend_port=18443,
        round_interval_seconds=60.0,
        browser_every_rounds=15,
        restart_every_rounds=15,
        authorization_grace_seconds=3600,
        ack_private_beta_soak=True,
    )


def passed_summary(path: Path, hours: int) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": SUMMARY_SCHEMA,
                "passed": True,
                "status": "passed",
                "tier_hours": hours,
                "requested_duration_seconds": hours * 3600,
                "elapsed_seconds": hours * 3600,
                "cleanup": {"passed": True},
            }
        )
    )


def test_stage_authorization_binds_previous_passed_summary(tmp_path: Path) -> None:
    candidate, frontend, materials = assets(tmp_path)
    first = tmp_path / "1h-auth.json"
    assert authorize(auth_args(candidate, frontend, materials, first)) == 0
    assert json.loads(first.read_text())["previous_summary_sha256"] is None

    previous = tmp_path / "1h-summary.json"
    passed_summary(previous, 1)
    second = tmp_path / "8h-auth.json"
    assert authorize(
        auth_args(
            candidate,
            frontend,
            materials,
            second,
            hours=8,
            previous_summary=previous,
        )
    ) == 0
    assert json.loads(second.read_text())["previous_summary_sha256"] == sha256(previous)


def test_stage_authorization_rejects_missing_dependency_and_tampering(tmp_path: Path) -> None:
    candidate, frontend, materials = assets(tmp_path)
    with pytest.raises(SystemExit, match="requires a passed 1h summary"):
        authorize(auth_args(candidate, frontend, materials, tmp_path / "auth.json", hours=8))

    output = tmp_path / "1h-auth.json"
    authorize(auth_args(candidate, frontend, materials, output))
    (materials / "vm1.service").write_text("tampered\n")
    with pytest.raises(SystemExit, match="material hash mismatch"):
        authorize(auth_args(candidate, frontend, materials, tmp_path / "other.json"))


def test_round_journal_detects_payload_and_evidence_tampering(tmp_path: Path) -> None:
    evidence = tmp_path / "round-1.json"
    evidence.write_text('{"passed":true}\n')
    record = {
        "schema_version": ROUND_SCHEMA,
        "round": 1,
        "passed": True,
        "evidence": str(evidence),
        "evidence_sha256": sha256(evidence),
    }
    record["journal_payload_sha256"] = journal_payload_sha256(record)
    journal = tmp_path / "rounds.jsonl"
    append_jsonl(journal, record)
    assert load_rounds(journal) == [record]

    evidence.write_text('{"passed":false}\n')
    with pytest.raises(RuntimeError, match="evidence hash mismatch"):
        load_rounds(journal)

    evidence.write_text('{"passed":true}\n')
    tampered = json.loads(journal.read_text())
    tampered["passed"] = False
    journal.write_text(json.dumps(tampered) + "\n")
    with pytest.raises(RuntimeError, match="payload hash mismatch"):
        load_rounds(journal)
