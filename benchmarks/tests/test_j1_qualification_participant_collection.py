from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from benchmarks.j1.controlled_comparison import canonical_sha256, write_private_json
from benchmarks.j1.qualification_participant_collection import TEMPLATE_FILENAMES
from benchmarks.j1.qualification_participant_evidence import (
    validate_evidence_artifact,
    validate_participant_packet,
)
from benchmarks.j1_qualification_participant_collection import (
    prepare_collection_package,
)
from benchmarks.j1_qualification_protocol_freeze_gate import GATE_SCHEMA
from benchmarks.tests.test_j1_qualification_roster_intake import _protocol


def _inputs(tmp_path: Path) -> tuple[Path, Path, dict]:
    protocol = _protocol()
    protocol_path = tmp_path / "qualification-protocol.json"
    write_private_json(protocol_path, protocol)
    freeze_path = tmp_path / "qualification-protocol-freeze-report.json"
    write_private_json(
        freeze_path,
        {
            "schema_version": GATE_SCHEMA,
            "passed": True,
            "qualification_protocol_sha256": canonical_sha256(protocol),
            "readiness": {"qualification_protocol_frozen": True},
        },
    )
    return protocol_path, freeze_path, protocol


def _prepare(tmp_path: Path) -> tuple[dict, Path, Path]:
    protocol_path, freeze_path, _ = _inputs(tmp_path)
    output_root = tmp_path / "collection"
    evidence_root = tmp_path / "participant-evidence"
    manifest = prepare_collection_package(
        collection_id="j1q-participant-collection-20260721-r1",
        prepared_at="2026-07-21T00:10:00+08:00",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_path,
        evidence_root=evidence_root,
        roster_id="j1q-roster-20260721-r1",
        roster_output_path=tmp_path / "private" / "qualification-roster.json",
        output_root=output_root,
    )
    return manifest, output_root, evidence_root


def test_writes_private_protocol_bound_collection_package(tmp_path: Path) -> None:
    manifest, output_root, evidence_root = _prepare(tmp_path)
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}

    assert manifest["manifest_sha256"] == canonical_sha256(body)
    assert manifest["passed"] is True
    assert manifest["status"] == "collection_open_real_participant_evidence_required"
    assert manifest["policy"]["templates_are_evidence"] is False
    assert manifest["execution_boundary"]["identity_generation_performed"] is False
    assert manifest["observed_participant_packet_files"] == 0
    assert len(manifest["collection_slots"]) == 20
    assert evidence_root.stat().st_mode & 0o777 == 0o700
    assert output_root.stat().st_mode & 0o777 == 0o700
    assert (output_root / "collection-manifest.json").stat().st_mode & 0o777 == 0o600
    assert (output_root / "run_intake.sh").stat().st_mode & 0o777 == 0o700
    assert not list(evidence_root.glob("*.participant.json"))


def test_all_templates_are_deliberately_rejected_by_intake(tmp_path: Path) -> None:
    manifest, output_root, _ = _prepare(tmp_path)
    protocol_hash = manifest["qualification_protocol_sha256"]
    packet = json.loads(
        (
            output_root / "templates" / TEMPLATE_FILENAMES["participant_packet"]
        ).read_text(encoding="utf-8")
    )
    stack = packet["stack"]

    assert validate_participant_packet(
        packet,
        expected_stack=stack,
        qualification_protocol_sha256=protocol_hash,
    )
    for kind, filename in TEMPLATE_FILENAMES.items():
        assert filename.endswith(".template.json")
        if kind == "participant_packet":
            continue
        artifact = json.loads(
            (output_root / "templates" / filename).read_text(encoding="utf-8")
        )
        assert validate_evidence_artifact(
            kind,
            artifact,
            packet=packet,
            qualification_protocol_sha256=protocol_hash,
        )


def test_intake_runner_is_repeatable_and_keeps_roster_absent(tmp_path: Path) -> None:
    _, output_root, _ = _prepare(tmp_path)
    environment = {
        **os.environ,
        "CIVITASOS_AGENT_ROOT": str(Path(__file__).resolve().parents[2]),
        "CIVITASOS_AGENT_PYTHON": sys.executable,
    }

    for _ in range(2):
        result = subprocess.run(
            [str(output_root / "run_intake.sh")],
            cwd=output_root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1

    reports = list((output_root / "reports").glob("qualification-roster-intake-*.json"))
    assert len(reports) == 2
    assert not (tmp_path / "private" / "qualification-roster.json").exists()


def test_rejects_freeze_hash_mismatch_without_writing_package(tmp_path: Path) -> None:
    protocol_path, freeze_path, _ = _inputs(tmp_path)
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    freeze["qualification_protocol_sha256"] = "0" * 64
    write_private_json(freeze_path, freeze)
    output_root = tmp_path / "collection"

    report = prepare_collection_package(
        collection_id="j1q-participant-collection-20260721-r1",
        prepared_at="2026-07-21T00:10:00+08:00",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_path,
        evidence_root=tmp_path / "participant-evidence",
        roster_id="j1q-roster-20260721-r1",
        roster_output_path=tmp_path / "private" / "qualification-roster.json",
        output_root=output_root,
    )

    assert report["passed"] is False
    assert "qualification_protocol_freeze_hash_mismatch" in report["failure_reasons"]
    assert report["readiness"]["qualification_protocol_frozen"] is False
    assert not output_root.exists()


def test_refuses_existing_output_and_evidence_overlap(tmp_path: Path) -> None:
    manifest, output_root, _ = _prepare(tmp_path)
    assert manifest["manifest_sha256"]
    protocol_path, freeze_path, _ = _inputs(tmp_path / "second")

    with pytest.raises(ValueError, match="output already exists"):
        prepare_collection_package(
            collection_id="j1q-participant-collection-20260721-r2",
            prepared_at="2026-07-21T00:20:00+08:00",
            qualification_protocol_path=protocol_path,
            protocol_freeze_report_path=freeze_path,
            evidence_root=tmp_path / "participant-evidence-2",
            roster_id="j1q-roster-20260721-r2",
            roster_output_path=tmp_path / "private" / "qualification-roster-2.json",
            output_root=output_root,
        )

    overlap = tmp_path / "evidence" / "collection"
    report = prepare_collection_package(
        collection_id="j1q-participant-collection-20260721-r3",
        prepared_at="2026-07-21T00:30:00+08:00",
        qualification_protocol_path=protocol_path,
        protocol_freeze_report_path=freeze_path,
        evidence_root=tmp_path / "evidence",
        roster_id="j1q-roster-20260721-r3",
        roster_output_path=tmp_path / "private" / "qualification-roster-3.json",
        output_root=overlap,
    )

    assert (
        "collection_output_must_be_separate_from_evidence_root"
        in report["failure_reasons"]
    )
    assert report["readiness"]["qualification_protocol_frozen"] is True
    assert not overlap.exists()
