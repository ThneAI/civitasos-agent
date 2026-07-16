#!/usr/bin/env python3
"""Verify an archived P3 graded-soak report and every round artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import tarfile
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        parts = line.split(maxsplit=1)
        require(len(parts) == 2, f"invalid manifest line {line_number}")
        checksum, name = parts
        name = name.lstrip("*")
        require(len(checksum) == 64, f"invalid checksum on manifest line {line_number}")
        require(name not in entries, f"duplicate manifest entry: {name}")
        entries[name] = checksum
    return entries


def verify_file(path: Path, expected: str) -> bytes:
    data = path.read_bytes()
    require(digest(data) == expected, f"sha256 mismatch: {path}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()

    root = args.evidence_dir.resolve()
    summary = json.loads((root / "summary.json").read_text())
    require(summary.get("schema_version") == "civitasos-p3-soak-evidence:v1", "unsupported summary schema")

    artifacts = summary["artifacts"]
    report_meta = artifacts["graded_soak_report"]
    compressed_report = verify_file(root / report_meta["compressed_path"], report_meta["compressed_sha256"])
    report_bytes = gzip.decompress(compressed_report)
    require(digest(report_bytes) == report_meta["uncompressed_sha256"], "uncompressed report sha256 mismatch")
    report = json.loads(report_bytes)

    result = summary["result"]
    rounds = report.get("rounds", [])
    require(report.get("schema_version") == "civitasos-p3-graded-soak:v1", "unsupported report schema")
    require(report.get("status") == "passed" and report.get("passed") is True, "graded soak did not pass")
    require(report.get("requested_duration_seconds") == result["requested_duration_seconds"], "duration mismatch")
    require(report.get("elapsed_seconds", 0) >= report["requested_duration_seconds"], "graded soak ended early")
    require(report.get("round_count") == len(rounds) == result["round_count"], "round count mismatch")
    require(all(item.get("passed") is True and item.get("return_code") == 0 for item in rounds), "failed round found")
    require([item.get("round") for item in rounds] == list(range(1, len(rounds) + 1)), "round sequence mismatch")

    manifest_meta = artifacts["round_evidence_manifest"]
    manifest_path = root / manifest_meta["path"]
    verify_file(manifest_path, manifest_meta["sha256"])
    manifest = load_manifest(manifest_path)
    require(len(manifest) == len(rounds), "round manifest count mismatch")
    expected_round_artifacts = {Path(item["evidence"]).name for item in rounds}
    require(set(manifest) == expected_round_artifacts, "report and manifest round entries differ")

    archive_meta = artifacts["round_evidence_archive"]
    archive_path = root / archive_meta["path"]
    verify_file(archive_path, archive_meta["sha256"])
    archived: set[str] = set()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            require(member.isfile(), f"unexpected archive member: {member.name}")
            require(Path(member.name).name == member.name, f"unsafe archive member: {member.name}")
            require(member.name in manifest, f"archive member missing from manifest: {member.name}")
            stream = archive.extractfile(member)
            require(stream is not None, f"cannot read archive member: {member.name}")
            member_data = stream.read()
            require(digest(member_data) == manifest[member.name], f"round sha256 mismatch: {member.name}")
            round_report = json.loads(member_data)
            require(round_report.get("schema_version") == "civitasos-p3-fault-matrix:v1", f"invalid round schema: {member.name}")
            require(round_report.get("passed") is True, f"failed archived round: {member.name}")
            require(round_report.get("decision") == "go_p3_soak_candidate", f"invalid round decision: {member.name}")
            require(all(case.get("passed") is True and case.get("return_code") == 0 for case in round_report.get("cases", [])), f"failed archived case: {member.name}")
            require(member.name not in archived, f"duplicate archive member: {member.name}")
            archived.add(member.name)
    require(archived == set(manifest), "archive and manifest entries differ")

    output = {
        "schema_version": "civitasos-p3-soak-evidence-check:v1",
        "passed": True,
        "decision": summary["decision"],
        "elapsed_seconds": report["elapsed_seconds"],
        "round_count": len(rounds),
        "verified_round_artifacts": len(archived),
        "boundaries": summary["boundaries"],
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
