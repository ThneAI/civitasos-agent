"""Create a private collection package for real J1-D participant Evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import canonical_sha256, read_json_object
from benchmarks.j1.qualification_participant_collection import (
    COLLECTION_SCHEMA,
    TEMPLATE_FILENAMES,
    build_collection_templates,
    collection_policy,
    collection_slots,
)
from benchmarks.j1.qualification_participant_evidence import (
    validate_evidence_artifact,
    validate_participant_packet,
)
from benchmarks.j1.qualification_roster import validate_qualification_protocol
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST
from benchmarks.j1_qualification_protocol_freeze_gate import GATE_SCHEMA


def prepare_collection_package(
    *,
    collection_id: str,
    prepared_at: str,
    qualification_protocol_path: Path,
    protocol_freeze_report_path: Path,
    evidence_root: Path,
    roster_id: str,
    roster_output_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists():
        raise ValueError(f"output already exists: {output_root}")
    failures: list[str] = []
    protocol, protocol_bytes = _read_private(
        qualification_protocol_path, "qualification_protocol", failures
    )
    freeze_report, freeze_bytes = _read_private(
        protocol_freeze_report_path, "qualification_protocol_freeze_report", failures
    )
    request = read_json_object(DEFAULT_REQUEST)
    protocol_hash = canonical_sha256(protocol) if protocol else ""
    protocol_failures: list[str] = []
    if protocol:
        protocol_failures.extend(
            validate_qualification_protocol(
                protocol, admission_request_sha256=canonical_sha256(request)
            )
        )
    protocol_failures.extend(_freeze_failures(freeze_report, protocol_hash))
    protocol_frozen = bool(protocol_hash) and not protocol_failures
    failures.extend(protocol_failures)
    failures.extend(_metadata_failures(collection_id, roster_id, prepared_at))
    failures.extend(_path_failures(output_root, evidence_root, roster_output_path))
    stack = _expected_stack(protocol)
    templates = build_collection_templates(
        qualification_protocol_sha256=protocol_hash,
        stack=stack,
    )
    failures.extend(_template_safety_failures(templates, protocol_hash, stack))
    failures = list(dict.fromkeys(failures))
    if failures:
        return _blocked_report(
            collection_id=collection_id,
            protocol_hash=protocol_hash,
            evidence_root=evidence_root,
            failures=failures,
            protocol_frozen=protocol_frozen,
        )

    _prepare_private_directory(evidence_root)
    _prepare_private_directory(output_root)
    templates_root = output_root / "templates"
    reports_root = output_root / "reports"
    _prepare_private_directory(templates_root)
    _prepare_private_directory(reports_root)
    template_artifacts: dict[str, dict[str, str]] = {}
    for kind, value in templates.items():
        path = templates_root / TEMPLATE_FILENAMES[kind]
        _write_private_json(path, value)
        template_artifacts[kind] = _artifact(path)
    readme_path = output_root / "README.md"
    _write_private_text(readme_path, _readme(evidence_root, roster_output_path))
    runner_path = output_root / "run_intake.sh"
    _write_private_text(
        runner_path,
        _runner(
            roster_id=roster_id,
            protocol_path=qualification_protocol_path,
            freeze_report_path=protocol_freeze_report_path,
            evidence_root=evidence_root,
            roster_output_path=roster_output_path,
        ),
        mode=0o700,
    )
    manifest = {
        "schema_version": COLLECTION_SCHEMA,
        "passed": True,
        "collection_id": collection_id,
        "status": "collection_open_real_participant_evidence_required",
        "prepared_at": prepared_at,
        "qualification_protocol_sha256": protocol_hash,
        "source_artifacts": {
            "qualification_protocol": _artifact_from_bytes(
                qualification_protocol_path, protocol_bytes
            ),
            "protocol_freeze_report": _artifact_from_bytes(
                protocol_freeze_report_path, freeze_bytes
            ),
        },
        "evidence_root": str(evidence_root.resolve()),
        "roster_id": roster_id,
        "roster_output": str(roster_output_path.resolve()),
        "policy": collection_policy(),
        "collection_slots": collection_slots(),
        "template_artifacts": template_artifacts,
        "runner_artifact": _artifact(runner_path),
        "readme_artifact": _artifact(readme_path),
        "source_content_recorded": False,
        "observed_participant_packet_files": len(
            list(evidence_root.glob("*.participant.json"))
        ),
        "readiness": {
            "qualification_protocol_frozen": True,
            "participant_evidence_complete": False,
            "independent_roster_review_required": False,
            "real_participant_roster_bound": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "collection_templates_only": True,
            "identity_generation_performed": False,
            "automatic_matching_performed": False,
            "operator_review_automated": False,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    _write_private_json(output_root / "collection-manifest.json", manifest)
    return manifest


def _freeze_failures(report: dict[str, Any], protocol_hash: str) -> list[str]:
    checks = {
        "qualification_protocol_freeze_report_schema_invalid": report.get(
            "schema_version"
        )
        == GATE_SCHEMA,
        "qualification_protocol_freeze_not_passed": report.get("passed") is True,
        "qualification_protocol_freeze_hash_mismatch": report.get(
            "qualification_protocol_sha256"
        )
        == protocol_hash,
        "qualification_protocol_freeze_readiness_invalid": report.get(
            "readiness", {}
        ).get("qualification_protocol_frozen")
        is True,
    }
    return [code for code, passed in checks.items() if not passed]


def _metadata_failures(
    collection_id: str, roster_id: str, prepared_at: str
) -> list[str]:
    failures: list[str] = []
    if not collection_id.strip():
        failures.append("collection_id_missing")
    if not roster_id.strip():
        failures.append("roster_id_missing")
    try:
        parsed = datetime.fromisoformat(prepared_at.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None:
        failures.append("collection_prepared_at_invalid")
    return failures


def _path_failures(
    output_root: Path, evidence_root: Path, roster_output_path: Path
) -> list[str]:
    failures: list[str] = []
    output = output_root.resolve()
    evidence = evidence_root.resolve()
    if output == evidence or evidence in output.parents or output in evidence.parents:
        failures.append("collection_output_must_be_separate_from_evidence_root")
    if evidence_root.exists():
        if not evidence_root.is_dir() or evidence_root.is_symlink():
            failures.append("participant_evidence_root_unreadable")
        elif evidence_root.stat().st_mode & 0o077:
            failures.append("participant_evidence_root_permissions_too_open")
    if roster_output_path.exists():
        failures.append("qualification_roster_output_already_exists")
    return failures


def _template_safety_failures(
    templates: dict[str, dict[str, Any]],
    protocol_hash: str,
    stack: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    packet = templates["participant_packet"]
    if not validate_participant_packet(
        packet,
        expected_stack=stack,
        qualification_protocol_sha256=protocol_hash,
    ):
        failures.append("participant_packet_template_must_fail_validation")
    for kind in TEMPLATE_FILENAMES:
        if not TEMPLATE_FILENAMES[kind].endswith(".template.json"):
            failures.append(f"{kind}_template_filename_must_not_match_intake")
        if kind == "participant_packet":
            continue
        if not validate_evidence_artifact(
            kind,
            templates[kind],
            packet=packet,
            qualification_protocol_sha256=protocol_hash,
        ):
            failures.append(f"{kind}_template_must_fail_validation")
    return failures


def _blocked_report(
    *,
    collection_id: str,
    protocol_hash: str,
    evidence_root: Path,
    failures: list[str],
    protocol_frozen: bool,
) -> dict[str, Any]:
    return {
        "schema_version": COLLECTION_SCHEMA,
        "passed": False,
        "collection_id": collection_id,
        "status": "blocked_participant_collection_package_preparation",
        "failure_reasons": failures,
        "qualification_protocol_sha256": protocol_hash or None,
        "evidence_root": str(evidence_root.resolve()),
        "readiness": {
            "qualification_protocol_frozen": protocol_frozen,
            "participant_evidence_complete": False,
            "real_participant_roster_bound": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
    }


def _read_private(
    path: Path, label: str, failures: list[str]
) -> tuple[dict[str, Any], bytes]:
    try:
        if path.is_symlink():
            raise OSError
        raw = path.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError
        if path.stat().st_mode & 0o077:
            failures.append(f"{label}_permissions_too_open")
        return value, raw
    except (OSError, ValueError, json.JSONDecodeError):
        failures.append(f"{label}_unreadable")
        return {}, b""


def _expected_stack(protocol: dict[str, Any]) -> dict[str, str]:
    frozen = protocol.get("frozen_stack", {})
    corpus = protocol.get("task_corpus", {})
    return {
        "provider_id": str(frozen.get("provider_id", "")),
        "model_id": str(frozen.get("model_id", "")),
        "budget_id": str(frozen.get("budget_id", "")),
        "corpus_id": str(corpus.get("corpus_id", "")),
        "verifier_id": str(frozen.get("verifier_id", "")),
    }


def _prepare_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    _write_private_text(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _write_private_text(path: Path, value: str, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)


def _artifact(path: Path) -> dict[str, str]:
    return _artifact_from_bytes(path, path.read_bytes())


def _artifact_from_bytes(path: Path, value: bytes) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def _readme(evidence_root: Path, roster_output_path: Path) -> str:
    return f"""# J1-D Real Participant Evidence Collection

This package contains blank templates, not participant Evidence.

1. Collect real public-only baseline, identity, custody, isolation and consent artifacts.
2. Never place a seed, private key, API credential, PIN or passphrase in any artifact.
3. Remove `_template`, replace every placeholder and compute hashes from actual file bytes.
4. Write final files as mode 0600 under `{evidence_root.resolve()}` (directory mode 0700).
5. Name participant packets `*.participant.json`; keep template files outside the Evidence root.
6. Run `./run_intake.sh`. A complete intake may create `{roster_output_path.resolve()}` with status `review_required` only.

Independent operator review and a separate single-use authorization remain mandatory.
"""


def _runner(
    *,
    roster_id: str,
    protocol_path: Path,
    freeze_report_path: Path,
    evidence_root: Path,
    roster_output_path: Path,
) -> str:
    agent_root = Path(__file__).resolve().parents[1]
    values = {
        "agent_root": shlex.quote(str(agent_root)),
        "roster_id": shlex.quote(roster_id),
        "protocol": shlex.quote(str(protocol_path.resolve())),
        "freeze": shlex.quote(str(freeze_report_path.resolve())),
        "evidence": shlex.quote(str(evidence_root.resolve())),
        "roster": shlex.quote(str(roster_output_path.resolve())),
    }
    return f"""#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
AGENT_ROOT="${{CIVITASOS_AGENT_ROOT:-{values["agent_root"]}}}"
PYTHON="${{CIVITASOS_AGENT_PYTHON:-$AGENT_ROOT/.venv/bin/python}}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"

cd "$AGENT_ROOT"
exec "$PYTHON" -m benchmarks.j1_qualification_roster_intake \\
  --roster-id {values["roster_id"]} \\
  --qualification-protocol {values["protocol"]} \\
  --protocol-freeze-report {values["freeze"]} \\
  --evidence-root {values["evidence"]} \\
  --output {values["roster"]} \\
  --report "$ROOT/reports/qualification-roster-intake-$STAMP.json"
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collection-id", required=True)
    parser.add_argument("--prepared-at", default=_timestamp())
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--protocol-freeze-report", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--roster-id", required=True)
    parser.add_argument("--roster-output", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = prepare_collection_package(
            collection_id=args.collection_id,
            prepared_at=args.prepared_at,
            qualification_protocol_path=args.qualification_protocol,
            protocol_freeze_report_path=args.protocol_freeze_report,
            evidence_root=args.evidence_root,
            roster_id=args.roster_id,
            roster_output_path=args.roster_output,
            output_root=args.output_root,
        )
    except ValueError as error:
        print(json.dumps({"passed": False, "error": str(error)}, indent=2))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("manifest_sha256") else 1


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


if __name__ == "__main__":
    raise SystemExit(main())
