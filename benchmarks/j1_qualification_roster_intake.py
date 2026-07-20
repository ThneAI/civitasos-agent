"""Validate real J1-D participant Evidence and prepare a roster draft."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import (
    canonical_sha256,
    read_json_object,
    write_private_json,
)
from benchmarks.j1.qualification_participant_evidence import (
    EVIDENCE_SCHEMAS,
    roster_entry_from_packet,
    validate_evidence_artifact,
    validate_participant_packet,
)
from benchmarks.j1.qualification_roster import (
    ROSTER_SCHEMA,
    validate_qualification_protocol,
    validate_roster_participants,
)
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST
from benchmarks.j1_qualification_protocol_freeze_gate import GATE_SCHEMA


REPORT_SCHEMA = "j1-qualification-roster-intake:v1"


def prepare_roster_draft(
    *,
    roster_id: str,
    qualification_protocol_path: Path,
    protocol_freeze_report_path: Path,
    evidence_root: Path,
    output_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    for path in (output_path, report_path):
        if path.exists():
            raise ValueError(f"output already exists: {path}")
    failures: list[str] = []
    protocol = _read_private_object(
        qualification_protocol_path, "qualification_protocol", failures
    )
    freeze_report = _read_private_object(
        protocol_freeze_report_path, "qualification_protocol_freeze_report", failures
    )
    request = read_json_object(DEFAULT_REQUEST)
    request_hash = canonical_sha256(request)
    protocol_hash = canonical_sha256(protocol) if protocol else ""
    if protocol:
        failures.extend(
            validate_qualification_protocol(
                protocol, admission_request_sha256=request_hash
            )
        )
    _validate_freeze_report(freeze_report, protocol_hash, failures)
    packet_paths = _packet_paths(evidence_root, failures)
    stack = _expected_stack(protocol)
    entries: list[dict[str, Any]] = []
    packet_reports: list[dict[str, Any]] = []
    for index, packet_path in enumerate(packet_paths):
        packet, packet_bytes = _read_private(
            packet_path, f"participant_packet_{index}", failures
        )
        packet_failures = validate_participant_packet(
            packet,
            expected_stack=stack,
            qualification_protocol_sha256=protocol_hash,
        )
        evidence_hashes: dict[str, str] = {}
        for kind in EVIDENCE_SCHEMAS:
            artifact, artifact_hash, artifact_failures = _load_evidence(
                evidence_root=evidence_root,
                packet=packet,
                kind=kind,
                protocol_hash=protocol_hash,
            )
            del artifact
            evidence_hashes[kind] = artifact_hash
            packet_failures.extend(artifact_failures)
        packet_failures = list(dict.fromkeys(packet_failures))
        failures.extend(
            f"participant_packet_{index}:{failure}" for failure in packet_failures
        )
        if packet and not packet_failures:
            entries.append(
                roster_entry_from_packet(packet, evidence_hashes=evidence_hashes)
            )
        packet_reports.append(
            {
                "path": str(packet_path.resolve()),
                "sha256": hashlib.sha256(packet_bytes).hexdigest()
                if packet_bytes
                else None,
                "participant_id": packet.get("participant_id") if packet else None,
                "pair_id": packet.get("pair_id") if packet else None,
                "passed": not packet_failures,
                "failure_reasons": packet_failures,
                "source_content_recorded": False,
            }
        )
    participant_failures = validate_roster_participants(entries, stack)
    failures.extend(participant_failures)
    failures.extend(_baseline_uniqueness_failures(entries))
    failures = list(dict.fromkeys(failures))
    protocol_frozen = bool(protocol_hash) and not any(
        failure.startswith("qualification_protocol") for failure in failures
    )
    passed = not failures
    draft_artifact = None
    if passed:
        draft = {
            "schema_version": ROSTER_SCHEMA,
            "roster_id": roster_id,
            "status": "review_required",
            "admission_request_sha256": request_hash,
            "qualification_protocol_sha256": protocol_hash,
            "participants": sorted(entries, key=lambda item: item["participant_id"]),
        }
        draft["roster_sha256"] = canonical_sha256(draft)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.chmod(0o700)
        write_private_json(output_path, draft)
        draft_artifact = _artifact(output_path)
    pair_counts = Counter(entry.get("pair_id") for entry in entries)
    report = {
        "schema_version": REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "state": (
            "qualification_roster_draft_ready_independent_review_required"
            if passed
            else "blocked_qualification_participant_evidence_intake"
        ),
        "qualification_protocol": {
            "path": str(qualification_protocol_path.resolve()),
            "canonical_sha256": protocol_hash or None,
            "freeze_validated": protocol_frozen,
        },
        "evidence_root": str(evidence_root.resolve()),
        "packet_inventory": packet_reports,
        "counts": {
            "required_participants": 40,
            "valid_participants": len(entries),
            "missing_participants": max(0, 40 - len(entries)),
            "required_pairs": 20,
            "complete_pairs": sum(count == 2 for count in pair_counts.values()),
        },
        "roster_draft": draft_artifact,
        "readiness": {
            "qualification_protocol_frozen": protocol_frozen,
            "participant_evidence_complete": passed,
            "independent_roster_review_required": passed,
            "real_participant_roster_bound": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "evidence_validation_only": True,
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
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.chmod(0o700)
    write_private_json(report_path, report)
    return report


def _validate_freeze_report(
    report: dict[str, Any], protocol_hash: str, failures: list[str]
) -> None:
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
    failures.extend(code for code, passed in checks.items() if not passed)


def _packet_paths(root: Path, failures: list[str]) -> list[Path]:
    try:
        if not root.is_dir() or root.is_symlink():
            raise OSError
        if root.stat().st_mode & 0o077:
            failures.append("participant_evidence_root_permissions_too_open")
        paths = sorted(root.glob("*.participant.json"))
    except OSError:
        failures.append("participant_evidence_root_unreadable")
        return []
    if not paths:
        failures.append("qualification_participant_evidence_missing")
    return paths


def _load_evidence(
    *,
    evidence_root: Path,
    packet: dict[str, Any],
    kind: str,
    protocol_hash: str,
) -> tuple[dict[str, Any], str, list[str]]:
    failures: list[str] = []
    evidence = packet.get("evidence")
    reference = evidence.get(kind, {}) if isinstance(evidence, dict) else {}
    relative = Path(str(reference.get("path", "")))
    candidate = evidence_root / relative
    path = candidate.resolve()
    try:
        path.relative_to(evidence_root.resolve())
    except ValueError:
        return {}, "", [f"participant_{kind}_path_escapes_root"]
    if _contains_symlink(candidate, evidence_root):
        return {}, "", [f"participant_{kind}_path_uses_symlink"]
    artifact, raw = _read_private(path, f"participant_{kind}", failures)
    artifact_hash = hashlib.sha256(raw).hexdigest() if raw else ""
    if artifact_hash != reference.get("sha256"):
        failures.append(f"participant_{kind}_artifact_hash_mismatch")
    failures.extend(
        validate_evidence_artifact(
            kind,
            artifact,
            packet=packet,
            qualification_protocol_sha256=protocol_hash,
        )
    )
    return artifact, artifact_hash, list(dict.fromkeys(failures))


def _baseline_uniqueness_failures(entries: list[dict[str, Any]]) -> list[str]:
    pair_baselines: dict[str, str] = {}
    for entry in entries:
        pair_id = str(entry.get("pair_id", ""))
        baseline = str(entry.get("cognitive_baseline_sha256", ""))
        pair_baselines.setdefault(pair_id, baseline)
    values = [value for value in pair_baselines.values() if value]
    return (
        ["pair_cognitive_baseline_artifact_duplicate"]
        if len(values) != len(set(values))
        else []
    )


def _contains_symlink(path: Path, root: Path) -> bool:
    resolved_root = root.resolve()
    current = path
    while current.resolve(strict=False) != resolved_root:
        if current.is_symlink() or current.parent == current:
            return True
        current = current.parent
    return False


def _expected_stack(protocol: dict[str, Any]) -> dict[str, str]:
    stack = protocol.get("frozen_stack", {})
    corpus = protocol.get("task_corpus", {})
    return {
        "provider_id": str(stack.get("provider_id", "")),
        "model_id": str(stack.get("model_id", "")),
        "budget_id": str(stack.get("budget_id", "")),
        "corpus_id": str(corpus.get("corpus_id", "")),
        "verifier_id": str(stack.get("verifier_id", "")),
    }


def _read_private_object(path: Path, label: str, failures: list[str]) -> dict[str, Any]:
    value, _ = _read_private(path, label, failures)
    return value


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


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roster-id", required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--protocol-freeze-report", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = prepare_roster_draft(
            roster_id=args.roster_id,
            qualification_protocol_path=args.qualification_protocol,
            protocol_freeze_report_path=args.protocol_freeze_report,
            evidence_root=args.evidence_root,
            output_path=args.output,
            report_path=args.report,
        )
    except ValueError as error:
        print(
            json.dumps(
                {
                    "schema_version": REPORT_SCHEMA,
                    "passed": False,
                    "state": "blocked_qualification_roster_intake_output_collision",
                    "error": str(error),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
