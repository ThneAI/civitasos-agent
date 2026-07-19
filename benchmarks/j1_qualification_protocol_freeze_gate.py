"""Freeze a J1-D qualification protocol without authorizing execution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import (
    canonical_sha256,
    read_json_object,
    write_private_json,
)
from benchmarks.j1.qualification_protocol_freeze import validate_freeze
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST


GATE_SCHEMA = "j1-qualification-protocol-freeze-gate:v1"


def run_gate(
    *, protocol_path: Path, corpus_path: Path, verifier_path: Path, output_path: Path
) -> dict[str, Any]:
    failures: list[str] = []
    protocol, protocol_bytes = _read(protocol_path, "qualification_protocol", failures)
    corpus, corpus_bytes = _read(corpus_path, "qualification_corpus", failures)
    verifier, verifier_bytes = _read(verifier_path, "qualification_verifier", failures)
    request = read_json_object(DEFAULT_REQUEST)
    if protocol and corpus and verifier:
        failures.extend(
            validate_freeze(
                protocol,
                corpus,
                verifier,
                request,
                corpus_bytes=corpus_bytes,
                verifier_bytes=verifier_bytes,
            )
        )
    passed = not failures
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": list(dict.fromkeys(failures)),
        "admission_request_sha256": canonical_sha256(request),
        "qualification_protocol_sha256": canonical_sha256(protocol)
        if protocol
        else None,
        "corpus_artifact_sha256": _sha256(corpus_bytes) if corpus_bytes else None,
        "verifier_artifact_sha256": _sha256(verifier_bytes) if verifier_bytes else None,
        "source_content_recorded": False,
        "readiness": {
            "state": "j1d_qualification_protocol_frozen_roster_required"
            if passed
            else "blocked_j1d_qualification_protocol_freeze",
            "qualification_protocol_frozen": passed,
            "real_participant_roster_bound": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "artifact_validation_only": True,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    write_private_json(output_path, report)
    return report


def _read(path: Path, label: str, failures: list[str]) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError
        return value, raw
    except (OSError, ValueError, json.JSONDecodeError):
        failures.append(f"{label}_unreadable")
        return {}, b""


def _sha256(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        protocol_path=args.protocol,
        corpus_path=args.corpus,
        verifier_path=args.verifier,
        output_path=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
