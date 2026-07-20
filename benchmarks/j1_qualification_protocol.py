"""Prepare an artifact-bound J1-D qualification protocol without execution."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import (
    canonical_sha256,
    read_json_object,
    write_private_json,
)
from benchmarks.j1.qualification_protocol_freeze import (
    build_qualification_protocol,
    validate_freeze,
)
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST


REPORT_SCHEMA = "j1-qualification-protocol-preparation:v1"


def prepare_qualification_protocol(
    *,
    experiment_id: str,
    hypothesis: str,
    budget_id: str,
    frozen_at: str,
    admission_request_path: Path,
    corpus_path: Path,
    verifier_path: Path,
    review_receipt_path: Path,
    output_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    for path in (output_path, report_path):
        if path.exists():
            raise ValueError(f"output already exists: {path}")
    failures: list[str] = []
    corpus, corpus_bytes = _read_private(corpus_path, "qualification_corpus", failures)
    verifier, verifier_bytes = _read_private(
        verifier_path, "qualification_verifier", failures
    )
    receipt, receipt_bytes = _read_private(
        review_receipt_path, "qualification_material_review_receipt", failures
    )
    try:
        admission_request = read_json_object(admission_request_path)
    except (OSError, ValueError, json.JSONDecodeError):
        admission_request = {}
        failures.append("admission_request_unreadable")
    protocol: dict[str, Any] = {}
    if not failures:
        try:
            protocol = build_qualification_protocol(
                experiment_id=experiment_id,
                hypothesis=hypothesis,
                budget_id=budget_id,
                frozen_at=frozen_at,
                corpus=corpus,
                verifier=verifier,
                admission_request=admission_request,
                review_receipt=receipt,
                corpus_bytes=corpus_bytes,
                verifier_bytes=verifier_bytes,
                review_receipt_bytes=receipt_bytes,
            )
        except ValueError as error:
            failures.append(str(error))
        if protocol:
            failures.extend(
                validate_freeze(
                    protocol,
                    corpus,
                    verifier,
                    admission_request,
                    corpus_bytes=corpus_bytes,
                    verifier_bytes=verifier_bytes,
                    review_receipt=receipt,
                    review_receipt_bytes=receipt_bytes,
                )
            )
    failures = list(dict.fromkeys(failures))
    passed = not failures
    protocol_artifact = None
    if passed:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.chmod(0o700)
        write_private_json(output_path, protocol)
        protocol_artifact = _artifact(output_path)
        protocol_artifact["canonical_sha256"] = canonical_sha256(protocol)
    report = {
        "schema_version": REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "state": (
            "qualification_protocol_prepared_freeze_gate_required"
            if passed
            else "blocked_qualification_protocol_preparation"
        ),
        "experiment_id": experiment_id,
        "frozen_at": frozen_at,
        "source_artifacts": {
            "admission_request": _artifact_if_readable(admission_request_path),
            "operator_reviewed_corpus": _artifact_if_readable(corpus_path),
            "operator_reviewed_verifier": _artifact_if_readable(verifier_path),
            "signed_review_receipt": _artifact_if_readable(review_receipt_path),
        },
        "qualification_protocol": protocol_artifact,
        "source_content_recorded": False,
        "execution_boundary": {
            "artifact_preparation_only": True,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
            "execution_authorized": False,
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.chmod(0o700)
    write_private_json(report_path, report)
    return report


def _read_private(
    path: Path, label: str, failures: list[str]
) -> tuple[dict[str, Any], bytes]:
    try:
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


def _artifact_if_readable(path: Path) -> dict[str, str] | None:
    try:
        return _artifact(path)
    except OSError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--hypothesis", required=True)
    parser.add_argument("--budget-id", required=True)
    parser.add_argument("--frozen-at", default=_timestamp())
    parser.add_argument("--admission-request", type=Path, default=DEFAULT_REQUEST)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--review-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = prepare_qualification_protocol(
            experiment_id=args.experiment_id,
            hypothesis=args.hypothesis,
            budget_id=args.budget_id,
            frozen_at=args.frozen_at,
            admission_request_path=args.admission_request,
            corpus_path=args.corpus,
            verifier_path=args.verifier,
            review_receipt_path=args.review_receipt,
            output_path=args.output,
            report_path=args.report,
        )
    except ValueError as error:
        print(
            json.dumps(
                {
                    "schema_version": REPORT_SCHEMA,
                    "passed": False,
                    "state": "blocked_qualification_protocol_output_collision",
                    "error": str(error),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


if __name__ == "__main__":
    raise SystemExit(main())
