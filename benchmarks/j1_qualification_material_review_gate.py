"""Promote J1-D materials only after an externally signed operator review."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_material_review import (
    REVIEW_GATE_SCHEMA,
    promote_reviewed_materials,
    validate_candidate_materials,
)
from benchmarks.j1.qualification_review_receipt import validate_review_receipt


def run_gate(
    *,
    corpus_path: Path,
    verifier_path: Path,
    verifier_source_path: Path,
    review_receipt_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    output_root.chmod(0o700)
    failures: list[str] = []
    corpus, corpus_bytes = _read_private(
        corpus_path, "review_candidate_corpus", failures
    )
    verifier, verifier_bytes = _read_private(
        verifier_path, "review_candidate_verifier", failures
    )
    receipt, receipt_bytes = _read_private(
        review_receipt_path, "review_receipt", failures
    )
    try:
        verifier_source_bytes = verifier_source_path.read_bytes()
    except OSError:
        verifier_source_bytes = b""
        failures.append("verifier_source_unreadable")
    if not verifier_source_bytes:
        failures.append("verifier_source_empty")
    if corpus and verifier and verifier_source_bytes:
        failures.extend(
            validate_candidate_materials(
                corpus,
                verifier,
                verifier_source_bytes=verifier_source_bytes,
            )
        )
    receipt_failures: list[str] = []
    receipt_validated = False
    if corpus and verifier and receipt and verifier_source_bytes:
        receipt_validated = True
        receipt_failures = validate_review_receipt(
            receipt,
            corpus=corpus,
            verifier=verifier,
            corpus_bytes=corpus_bytes,
            verifier_bytes=verifier_bytes,
            verifier_source_bytes=verifier_source_bytes,
        )
        failures.extend(receipt_failures)
        if (
            not receipt_failures
            and receipt.get("decision") != "approve_qualification_materials"
        ):
            failures.append("review_decision_does_not_approve")
    passed = not failures
    promoted: dict[str, Any] | None = None
    if passed:
        reviewed_corpus, reviewed_verifier = promote_reviewed_materials(
            corpus=corpus,
            verifier=verifier,
            review_receipt_bytes=receipt_bytes,
        )
        corpus_output = output_root / "qualification-corpus.operator-reviewed.json"
        verifier_output = output_root / "qualification-verifier.operator-reviewed.json"
        write_private_json(corpus_output, reviewed_corpus)
        write_private_json(verifier_output, reviewed_verifier)
        promoted = {
            "corpus": _artifact(corpus_output),
            "verifier": _artifact(verifier_output),
        }
    report = {
        "schema_version": REVIEW_GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": list(dict.fromkeys(failures)),
        "state": (
            "j1d_material_review_passed_protocol_freeze_required"
            if passed
            else "blocked_j1d_material_review"
        ),
        "candidate_artifacts": {
            "corpus": _artifact(corpus_path) if corpus_bytes else None,
            "verifier": _artifact(verifier_path) if verifier_bytes else None,
            "verifier_source_sha256": (
                hashlib.sha256(verifier_source_bytes).hexdigest()
                if verifier_source_bytes
                else None
            ),
        },
        "review_receipt": _artifact(review_receipt_path) if receipt_bytes else None,
        "review_receipt_signature_valid": receipt_validated and not receipt_failures,
        "review_decision": receipt.get("decision") if receipt else None,
        "promoted_artifacts": promoted,
        "readiness": {
            "qualification_materials_operator_reviewed": passed,
            "qualification_protocol_freeze_ready": passed,
            "real_participant_roster_bound": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "review_validation_only": True,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    write_private_json(output_root / "material-review-gate-report.json", report)
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--verifier-source", type=Path, required=True)
    parser.add_argument("--review-receipt", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        corpus_path=args.corpus,
        verifier_path=args.verifier,
        verifier_source_path=args.verifier_source,
        review_receipt_path=args.review_receipt,
        output_root=args.output_root,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
