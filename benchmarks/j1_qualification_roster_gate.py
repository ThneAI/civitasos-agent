"""Validate a signed, reviewed J1-D qualification roster without executing it."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import (
    canonical_sha256,
    read_json_object,
    write_private_json,
)
from benchmarks.j1.qualification_roster import (
    validate_qualification_protocol,
    validate_roster,
    validate_roster_draft,
)
from benchmarks.j1.qualification_roster_review import (
    validate_reviewed_roster_binding,
    validate_roster_review_receipt,
)
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST


GATE_SCHEMA = "j1-qualification-roster-gate:v2"


def run_gate(
    *,
    roster_path: Path,
    source_roster_path: Path,
    review_receipt_path: Path,
    reviewer_profile_path: Path,
    qualification_protocol_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    roster, roster_raw = _read_artifact(
        roster_path, "qualification_roster_unreadable", failures
    )
    source, source_raw = _read_artifact(
        source_roster_path, "source_roster_unreadable", failures
    )
    receipt, receipt_raw = _read_artifact(
        review_receipt_path, "roster_review_receipt_unreadable", failures
    )
    reviewer, reviewer_raw = _read_artifact(
        reviewer_profile_path, "reviewer_identity_profile_unreadable", failures
    )
    protocol, protocol_raw = _read_artifact(
        qualification_protocol_path, "qualification_protocol_unreadable", failures
    )

    request_hash = canonical_sha256(read_json_object(DEFAULT_REQUEST))
    protocol_failures: list[str] = []
    if protocol:
        protocol_failures = validate_qualification_protocol(
            protocol, admission_request_sha256=request_hash
        )
        failures.extend(protocol_failures)
    protocol_frozen = bool(protocol) and not protocol_failures
    protocol_hash = canonical_sha256(protocol) if protocol else None
    expected_stack = _expected_stack(protocol)

    if source and protocol_hash:
        failures.extend(
            validate_roster_draft(
                source,
                admission_request_sha256=request_hash,
                qualification_protocol_sha256=protocol_hash,
                expected_stack=expected_stack,
            )
        )
    if receipt and source and reviewer:
        failures.extend(
            validate_roster_review_receipt(
                receipt,
                candidate_roster=source,
                candidate_artifact_sha256=hashlib.sha256(source_raw).hexdigest(),
                source_evidence=receipt.get("source_evidence", {}),
                reviewer_profile=reviewer,
                reviewer_profile_sha256=hashlib.sha256(reviewer_raw).hexdigest(),
                review_implementation=receipt.get("review_implementation", {}),
            )
        )
    if roster and protocol_hash:
        failures.extend(
            validate_roster(
                roster,
                admission_request_sha256=request_hash,
                qualification_protocol_sha256=protocol_hash,
                expected_stack=expected_stack,
            )
        )
    if roster and source and receipt:
        failures.extend(
            validate_reviewed_roster_binding(
                roster,
                candidate_roster=source,
                receipt=receipt,
                receipt_sha256=hashlib.sha256(receipt_raw).hexdigest(),
            )
        )

    failure_reasons = list(dict.fromkeys(failures))
    passed = not failure_reasons
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": failure_reasons,
        "artifacts": {
            "reviewed_roster": _artifact_reference(roster_path, roster_raw),
            "source_roster": _artifact_reference(source_roster_path, source_raw),
            "review_receipt": _artifact_reference(review_receipt_path, receipt_raw),
            "reviewer_identity_profile": _artifact_reference(
                reviewer_profile_path, reviewer_raw
            ),
            "qualification_protocol": _artifact_reference(
                qualification_protocol_path, protocol_raw
            ),
        },
        "admission_request_sha256": request_hash,
        "qualification_protocol_sha256": protocol_hash,
        "roster_content_recorded": False,
        "roster_sha256": roster.get("roster_sha256") if roster else None,
        "participant_count": len(roster.get("participants", [])) if roster else 0,
        "readiness": {
            "state": (
                "j1d_qualification_roster_bound_authorization_required"
                if passed
                else "blocked_j1d_qualification_roster_binding"
            ),
            "signed_roster_review_verified": passed,
            "real_participant_roster_bound": passed,
            "qualification_protocol_frozen": protocol_frozen,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "roster_validation_only": True,
            "identity_generation_allowed": False,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    write_private_json(output_path, report)
    return report


def _read_artifact(
    path: Path, failure: str, failures: list[str]
) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("artifact must contain a JSON object")
        return value, raw
    except (OSError, ValueError, json.JSONDecodeError):
        failures.append(failure)
        return {}, b""


def _expected_stack(protocol: dict[str, Any]) -> dict[str, str]:
    stack = protocol.get("frozen_stack", {})
    corpus = protocol.get("task_corpus", {})
    return {
        "provider_id": stack.get("provider_id", ""),
        "model_id": stack.get("model_id", ""),
        "budget_id": stack.get("budget_id", ""),
        "corpus_id": corpus.get("corpus_id", ""),
        "verifier_id": stack.get("verifier_id", ""),
    }


def _artifact_reference(path: Path, raw: bytes) -> dict[str, str | None]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--source-roster", type=Path, required=True)
    parser.add_argument("--review-receipt", type=Path, required=True)
    parser.add_argument("--reviewer-identity-profile", type=Path, required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        roster_path=args.roster,
        source_roster_path=args.source_roster,
        review_receipt_path=args.review_receipt,
        reviewer_profile_path=args.reviewer_identity_profile,
        qualification_protocol_path=args.qualification_protocol,
        output_path=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
