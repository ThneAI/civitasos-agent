"""Validate the signed J1-D mentor/control cohort assignment."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_cohort_assignment import (
    validate_assignment_proposal,
    validate_assignment_review_receipt,
    validate_reviewed_assignment_binding,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)


GATE_SCHEMA = "j1-qualification-cohort-assignment-gate:v1"
CONTRACT_SOURCE = Path(__file__).parent / "j1" / "qualification_cohort_assignment.py"
OPERATION_SOURCE = Path(__file__).parent / "j1_qualification_cohort_assignment.py"


def run_gate(
    *,
    proposal_path: Path,
    review_receipt_path: Path,
    reviewed_assignment_path: Path,
    qualification_protocol_path: Path,
    reviewed_pairing_path: Path,
    reviewed_roster_path: Path,
    reviewer_profile_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    proposal, proposal_raw = _read_private(
        proposal_path, "assignment_proposal_unreadable", failures
    )
    receipt, receipt_raw = _read_private(
        review_receipt_path, "assignment_review_receipt_unreadable", failures
    )
    reviewed, reviewed_raw = _read_private(
        reviewed_assignment_path, "reviewed_assignment_unreadable", failures
    )
    protocol, protocol_raw = _read_private(
        qualification_protocol_path, "qualification_protocol_unreadable", failures
    )
    pairing, pairing_raw = _read_private(
        reviewed_pairing_path, "reviewed_pairing_unreadable", failures
    )
    roster, roster_raw = _read_private(
        reviewed_roster_path, "reviewed_roster_unreadable", failures
    )
    reviewer, reviewer_raw = _read_private(
        reviewer_profile_path, "reviewer_profile_unreadable", failures
    )
    if not failures:
        failures.extend(
            validate_assignment_proposal(
                proposal,
                protocol=protocol,
                reviewed_pairing=pairing,
                reviewed_roster=roster,
            )
        )
        failures.extend(validate_reviewer_identity_profile(reviewer))
        implementation = {
            "agent_revision": receipt.get("implementation", {}).get("agent_revision"),
            "contract_source_sha256": hashlib.sha256(
                CONTRACT_SOURCE.read_bytes()
            ).hexdigest(),
            "operation_source_sha256": hashlib.sha256(
                OPERATION_SOURCE.read_bytes()
            ).hexdigest(),
        }
        failures.extend(
            validate_assignment_review_receipt(
                receipt,
                proposal=proposal,
                proposal_artifact_sha256=hashlib.sha256(proposal_raw).hexdigest(),
                reviewer_profile=reviewer,
                reviewer_profile_sha256=hashlib.sha256(reviewer_raw).hexdigest(),
                implementation=implementation,
            )
        )
        failures.extend(
            validate_reviewed_assignment_binding(
                reviewed,
                proposal=proposal,
                receipt=receipt,
                receipt_artifact_sha256=hashlib.sha256(receipt_raw).hexdigest(),
            )
        )
        _validate_source_artifacts(
            reviewed,
            protocol_raw=protocol_raw,
            pairing_raw=pairing_raw,
            roster_raw=roster_raw,
            failures=failures,
        )
    failures = list(dict.fromkeys(failures))
    passed = not failures
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "reviewed_assignment_sha256": reviewed.get("reviewed_assignment_sha256"),
        "participant_count": reviewed.get("participant_count"),
        "pair_count": reviewed.get("pair_count"),
        "artifacts": {
            "proposal": _artifact(proposal_path, proposal_raw),
            "review_receipt": _artifact(review_receipt_path, receipt_raw),
            "reviewed_assignment": _artifact(reviewed_assignment_path, reviewed_raw),
            "qualification_protocol": _artifact(
                qualification_protocol_path, protocol_raw
            ),
            "reviewed_pairing": _artifact(reviewed_pairing_path, pairing_raw),
            "reviewed_roster": _artifact(reviewed_roster_path, roster_raw),
            "reviewer_profile": _artifact(reviewer_profile_path, reviewer_raw),
        },
        "readiness": {
            "cohort_assignment_reviewed": passed,
            "cohort_assignment_bound": passed,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "assignment_validation_only": True,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    write_private_json(output_path, report)
    return report


def _validate_source_artifacts(
    reviewed: dict[str, Any],
    *,
    protocol_raw: bytes,
    pairing_raw: bytes,
    roster_raw: bytes,
    failures: list[str],
) -> None:
    if not protocol_raw or not pairing_raw or not roster_raw:
        return
    # Canonical hashes are signed inside the reviewed assignment; raw hashes remain in the Gate.
    if reviewed.get("qualification_protocol_sha256") is None:
        failures.append("assignment_protocol_binding_missing")
    if reviewed.get("reviewed_pairing_sha256") is None:
        failures.append("assignment_pairing_binding_missing")
    if reviewed.get("reviewed_roster_sha256") is None:
        failures.append("assignment_roster_binding_missing")


def _read_private(
    path: Path, failure: str, failures: list[str]
) -> tuple[dict[str, Any], bytes]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            raise ValueError("private artifact invalid")
        raw = path.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("artifact must be a JSON object")
        return value, raw
    except (OSError, ValueError, json.JSONDecodeError):
        failures.append(failure)
        return {}, b""


def _artifact(path: Path, raw: bytes) -> dict[str, str | None]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--review-receipt", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--reviewed-pairing", type=Path, required=True)
    parser.add_argument("--reviewed-roster", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        proposal_path=args.proposal,
        review_receipt_path=args.review_receipt,
        reviewed_assignment_path=args.reviewed_assignment,
        qualification_protocol_path=args.qualification_protocol,
        reviewed_pairing_path=args.reviewed_pairing,
        reviewed_roster_path=args.reviewed_roster,
        reviewer_profile_path=args.reviewer_profile,
        output_path=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
