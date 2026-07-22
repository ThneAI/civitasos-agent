"""Validate the signed J1-D execution-design review chain."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_execution_design import (
    validate_execution_design,
    validate_execution_design_review_receipt,
    validate_reviewed_execution_design_binding,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_execution_design import (
    validate_execution_design_sources,
)


GATE_SCHEMA = "j1-qualification-execution-design-review-gate:v1"
DESIGN_CONTRACT_SOURCE = (
    Path(__file__).parent / "j1" / "qualification_execution_design.py"
)
OPERATION_SOURCE = Path(__file__).parent / "j1_qualification_execution_design_review.py"
GATE_SOURCE = Path(__file__)


def run_gate(
    *,
    design_path: Path,
    review_receipt_path: Path,
    reviewed_design_path: Path,
    qualification_protocol_path: Path,
    corpus_path: Path,
    reviewed_assignment_path: Path,
    assignment_gate_path: Path,
    reviewer_profile_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    failures: list[str] = []
    loaded = {
        "design": _read_private(design_path, "execution_design_unreadable", failures),
        "receipt": _read_private(
            review_receipt_path, "execution_design_review_receipt_unreadable", failures
        ),
        "reviewed": _read_private(
            reviewed_design_path, "reviewed_execution_design_unreadable", failures
        ),
        "protocol": _read_private(
            qualification_protocol_path, "qualification_protocol_unreadable", failures
        ),
        "corpus": _read_private(
            corpus_path, "qualification_corpus_unreadable", failures
        ),
        "assignment": _read_private(
            reviewed_assignment_path, "reviewed_assignment_unreadable", failures
        ),
        "assignment_gate": _read_private(
            assignment_gate_path, "assignment_gate_unreadable", failures
        ),
        "reviewer": _read_private(
            reviewer_profile_path, "reviewer_profile_unreadable", failures
        ),
    }
    if not failures:
        design, design_raw = loaded["design"]
        receipt, receipt_raw = loaded["receipt"]
        reviewed, _ = loaded["reviewed"]
        protocol, protocol_raw = loaded["protocol"]
        corpus, corpus_raw = loaded["corpus"]
        assignment, assignment_raw = loaded["assignment"]
        assignment_gate, _ = loaded["assignment_gate"]
        reviewer, reviewer_raw = loaded["reviewer"]
        try:
            validate_execution_design_sources(
                protocol=protocol,
                protocol_path=qualification_protocol_path,
                protocol_raw=protocol_raw,
                corpus=corpus,
                corpus_path=corpus_path,
                corpus_raw=corpus_raw,
                assignment=assignment,
                assignment_path=reviewed_assignment_path,
                assignment_raw=assignment_raw,
                assignment_gate=assignment_gate,
            )
        except ValueError as error:
            failures.append(f"execution_design_source_chain_invalid:{error}")
        failures.extend(
            validate_execution_design(
                design,
                protocol=protocol,
                corpus=corpus,
                reviewed_assignment=assignment,
            )
        )
        failures.extend(validate_reviewer_identity_profile(reviewer))
        implementation = {
            "agent_revision": receipt.get("implementation", {}).get("agent_revision"),
            "design_contract_source_sha256": hashlib.sha256(
                DESIGN_CONTRACT_SOURCE.read_bytes()
            ).hexdigest(),
            "operation_source_sha256": hashlib.sha256(
                OPERATION_SOURCE.read_bytes()
            ).hexdigest(),
            "gate_source_sha256": hashlib.sha256(GATE_SOURCE.read_bytes()).hexdigest(),
        }
        failures.extend(
            validate_execution_design_review_receipt(
                receipt,
                design=design,
                design_artifact_sha256=hashlib.sha256(design_raw).hexdigest(),
                protocol=protocol,
                corpus=corpus,
                reviewed_assignment=assignment,
                reviewer_profile=reviewer,
                reviewer_profile_sha256=hashlib.sha256(reviewer_raw).hexdigest(),
                implementation=implementation,
            )
        )
        failures.extend(
            validate_reviewed_execution_design_binding(
                reviewed,
                design=design,
                receipt=receipt,
                receipt_artifact_sha256=hashlib.sha256(receipt_raw).hexdigest(),
            )
        )
    failures = list(dict.fromkeys(failures))
    passed = not failures
    reviewed = loaded["reviewed"][0]
    report = {
        "schema_version": GATE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "reviewed_design_sha256": reviewed.get("reviewed_design_sha256"),
        "design_id": reviewed.get("design_id"),
        "artifacts": {
            "design": _artifact(design_path, loaded["design"][1]),
            "review_receipt": _artifact(review_receipt_path, loaded["receipt"][1]),
            "reviewed_design": _artifact(reviewed_design_path, loaded["reviewed"][1]),
            "qualification_protocol": _artifact(
                qualification_protocol_path, loaded["protocol"][1]
            ),
            "corpus": _artifact(corpus_path, loaded["corpus"][1]),
            "reviewed_assignment": _artifact(
                reviewed_assignment_path, loaded["assignment"][1]
            ),
            "assignment_gate": _artifact(
                assignment_gate_path, loaded["assignment_gate"][1]
            ),
            "reviewer_profile": _artifact(reviewer_profile_path, loaded["reviewer"][1]),
        },
        "readiness": {
            "execution_design_reviewed": passed,
            "execution_design_bound": passed,
            "mentor_identity_provisioned": False,
            "provider_broker_ready": False,
            "single_use_authorization_issued": False,
            "controlled_experiment_execution_ready": False,
        },
        "execution_boundary": {
            "execution_design_validation_only": True,
            "mentor_identity_provisioning_allowed": False,
            "provider_api_call_allowed": False,
            "model_invocation_allowed": False,
            "agent_execution_allowed": False,
            "backend_fact_append_allowed": False,
            "ledger_append_allowed": False,
        },
    }
    write_private_json(output_path, report)
    return report


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
    parser.add_argument("--design", type=Path, required=True)
    parser.add_argument("--review-receipt", type=Path, required=True)
    parser.add_argument("--reviewed-design", type=Path, required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--reviewed-assignment", type=Path, required=True)
    parser.add_argument("--assignment-gate", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_gate(
        design_path=args.design,
        review_receipt_path=args.review_receipt,
        reviewed_design_path=args.reviewed_design,
        qualification_protocol_path=args.qualification_protocol,
        corpus_path=args.corpus,
        reviewed_assignment_path=args.reviewed_assignment,
        assignment_gate_path=args.assignment_gate,
        reviewer_profile_path=args.reviewer_profile,
        output_path=args.output,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
