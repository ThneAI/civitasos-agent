"""Prepare and sign the exact J1-D mentor/control cohort assignment."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pkcs11
from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import (
    canonical_sha256,
    write_private_json,
)
from benchmarks.j1.qualification_cohort_assignment import (
    build_assignment_proposal,
    build_assignment_review_receipt,
    build_reviewed_assignment,
    validate_assignment_proposal,
    validate_assignment_review_receipt,
    validate_reviewed_assignment,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = "j1-qualification-cohort-assignment-operation:v1"
CONTRACT_SOURCE = Path(__file__).parent / "j1" / "qualification_cohort_assignment.py"
OPERATION_SOURCE = Path(__file__)


def prepare_assignment_review(
    *,
    assignment_id: str,
    created_at: str,
    qualification_protocol_path: Path,
    reviewed_pairing_path: Path,
    reviewed_roster_path: Path,
    roster_gate_report_path: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    candidate_root: Path,
) -> dict[str, Any]:
    if candidate_root.exists():
        raise ValueError(f"assignment candidate root already exists: {candidate_root}")
    context = _load_context(
        qualification_protocol_path=qualification_protocol_path,
        reviewed_pairing_path=reviewed_pairing_path,
        reviewed_roster_path=reviewed_roster_path,
        roster_gate_report_path=roster_gate_report_path,
        reviewer_profile_path=reviewer_profile_path,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    proposal = build_assignment_proposal(
        assignment_id=assignment_id,
        created_at=created_at,
        protocol=context["protocol"],
        reviewed_pairing=context["pairing"],
        reviewed_roster=context["roster"],
    )
    candidate_root.mkdir(parents=True, mode=0o700)
    candidate_root.chmod(0o700)
    try:
        proposal_path = candidate_root / "cohort-assignment.review-required.json"
        write_private_json(proposal_path, proposal)
        artifact_sha256 = hashlib.sha256(proposal_path.read_bytes()).hexdigest()
        statement = approval_statement(proposal, artifact_sha256)
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "cohort_assignment_prepared_explicit_owner_review_required",
            "proposal": {
                **_artifact(proposal_path),
                "canonical_sha256": proposal["assignment_sha256"],
                "participant_count": 40,
                "pair_count": 20,
            },
            "approval_request": {
                "required_exact_statement": statement,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                "approve_exact_assignment_required": True,
            },
            "reviewer_did": context["reviewer"]["reviewer"]["did"],
            "token_pin_state": context["pin_state"],
            "pin_read": False,
            "token_login_attempted": False,
            "signature_performed": False,
            "execution_boundary": _execution_boundary(),
        }
        write_private_json(candidate_root / "cohort-assignment-preflight.json", report)
        return report
    except Exception:
        shutil.rmtree(candidate_root, ignore_errors=True)
        raise


def approve_assignment_review(
    *,
    review_id: str,
    reviewed_at: str,
    authorization_id: str,
    authorization_statement: str,
    authorization_statement_sha256: str,
    proposal_path: Path,
    qualification_protocol_path: Path,
    reviewed_pairing_path: Path,
    reviewed_roster_path: Path,
    roster_gate_report_path: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    agent_revision: str,
    pin: str,
    output_root: Path,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    if output_root.exists():
        raise ValueError(f"assignment review output already exists: {output_root}")
    context = _load_context(
        qualification_protocol_path=qualification_protocol_path,
        reviewed_pairing_path=reviewed_pairing_path,
        reviewed_roster_path=reviewed_roster_path,
        roster_gate_report_path=roster_gate_report_path,
        reviewer_profile_path=reviewer_profile_path,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
    )
    proposal, proposal_raw = _read_private(proposal_path)
    failures = validate_assignment_proposal(
        proposal,
        protocol=context["protocol"],
        reviewed_pairing=context["pairing"],
        reviewed_roster=context["roster"],
    )
    if failures:
        raise ValueError(f"cohort assignment proposal invalid: {failures}")
    artifact_sha256 = hashlib.sha256(proposal_raw).hexdigest()
    expected_statement = approval_statement(proposal, artifact_sha256)
    if (
        authorization_statement != expected_statement
        or hashlib.sha256(authorization_statement.encode()).hexdigest()
        != authorization_statement_sha256
    ):
        raise ValueError("cohort assignment approval statement/hash mismatch")
    if not _text(review_id) or not _text(authorization_id) or not _rfc3339(reviewed_at):
        raise ValueError("cohort assignment review metadata invalid")
    implementation = _implementation(agent_revision)

    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        reviewer = context["reviewer"]
        with Pkcs11Ed25519Signer(
            str(Path(module_path).resolve()),
            token_label,
            key_label,
            reviewer["reviewer"]["public_key_hex"],
            pin,
            key_id=key_id_hex,
        ) as signer:
            receipt = build_assignment_review_receipt(
                review_id=review_id,
                reviewed_at=reviewed_at,
                authorization_id=authorization_id,
                authorization_statement_sha256=authorization_statement_sha256,
                proposal=proposal,
                proposal_artifact_sha256=artifact_sha256,
                reviewer_profile=reviewer,
                reviewer_profile_sha256=context["reviewer_sha256"],
                implementation=implementation,
                signer=signer,
            )
        receipt_path = output_root / "cohort-assignment-review-receipt.json"
        write_private_json(receipt_path, receipt)
        receipt_artifact_sha256 = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        reviewed = build_reviewed_assignment(
            proposal=proposal,
            receipt=receipt,
            receipt_artifact_sha256=receipt_artifact_sha256,
        )
        reviewed_path = output_root / "cohort-assignment.operator-reviewed.json"
        write_private_json(reviewed_path, reviewed)
        failures = validate_assignment_review_receipt(
            receipt,
            proposal=proposal,
            proposal_artifact_sha256=artifact_sha256,
            reviewer_profile=reviewer,
            reviewer_profile_sha256=context["reviewer_sha256"],
            implementation=implementation,
        )
        failures.extend(validate_reviewed_assignment(reviewed))
        if failures:
            raise ValueError(f"reviewed cohort assignment invalid: {failures}")
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "cohort_assignment_reviewed_execution_authorization_binding_required",
            "review_id": review_id,
            "reviewed_at": reviewed_at,
            "proposal": _artifact(proposal_path),
            "review_receipt": _artifact(receipt_path),
            "reviewed_assignment": {
                **_artifact(reviewed_path),
                "canonical_sha256": reviewed["reviewed_assignment_sha256"],
            },
            "authorization": {
                "authorization_id": authorization_id,
                "statement": authorization_statement,
                "authorization_statement_sha256": authorization_statement_sha256,
            },
            "pin_recorded": False,
            "execution_boundary": _execution_boundary(),
        }
        write_private_json(
            output_root / "cohort-assignment-operation-report.json", report
        )
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def approval_statement(proposal: dict[str, Any], artifact_sha256: str) -> str:
    return (
        "I approve exactly the J1-D mentor/control cohort assignment artifact "
        f"{artifact_sha256}, canonical assignment {proposal['assignment_sha256']}, "
        f"covering {proposal['participant_count']} participants in {proposal['pair_count']} "
        "balanced pairs. I acknowledge that participant substitution or cohort reassignment "
        "requires a new reviewed assignment and that this approval does not authorize provider, "
        "model, agent, Backend, Ledger, or experiment execution."
    )


def _load_context(**values: Any) -> dict[str, Any]:
    protocol, _ = _read_private(Path(values["qualification_protocol_path"]))
    pairing, _ = _read_private(Path(values["reviewed_pairing_path"]))
    roster, _ = _read_private(Path(values["reviewed_roster_path"]))
    roster_gate, _ = _read_private(Path(values["roster_gate_report_path"]))
    reviewer, reviewer_raw = _read_private(Path(values["reviewer_profile_path"]))
    review_receipt_ref = roster_gate.get("artifacts", {}).get("review_receipt", {})
    review_receipt_path = Path(str(review_receipt_ref.get("path", ""))).resolve()
    roster_path = Path(values["reviewed_roster_path"]).resolve()
    if review_receipt_path.parent != roster_path.parent:
        raise ValueError("roster review receipt path escapes reviewed roster root")
    review_receipt, review_receipt_raw = _read_private(review_receipt_path)
    if not (
        roster_gate.get("passed") is True
        and roster_gate.get("failure_reasons") == []
        and roster_gate.get("roster_sha256") == roster.get("roster_sha256")
        and roster_gate.get("qualification_protocol_sha256")
        == canonical_sha256(protocol)
        and roster_gate.get("readiness", {}).get("signed_roster_review_verified")
        is True
        and review_receipt_ref.get("sha256")
        == hashlib.sha256(review_receipt_raw).hexdigest()
        and roster.get("operator_review", {}).get("review_receipt_sha256")
        == review_receipt_ref.get("sha256")
        and review_receipt.get("source_evidence", {}).get("reviewed_pairing_sha256")
        == pairing.get("reviewed_pairing_sha256")
    ):
        raise ValueError(
            "signed roster Gate/review receipt is not valid for cohort assignment"
        )
    reviewer_failures = validate_reviewer_identity_profile(reviewer)
    if reviewer_failures:
        raise ValueError(f"reviewer identity profile invalid: {reviewer_failures}")
    _validate_reviewer_configuration(reviewer, values)
    pin_state = inspect_token_pin_state(
        module_path=str(Path(values["module_path"]).resolve()),
        token_label=values["token_label"],
    )
    if not (
        pin_state["token_initialized"]
        and pin_state["user_pin_initialized"]
        and pin_state["safe_to_attempt_user_login"]
    ):
        raise ValueError(f"reviewer token not ready: {pin_state}")
    return {
        "protocol": protocol,
        "pairing": pairing,
        "roster": roster,
        "reviewer": reviewer,
        "reviewer_sha256": hashlib.sha256(reviewer_raw).hexdigest(),
        "pin_state": pin_state,
    }


def _validate_reviewer_configuration(
    profile: dict[str, Any], values: dict[str, Any]
) -> None:
    key = profile["pkcs11_key"]
    module = str(Path(values["module_path"]).resolve())
    expected = {
        "module_path": module,
        "token_label": values["token_label"],
        "key_label": values["key_label"],
        "key_id_hex": str(values["key_id_hex"]).lower(),
    }
    if any(
        key.get(field) != expected_value for field, expected_value in expected.items()
    ):
        raise ValueError("reviewer PKCS#11 configuration mismatch")
    if (
        key.get("module_sha256")
        != hashlib.sha256(Path(module).read_bytes()).hexdigest()
    ):
        raise ValueError("reviewer PKCS#11 module hash mismatch")


def _implementation(agent_revision: str) -> dict[str, str]:
    repository = OPERATION_SOURCE.parent.parent
    revision = agent_revision.lower()
    head = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    status = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain"],
        check=False,
        capture_output=True,
        text=True,
    )
    if head.returncode or head.stdout.strip().lower() != revision:
        raise ValueError("assignment review revision is not checked out")
    if status.returncode or status.stdout.strip():
        raise ValueError("assignment review worktree must be clean")
    return {
        "agent_revision": revision,
        "contract_source_sha256": hashlib.sha256(
            CONTRACT_SOURCE.read_bytes()
        ).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }


def _execution_boundary() -> dict[str, bool]:
    return {
        "cohort_assignment_only": True,
        "single_use_authorization_issued": False,
        "provider_api_call_performed": False,
        "model_invocation_performed": False,
        "agent_execution_performed": False,
        "backend_fact_append_performed": False,
        "ledger_append_performed": False,
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(f"private JSON artifact invalid: {path}")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be object: {path}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _rfc3339(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        return (
            datetime.fromisoformat(str(value).replace("Z", "+00:00")).tzinfo is not None
        )
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assignment-id", required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--reviewed-pairing", type=Path, required=True)
    parser.add_argument("--reviewed-roster", type=Path, required=True)
    parser.add_argument("--roster-gate-report", type=Path, required=True)
    parser.add_argument("--reviewer-profile", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--approve", action="store_true")
    parser.add_argument("--proposal", type=Path)
    parser.add_argument("--review-id")
    parser.add_argument("--authorization-id")
    parser.add_argument("--authorization-statement")
    parser.add_argument("--authorization-statement-sha256")
    parser.add_argument("--agent-revision")
    parser.add_argument("--pin-file", type=Path)
    parser.add_argument("--output-root", type=Path)
    args = parser.parse_args()
    common = {
        "qualification_protocol_path": args.qualification_protocol,
        "reviewed_pairing_path": args.reviewed_pairing,
        "reviewed_roster_path": args.reviewed_roster,
        "roster_gate_report_path": args.roster_gate_report,
        "reviewer_profile_path": args.reviewer_profile,
        "module_path": args.module,
        "token_label": args.token_label,
        "key_label": args.key_label,
        "key_id_hex": args.key_id,
    }
    try:
        if not args.approve:
            report = prepare_assignment_review(
                **common,
                assignment_id=args.assignment_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                candidate_root=args.candidate_root,
            )
        else:
            required = (
                args.proposal,
                args.review_id,
                args.authorization_id,
                args.authorization_statement,
                args.authorization_statement_sha256,
                args.agent_revision,
                args.output_root,
            )
            if any(value is None for value in required):
                raise ValueError("assignment approval metadata is incomplete")
            pin = read_pin(args.pin_file)
            try:
                report = approve_assignment_review(
                    **common,
                    review_id=str(args.review_id),
                    reviewed_at=datetime.now(timezone.utc).isoformat(),
                    authorization_id=str(args.authorization_id),
                    authorization_statement=str(args.authorization_statement),
                    authorization_statement_sha256=str(
                        args.authorization_statement_sha256
                    ),
                    proposal_path=Path(args.proposal),
                    agent_revision=str(args.agent_revision),
                    pin=pin,
                    output_root=Path(args.output_root),
                )
            finally:
                pin = ""
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        json.JSONDecodeError,
        pkcs11.PKCS11Error,
    ) as error:
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": False,
            "state": "blocked_cohort_assignment_operation",
            "error_class": type(error).__name__,
            "error": str(error),
            "pin_recorded": False,
            "provider_api_call_performed": False,
            "model_invocation_performed": False,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
