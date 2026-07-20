"""Preflight and sign an independent J1-D qualification roster review."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pkcs11
from civitasos import Pkcs11Ed25519Signer

from benchmarks.j1.controlled_comparison import (
    canonical_sha256,
    read_json_object,
    write_private_json,
)
from benchmarks.j1.qualification_pairing_review import validate_reviewed_pairing
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1.qualification_roster import (
    validate_qualification_protocol,
    validate_roster_draft,
)
from benchmarks.j1.qualification_roster_review import (
    build_reviewed_roster,
    build_roster_review_receipt,
    validate_reviewed_roster_binding,
)
from benchmarks.j1_qualification_admission_gate import DEFAULT_REQUEST
from benchmarks.j1_qualification_roster_intake import prepare_roster_draft
from benchmarks.j1_qualification_reviewer_identity import inspect_token_pin_state
from scripts.pkcs11_identity_probe import DEFAULT_MODULE, read_pin


REPORT_SCHEMA = "j1-qualification-roster-review-operation:v1"
MANIFEST_SCHEMA = "j1-qualification-baseline-consent-manifest:v1"
CONTRACT_SOURCE = Path(__file__).parent / "j1" / "qualification_roster_review.py"
OPERATION_SOURCE = Path(__file__)


def preflight_roster_review(
    *,
    review_id: str,
    candidate_roster_path: Path,
    qualification_protocol_path: Path,
    protocol_freeze_report_path: Path,
    reviewed_pairing_path: Path,
    evidence_root: Path,
    manifest_path: Path,
    intake_report_path: Path,
    reviewer_profile_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id_hex: str,
    agent_revision: str,
    output_root: Path,
) -> dict[str, Any]:
    context = _load_context(
        review_id=review_id,
        candidate_roster_path=candidate_roster_path,
        qualification_protocol_path=qualification_protocol_path,
        protocol_freeze_report_path=protocol_freeze_report_path,
        reviewed_pairing_path=reviewed_pairing_path,
        evidence_root=evidence_root,
        manifest_path=manifest_path,
        intake_report_path=intake_report_path,
        reviewer_profile_path=reviewer_profile_path,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id_hex=key_id_hex,
        agent_revision=agent_revision,
        output_root=output_root,
    )
    candidate_hash = context["candidate_artifact_sha256"]
    statement = (
        "I disclose all reviewer conflicts, affirm independent judgment, and approve "
        f"J1-D roster artifact {candidate_hash} for roster binding only. This approval "
        "does not authorize provider, model, agent, backend, ledger, or experiment execution."
    )
    return {
        "schema_version": REPORT_SCHEMA,
        "passed": True,
        "state": "roster_review_preflight_passed_explicit_human_approval_required",
        "review_id": review_id,
        "candidate_roster": {
            "path": str(candidate_roster_path.resolve()),
            "artifact_sha256": candidate_hash,
            "canonical_sha256": context["candidate_roster"]["roster_sha256"],
            "participant_count": 40,
            "pair_count": 20,
        },
        "source_evidence": context["source_evidence"],
        "reviewer_did": context["reviewer_profile"]["reviewer"]["did"],
        "token_pin_state": context["token_pin_state"],
        "approval_request": {
            "required_exact_statement": statement,
            "statement_sha256": hashlib.sha256(statement.encode("utf-8")).hexdigest(),
            "approve_exact_roster_required": True,
            "conflicts_disclosed_required": True,
            "independent_judgment_required": True,
        },
        "pin_read": False,
        "token_login_attempted": False,
        "signature_performed": False,
        "execution_boundary": _false_execution_boundary(),
    }


def approve_roster(
    *,
    reviewed_at: str,
    authorization_id: str,
    authorization_statement: str,
    authorization_statement_sha256: str,
    pin: str,
    **values: Any,
) -> dict[str, Any]:
    if not pin:
        raise ValueError("SoftHSM user PIN is empty")
    context = _load_context(**values)
    _validate_approval_metadata(
        reviewed_at,
        authorization_id,
        authorization_statement,
        authorization_statement_sha256,
        context["candidate_artifact_sha256"],
    )
    module = str(Path(context["module_path"]).resolve())
    pin_state = inspect_token_pin_state(
        module_path=module, token_label=context["token_label"]
    )
    if not pin_state["safe_to_attempt_user_login"]:
        raise ValueError(
            f"token user PIN retry risk: {pin_state['user_pin_risk_flags']}"
        )
    implementation = {
        "agent_revision": context["agent_revision"],
        "contract_source_sha256": hashlib.sha256(
            CONTRACT_SOURCE.read_bytes()
        ).hexdigest(),
        "operation_source_sha256": hashlib.sha256(
            OPERATION_SOURCE.read_bytes()
        ).hexdigest(),
    }
    output_root = Path(context["output_root"])
    output_root.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    try:
        reviewer = context["reviewer_profile"]
        with Pkcs11Ed25519Signer(
            module,
            context["token_label"],
            context["key_label"],
            reviewer["reviewer"]["public_key_hex"],
            pin,
            key_id=context["key_id_hex"],
        ) as signer:
            receipt = build_roster_review_receipt(
                review_id=context["review_id"],
                reviewed_at=reviewed_at,
                authorization_id=authorization_id,
                authorization_statement_sha256=authorization_statement_sha256,
                candidate_roster=context["candidate_roster"],
                candidate_artifact_sha256=context["candidate_artifact_sha256"],
                source_evidence=context["source_evidence"],
                reviewer_profile=reviewer,
                reviewer_profile_sha256=context["reviewer_profile_sha256"],
                review_implementation=implementation,
                signer=signer,
            )
        receipt_path = output_root / "roster-review-receipt.json"
        write_private_json(receipt_path, receipt)
        receipt_sha256 = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        reviewed = build_reviewed_roster(
            candidate_roster=context["candidate_roster"],
            receipt=receipt,
            receipt_sha256=receipt_sha256,
        )
        reviewed_path = output_root / "qualification-roster.operator-reviewed.json"
        write_private_json(reviewed_path, reviewed)
        binding_failures = validate_reviewed_roster_binding(
            reviewed,
            candidate_roster=context["candidate_roster"],
            receipt=receipt,
            receipt_sha256=receipt_sha256,
        )
        if binding_failures:
            raise ValueError(f"reviewed roster binding invalid: {binding_failures}")
        report = {
            "schema_version": REPORT_SCHEMA,
            "passed": True,
            "state": "qualification_roster_reviewed_single_use_authorization_required",
            "review_id": context["review_id"],
            "reviewed_at": reviewed_at,
            "authorization": {
                "authorization_id": authorization_id,
                "statement": authorization_statement,
                "authorization_statement_sha256": authorization_statement_sha256,
            },
            "candidate_roster": _artifact(Path(context["candidate_roster_path"])),
            "review_receipt": _artifact(receipt_path),
            "reviewed_roster": _artifact(reviewed_path),
            "reviewed_roster_canonical_sha256": reviewed["roster_sha256"],
            "source_evidence": context["source_evidence"],
            "readiness": {
                "participant_evidence_complete": True,
                "roster_operator_reviewed": True,
                "real_participant_roster_bound": False,
                "single_use_authorization_issued": False,
                "controlled_experiment_execution_ready": False,
            },
            "execution_boundary": _false_execution_boundary(),
        }
        write_private_json(output_root / "roster-review-operation-report.json", report)
        return report
    except Exception:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _load_context(**values: Any) -> dict[str, Any]:
    output_root = Path(values["output_root"])
    if output_root.exists():
        raise ValueError(f"roster review output already exists: {output_root}")
    _validate_basic_metadata(values["review_id"], values["agent_revision"])
    candidate, candidate_raw = _read_private(Path(values["candidate_roster_path"]))
    protocol, _ = _read_private(Path(values["qualification_protocol_path"]))
    freeze_report, _ = _read_private(Path(values["protocol_freeze_report_path"]))
    reviewed_pairing, _ = _read_private(Path(values["reviewed_pairing_path"]))
    manifest, manifest_raw = _read_private(Path(values["manifest_path"]))
    intake_report, intake_raw = _read_private(Path(values["intake_report_path"]))
    reviewer_profile, reviewer_raw = _read_private(
        Path(values["reviewer_profile_path"])
    )
    request_hash = canonical_sha256(read_json_object(DEFAULT_REQUEST))
    protocol_hash = canonical_sha256(protocol)
    failures = validate_qualification_protocol(
        protocol, admission_request_sha256=request_hash
    )
    if failures:
        raise ValueError(f"qualification protocol invalid: {failures}")
    _validate_freeze_report(freeze_report, protocol_hash)
    pairing_failures = validate_reviewed_pairing(reviewed_pairing)
    if (
        pairing_failures
        or reviewed_pairing.get("qualification_protocol_sha256") != protocol_hash
    ):
        raise ValueError(
            f"reviewed pairing invalid: {pairing_failures or ['protocol_hash_mismatch']}"
        )
    stack = _expected_stack(protocol)
    candidate_failures = validate_roster_draft(
        candidate,
        admission_request_sha256=request_hash,
        qualification_protocol_sha256=protocol_hash,
        expected_stack=stack,
    )
    if candidate_failures:
        raise ValueError(f"candidate roster invalid: {candidate_failures}")
    candidate_hash = hashlib.sha256(candidate_raw).hexdigest()
    _validate_intake_report(
        intake_report, candidate_hash, protocol_hash, reviewed_pairing
    )
    _validate_manifest(
        manifest, manifest_raw, Path(values["evidence_root"]), reviewed_pairing
    )
    _revalidate_intake(
        candidate,
        candidate_raw,
        qualification_protocol_path=Path(values["qualification_protocol_path"]),
        protocol_freeze_report_path=Path(values["protocol_freeze_report_path"]),
        reviewed_pairing_path=Path(values["reviewed_pairing_path"]),
        evidence_root=Path(values["evidence_root"]),
    )
    reviewer_failures = validate_reviewer_identity_profile(reviewer_profile)
    if reviewer_failures:
        raise ValueError(f"reviewer profile invalid: {reviewer_failures}")
    _validate_reviewer_configuration(reviewer_profile, values)
    token_pin_state = inspect_token_pin_state(
        module_path=values["module_path"], token_label=values["token_label"]
    )
    if not (
        token_pin_state["token_initialized"]
        and token_pin_state["user_pin_initialized"]
        and token_pin_state["safe_to_attempt_user_login"]
    ):
        raise ValueError(f"reviewer token not ready: {token_pin_state}")
    _validate_stopped_isolation(Path(values["evidence_root"]))
    source_evidence = {
        "reviewed_pairing_sha256": reviewed_pairing["reviewed_pairing_sha256"],
        "baseline_consent_manifest_sha256": manifest["manifest_sha256"],
        "manifest_artifact_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "intake_report_artifact_sha256": hashlib.sha256(intake_raw).hexdigest(),
        "evidence_artifact_count": 220,
        "cognitive_baseline_count": 20,
        "participant_consent_count": 40,
        "participant_packet_count": 40,
    }
    return {
        **values,
        "candidate_roster": candidate,
        "candidate_artifact_sha256": candidate_hash,
        "reviewer_profile": reviewer_profile,
        "reviewer_profile_sha256": hashlib.sha256(reviewer_raw).hexdigest(),
        "source_evidence": source_evidence,
        "token_pin_state": token_pin_state,
    }


def _revalidate_intake(
    candidate: dict[str, Any],
    candidate_raw: bytes,
    *,
    qualification_protocol_path: Path,
    protocol_freeze_report_path: Path,
    reviewed_pairing_path: Path,
    evidence_root: Path,
) -> None:
    with tempfile.TemporaryDirectory(prefix="civitas-j1-roster-review-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        output = root / "roster.json"
        report_path = root / "intake-report.json"
        report = prepare_roster_draft(
            roster_id=candidate["roster_id"],
            qualification_protocol_path=qualification_protocol_path,
            protocol_freeze_report_path=protocol_freeze_report_path,
            reviewed_pairing_path=reviewed_pairing_path,
            evidence_root=evidence_root,
            output_path=output,
            report_path=report_path,
        )
        if not report["passed"] or output.read_bytes() != candidate_raw:
            raise ValueError(
                "independent Evidence intake does not reproduce candidate roster"
            )


def _validate_manifest(
    manifest: dict[str, Any],
    raw: bytes,
    evidence_root: Path,
    reviewed_pairing: dict[str, Any],
) -> None:
    if (
        evidence_root.is_symlink()
        or not evidence_root.is_dir()
        or evidence_root.stat().st_mode & 0o077
    ):
        raise ValueError(
            "Evidence root is missing, symlinked, or permissions are too open"
        )
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ValueError("baseline/consent manifest schema invalid")
    body = {key: item for key, item in manifest.items() if key != "manifest_sha256"}
    if manifest.get("manifest_sha256") != canonical_sha256(body):
        raise ValueError("baseline/consent manifest hash invalid")
    if manifest.get("reviewed_pairing_sha256") != reviewed_pairing.get(
        "reviewed_pairing_sha256"
    ):
        raise ValueError("baseline/consent manifest pairing mismatch")
    counts = manifest.get("counts", {})
    if counts != {
        "cognitive_baselines": 20,
        "participant_consents": 40,
        "participant_packets": 40,
        "total_json_artifacts": 220,
    }:
        raise ValueError("baseline/consent manifest counts invalid")
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) != 220:
        raise ValueError("baseline/consent manifest inventory invalid")
    resolved_root = evidence_root.resolve()
    seen: set[Path] = set()
    for reference in artifacts:
        path = Path(str(reference.get("path", "")))
        resolved = path.resolve()
        try:
            resolved.relative_to(resolved_root)
        except ValueError as error:
            raise ValueError("manifest artifact escapes Evidence root") from error
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            raise ValueError(f"manifest artifact unsafe: {path}")
        if resolved in seen or hashlib.sha256(
            path.read_bytes()
        ).hexdigest() != reference.get("sha256"):
            raise ValueError(f"manifest artifact hash/uniqueness invalid: {path}")
        seen.add(resolved)
    if not raw:
        raise ValueError("baseline/consent manifest is empty")


def _validate_intake_report(
    report: dict[str, Any],
    candidate_hash: str,
    protocol_hash: str,
    pairing: dict[str, Any],
) -> None:
    if report.get("passed") is not True or report.get("failure_reasons") != []:
        raise ValueError("participant Evidence intake report not passed")
    if report.get("counts") != {
        "complete_pairs": 20,
        "missing_participants": 0,
        "required_pairs": 20,
        "required_participants": 40,
        "valid_participants": 40,
    }:
        raise ValueError("participant Evidence intake counts invalid")
    if (
        report.get("qualification_protocol", {}).get("canonical_sha256")
        != protocol_hash
    ):
        raise ValueError("participant Evidence intake protocol mismatch")
    if report.get("reviewed_pairing", {}).get("reviewed_pairing_sha256") != pairing.get(
        "reviewed_pairing_sha256"
    ):
        raise ValueError("participant Evidence intake pairing mismatch")
    if report.get("roster_draft", {}).get("sha256") != candidate_hash:
        raise ValueError("participant Evidence intake roster hash mismatch")


def _validate_stopped_isolation(evidence_root: Path) -> None:
    isolation_ids = [
        read_json_object(path)["isolation_id"]
        for path in sorted(evidence_root.glob("*.isolation.json"))
    ]
    if len(isolation_ids) != 40:
        raise ValueError("exactly 40 isolation artifacts are required")
    result = subprocess.run(
        ["docker", "inspect", *isolation_ids],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(
            f"participant isolation inspect failed: {result.stderr.strip()}"
        )
    inspected = json.loads(result.stdout)
    if len(inspected) != 40 or any(
        item.get("State", {}).get("Running") is not False for item in inspected
    ):
        raise ValueError("all 40 participant containers must remain stopped")


def _validate_freeze_report(report: dict[str, Any], protocol_hash: str) -> None:
    if not (
        report.get("passed") is True
        and report.get("qualification_protocol_sha256") == protocol_hash
        and report.get("readiness", {}).get("qualification_protocol_frozen") is True
    ):
        raise ValueError("qualification protocol freeze report invalid")


def _validate_reviewer_configuration(
    profile: dict[str, Any], values: dict[str, Any]
) -> None:
    key = profile["pkcs11_key"]
    expected = {
        "module_path": str(Path(values["module_path"]).resolve()),
        "token_label": values["token_label"],
        "key_label": values["key_label"],
        "key_id_hex": str(values["key_id_hex"]).lower(),
    }
    failures = [
        field
        for field, expected_value in expected.items()
        if key.get(field) != expected_value
    ]
    if failures:
        raise ValueError(f"reviewer PKCS#11 configuration mismatch: {failures}")
    if (
        key.get("module_sha256")
        != hashlib.sha256(Path(expected["module_path"]).read_bytes()).hexdigest()
    ):
        raise ValueError("reviewer PKCS#11 module hash mismatch")


def _validate_approval_metadata(
    reviewed_at: str,
    authorization_id: str,
    statement: str,
    statement_hash: str,
    candidate_hash: str,
) -> None:
    try:
        parsed = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("reviewed_at must be RFC3339") from error
    if parsed.tzinfo is None or not authorization_id.strip():
        raise ValueError("roster review approval metadata incomplete")
    expected = (
        "I disclose all reviewer conflicts, affirm independent judgment, and approve "
        f"J1-D roster artifact {candidate_hash} for roster binding only. This approval "
        "does not authorize provider, model, agent, backend, ledger, or experiment execution."
    )
    if (
        statement != expected
        or hashlib.sha256(statement.encode("utf-8")).hexdigest() != statement_hash
    ):
        raise ValueError("roster review authorization statement/hash mismatch")


def _validate_basic_metadata(review_id: str, agent_revision: str) -> None:
    if not review_id.strip():
        raise ValueError("roster review id missing")
    revision = agent_revision.lower()
    if not 7 <= len(revision) <= 64 or any(
        char not in "0123456789abcdef" for char in revision
    ):
        raise ValueError("roster review Agent revision invalid")


def _expected_stack(protocol: dict[str, Any]) -> dict[str, str]:
    frozen = protocol["frozen_stack"]
    return {
        "provider_id": frozen["provider_id"],
        "model_id": frozen["model_id"],
        "budget_id": frozen["budget_id"],
        "corpus_id": protocol["task_corpus"]["corpus_id"],
        "verifier_id": frozen["verifier_id"],
    }


def _false_execution_boundary() -> dict[str, bool]:
    return {
        "roster_binding_approved": False,
        "provider_api_call_allowed": False,
        "model_invocation_allowed": False,
        "agent_execution_allowed": False,
        "backend_fact_append_allowed": False,
        "ledger_append_allowed": False,
        "single_use_authorization_issued": False,
        "controlled_experiment_execution_ready": False,
    }


def _read_private(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError(
            f"private JSON artifact unreadable or permissions too open: {path}"
        )
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"private JSON artifact must be an object: {path}")
    return value, raw


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--candidate-roster", type=Path, required=True)
    parser.add_argument("--qualification-protocol", type=Path, required=True)
    parser.add_argument("--protocol-freeze-report", type=Path, required=True)
    parser.add_argument("--reviewed-pairing", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--intake-report", type=Path, required=True)
    parser.add_argument("--reviewer-identity-profile", type=Path, required=True)
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--token-label", required=True)
    parser.add_argument("--key-label", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--agent-revision", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--preflight-report", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--approve-exact-roster", action="store_true")
    parser.add_argument("--conflicts-disclosed", action="store_true")
    parser.add_argument("--independent-judgment", action="store_true")
    parser.add_argument("--reviewed-at")
    parser.add_argument("--authorization-id")
    parser.add_argument("--authorization-statement")
    parser.add_argument("--authorization-statement-sha256")
    parser.add_argument("--pin-file", type=Path)
    args = parser.parse_args()
    values = {
        "review_id": args.review_id,
        "candidate_roster_path": args.candidate_roster,
        "qualification_protocol_path": args.qualification_protocol,
        "protocol_freeze_report_path": args.protocol_freeze_report,
        "reviewed_pairing_path": args.reviewed_pairing,
        "evidence_root": args.evidence_root,
        "manifest_path": args.manifest,
        "intake_report_path": args.intake_report,
        "reviewer_profile_path": args.reviewer_identity_profile,
        "module_path": args.module,
        "token_label": args.token_label,
        "key_label": args.key_label,
        "key_id_hex": args.key_id,
        "agent_revision": args.agent_revision,
        "output_root": args.output_root,
    }
    try:
        preflight = preflight_roster_review(**values)
        write_private_json(args.preflight_report, preflight)
        if args.preflight_only:
            print(json.dumps(preflight, ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if not (
            args.approve_exact_roster
            and args.conflicts_disclosed
            and args.independent_judgment
        ):
            raise ValueError(
                "explicit exact-roster approval, conflict disclosure, and independent judgment are required"
            )
        required = (
            args.reviewed_at,
            args.authorization_id,
            args.authorization_statement,
            args.authorization_statement_sha256,
        )
        if any(item is None for item in required):
            raise ValueError("signed roster review approval metadata is incomplete")
        pin = read_pin(args.pin_file)
        try:
            report = approve_roster(
                **values,
                reviewed_at=str(args.reviewed_at),
                authorization_id=str(args.authorization_id),
                authorization_statement=str(args.authorization_statement),
                authorization_statement_sha256=str(args.authorization_statement_sha256),
                pin=pin,
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
            "state": "blocked_roster_review_operation",
            "error_class": type(error).__name__,
            "error": str(error),
            "pin_recorded": False,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
