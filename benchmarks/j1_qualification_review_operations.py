"""Operate the human-bound J1-D qualification material review workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmarks.j1.controlled_comparison import write_private_json
from benchmarks.j1.qualification_review_operations import (
    REVIEW_DECISION_SCHEMA,
    assemble_review_receipt,
    build_review_receipt_body,
    build_review_request,
    sign_review_decision,
    validate_review_decision,
    validate_review_request,
)
from benchmarks.j1.qualification_reviewer_identity import (
    validate_reviewer_identity_profile,
)
from benchmarks.j1.qualification_review_receipt import (
    REQUIRED_CHECKS,
    review_signature_payload,
)


DEFAULT_MODULE = os.environ.get(
    "CIVITASOS_PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so"
)
REPORT_SCHEMA = "j1-qualification-material-review-operation:v1"


def prepare_request(
    *,
    corpus_path: Path,
    verifier_path: Path,
    verifier_source_path: Path,
    output_root: Path,
    request_id: str,
    created_at: str,
) -> dict[str, Any]:
    corpus, corpus_bytes = _read_json(corpus_path, require_private=True)
    verifier, verifier_bytes = _read_json(verifier_path, require_private=True)
    verifier_source_bytes = _read_bytes(verifier_source_path, require_private=False)
    request = build_review_request(
        request_id=request_id,
        created_at=created_at,
        corpus_path=str(corpus_path.resolve()),
        verifier_path=str(verifier_path.resolve()),
        verifier_source_path=str(verifier_source_path.resolve()),
        corpus=corpus,
        verifier=verifier,
        corpus_bytes=corpus_bytes,
        verifier_bytes=verifier_bytes,
        verifier_source_bytes=verifier_source_bytes,
    )
    output_root.mkdir(parents=True, exist_ok=True)
    output_root.chmod(0o700)
    request_path = output_root / "review-request.json"
    template_path = output_root / "review-decision.template.json"
    write_private_json(request_path, request)
    write_private_json(template_path, _decision_template(request))
    report = {
        "schema_version": REPORT_SCHEMA,
        "operation": "prepare",
        "passed": True,
        "state": "awaiting_independent_operator_decision",
        "request": _artifact(request_path),
        "decision_template": _artifact(template_path),
        "request_sha256": request["request_sha256"],
        "execution_boundary": _operation_boundary(),
    }
    write_private_json(output_root / "review-request-preparation-report.json", report)
    return report


def prepare_signature_payload(
    *, request_path: Path, decision_path: Path, output_path: Path
) -> dict[str, Any]:
    request, decision, bundle = _load_review_bundle(request_path, decision_path)
    failures = validate_review_decision(decision, request=request)
    if failures:
        raise ValueError(f"review decision invalid: {failures}")
    body = build_review_receipt_body(request, decision)
    payload = review_signature_payload(body)
    _write_private_bytes(output_path, payload)
    report = {
        "schema_version": REPORT_SCHEMA,
        "operation": "prepare_signature_payload",
        "passed": True,
        "state": "awaiting_non_exportable_signature",
        "review_request_sha256": request["request_sha256"],
        "payload": _artifact(output_path),
        "reviewer_did": decision["reviewer"]["did"],
        "signer_kind": decision["reviewer"]["signer_kind"],
        "candidate_scope_verified": bundle["request_validated"],
        "execution_boundary": _operation_boundary(),
    }
    _write_report(output_path, report)
    return report


def bind_reviewer_identity(
    *,
    request_path: Path,
    reviewer_identity_profile_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    if output_path.exists():
        raise ValueError(f"output already exists: {output_path}")
    request, _ = _load_request_bundle(request_path)
    profile, profile_bytes = _read_json(
        reviewer_identity_profile_path, require_private=True
    )
    profile_failures = validate_reviewer_identity_profile(profile)
    if profile_failures:
        raise ValueError(f"reviewer identity profile invalid: {profile_failures}")
    profile_sha256 = hashlib.sha256(profile_bytes).hexdigest()
    decision = _decision_template(request)
    profile_reviewer = profile["reviewer"]
    decision["reviewer"] = {
        "did": profile_reviewer["did"],
        "public_key_hex": profile_reviewer["public_key_hex"],
        "credential_version": profile_reviewer["credential_version"],
        "signer_kind": profile_reviewer["signer_kind"],
        "custody_provenance_sha256": profile_sha256,
        "signer_attestation_sha256": profile_sha256,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.chmod(0o700)
    write_private_json(output_path, decision)
    report = {
        "schema_version": REPORT_SCHEMA,
        "operation": "bind_reviewer_identity",
        "passed": True,
        "state": "reviewer_identity_bound_operator_material_review_required",
        "review_request_sha256": request["request_sha256"],
        "reviewer_did": profile_reviewer["did"],
        "reviewer_identity_profile": {
            "path": str(reviewer_identity_profile_path.resolve()),
            "sha256": profile_sha256,
        },
        "decision_template": _artifact(output_path),
        "readiness": {
            "reviewer_identity_bound": True,
            "operator_review_id_complete": False,
            "operator_decision_complete": False,
            "reviewed_at_complete": False,
            "independence_attested": False,
            "review_checklist_complete": False,
            "signature_payload_ready": False,
        },
        "execution_boundary": _operation_boundary(),
    }
    _write_report(output_path, report)
    return report


def run_review_preflight(
    *,
    request_path: Path,
    decision_path: Path,
    output_path: Path,
    module_path: str = DEFAULT_MODULE,
    token_label: str | None = None,
    key_label: str | None = None,
    key_id: str | None = None,
    reviewer_identity_profile_path: Path | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    diagnostics: list[str] = []
    request: dict[str, Any] = {}
    decision: dict[str, Any] = {}
    request_validated = False
    try:
        request, _ = _load_request_bundle(request_path)
        request_validated = True
    except (OSError, ValueError, KeyError) as error:
        failures.append("review_request_bundle_invalid")
        diagnostics.append(str(error))
    try:
        decision, _ = _read_json(decision_path, require_private=True)
    except (OSError, ValueError) as error:
        failures.append("review_decision_unreadable")
        diagnostics.append(str(error))
    decision_failures = (
        validate_review_decision(decision, request=request)
        if request_validated and decision
        else []
    )
    failures.extend(decision_failures)
    signer_kind = (
        decision.get("reviewer", {}).get("signer_kind")
        if isinstance(decision.get("reviewer"), dict)
        else None
    )
    signer_configuration = _signer_preflight(
        signer_kind=signer_kind,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id=key_id,
    )
    identity_profile = _identity_profile_preflight(
        profile_path=reviewer_identity_profile_path,
        decision=decision,
        signer_kind=signer_kind,
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id=key_id,
    )
    if request_validated and decision and not decision_failures:
        failures.extend(signer_configuration["failure_reasons"])
        failures.extend(identity_profile["failure_reasons"])
    failures = list(dict.fromkeys(failures))
    passed = not failures
    report = {
        "schema_version": REPORT_SCHEMA,
        "operation": "preflight",
        "passed": passed,
        "failure_reasons": failures,
        "diagnostics": diagnostics,
        "state": (
            "review_handoff_preflight_passed_signer_action_required"
            if passed
            else "blocked_independent_operator_review_handoff"
        ),
        "review_request_sha256": request.get("request_sha256"),
        "request_validated": request_validated,
        "decision_validated": request_validated
        and bool(decision)
        and not decision_failures,
        "decision": decision.get("decision"),
        "reviewer_did": (
            decision.get("reviewer", {}).get("did")
            if isinstance(decision.get("reviewer"), dict)
            else None
        ),
        "signer_preflight": signer_configuration,
        "reviewer_identity_profile": identity_profile,
        "readiness": {
            "candidate_scope_verified": request_validated,
            "operator_decision_complete": request_validated
            and bool(decision)
            and not decision_failures,
            "signature_payload_ready": passed,
            "hardware_identity_probe_required": passed
            and signer_kind == "pkcs11_ed25519",
            "external_signature_required": passed
            and signer_kind == "non_exportable_ed25519_callback",
            "signed_receipt_present": False,
            "material_review_gate_ready": False,
        },
        "execution_boundary": {
            **_operation_boundary(),
            "hardware_contact_performed": False,
            "pin_read": False,
            "signature_performed": False,
        },
    }
    write_private_json(output_path, report)
    return report


def sign_with_pkcs11(
    *,
    request_path: Path,
    decision_path: Path,
    output_path: Path,
    module_path: str,
    token_label: str,
    key_label: str,
    key_id: str,
    pin_file: Path | None,
    reviewer_identity_profile_path: Path,
) -> dict[str, Any]:
    from civitasos import Pkcs11Ed25519Signer
    from scripts.pkcs11_identity_probe import read_pin

    request, decision, bundle = _load_review_bundle(request_path, decision_path)
    if decision.get("reviewer", {}).get("signer_kind") != "pkcs11_ed25519":
        raise ValueError(
            "PKCS#11 operation requires reviewer signer_kind pkcs11_ed25519"
        )
    identity_profile = _identity_profile_preflight(
        profile_path=reviewer_identity_profile_path,
        decision=decision,
        signer_kind="pkcs11_ed25519",
        module_path=module_path,
        token_label=token_label,
        key_label=key_label,
        key_id=key_id,
    )
    if identity_profile["failure_reasons"]:
        raise ValueError(
            f"reviewer identity profile invalid: {identity_profile['failure_reasons']}"
        )
    pin = read_pin(pin_file)
    try:
        with Pkcs11Ed25519Signer(
            module_path,
            token_label,
            key_label,
            decision["reviewer"]["public_key_hex"],
            pin,
            key_id=key_id,
        ) as signer:
            receipt = sign_review_decision(
                request=request,
                decision=decision,
                signer=signer,
                **bundle["validation_inputs"],
            )
            key_reference = signer.key_reference
    finally:
        pin = ""
    write_private_json(output_path, receipt)
    report = _receipt_report(
        operation="sign_pkcs11",
        request=request,
        decision=decision,
        receipt_path=output_path,
    )
    report["key_reference"] = key_reference
    report["token_label"] = token_label
    report["key_label"] = key_label
    report["key_id"] = key_id.lower()
    report["reviewer_identity_profile"] = identity_profile["artifact"]
    _write_report(output_path, report)
    return report


def assemble_detached_signature(
    *,
    request_path: Path,
    decision_path: Path,
    signature_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    request, decision, bundle = _load_review_bundle(request_path, decision_path)
    if (
        decision.get("reviewer", {}).get("signer_kind")
        != "non_exportable_ed25519_callback"
    ):
        raise ValueError(
            "detached assembly requires reviewer signer_kind "
            "non_exportable_ed25519_callback"
        )
    signature = _read_signature(signature_path)
    receipt = assemble_review_receipt(
        request=request,
        decision=decision,
        signature=signature,
        **bundle["validation_inputs"],
    )
    write_private_json(output_path, receipt)
    report = _receipt_report(
        operation="assemble_detached_signature",
        request=request,
        decision=decision,
        receipt_path=output_path,
    )
    report["detached_signature_sha256"] = hashlib.sha256(signature).hexdigest()
    _write_report(output_path, report)
    return report


def _load_review_bundle(
    request_path: Path, decision_path: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    decision, _ = _read_json(decision_path, require_private=True)
    request, bundle = _load_request_bundle(request_path)
    return request, decision, bundle


def _load_request_bundle(
    request_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request, _ = _read_json(request_path, require_private=True)
    artifacts = request.get("candidate_artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("review request candidate_artifacts is invalid")
    try:
        corpus_path = Path(artifacts["corpus"]["path"])
        verifier_path = Path(artifacts["verifier"]["path"])
        verifier_source_path = Path(artifacts["verifier_source"]["path"])
    except (KeyError, TypeError) as error:
        raise ValueError("review request artifact paths are invalid") from error
    corpus, corpus_bytes = _read_json(corpus_path, require_private=True)
    verifier, verifier_bytes = _read_json(verifier_path, require_private=True)
    verifier_source_bytes = _read_bytes(verifier_source_path, require_private=False)
    validation_inputs = {
        "corpus": corpus,
        "verifier": verifier,
        "corpus_bytes": corpus_bytes,
        "verifier_bytes": verifier_bytes,
        "verifier_source_bytes": verifier_source_bytes,
    }
    failures = validate_review_request(request, **validation_inputs)
    if failures:
        raise ValueError(f"review request invalid: {failures}")
    return request, {
        "request_validated": True,
        "validation_inputs": validation_inputs,
    }


def _decision_template(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": REVIEW_DECISION_SCHEMA,
        "review_id": "REQUIRED_INDEPENDENT_REVIEW_ID",
        "review_request_sha256": request["request_sha256"],
        "decision": "REQUIRED_ALLOWED_DECISION",
        "reviewed_at": "REQUIRED_RFC3339_TIMESTAMP",
        "reviewer": {
            "did": "REQUIRED_DID_CIV_MAINNET_OR_TESTNET",
            "public_key_hex": "REQUIRED_ED25519_PUBLIC_KEY_HEX",
            "credential_version": 0,
            "signer_kind": "REQUIRED_ALLOWED_SIGNER_KIND",
            "custody_provenance_sha256": "REQUIRED_SHA256",
            "signer_attestation_sha256": "REQUIRED_SHA256",
        },
        "independence": {
            "independent_from_authoring": False,
            "conflicts_disclosed": False,
            "ai_assisted_authoring_disclosed": False,
        },
        "checklist": {name: False for name in sorted(REQUIRED_CHECKS)},
    }


def _read_json(path: Path, *, require_private: bool) -> tuple[dict[str, Any], bytes]:
    raw = _read_bytes(path, require_private=require_private)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"JSON artifact is invalid: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return value, raw


def _read_bytes(path: Path, *, require_private: bool) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"artifact must be a regular file: {path}")
        if require_private and metadata.st_uid != os.geteuid():
            raise ValueError(f"private artifact must be owned by current user: {path}")
        if require_private and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"private artifact permissions are too open: {path}")
        raw = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            raw.extend(chunk)
    finally:
        os.close(descriptor)
    if not raw:
        raise ValueError(f"artifact is empty: {path}")
    return bytes(raw)


def _read_signature(path: Path) -> bytes:
    raw = _read_bytes(path, require_private=False)
    stripped = raw.strip()
    if len(stripped) == 128:
        try:
            return bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            pass
    if len(raw) == 64:
        return raw
    raise ValueError("detached signature must be 64 raw bytes or 128 hex characters")


def _write_private_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_bytes(value)
    path.chmod(0o600)


def _write_report(output_path: Path, report: dict[str, Any]) -> None:
    write_private_json(
        output_path.with_suffix(output_path.suffix + ".report.json"), report
    )


def _receipt_report(
    *,
    operation: str,
    request: dict[str, Any],
    decision: dict[str, Any],
    receipt_path: Path,
) -> dict[str, Any]:
    return {
        "schema_version": REPORT_SCHEMA,
        "operation": operation,
        "passed": True,
        "state": "signed_review_receipt_ready_for_material_review_gate",
        "review_request_sha256": request["request_sha256"],
        "review_id": decision["review_id"],
        "reviewer_did": decision["reviewer"]["did"],
        "decision": decision["decision"],
        "receipt": _artifact(receipt_path),
        "private_key_exported": False,
        "execution_boundary": _operation_boundary(),
    }


def _artifact(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _operation_boundary() -> dict[str, bool]:
    return {
        "operator_decision_automated": False,
        "model_invocation_allowed": False,
        "agent_execution_allowed": False,
        "backend_fact_append_allowed": False,
        "ledger_append_allowed": False,
        "protocol_freeze_automatic": False,
    }


def _signer_preflight(
    *,
    signer_kind: Any,
    module_path: str,
    token_label: str | None,
    key_label: str | None,
    key_id: str | None,
) -> dict[str, Any]:
    failures: list[str] = []
    module = Path(module_path)
    module_ready: bool | None = None
    key_id_valid: bool | None = None
    token_label_configured: bool | None = None
    key_label_configured: bool | None = None
    module_path_value: str | None = None
    if signer_kind == "pkcs11_ed25519":
        module_path_value = module_path
        try:
            metadata = module.stat()
            module_ready = stat.S_ISREG(metadata.st_mode) and os.access(module, os.R_OK)
        except OSError:
            module_ready = False
        if not module_ready:
            failures.append("pkcs11_module_unreadable")
        token_label_configured = bool(str(token_label or "").strip())
        if not token_label_configured:
            failures.append("pkcs11_token_label_missing")
        key_label_configured = bool(str(key_label or "").strip())
        if not key_label_configured:
            failures.append("pkcs11_key_label_missing")
        key_id_text = str(key_id or "").strip().lower()
        key_id_valid = (
            bool(key_id_text)
            and len(key_id_text) % 2 == 0
            and all(char in "0123456789abcdef" for char in key_id_text)
        )
        if not key_id_valid:
            failures.append("pkcs11_key_id_invalid")
    elif signer_kind == "non_exportable_ed25519_callback":
        pass
    else:
        failures.append("reviewer_signer_kind_invalid")
    return {
        "signer_kind": signer_kind,
        "configuration_complete": not failures,
        "failure_reasons": failures,
        "pkcs11_module_path": (
            str(module.resolve()) if module_ready else module_path_value
        ),
        "pkcs11_module_readable": module_ready,
        "pkcs11_token_label_configured": token_label_configured,
        "pkcs11_key_label_configured": key_label_configured,
        "pkcs11_key_id_valid": key_id_valid,
        "hardware_contact_performed": False,
        "pin_read": False,
        "signature_performed": False,
    }


def _identity_profile_preflight(
    *,
    profile_path: Path | None,
    decision: dict[str, Any],
    signer_kind: Any,
    module_path: str,
    token_label: str | None,
    key_label: str | None,
    key_id: str | None,
) -> dict[str, Any]:
    if signer_kind != "pkcs11_ed25519":
        return {
            "required": False,
            "present": profile_path is not None,
            "validated": None,
            "failure_reasons": [],
            "artifact": None,
        }
    if profile_path is None:
        return {
            "required": True,
            "present": False,
            "validated": False,
            "failure_reasons": ["reviewer_identity_profile_required"],
            "artifact": None,
        }
    failures: list[str] = []
    try:
        profile, profile_bytes = _read_json(profile_path, require_private=True)
    except (OSError, ValueError) as error:
        return {
            "required": True,
            "present": True,
            "validated": False,
            "failure_reasons": ["reviewer_identity_profile_unreadable"],
            "diagnostic": str(error),
            "artifact": None,
        }
    failures.extend(validate_reviewer_identity_profile(profile))
    reviewer = decision.get("reviewer")
    reviewer_value = reviewer if isinstance(reviewer, dict) else {}
    profile_reviewer = profile.get("reviewer")
    profile_reviewer_value = (
        profile_reviewer if isinstance(profile_reviewer, dict) else {}
    )
    for field in ("did", "public_key_hex", "credential_version", "signer_kind"):
        if reviewer_value.get(field) != profile_reviewer_value.get(field):
            failures.append(f"reviewer_identity_profile_{field}_mismatch")
    profile_sha256 = hashlib.sha256(profile_bytes).hexdigest()
    for field in ("custody_provenance_sha256", "signer_attestation_sha256"):
        if reviewer_value.get(field) != profile_sha256:
            failures.append(f"reviewer_identity_profile_{field}_mismatch")
    key = profile.get("pkcs11_key")
    key_value = key if isinstance(key, dict) else {}
    expected_key = {
        "module_path": str(Path(module_path).resolve()),
        "token_label": token_label,
        "key_label": key_label,
        "key_id_hex": str(key_id or "").lower(),
    }
    for field, expected in expected_key.items():
        if key_value.get(field) != expected:
            failures.append(f"reviewer_identity_profile_{field}_mismatch")
    try:
        module_sha256 = hashlib.sha256(Path(module_path).read_bytes()).hexdigest()
    except OSError:
        module_sha256 = None
    if key_value.get("module_sha256") != module_sha256:
        failures.append("reviewer_identity_profile_module_hash_mismatch")
    failures = list(dict.fromkeys(failures))
    return {
        "required": True,
        "present": True,
        "validated": not failures,
        "failure_reasons": failures,
        "artifact": {
            "path": str(profile_path.resolve()),
            "sha256": profile_sha256,
        },
    }


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--corpus", type=Path, required=True)
    prepare.add_argument("--verifier", type=Path, required=True)
    prepare.add_argument("--verifier-source", type=Path, required=True)
    prepare.add_argument("--output-root", type=Path, required=True)
    prepare.add_argument("--request-id", required=True)
    prepare.add_argument("--created-at", default=None)

    payload = subparsers.add_parser("payload")
    payload.add_argument("--request", type=Path, required=True)
    payload.add_argument("--decision", type=Path, required=True)
    payload.add_argument("--output", type=Path, required=True)

    bind_reviewer = subparsers.add_parser("bind-reviewer")
    bind_reviewer.add_argument("--request", type=Path, required=True)
    bind_reviewer.add_argument("--reviewer-identity-profile", type=Path, required=True)
    bind_reviewer.add_argument("--output", type=Path, required=True)

    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--request", type=Path, required=True)
    preflight.add_argument("--decision", type=Path, required=True)
    preflight.add_argument("--output", type=Path, required=True)
    preflight.add_argument("--module", default=DEFAULT_MODULE)
    preflight.add_argument("--token-label")
    preflight.add_argument("--key-label")
    preflight.add_argument("--key-id", help="CKA_ID as hex")
    preflight.add_argument("--reviewer-identity-profile", type=Path)

    pkcs11 = subparsers.add_parser("sign-pkcs11")
    pkcs11.add_argument("--request", type=Path, required=True)
    pkcs11.add_argument("--decision", type=Path, required=True)
    pkcs11.add_argument("--output", type=Path, required=True)
    pkcs11.add_argument("--module", default=DEFAULT_MODULE)
    pkcs11.add_argument("--token-label", required=True)
    pkcs11.add_argument("--key-label", required=True)
    pkcs11.add_argument("--key-id", required=True, help="CKA_ID as hex")
    pkcs11.add_argument("--pin-file", type=Path)
    pkcs11.add_argument("--reviewer-identity-profile", type=Path, required=True)

    detached = subparsers.add_parser("assemble")
    detached.add_argument("--request", type=Path, required=True)
    detached.add_argument("--decision", type=Path, required=True)
    detached.add_argument("--signature", type=Path, required=True)
    detached.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    try:
        if args.command == "prepare":
            report = prepare_request(
                corpus_path=args.corpus,
                verifier_path=args.verifier,
                verifier_source_path=args.verifier_source,
                output_root=args.output_root,
                request_id=args.request_id,
                created_at=args.created_at or _timestamp(),
            )
        elif args.command == "payload":
            report = prepare_signature_payload(
                request_path=args.request,
                decision_path=args.decision,
                output_path=args.output,
            )
        elif args.command == "bind-reviewer":
            report = bind_reviewer_identity(
                request_path=args.request,
                reviewer_identity_profile_path=args.reviewer_identity_profile,
                output_path=args.output,
            )
        elif args.command == "preflight":
            report = run_review_preflight(
                request_path=args.request,
                decision_path=args.decision,
                output_path=args.output,
                module_path=args.module,
                token_label=args.token_label,
                key_label=args.key_label,
                key_id=args.key_id,
                reviewer_identity_profile_path=args.reviewer_identity_profile,
            )
        elif args.command == "sign-pkcs11":
            report = sign_with_pkcs11(
                request_path=args.request,
                decision_path=args.decision,
                output_path=args.output,
                module_path=args.module,
                token_label=args.token_label,
                key_label=args.key_label,
                key_id=args.key_id,
                pin_file=args.pin_file,
                reviewer_identity_profile_path=args.reviewer_identity_profile,
            )
        else:
            report = assemble_detached_signature(
                request_path=args.request,
                decision_path=args.decision,
                signature_path=args.signature,
                output_path=args.output,
            )
    except (OSError, ValueError, KeyError) as error:
        print(
            json.dumps(
                {
                    "schema_version": REPORT_SCHEMA,
                    "operation": args.command,
                    "passed": False,
                    "error": str(error),
                    "execution_boundary": _operation_boundary(),
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
