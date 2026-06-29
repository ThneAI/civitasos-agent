"""Bind a real external user identity and consent for PostH3 usage review.

PostH3-U consumes the PostH3-T external user usage review summary and validates
an external user's consent package. It binds identity through an SSH signature and
an identity-provider key proof, then writes an identity/consent receipt. It does
not authorize or execute external user usage, open ingress, start runtime workers,
contact VMs, deploy, access production data, or write source/Git state.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, sha256_json, sha256_text, write_json_object
from benchmarks.post_h3_external_user_usage_review_gate import (
    BOUNDARY_REPORT_SCHEMA as POST_H3T_BOUNDARY_REPORT_SCHEMA,
    CHAIN_SCHEMA as POST_H3T_SCHEMA,
    REVIEW_RECONCILIATION_SCHEMA as POST_H3T_RECONCILIATION_SCHEMA,
)

CHAIN_SCHEMA = "post-h3-external-user-identity-consent-chain:v1"
CONTEXT_SCHEMA = "post-h3u-post-h3t-context-validation:v1"
IDENTITY_RECORD_SCHEMA = "post-h3u-external-user-identity-record:v1"
CONSENT_RECEIPT_SCHEMA = "post-h3u-external-user-consent-receipt:v1"
BOUNDARY_REPORT_SCHEMA = "post-h3u-external-user-identity-consent-boundary-report:v1"

SIGNATURE_NAMESPACE = "civitasos-posth3-external-user-consent"
REQUIRED_FALSE_FLAGS = (
    "production_data_access_allowed",
    "source_write_allowed",
    "git_write_allowed",
    "deploy_allowed",
)
REMAINING_REQUIREMENTS_AFTER_U = (
    "production_grade_public_ingress_not_authorized",
    "sustained_runtime_expansion_not_authorized",
    "external_user_task_scope_not_bound",
    "external_user_monitoring_slo_not_bound",
    "external_user_rollback_abort_owner_not_bound",
)
NON_CLAIMS = (
    "post_h3u_binds_identity_and_consent_only",
    "post_h3u_does_not_authorize_external_user_usage",
    "post_h3u_does_not_execute_external_user_usage",
    "post_h3u_does_not_open_public_ingress",
    "post_h3u_does_not_start_runtime_workers",
    "post_h3u_does_not_execute_runtime_task",
    "post_h3u_does_not_contact_vm_targets",
    "post_h3u_does_not_deploy",
    "post_h3u_does_not_access_production_data",
    "post_h3u_does_not_write_source_or_git",
)


def run_gate(
    *,
    post_h3t_summary_path: Path,
    consent_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    identity_provider_keys_path: Path,
    output_root: Path,
    external_user_handle: str,
    signature_namespace: str = SIGNATURE_NAMESPACE,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "context_validation": output_root / "post_h3u_post_h3t_context_validation.json",
        "identity_record": output_root / "post_h3u_external_user_identity_record.json",
        "consent_receipt": output_root / "post_h3u_external_user_consent_receipt.json",
        "boundary_report": output_root / "post_h3u_external_user_identity_consent_boundary_report.json",
        "summary": output_root / "post_h3u_external_user_identity_consent_summary.json",
    }
    context = validate_post_h3t_context(post_h3t_summary_path, output=artifacts["context_validation"])
    identity = _write_identity_record(
        context=context,
        consent_path=consent_path,
        allowed_signers_path=allowed_signers_path,
        identity_provider_keys_path=identity_provider_keys_path,
        output=artifacts["identity_record"],
        external_user_handle=external_user_handle,
    )
    consent = _write_consent_receipt(
        context=context,
        identity_path=artifacts["identity_record"],
        consent_path=consent_path,
        signature_path=signature_path,
        allowed_signers_path=allowed_signers_path,
        output=artifacts["consent_receipt"],
        external_user_handle=external_user_handle,
        signature_namespace=signature_namespace,
    )
    boundary = _write_boundary_report(context=context, identity_path=artifacts["identity_record"], consent_path=artifacts["consent_receipt"], output=artifacts["boundary_report"])
    reports = [context, identity, consent, boundary]
    passed = all(report.get("passed") is True for report in reports)
    consent_fields = object_value(consent.get("consent_fields"))
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"post_h3t_summary": artifact_ref(post_h3t_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "external_user_identity_consent_id": consent.get("external_user_identity_consent_id"),
        "external_user_provider": consent_fields.get("external_user_provider"),
        "external_user_handle": consent_fields.get("external_user_handle"),
        "readiness": {
            "state": "post_h3_external_user_identity_consent_bound" if passed else "blocked_post_h3_external_user_identity_consent",
            "external_user_identity_and_consent_bound": passed,
            "external_user_usage_review_rerun_ready": passed,
            "external_user_usage_allowed": False,
            "external_user_usage_execution_ready": False,
            "external_public_ingress_opened": False,
            "runtime_workers_currently_running": False,
            "runtime_execution_performed": False,
            "production_runtime_receipt_write_allowed": False,
        },
        "remaining_requirements": [] if not passed else list(REMAINING_REQUIREMENTS_AFTER_U),
        "boundary": _boundary(
            context_validation_written=context.get("passed") is True,
            identity_record_written=identity.get("passed") is True,
            consent_receipt_written=consent.get("passed") is True,
            boundary_report_written=boundary.get("passed") is True,
            external_user_identity_and_consent_bound=passed,
            external_user_usage_review_rerun_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def validate_post_h3t_context(post_h3t_summary_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    try:
        summary = read_json_object(post_h3t_summary_path)
    except Exception as exc:  # noqa: BLE001
        return _write_optional(_report(CONTEXT_SCHEMA, False, [f"post_h3t_summary_unreadable:{exc}"], checks), output)
    artifacts = object_value(summary.get("artifacts"))
    reconciliation = _read_verified_ref(artifacts.get("review_reconciliation"), checks, failures, "post_h3t_review_reconciliation")
    boundary_report = _read_verified_ref(artifacts.get("boundary_report"), checks, failures, "post_h3t_boundary_report")
    _check_t_summary(summary, checks, failures)
    _check_t_reconciliation(reconciliation, checks, failures)
    _check_t_boundary_report(boundary_report, checks, failures)
    passed = _passed(checks, failures)
    report = {
        "schema_version": CONTEXT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "post_h3t_summary": summary,
        "review_reconciliation": reconciliation,
        "boundary_report": boundary_report,
        "source_artifacts": {"post_h3t_summary": artifact_ref(post_h3t_summary_path)},
        "boundary": _boundary(context_validation_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    return _write_optional(report, output)


def _write_identity_record(
    *,
    context: dict[str, Any],
    consent_path: Path,
    allowed_signers_path: Path,
    identity_provider_keys_path: Path,
    output: Path,
    external_user_handle: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    consent_fields = _parse_consent(consent_path)
    provider = str(consent_fields.get("external_user_provider") or "")
    consent_handle = str(consent_fields.get("external_user_handle") or "")
    allowed_key = _find_allowed_signer_key(allowed_signers_path, external_user_handle)
    provider_keys = _read_identity_provider_keys(identity_provider_keys_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "consent_file_present", consent_path.is_file())
    check(checks, failures, "external_user_handle_present", bool(external_user_handle.strip()))
    check(checks, failures, "consent_handle_matches", consent_handle == external_user_handle)
    check(checks, failures, "provider_supported", provider == "github")
    check(checks, failures, "allowed_signer_key_present", allowed_key != "")
    check(checks, failures, "identity_provider_keys_present", bool(provider_keys))
    check(checks, failures, "allowed_key_in_identity_provider_keys", allowed_key != "" and allowed_key in provider_keys)
    passed = _passed(checks, failures)
    record = {
        "schema_version": IDENTITY_RECORD_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "written_at": _now(),
        "identity_record_id": f"post-h3u-identity:{sha256_json([external_user_handle, allowed_key, artifact_ref(consent_path) if consent_path.is_file() else {}])[:24]}",
        "external_user_provider": provider,
        "external_user_handle": consent_handle,
        "public_key_sha256": sha256_text(allowed_key) if allowed_key else "",
        "proofs": {
            "allowed_signers": artifact_ref(allowed_signers_path) if allowed_signers_path.is_file() else {},
            "identity_provider_keys": artifact_ref(identity_provider_keys_path) if identity_provider_keys_path.is_file() else {},
            "consent": artifact_ref(consent_path) if consent_path.is_file() else {},
        },
        "readiness": {
            "external_user_identity_bound": passed,
            "external_user_consent_receipt_ready": passed,
            "external_user_usage_allowed": False,
        },
        "boundary": _boundary(identity_record_written=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, record)
    return record


def _write_consent_receipt(
    *,
    context: dict[str, Any],
    identity_path: Path,
    consent_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    output: Path,
    external_user_handle: str,
    signature_namespace: str,
) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    identity = read_json_object(identity_path)
    consent_fields = _parse_consent(consent_path)
    verification = _verify_ssh_signature(
        consent_path=consent_path,
        signature_path=signature_path,
        allowed_signers_path=allowed_signers_path,
        external_user_handle=external_user_handle,
        signature_namespace=signature_namespace,
    )
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "identity_record_passed", identity.get("passed") is True)
    check(checks, failures, "signature_verified", verification.get("verified") is True)
    _check_consent_fields(consent_fields, external_user_handle, checks, failures)
    passed = _passed(checks, failures)
    receipt = {
        "schema_version": CONSENT_RECEIPT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "verified_at": _now(),
        "external_user_identity_consent_id": f"post-h3u-consent:{sha256_json([artifact_ref(identity_path), artifact_ref(consent_path) if consent_path.is_file() else {}, artifact_ref(signature_path) if signature_path.is_file() else {}])[:24]}",
        "external_user_handle": external_user_handle,
        "signature_namespace": signature_namespace,
        "signature_verification": verification,
        "consent_fields": consent_fields,
        "source_artifacts": {
            "identity_record": artifact_ref(identity_path),
            "consent": artifact_ref(consent_path) if consent_path.is_file() else {},
            "signature": artifact_ref(signature_path) if signature_path.is_file() else {},
            "allowed_signers": artifact_ref(allowed_signers_path) if allowed_signers_path.is_file() else {},
        },
        "readiness": {
            "external_user_identity_and_consent_bound": passed,
            "external_user_usage_review_rerun_ready": passed,
            "external_user_usage_allowed": False,
        },
        "boundary": _boundary(consent_receipt_written=passed, external_user_identity_and_consent_bound=passed, external_user_usage_review_rerun_ready=passed),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, receipt)
    return receipt


def _write_boundary_report(*, context: dict[str, Any], identity_path: Path, consent_path: Path, output: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    failures: list[str] = []
    identity = read_json_object(identity_path)
    consent = read_json_object(consent_path)
    check(checks, failures, "context_passed", context.get("passed") is True)
    check(checks, failures, "identity_record_passed", identity.get("passed") is True)
    check(checks, failures, "consent_receipt_passed", consent.get("passed") is True)
    check(checks, failures, "usage_not_allowed", object_value(consent.get("readiness")).get("external_user_usage_allowed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BOUNDARY_REPORT_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "source_artifacts": {"identity_record": artifact_ref(identity_path), "consent_receipt": artifact_ref(consent_path)},
        "boundary": _boundary(
            boundary_report_written=passed,
            external_user_identity_and_consent_bound=passed,
            external_user_usage_review_rerun_ready=passed,
        ),
        "non_claims": list(NON_CLAIMS),
    }
    write_json_object(output, report)
    return report


def _check_t_summary(summary: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(summary.get("readiness"))
    check(checks, failures, "post_h3t_schema_valid", summary.get("schema_version") == POST_H3T_SCHEMA)
    check(checks, failures, "post_h3t_passed", summary.get("passed") is True)
    check(checks, failures, "usage_review_complete", readiness.get("external_user_usage_review_complete") is True)
    check(checks, failures, "usage_revision_required", readiness.get("external_user_usage_revision_required") is True)
    check(checks, failures, "usage_not_allowed", readiness.get("external_user_usage_allowed") is False)
    check(checks, failures, "usage_execution_not_ready", readiness.get("external_user_usage_execution_ready") is False)


def _check_t_reconciliation(reconciliation: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    readiness = object_value(reconciliation.get("readiness"))
    missing = reconciliation.get("missing_requirements") if isinstance(reconciliation.get("missing_requirements"), list) else []
    check(checks, failures, "t_reconciliation_schema_valid", reconciliation.get("schema_version") == POST_H3T_RECONCILIATION_SCHEMA)
    check(checks, failures, "t_reconciliation_passed", reconciliation.get("passed") is True)
    check(checks, failures, "t_revision_required", readiness.get("external_user_usage_revision_required") is True)
    check(checks, failures, "t_missing_identity_consent", "real_external_user_identity_and_consent_not_bound" in missing)


def _check_t_boundary_report(report: dict[str, Any], checks: dict[str, bool], failures: list[str]) -> None:
    boundary = object_value(report.get("boundary"))
    check(checks, failures, "t_boundary_schema_valid", report.get("schema_version") == POST_H3T_BOUNDARY_REPORT_SCHEMA and report.get("passed") is True)
    for key in ("external_public_ingress_opened", "runtime_workers_currently_running", "runtime_execution_performed", "vm_contact_performed", "deploy_performed", "production_data_accessed", "source_tree_write_performed", "git_write_performed"):
        check(checks, failures, f"t_boundary_no_{key}", boundary.get(key) is False)


def _check_consent_fields(fields: dict[str, str], external_user_handle: str, checks: dict[str, bool], failures: list[str]) -> None:
    check(checks, failures, "consent_provider_github", fields.get("external_user_provider") == "github")
    check(checks, failures, "consent_handle_matches", fields.get("external_user_handle") == external_user_handle)
    check(checks, failures, "consent_scope_present", bool(fields.get("consent_scope", "").strip()))
    check(checks, failures, "allowed_usage_scope_present", bool(fields.get("allowed_usage_scope", "").strip()) and fields.get("allowed_usage_scope") != "none")
    check(checks, failures, "max_external_users_one", _parse_int(fields.get("max_external_users")) == 1)
    check(checks, failures, "max_runtime_tasks_one", _parse_int(fields.get("max_runtime_tasks")) == 1)
    for flag in REQUIRED_FALSE_FLAGS:
        check(checks, failures, f"{flag}_false", _parse_bool(fields.get(flag)) is False)
    check(checks, failures, "valid_until_future", _parse_datetime(fields.get("valid_until_utc")) > datetime.now(timezone.utc))
    for key in ("withdrawal_path", "rollback_owner", "monitoring_owner", "audit_owner"):
        check(checks, failures, f"{key}_present", bool(fields.get(key, "").strip()))
    check(checks, failures, "confirmation_present", fields.get("confirmation") == "I confirm")


def _parse_consent(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            if line.strip() == "I confirm":
                fields["confirmation"] = "I confirm"
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key:
            fields[key] = value.strip()
    return fields


def _verify_ssh_signature(*, consent_path: Path, signature_path: Path, allowed_signers_path: Path, external_user_handle: str, signature_namespace: str) -> dict[str, Any]:
    if not consent_path.is_file() or not signature_path.is_file() or not allowed_signers_path.is_file():
        return {"verified": False, "returncode": 127, "stdout": "", "stderr": "missing signature input"}
    command = [
        "ssh-keygen",
        "-Y",
        "verify",
        "-f",
        str(allowed_signers_path),
        "-I",
        external_user_handle,
        "-n",
        signature_namespace,
        "-s",
        str(signature_path),
    ]
    result = subprocess.run(command, input=consent_path.read_bytes(), capture_output=True, check=False)
    return {
        "verified": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": result.stdout.decode("utf-8", errors="replace"),
        "stderr": result.stderr.decode("utf-8", errors="replace"),
    }


def _find_allowed_signer_key(path: Path, principal: str) -> str:
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if len(parts) < 3 or parts[0] != principal:
            continue
        return f"{parts[1]} {parts[2]}"
    return ""


def _read_identity_provider_keys(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, list):
        return {str(item.get("key", "")).strip() for item in value if isinstance(item, dict) and item.get("key")}
    if isinstance(value, dict) and isinstance(value.get("keys"), list):
        return {str(item).strip() for item in value["keys"]}
    return set()


def _parse_bool(value: str | None) -> bool | None:
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _parse_int(value: str | None) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _boundary(**overrides: bool) -> dict[str, bool]:
    boundary = {
        "context_validation_written": False,
        "identity_record_written": False,
        "consent_receipt_written": False,
        "boundary_report_written": False,
        "external_user_identity_and_consent_bound": False,
        "external_user_usage_review_rerun_ready": False,
        "external_user_usage_allowed": False,
        "external_public_ingress_opened": False,
        "runtime_workers_currently_running": False,
        "runtime_execution_performed": False,
        "vm_contact_performed": False,
        "deploy_performed": False,
        "production_data_accessed": False,
        "production_runtime_receipt_write_allowed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "secrets_recorded": False,
    }
    boundary.update(overrides)
    return boundary


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {"schema_version": schema, "passed": passed, "failure_reasons": failures, "checks": checks, "checked_at": _now(), "boundary": _boundary(), "non_claims": list(NON_CLAIMS)}


def _write_optional(report: dict[str, Any], output: Path | None) -> dict[str, Any]:
    if output is not None:
        write_json_object(output, report)
    return report


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    for report in reports:
        failures.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(failures))


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PostH3-U external user identity and consent gate")
    parser.add_argument("--post-h3t-summary", required=True, type=Path)
    parser.add_argument("--consent", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--allowed-signers", required=True, type=Path)
    parser.add_argument("--identity-provider-keys", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--external-user-handle", required=True)
    parser.add_argument("--signature-namespace", default=SIGNATURE_NAMESPACE)
    args = parser.parse_args()
    summary = run_gate(
        post_h3t_summary_path=args.post_h3t_summary,
        consent_path=args.consent,
        signature_path=args.signature,
        allowed_signers_path=args.allowed_signers,
        identity_provider_keys_path=args.identity_provider_keys,
        output_root=args.output_root,
        external_user_handle=args.external_user_handle,
        signature_namespace=args.signature_namespace,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
