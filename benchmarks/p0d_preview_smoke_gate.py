"""Run P0-D local/private preview smoke gate.

P0-D consumes a passed P0-C controlled task-pool execution summary. It verifies
artifact integrity, checks backend read-model visibility for the delivered task,
and writes an owner/audit review packet. It does not contact VM targets, deploy,
open public ingress, mutate source/Git, transition to production, or write
production receipts.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from benchmarks.i_gate_evidence import artifact_ref, check, object_value, read_json_object, sha256_file, write_json_object
from benchmarks.p0c_controlled_task_pool_execution import CHAIN_SCHEMA as P0C_EXECUTION_SCHEMA
from benchmarks.p0c_controlled_task_pool_execution import NO_PRODUCTION_SCHEMA, PREVIEW_SCHEMA, ROLLBACK_OR_ABORT_SCHEMA, TASK_RECEIPT_SCHEMA

try:
    from scripts.civitasos_contracts.auth import CivitasHttpClient
except ModuleNotFoundError:  # pragma: no cover
    from civitasos_contracts.auth import CivitasHttpClient  # type: ignore

CHAIN_SCHEMA = "p0d-preview-smoke-chain:v1"
INTEGRITY_SCHEMA = "p0d-preview-artifact-integrity:v1"
BACKEND_SMOKE_SCHEMA = "p0d-backend-smoke-receipt:v1"
OWNER_AUDIT_PACKET_SCHEMA = "p0d-owner-audit-review-packet:v1"
DEFAULT_BACKEND_URL = "http://127.0.0.1:8099"
DEFAULT_SERVICE_ID = "p0d_preview_smoke_gate"
REQUIRED_SCOPES = {"pool:read", "audit:read"}


class JsonClient(Protocol):
    def healthz(self) -> Any: ...

    def get(self, path: str) -> Any: ...

    def auth_report(self) -> dict[str, Any]: ...


class HttpJsonClient(CivitasHttpClient):
    def __init__(self, base_url: str, *, service_token_secret: str, service_id: str, service_scopes: list[str]) -> None:
        super().__init__(
            base_url,
            service_token_secret=service_token_secret,
            service_id=service_id,
            service_scopes=service_scopes,
            require_service_token=True,
            demo_login_agent_id=None,
            required_service_token_error="P0-D preview smoke requires service-token auth; demo-login is forbidden",
            timeout=30,
        )

    def healthz(self) -> Any:
        return self.get("/healthz")

    def auth_report(self) -> dict[str, Any]:
        return self.auth_session().report()


def run_gate(*, p0c_execution_summary_path: Path, output_root: Path, client: JsonClient, backend_url: str = DEFAULT_BACKEND_URL, operator_id: str = "operator-cc") -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "artifact_integrity": output_root / "p0d_preview_artifact_integrity.json",
        "backend_smoke": output_root / "p0d_backend_smoke_receipt.json",
        "owner_audit_review_packet": output_root / "p0d_owner_audit_review_packet.json",
        "summary": output_root / "p0d_preview_smoke_chain_summary.json",
    }
    integrity = write_artifact_integrity_report(p0c_execution_summary_path=p0c_execution_summary_path, output=artifacts["artifact_integrity"])
    backend = write_backend_smoke_receipt(
        p0c_execution_summary_path=p0c_execution_summary_path,
        integrity_report_path=artifacts["artifact_integrity"],
        output=artifacts["backend_smoke"],
        client=client,
        backend_url=backend_url,
    )
    review = write_owner_audit_review_packet(
        p0c_execution_summary_path=p0c_execution_summary_path,
        integrity_report_path=artifacts["artifact_integrity"],
        backend_smoke_path=artifacts["backend_smoke"],
        output=artifacts["owner_audit_review_packet"],
        operator_id=operator_id,
    )
    reports = [integrity, backend, review]
    passed = all(report.get("passed") is True for report in reports)
    summary = {
        "schema_version": CHAIN_SCHEMA,
        "passed": passed,
        "failure_reasons": _failures(reports),
        "checked_at": _now(),
        "source_artifacts": {"p0c_execution_summary": artifact_ref(p0c_execution_summary_path)},
        "artifacts": {name: artifact_ref(path) for name, path in artifacts.items() if name != "summary"},
        "task_id": integrity.get("task_id"),
        "readiness": {
            "state": "p0d_preview_smoke_passed" if passed else "blocked_p0d_preview_smoke",
            "p0d_preview_smoke_complete": passed,
            "owner_audit_review_required": True,
            "p0e_rollback_drill_ready": passed and review.get("review_packet", {}).get("callback_sink_review_required") is False,
            "production_transition_allowed": False,
        },
        "boundary": _boundary(
            service_token_used=backend.get("checks", {}).get("service_token_used") is True,
            preview_artifact_verified=integrity.get("checks", {}).get("preview_passed") is True,
            backend_read_model_checked=backend.get("checks", {}).get("operator_read_model_present") is True,
            audit_endpoint_checked=backend.get("checks", {}).get("audit_events_endpoint_present") is True and backend.get("checks", {}).get("audit_log_endpoint_present") is True,
            owner_audit_review_packet_written=review.get("passed") is True,
        ),
        "non_claims": _non_claims(),
    }
    write_json_object(artifacts["summary"], summary)
    return summary


def write_artifact_integrity_report(*, p0c_execution_summary_path: Path, output: Path) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    try:
        summary = read_json_object(p0c_execution_summary_path)
    except Exception as exc:  # noqa: BLE001
        report = _report(INTEGRITY_SCHEMA, False, [f"p0c_execution_summary_unreadable:{exc}"], checks)
        write_json_object(output, report)
        return report
    refs = object_value(summary.get("artifacts"))
    task_receipt = _read_verified_ref(refs.get("task_pool_execution_receipt"), checks, failures, "task_pool_execution_receipt")
    preview = _read_verified_ref(refs.get("preview_artifact"), checks, failures, "preview_artifact")
    no_prod = _read_verified_ref(refs.get("no_production_attestation"), checks, failures, "no_production_attestation")
    rollback = _read_verified_ref(refs.get("rollback_or_abort_ref"), checks, failures, "rollback_or_abort_ref")
    consumption = _read_verified_ref(refs.get("authorization_consumption"), checks, failures, "authorization_consumption")
    boundary = object_value(summary.get("boundary"))
    readiness = object_value(summary.get("readiness"))
    task_id = str(summary.get("task_id") or task_receipt.get("task_id") or "")
    check(checks, failures, "p0c_execution_summary_passed", summary.get("schema_version") == P0C_EXECUTION_SCHEMA and summary.get("passed") is True)
    check(checks, failures, "p0c_execution_performed", readiness.get("p0c_execution_performed") is True)
    check(checks, failures, "task_receipt_passed", task_receipt.get("schema_version") == TASK_RECEIPT_SCHEMA and task_receipt.get("passed") is True)
    check(checks, failures, "task_delivered", object_value(task_receipt.get("final_task")).get("status") in {"Delivered", "Completed"})
    check(checks, failures, "preview_passed", preview.get("schema_version") == PREVIEW_SCHEMA and preview.get("passed") is True)
    check(checks, failures, "no_production_attestation_passed", no_prod.get("schema_version") == NO_PRODUCTION_SCHEMA and no_prod.get("passed") is True)
    check(checks, failures, "rollback_or_abort_ref_passed", rollback.get("schema_version") == ROLLBACK_OR_ABORT_SCHEMA and rollback.get("passed") is True)
    check(checks, failures, "authorization_consumption_present", consumption.get("schema_version") == "p0c-one-time-authorization-consumption:v1")
    check(checks, failures, "no_demo_login", boundary.get("demo_login_used") is False)
    check(checks, failures, "no_vm_contact", boundary.get("vm_contact_performed") is False)
    check(checks, failures, "no_deploy", boundary.get("deploy_performed") is False)
    check(checks, failures, "no_production_receipt", boundary.get("production_receipt_write_allowed") is False)
    passed = _passed(checks, failures)
    report = {
        "schema_version": INTEGRITY_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "task_id": task_id,
        "source_artifacts": {"p0c_execution_summary": artifact_ref(p0c_execution_summary_path)},
        "verified_artifacts": {name: refs.get(name) for name in refs},
        "p0c_boundary": boundary,
    }
    write_json_object(output, report)
    return report


def write_backend_smoke_receipt(*, p0c_execution_summary_path: Path, integrity_report_path: Path, output: Path, client: JsonClient, backend_url: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    integrity = read_json_object(integrity_report_path)
    task_id = str(integrity.get("task_id") or "")
    auth_report: dict[str, Any] = {}
    endpoint_results: dict[str, Any] = {}
    task: dict[str, Any] = {}
    operator_read_model: dict[str, Any] = {}
    try:
        client.healthz()
        endpoint_results["healthz"] = {"passed": True}
    except Exception as exc:  # noqa: BLE001
        endpoint_results["healthz"] = {"passed": False, "error": str(exc)}
        failures.append(f"healthz_failed:{exc}")
    try:
        auth_report = client.auth_report()
    except Exception as exc:  # noqa: BLE001
        failures.append(f"service_token_auth_failed:{exc}")
    for name, path in _read_endpoints(task_id):
        try:
            value = client.get(path)
            endpoint_results[name] = {"passed": isinstance(value, (dict, list)) or value is None, "path": path, "body": value}
            if name == "task_readback" and isinstance(value, dict):
                task = object_value(value.get("task"))
            if name == "operator_read_model" and isinstance(value, dict):
                operator_read_model = value
        except Exception as exc:  # noqa: BLE001
            endpoint_results[name] = {"passed": False, "path": path, "error": str(exc)}
            failures.append(f"endpoint_failed:{name}:{exc}")
    scopes = set(str(item) for item in auth_report.get("scopes", []) if str(item))
    check(checks, failures, "artifact_integrity_passed", integrity.get("passed") is True)
    check(checks, failures, "service_token_used", auth_report.get("auth_method") in {"service_token", "service-token"})
    check(checks, failures, "token_not_recorded", auth_report.get("token_recorded") is False)
    check(checks, failures, "demo_login_not_used", auth_report.get("auth_method") not in {"demo_login", "demo-login"})
    check(checks, failures, "production_not_allowed", auth_report.get("production_allowed") is False)
    check(checks, failures, "required_scopes_present", REQUIRED_SCOPES.issubset(scopes))
    check(checks, failures, "backend_url_private", _is_private_preview_url(backend_url))
    check(checks, failures, "task_readback_delivered", task.get("id") == task_id and task.get("status") in {"Delivered", "Completed"})
    check(checks, failures, "task_has_output", task.get("output") not in (None, "", {}, []))
    check(checks, failures, "operator_read_model_present", bool(operator_read_model))
    check(checks, failures, "audit_events_endpoint_present", endpoint_results.get("audit_events", {}).get("passed") is True)
    check(checks, failures, "audit_log_endpoint_present", endpoint_results.get("security_audit_log", {}).get("passed") is True)
    passed = _passed(checks, failures)
    report = {
        "schema_version": BACKEND_SMOKE_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "checked_at": _now(),
        "backend_url": backend_url,
        "task_id": task_id,
        "source_artifacts": {
            "p0c_execution_summary": artifact_ref(p0c_execution_summary_path),
            "artifact_integrity": artifact_ref(integrity_report_path),
        },
        "auth_context": {key: value for key, value in auth_report.items() if key != "token"},
        "endpoint_results": _compact_endpoint_results(endpoint_results),
        "task_readback": _task_summary(task),
        "operator_read_model_summary": _operator_read_model_summary(operator_read_model),
        "callback_sink_evidence_present": False,
        "boundary": _boundary(
            service_token_used=auth_report.get("auth_method") in {"service_token", "service-token"},
            backend_read_model_checked=checks.get("operator_read_model_present") is True,
            audit_endpoint_checked=checks.get("audit_events_endpoint_present") is True and checks.get("audit_log_endpoint_present") is True,
        ),
    }
    write_json_object(output, report)
    return report


def write_owner_audit_review_packet(*, p0c_execution_summary_path: Path, integrity_report_path: Path, backend_smoke_path: Path, output: Path, operator_id: str) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    integrity = read_json_object(integrity_report_path)
    backend = read_json_object(backend_smoke_path)
    p0c_summary = read_json_object(p0c_execution_summary_path)
    selected_task = object_value(p0c_summary.get("selected_task"))
    check(checks, failures, "artifact_integrity_passed", integrity.get("passed") is True)
    check(checks, failures, "backend_smoke_passed", backend.get("passed") is True)
    check(checks, failures, "operator_id_present", bool(str(operator_id).strip()))
    review_items = []
    if backend.get("callback_sink_evidence_present") is not True:
        review_items.append({
            "item": "callback_sink_absent",
            "severity": "medium",
            "decision_required": "accept_task_pool_delivered_state_for_local_preview_or_require_real_audit_callback_sink_before_vm_preview",
        })
    review_items.append({
        "item": "production_boundary",
        "severity": "high",
        "decision_required": "confirm_no_production_transition_and_no_production_receipt",
    })
    passed = _passed(checks, failures)
    packet = {
        "schema_version": OWNER_AUDIT_PACKET_SCHEMA,
        "passed": passed,
        "failure_reasons": failures,
        "checks": checks,
        "created_at": _now(),
        "operator_id": operator_id,
        "source_artifacts": {
            "p0c_execution_summary": artifact_ref(p0c_execution_summary_path),
            "artifact_integrity": artifact_ref(integrity_report_path),
            "backend_smoke": artifact_ref(backend_smoke_path),
        },
        "review_packet": {
            "owner_id": selected_task.get("owner_id") or "product_owner",
            "audit_owner_id": selected_task.get("audit_owner_id") or "audit_owner",
            "rollback_owner_id": selected_task.get("rollback_owner_id") or "rollback_owner",
            "vm_target_ids": selected_task.get("vm_target_ids") or [],
            "decision_state": "owner_audit_review_required_before_vm_preview",
            "callback_sink_review_required": backend.get("callback_sink_evidence_present") is not True,
            "review_items": review_items,
        },
        "boundary": _boundary(
            service_token_used=object_value(backend.get("checks")).get("service_token_used") is True,
            preview_artifact_verified=object_value(integrity.get("checks")).get("preview_passed") is True,
            backend_read_model_checked=object_value(backend.get("checks")).get("operator_read_model_present") is True,
            audit_endpoint_checked=object_value(backend.get("checks")).get("audit_events_endpoint_present") is True and object_value(backend.get("checks")).get("audit_log_endpoint_present") is True,
            owner_audit_review_packet_written=passed,
        ),
    }
    write_json_object(output, packet)
    return packet


def _read_verified_ref(value: Any, checks: dict[str, bool], failures: list[str], label: str) -> dict[str, Any]:
    ref = object_value(value)
    path = Path(str(ref.get("path") or ""))
    expected_hash = str(ref.get("sha256") or "")
    check(checks, failures, f"{label}_path_present", path.is_file())
    if not path.is_file():
        return {}
    check(checks, failures, f"{label}_hash_valid", bool(expected_hash) and sha256_file(path) == expected_hash)
    return read_json_object(path)


def _read_endpoints(task_id: str) -> list[tuple[str, str]]:
    return [
        ("status", "/api/v1/status"),
        ("task_readback", f"/api/v1/a2a/pool/tasks/{task_id}"),
        ("pool_tasks", "/api/v1/a2a/pool/tasks"),
        ("pool_failures", "/api/v1/a2a/pool/failures?since=0&limit=100"),
        ("audit_events", "/api/v1/audit/events"),
        ("operator_read_model", "/api/v1/a2a/operator/read-model"),
        ("security_audit_log", "/api/v1/audit/log"),
    ]


def _compact_endpoint_results(results: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {}
    for name, result in results.items():
        body = result.get("body")
        compact[name] = {key: value for key, value in result.items() if key != "body"}
        if isinstance(body, dict):
            compact[name]["body_keys"] = sorted(body.keys())[:20]
            if isinstance(body.get("tasks"), list):
                compact[name]["task_count"] = len(body["tasks"])
            if isinstance(body.get("events"), list):
                compact[name]["event_count"] = len(body["events"])
        elif isinstance(body, list):
            compact[name]["item_count"] = len(body)
    return compact


def _task_summary(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": task.get("id"),
        "status": task.get("status"),
        "requester": task.get("requester"),
        "claimed_by": task.get("claimed_by"),
        "posted_at": task.get("posted_at"),
        "claimed_at": task.get("claimed_at"),
        "delivered_at": task.get("delivered_at"),
        "has_output": task.get("output") not in (None, "", {}, []),
        "wake_trace_present": isinstance(task.get("wake_trace"), dict),
        "contract_rejection_present": isinstance(task.get("contract_rejection"), dict),
    }


def _operator_read_model_summary(model: dict[str, Any]) -> dict[str, Any]:
    data = object_value(model.get("data")) or model
    summary = object_value(data.get("summary"))
    return {
        "schema_version": data.get("schema_version") or model.get("schema_version"),
        "summary_keys": sorted(summary.keys()) if summary else [],
        "task_count": summary.get("task_count"),
        "wake_trace_task_count": summary.get("wake_trace_task_count"),
        "contract_rejection_task_count": summary.get("contract_rejection_task_count"),
        "scope_denial_present": isinstance(data.get("scope_denial"), dict),
    }


def _is_private_preview_url(url: str) -> bool:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    if host.startswith("192.168.") or host.startswith("10."):
        return True
    parts = host.split(".")
    if len(parts) == 4 and parts[0] == "172":
        try:
            return 16 <= int(parts[1]) <= 31
        except ValueError:
            return False
    return False


def _boundary(**overrides: bool) -> dict[str, bool]:
    base = {
        "service_token_used": False,
        "demo_login_used": False,
        "preview_artifact_verified": False,
        "backend_read_model_checked": False,
        "audit_endpoint_checked": False,
        "owner_audit_review_packet_written": False,
        "vm_contact_performed": False,
        "source_tree_write_performed": False,
        "git_write_performed": False,
        "deploy_performed": False,
        "external_public_ingress_opened": False,
        "production_transition_allowed": False,
        "production_receipt_write_allowed": False,
    }
    base.update(overrides)
    return base


def _non_claims() -> list[str]:
    return [
        "p0d_preview_smoke_is_local_private_preview_only",
        "p0d_does_not_contact_vm_targets",
        "p0d_does_not_deploy",
        "p0d_does_not_modify_source_or_git",
        "p0d_does_not_write_production_receipt",
        "p0d_does_not_authorize_production_transition",
    ]


def _failures(reports: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for report in reports:
        values.extend(str(item) for item in report.get("failure_reasons", []))
    return sorted(set(values))


def _report(schema: str, passed: bool, failures: list[str], checks: dict[str, bool]) -> dict[str, Any]:
    return {"schema_version": schema, "passed": passed, "failure_reasons": failures, "checks": checks}


def _passed(checks: dict[str, bool], failures: list[str]) -> bool:
    return bool(checks) and all(checks.values()) and not failures


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_env_file(path: Path | None) -> dict[str, str]:
    if path is None or not path.is_file():
        return {}
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _service_secret(path: Path | None, explicit: str | None) -> str:
    if explicit:
        return explicit
    env = _read_env_file(path)
    return env.get("CIVITASOS_SERVICE_TOKEN_SECRET") or os.getenv("CIVITASOS_SERVICE_TOKEN_SECRET", "")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run P0-D local/private preview smoke gate")
    parser.add_argument("--p0c-execution-summary", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--service-token-env-file")
    parser.add_argument("--service-token-secret")
    parser.add_argument("--service-id", default=DEFAULT_SERVICE_ID)
    parser.add_argument("--operator-id", default="operator-cc")
    args = parser.parse_args()
    env_file = Path(args.service_token_env_file) if args.service_token_env_file else None
    secret = _service_secret(env_file, args.service_token_secret)
    if not secret:
        raise SystemExit("P0-D requires CIVITASOS_SERVICE_TOKEN_SECRET; demo-login is forbidden")
    scopes = ["pool:read", "audit:read"]
    client = HttpJsonClient(args.backend_url, service_token_secret=secret, service_id=args.service_id, service_scopes=scopes)
    summary = run_gate(
        p0c_execution_summary_path=Path(args.p0c_execution_summary),
        output_root=Path(args.output_root),
        client=client,
        backend_url=args.backend_url,
        operator_id=args.operator_id,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
