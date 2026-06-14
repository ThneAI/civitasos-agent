#!/usr/bin/env python3
"""Beta-FE-10 frontend preview gate.

Consumes a FE-9 post-merge smoke receipt, checks a local/staging frontend
preview URL and backend read-model endpoints, then writes a preview receipt.
It does not push, open PRs, merge, deploy to production, execute production
runtime actions, or write production receipts.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
    from civitasos_contracts.auth import resolve_auth_session
    from civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_runtime_evidence,
    )
except ModuleNotFoundError:
    from scripts.civitasos_contracts.artifacts import artifact_ref, build_artifact_envelope
    from scripts.civitasos_contracts.auth import resolve_auth_session
    from scripts.civitasos_contracts.provenance import (
        build_git_release_provenance,
        build_runtime_evidence,
    )

FE9_SCHEMA = "beta-fe9-frontend-post-merge-smoke-receipt:v1"
RECEIPT_SCHEMA = "beta-fe10-frontend-preview-receipt:v1"
NON_CLAIMS = (
    "beta_fe10_preview_is_l1_controlled_pilot_only",
    "beta_fe10_preview_consumes_fe9_post_merge_smoke_receipt",
    "beta_fe10_preview_uses_local_or_staging_preview_only",
    "beta_fe10_preview_does_not_push_open_pr_merge_or_deploy",
    "beta_fe10_preview_does_not_claim_h3_production_readiness",
    "beta_fe10_preview_does_not_write_production_receipts",
)

READ_ENDPOINTS = (
    ("status", "GET", "/api/v1/status", False),
    # The browser client installs a fetch interceptor, so authenticated preview
    # smoke must exercise the same token-bearing read-model path.
    ("pool_tasks", "GET", "/api/v1/a2a/pool/tasks", True),
    ("pool_failures", "GET", "/api/v1/a2a/pool/failures?since=0&limit=100", True),
    ("audit_events", "GET", "/api/v1/audit/events", True),
    ("operator_read_model", "GET", "/api/v1/a2a/operator/read-model", True),
    ("security_audit_log", "GET", "/api/v1/audit/log", True),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-fe9-receipt", required=True)
    parser.add_argument("--frontend-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--frontend-url", required=True)
    parser.add_argument("--backend-url", required=True)
    parser.add_argument("--auth-mode", choices=("auto", "bearer-token", "service-token", "demo-login"), default="auto")
    parser.add_argument("--bearer-token")
    parser.add_argument("--bearer-token-file")
    parser.add_argument("--service-token-secret")
    parser.add_argument("--service-id", default="beta_fe10_preview_gate")
    parser.add_argument("--service-token-scope", action="append", default=[])
    parser.add_argument("--demo-login-agent-id", default="beta_fe10_preview_gate")
    parser.add_argument("--operator-id", default="local-operator-cc")
    parser.add_argument("--operator-authorization", default="current_chat_fe10_preview_gate_request")
    args = parser.parse_args(argv)
    report = run_preview_gate(
        source_fe9_receipt=Path(args.source_fe9_receipt),
        frontend_root=Path(args.frontend_root),
        output_root=Path(args.output_root),
        frontend_url=args.frontend_url,
        backend_url=args.backend_url,
        auth_mode=args.auth_mode,
        bearer_token=args.bearer_token,
        bearer_token_file=Path(args.bearer_token_file) if args.bearer_token_file else None,
        service_token_secret=args.service_token_secret,
        service_id=args.service_id,
        service_token_scopes=args.service_token_scope,
        demo_login_agent_id=args.demo_login_agent_id,
        operator_id=args.operator_id,
        operator_authorization=args.operator_authorization,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("passed") is True else 1


def run_preview_gate(
    *,
    source_fe9_receipt: Path,
    frontend_root: Path,
    output_root: Path,
    frontend_url: str,
    backend_url: str,
    auth_mode: str = "auto",
    bearer_token: str | None = None,
    bearer_token_file: Path | None = None,
    service_token_secret: str | None = None,
    service_id: str = "beta_fe10_preview_gate",
    service_token_scopes: list[str] | None = None,
    demo_login_agent_id: str = "beta_fe10_preview_gate",
    operator_id: str = "local-operator-cc",
    operator_authorization: str = "current_chat_fe10_preview_gate_request",
) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    fe9 = _read_json(source_fe9_receipt, failures, "FE-9 post-merge smoke receipt")
    _validate_fe9(fe9, failures)
    _validate_operator_authorization(operator_id, operator_authorization, failures)
    _validate_frontend_checkout(frontend_root, fe9, failures)
    frontend_url = frontend_url.rstrip("/")
    backend_url = backend_url.rstrip("/")
    if not _is_private_preview_url(frontend_url):
        failures.append("frontend_url must be local/private preview URL")
    if not _is_private_preview_url(backend_url):
        failures.append("backend_url must be local/private preview URL")

    frontend_checks = [] if failures else _check_frontend(frontend_url, failures)
    backend_checks: list[dict[str, Any]] = []
    auth_report: dict[str, Any] | None = None
    token = ""
    if not failures:
        health = _http_json(f"{backend_url}/healthz", None)
        backend_checks.append({"name": "healthz", "url": f"{backend_url}/healthz", **health})
        if health.get("status_code") != 200:
            failures.append("backend /healthz must return 200")
        try:
            session = resolve_auth_session(
                base_url=backend_url,
                auth_mode=auth_mode,
                bearer_token=bearer_token,
                bearer_token_files=_bearer_token_files(bearer_token_file),
                bearer_token_env_values=(
                    os.getenv("CIVITASOS_FE10_BEARER_TOKEN"),
                    os.getenv("CIVITASOS_BEARER_TOKEN"),
                ),
                service_token_secret=(
                    service_token_secret
                    or os.getenv("CIVITASOS_FE10_SERVICE_TOKEN_SECRET")
                    or os.getenv("CIVITASOS_SERVICE_TOKEN_SECRET")
                ),
                service_id=service_id,
                service_scopes=service_token_scopes or _default_service_token_scopes(),
                demo_login_agent_id=demo_login_agent_id,
            )
            token = session.token
            auth_report = session.report()
        except (RuntimeError, ValueError) as exc:
            auth_report = {
                "passed": False,
                "auth_method": auth_mode.replace("-", "_"),
                "token": "",
                "token_recorded": False,
                "error": str(exc),
            }
            failures.append(f"backend auth bootstrap failed for preview smoke: {auth_mode}")
        _validate_auth_boundary(auth_report, failures)
        for name, method, path, requires_auth in READ_ENDPOINTS:
            headers = {"Authorization": f"Bearer {token}"} if requires_auth and token else None
            result = _http_json(f"{backend_url}{path}", headers, method=method)
            backend_checks.append({"name": name, "url": f"{backend_url}{path}", "requires_auth": requires_auth, **result})
            if result.get("status_code") != 200:
                failures.append(f"backend read endpoint failed: {name}")
            if result.get("json_object") is not True:
                failures.append(f"backend read endpoint must return JSON object: {name}")

    source_ref = artifact_ref(source_fe9_receipt) if source_fe9_receipt.is_file() else None
    auth_method = str((auth_report or {}).get("auth_method") or "none")
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "artifact_envelope": build_artifact_envelope(
            artifact_kind="receipt",
            plane="runtime",
            schema_version=RECEIPT_SCHEMA,
            artifact_id=f"fe10-preview:{_ref_digest(source_ref)[:16]}",
            subject_id=f"frontend-preview:{frontend_root.name}",
            producer="beta_fe10_frontend_preview_gate",
            source_refs=[source_ref] if source_ref else [],
            scope="local_or_private_frontend_preview",
        ),
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe10_frontend_preview_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe9_receipt": source_ref,
        "frontend_root": str(frontend_root),
        "frontend_url": frontend_url,
        "backend_url": backend_url,
        "preview_scope": "local_or_private_preview_only",
        "frontend_checks": frontend_checks,
        "backend_auth": auth_report,
        "backend_read_model_checks": backend_checks,
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "runtime_evidence": build_runtime_evidence(
            {"post_merge_smoke_receipt": source_ref},
            assertions={
                "frontend_check_count": len(frontend_checks),
                "backend_read_model_check_count": len(backend_checks),
                "auth_method": auth_method,
                "private_preview_url_enforced": True,
            },
        ),
        "release_provenance": build_git_release_provenance(
            {"source_post_merge_smoke_receipt": source_ref},
            actions_observed={"commit": True, "push": True, "pr": True, "merge": True},
            actions_performed_by_current_step={},
        ),
        "git_actions_performed": {"commit": False, "push": False, "pr": False, "merge": False, "deploy": False},
        "boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe10_frontend_preview_receipt.json", receipt)
    return receipt


def _check_frontend(frontend_url: str, failures: list[str]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    index = _http_text(frontend_url)
    checks.append({"name": "frontend_index", "url": frontend_url, **index})
    if index.get("status_code") != 200:
        failures.append("frontend preview index must return 200")
        return checks
    body = str(index.get("body_excerpt") or "")
    if "root" not in body and "static/js" not in body:
        failures.append("frontend preview index must look like React app shell")
    match = re.search(r'src="(/static/js/main\.[^"]+\.js)"', str(index.get("body_full") or ""))
    if match:
        js_url = f"{frontend_url}{match.group(1)}"
        js = _http_text(js_url)
        checks.append({"name": "frontend_main_js", "url": js_url, **{k: v for k, v in js.items() if k != "body_full"}})
        if js.get("status_code") != 200:
            failures.append("frontend main JS asset must return 200")
    else:
        failures.append("frontend index must reference main JS asset")
    return checks


def _default_service_token_scopes() -> list[str]:
    raw = os.getenv("CIVITASOS_FE10_SERVICE_TOKEN_SCOPES", "pool:read,audit:read")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _bearer_token_files(argument_file: Path | None) -> list[Path]:
    paths = [argument_file] if argument_file else []
    env_file = os.getenv("CIVITASOS_FE10_BEARER_TOKEN_FILE")
    if env_file:
        paths.append(Path(env_file))
    return paths


def _http_json(url: str, headers: dict[str, str] | None, method: str = "GET") -> dict[str, Any]:
    result = _http_text(url, headers, method=method)
    body = str(result.pop("body_full", ""))
    try:
        parsed = json.loads(body) if body else None
    except json.JSONDecodeError:
        parsed = None
    result["json_object"] = isinstance(parsed, dict)
    if isinstance(parsed, dict):
        result["top_level_keys"] = sorted(str(key) for key in parsed.keys())[:20]
    return result


def _http_text(url: str, headers: dict[str, str] | None = None, method: str = "GET") -> dict[str, Any]:
    request = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8", errors="replace")
            return {"status_code": response.status, "body_excerpt": body[:500], "body_full": body}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"status_code": exc.code, "body_excerpt": body[:500], "body_full": body, "error": exc.reason}
    except Exception as exc:
        return {"status_code": None, "body_excerpt": "", "body_full": "", "error": str(exc)}


def _validate_fe9(value: Any, failures: list[str]) -> None:
    if not isinstance(value, dict):
        failures.append("FE-9 receipt must be an object")
        return
    if value.get("schema_version") != FE9_SCHEMA:
        failures.append(f"FE-9 schema_version must be {FE9_SCHEMA}")
    if value.get("passed") is not True or value.get("decision") != "beta_fe9_frontend_post_merge_smoke_passed":
        failures.append("FE-9 receipt must be passed")
    if value.get("remote_head") != value.get("merge_commit") or value.get("local_head") != value.get("merge_commit"):
        failures.append("FE-9 local and remote heads must match merge commit")
    commands = value.get("verification_commands")
    if not isinstance(commands, list) or not commands or not all(isinstance(item, dict) and item.get("returncode") == 0 for item in commands):
        failures.append("FE-9 verification commands must all pass")
    boundary = value.get("boundary") if isinstance(value.get("boundary"), dict) else {}
    if boundary.get("post_merge_smoke_allowed") is not True:
        failures.append("FE-9 boundary.post_merge_smoke_allowed must be true")
    for field in ("deploy_allowed", "production_runtime_execution_allowed", "production_receipt_write_allowed"):
        if boundary.get(field) is not False:
            failures.append(f"FE-9 boundary.{field} must be false")
    h3 = value.get("h3_boundary") if isinstance(value.get("h3_boundary"), dict) else {}
    if h3.get("h3_remains_blocked") is not True or h3.get("h3_production_readiness_claimed") is not False:
        failures.append("FE-9 must keep H.3 blocked")


def _validate_operator_authorization(operator_id: str, operator_authorization: str, failures: list[str]) -> None:
    if not str(operator_id or "").strip():
        failures.append("operator_id is required")
    authorization = str(operator_authorization or "").strip()
    if not authorization:
        failures.append("operator_authorization is required")
    if any(token in authorization.upper() for token in ("TODO", "REPLACE_ME", "PLACEHOLDER")):
        failures.append("operator_authorization must not be a placeholder")


def _validate_frontend_checkout(frontend_root: Path, fe9: Any, failures: list[str]) -> None:
    if not isinstance(fe9, dict):
        return
    recorded_root = str(fe9.get("frontend_root") or "").strip()
    if not recorded_root:
        failures.append("FE-9 frontend_root is required")
    elif Path(recorded_root).resolve() != frontend_root:
        failures.append("frontend_root must match FE-9 frontend_root")
    expected_head = str(fe9.get("merge_commit") or "").strip()
    head = _git_text(frontend_root, failures, "rev-parse", "HEAD").strip()
    if expected_head and head != expected_head:
        failures.append("frontend HEAD must match FE-9 merge commit")
    status = _git_text(frontend_root, failures, "status", "--porcelain").splitlines()
    if status:
        failures.append("frontend worktree must be clean before preview")
    if not (frontend_root / "build" / "index.html").is_file():
        failures.append("frontend build/index.html must exist before preview")


def _is_private_preview_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
            return False
        host = parsed.hostname.rstrip(".").lower()
        if host == "localhost":
            return True
        address = ipaddress.ip_address(host)
        return address.is_loopback or address.is_private
    except (ValueError, TypeError):
        return False


def _validate_auth_boundary(auth_report: Any, failures: list[str]) -> None:
    if not isinstance(auth_report, dict):
        failures.append("backend auth report must be an object")
        return
    if auth_report.get("auth_method") != "service_token":
        return
    if auth_report.get("production_allowed") is not False:
        failures.append("service token must set production_allowed=false")
    if auth_report.get("evidence_allowed") is not False:
        failures.append("service token must set evidence_allowed=false")


def _git_text(repo: Path, failures: list[str], *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        failures.append(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout


def _boundary() -> dict[str, bool]:
    return {
        "frontend_code_modified": True,
        "apply_allowed": True,
        "commit_allowed": True,
        "push_allowed": True,
        "pr_allowed": True,
        "review_allowed": True,
        "merge_allowed": True,
        "post_merge_smoke_allowed": True,
        "preview_allowed": True,
        "deploy_allowed": False,
        "production_runtime_execution_allowed": False,
        "production_receipt_write_allowed": False,
    }


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _read_json(path: Path, failures: list[str], label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
    except json.JSONDecodeError as exc:
        failures.append(f"{label} invalid JSON: {exc}")
    return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _artifact_ref(path: Path) -> dict[str, str | None]:
    return artifact_ref(path)


def _ref_digest(ref: Any) -> str:
    return str(ref.get("sha256") or "missing") if isinstance(ref, dict) else "missing"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
