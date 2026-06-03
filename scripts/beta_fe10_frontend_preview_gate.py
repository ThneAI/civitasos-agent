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
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    demo_login_agent_id: str,
    operator_id: str,
    operator_authorization: str,
) -> dict[str, Any]:
    frontend_root = frontend_root.resolve()
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    fe9 = _read_json(source_fe9_receipt, failures, "FE-9 post-merge smoke receipt")
    _validate_fe9(fe9, failures)
    frontend_url = frontend_url.rstrip("/")
    backend_url = backend_url.rstrip("/")
    if not frontend_url.startswith(("http://127.0.0.1", "http://localhost", "http://192.168.", "http://10.", "http://172.")):
        failures.append("frontend_url must be local/private preview URL")
    if not backend_url.startswith(("http://127.0.0.1", "http://localhost", "http://192.168.", "http://10.", "http://172.")):
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
        auth_report = _demo_login(backend_url, demo_login_agent_id)
        if auth_report.get("passed") is not True:
            failures.append("backend demo-login token bootstrap failed for preview smoke")
        token = str(auth_report.get("token") or "")
        auth_report["token"] = "<redacted>" if token else ""
        for name, method, path, requires_auth in READ_ENDPOINTS:
            headers = {"Authorization": f"Bearer {token}"} if requires_auth and token else None
            result = _http_json(f"{backend_url}{path}", headers, method=method)
            backend_checks.append({"name": name, "url": f"{backend_url}{path}", "requires_auth": requires_auth, **result})
            if result.get("status_code") != 200:
                failures.append(f"backend read endpoint failed: {name}")
            if result.get("json_object") is not True:
                failures.append(f"backend read endpoint must return JSON object: {name}")

    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "checked_at": _now(),
        "passed": not failures,
        "decision": "beta_fe10_frontend_preview_passed" if not failures else "blocked",
        "failure_reasons": failures,
        "source_fe9_receipt": _artifact_ref(source_fe9_receipt) if source_fe9_receipt.is_file() else None,
        "frontend_root": str(frontend_root),
        "frontend_url": frontend_url,
        "backend_url": backend_url,
        "preview_scope": "local_or_private_preview_only",
        "frontend_checks": frontend_checks,
        "backend_auth": auth_report,
        "backend_read_model_checks": backend_checks,
        "operator_id": operator_id,
        "operator_authorization": operator_authorization,
        "git_actions_performed": {"commit": True, "push": True, "pr": True, "merge": True, "deploy": False},
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


def _demo_login(backend_url: str, agent_id: str) -> dict[str, Any]:
    payload = json.dumps({"agent_id": agent_id}).encode("utf-8")
    request = urllib.request.Request(
        f"{backend_url}/api/v1/auth/demo-login",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return {"passed": False, "status_code": exc.code, "error": raw[:500], "token_recorded": False}
    except Exception as exc:
        return {"passed": False, "status_code": None, "error": str(exc), "token_recorded": False}
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return {"passed": False, "status_code": status, "error": "invalid JSON", "token_recorded": False}
    token = str(body.get("token") or body.get("data", {}).get("token") or "") if isinstance(body, dict) else ""
    return {"passed": bool(token), "status_code": status, "token": token, "token_recorded": False, "auth_method": body.get("auth_method") if isinstance(body, dict) else None}


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
    h3 = value.get("h3_boundary") if isinstance(value.get("h3_boundary"), dict) else {}
    if h3.get("h3_remains_blocked") is not True or h3.get("h3_production_readiness_claimed") is not False:
        failures.append("FE-9 must keep H.3 blocked")


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


def _artifact_ref(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


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
