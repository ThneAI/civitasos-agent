from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load("beta_fe10_frontend_preview_gate", SCRIPTS / "beta_fe10_frontend_preview_gate.py")


def test_fe10_preview_gate_checks_frontend_and_backend_read_models(tmp_path: Path) -> None:
    frontend = _server(_FrontendHandler)
    backend = _server(_BackendHandler)
    frontend_root = _frontend_repo(tmp_path / "frontend")
    fe9 = _write_fe9_receipt(tmp_path / "fe9.json", frontend_root)

    report = module.run_preview_gate(
        source_fe9_receipt=fe9,
        frontend_root=frontend_root,
        output_root=tmp_path / "out",
        frontend_url=frontend.url,
        backend_url=backend.url,
        demo_login_agent_id="tester",
        operator_id="operator",
        operator_authorization="test",
    )

    frontend.close()
    backend.close()
    assert report["passed"] is True
    assert report["schema_version"] == module.RECEIPT_SCHEMA
    assert report["backend_auth"]["token_recorded"] is False
    assert report["backend_auth"]["token"] == "<redacted>"
    assert {check["name"] for check in report["backend_read_model_checks"]} >= {
        "healthz",
        "pool_tasks",
        "pool_failures",
        "audit_events",
        "operator_read_model",
        "security_audit_log",
    }
    assert report["boundary"]["preview_allowed"] is True
    assert report["boundary"]["deploy_allowed"] is False
    assert report["artifact_envelope"]["artifact_kind"] == "receipt"
    assert report["artifact_envelope"]["plane"] == "runtime"
    assert report["release_provenance"]["runtime_evidence"] is False
    assert report["release_provenance"]["actions_observed"]["merge"] is True
    assert report["release_provenance"]["actions_performed_by_current_step"]["merge"] is False
    assert report["git_actions_performed"]["merge"] is False


def test_fe10_preview_gate_prefers_service_token_when_secret_supplied(tmp_path: Path) -> None:
    frontend = _server(_FrontendHandler)
    backend = _server(_BackendHandler)
    frontend_root = _frontend_repo(tmp_path / "frontend")
    fe9 = _write_fe9_receipt(tmp_path / "fe9.json", frontend_root)

    report = module.run_preview_gate(
        source_fe9_receipt=fe9,
        frontend_root=frontend_root,
        output_root=tmp_path / "out",
        frontend_url=frontend.url,
        backend_url=backend.url,
        auth_mode="service-token",
        service_token_secret="test-secret",
        service_id="preview-service",
        service_token_scopes=["pool:read", "audit:read"],
        demo_login_agent_id="tester",
        operator_id="operator",
        operator_authorization="test",
    )

    frontend.close()
    backend.close()
    assert report["passed"] is True
    assert report["backend_auth"]["auth_method"] == "service_token"
    assert report["backend_auth"]["token"] == "<redacted>"
    assert report["backend_auth"]["scopes"] == ["pool:read", "audit:read"]


def test_fe10_preview_gate_blocks_failed_fe9(tmp_path: Path) -> None:
    frontend = _server(_FrontendHandler)
    backend = _server(_BackendHandler)
    frontend_root = _frontend_repo(tmp_path / "frontend")
    fe9 = _write_fe9_receipt(tmp_path / "fe9.json", frontend_root, passed=False)

    report = module.run_preview_gate(
        source_fe9_receipt=fe9,
        frontend_root=frontend_root,
        output_root=tmp_path / "out",
        frontend_url=frontend.url,
        backend_url=backend.url,
        demo_login_agent_id="tester",
        operator_id="operator",
        operator_authorization="test",
    )

    frontend.close()
    backend.close()
    assert report["passed"] is False
    assert any("FE-9 receipt must be passed" in reason for reason in report["failure_reasons"])
    assert report["frontend_checks"] == []
    assert report["backend_read_model_checks"] == []


def test_fe10_rejects_hostname_prefix_spoof(tmp_path: Path) -> None:
    frontend_root = _frontend_repo(tmp_path / "frontend")
    fe9 = _write_fe9_receipt(tmp_path / "fe9.json", frontend_root)

    report = module.run_preview_gate(
        source_fe9_receipt=fe9,
        frontend_root=frontend_root,
        output_root=tmp_path / "out",
        frontend_url="http://127.0.0.1.example.test:3001",
        backend_url="http://localhost.example.test:8099",
        operator_id="operator",
        operator_authorization="test",
    )

    assert report["passed"] is False
    assert report["failure_reasons"].count("frontend_url must be local/private preview URL") == 1
    assert report["failure_reasons"].count("backend_url must be local/private preview URL") == 1


def test_fe10_service_token_boundary_rejects_production_capability() -> None:
    failures: list[str] = []
    module._validate_auth_boundary(
        {
            "auth_method": "service_token",
            "production_allowed": True,
            "evidence_allowed": False,
        },
        failures,
    )

    assert failures == ["service token must set production_allowed=false"]


class _FrontendHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/":
            self._send(200, "text/html", '<div id="root"></div><script src="/static/js/main.abc.js"></script>')
        elif self.path == "/static/js/main.abc.js":
            self._send(200, "application/javascript", "console.log('ok')")
        else:
            self._send(404, "text/plain", "not found")

    def _send(self, status: int, content_type: str, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, *_args):
        return


class _BackendHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        payloads = {
            "/healthz": {"ok": True},
            "/api/v1/status": {"success": True, "data": {"status": "ok"}},
            "/api/v1/a2a/pool/tasks": {"tasks": []},
            "/api/v1/a2a/pool/failures?since=0&limit=100": {"failures": []},
            "/api/v1/audit/events": {"events": []},
            "/api/v1/a2a/operator/read-model": {"data": {"schema_version": "operator-read-model:v1"}},
            "/api/v1/audit/log": {"data": {"entries": []}},
        }
        if self.path in payloads:
            self._json(200, payloads[self.path])
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path == "/api/v1/auth/demo-login":
            self._json(200, {"token": "preview-token", "auth_method": "demo_login"})
        elif self.path == "/api/v1/auth/service-token":
            self._json(200, {
                "success": True,
                "data": {
                    "token": "service-preview-token",
                    "auth_method": "service_token",
                    "service_id": "preview-service",
                    "scopes": ["pool:read", "audit:read"],
                    "production_allowed": False,
                    "evidence_allowed": False,
                },
                "token": "service-preview-token",
            })
        else:
            self._json(404, {"error": "not found"})

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class _Server:
    def __init__(self, handler):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.thread.join(timeout=2)
        self.httpd.server_close()


def _server(handler) -> _Server:
    return _Server(handler)


def _write_fe9_receipt(path: Path, frontend_root: Path, passed: bool = True) -> Path:
    commit_id = _git(frontend_root, "rev-parse", "HEAD")
    payload = {
        "schema_version": "beta-fe9-frontend-post-merge-smoke-receipt:v1",
        "passed": passed,
        "decision": "beta_fe9_frontend_post_merge_smoke_passed" if passed else "blocked",
        "frontend_root": str(frontend_root),
        "merge_commit": commit_id,
        "remote_head": commit_id,
        "local_head": commit_id,
        "verification_commands": [{"returncode": 0}],
        "boundary": {
            "post_merge_smoke_allowed": True,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _frontend_repo(path: Path) -> Path:
    (path / "build").mkdir(parents=True)
    (path / "build" / "index.html").write_text('<div id="root"></div>\n', encoding="utf-8")
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True, text=True)
    subprocess.run(["git", "add", "."], cwd=path, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "baseline"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    )
    return path


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return result.stdout.strip()
