from __future__ import annotations

import importlib.util
import json
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
    fe9 = _write_fe9_receipt(tmp_path / "fe9.json")

    report = module.run_preview_gate(
        source_fe9_receipt=fe9,
        frontend_root=tmp_path,
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


def test_fe10_preview_gate_blocks_failed_fe9(tmp_path: Path) -> None:
    frontend = _server(_FrontendHandler)
    backend = _server(_BackendHandler)
    fe9 = _write_fe9_receipt(tmp_path / "fe9.json", passed=False)

    report = module.run_preview_gate(
        source_fe9_receipt=fe9,
        frontend_root=tmp_path,
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


def _write_fe9_receipt(path: Path, passed: bool = True) -> Path:
    payload = {
        "schema_version": "beta-fe9-frontend-post-merge-smoke-receipt:v1",
        "passed": passed,
        "decision": "beta_fe9_frontend_post_merge_smoke_passed" if passed else "blocked",
        "merge_commit": "abc123",
        "remote_head": "abc123",
        "local_head": "abc123",
        "verification_commands": [{"returncode": 0}],
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
