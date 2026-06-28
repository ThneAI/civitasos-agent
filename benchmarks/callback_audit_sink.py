"""Private callback audit sink used by controlled task-pool gates."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib import request as urllib_request

from benchmarks.i_gate_evidence import object_value, sha256_text


class CallbackAuditSink:
    def __init__(
        self,
        *,
        enabled: bool,
        endpoint_path: str = "p0c-callback-sink",
        thread_name: str = "civitasos-callback-sink",
    ) -> None:
        self.enabled = enabled
        self.endpoint_path = endpoint_path.strip("/") or "civitasos-callback-sink"
        self.thread_name = thread_name
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._records: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.endpoint = ""

    def __enter__(self) -> "CallbackAuditSink":
        if not self.enabled:
            return self
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self) -> None:  # noqa: N802
                self.send_response(200)
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length)
                record = _callback_record(path=self.path, headers=dict(self.headers), body=body)
                with sink._lock:
                    sink._records.append(record)
                self.send_response(204)
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        host, port = self._server.server_address
        self.endpoint = f"http://{host}:{port}/{self.endpoint_path}"
        self._thread = threading.Thread(target=self._server.serve_forever, name=self.thread_name, daemon=True)
        self._thread.start()
        _wait_for_local_http(self.endpoint)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._records)

    def wait_for(self, *, task_id: str, event: str, timeout_seconds: float) -> bool:
        if not self.enabled:
            return False
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if any(callback_task_id(record) == task_id and callback_event(record) == event for record in self.records()):
                return True
            time.sleep(0.05)
        return False


def callback_event(record: dict[str, Any]) -> str:
    body = object_value(record.get("body"))
    return str(body.get("event") or "")


def callback_task_id(record: dict[str, Any]) -> str:
    body = object_value(record.get("body"))
    if body.get("task_id"):
        return str(body.get("task_id"))
    data = object_value(body.get("data"))
    return str(data.get("task_id") or "")


def _callback_record(*, path: str, headers: dict[str, str], body: bytes) -> dict[str, Any]:
    raw_body = body.decode("utf-8", errors="replace")
    try:
        json_body: Any = json.loads(raw_body) if raw_body else None
    except json.JSONDecodeError:
        json_body = None
    signature = _header_value(headers, "X-Civitas-Webhook-Signature")
    return {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "method": "POST",
        "path": path,
        "headers": {
            "content_type": _header_value(headers, "Content-Type") or None,
            "issuer": _header_value(headers, "X-Civitas-Webhook-Issuer") or None,
            "timestamp": _header_value(headers, "X-Civitas-Webhook-Timestamp") or None,
            "signature_present": bool(signature),
            "signature_sha256": sha256_text(signature) if signature else None,
        },
        "body_sha256": sha256_text(raw_body),
        "body": json_body if isinstance(json_body, dict) else {"raw": raw_body},
    }


def _header_value(headers: dict[str, str], name: str) -> str:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return ""


def _wait_for_local_http(endpoint: str) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            with urllib_request.urlopen(endpoint, timeout=0.2) as response:
                if response.status < 500:
                    return
        except Exception:
            time.sleep(0.02)
    raise RuntimeError(f"callback sink failed to start: {endpoint}")
