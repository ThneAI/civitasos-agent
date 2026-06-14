"""Canonical HTTP authentication for CivitasOS operator and gate clients."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


AUTH_CONTEXT_SCHEMA = "civitasos-auth-context:v1"
AUTH_MODES = frozenset({"auto", "bearer-token", "service-token", "demo-login"})


@dataclass(frozen=True)
class AuthSession:
    """Resolved bearer session plus a token-free audit context."""

    token: str
    context: dict[str, Any]

    def report(self) -> dict[str, Any]:
        return {
            "passed": bool(self.token),
            "token": "<redacted>" if self.token else "",
            "token_recorded": False,
            **self.context,
        }


class CivitasHttpClient:
    """Small JSON client with one explicit CivitasOS auth policy."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str | None = None,
        api_key: str | None = None,
        service_token_secret: str | None = None,
        service_id: str = "civitasos_operator_client",
        service_scopes: Iterable[str] = (),
        require_service_token: bool = False,
        demo_login_agent_id: str | None = None,
        required_service_token_error: str = "service-token mode requires a service token secret",
        timeout: float = 20,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._bearer_token = _text(bearer_token)
        self._api_key = _text(api_key)
        self._service_token_secret = _text(service_token_secret)
        self._service_id = _text(service_id) or "civitasos_operator_client"
        self._service_scopes = _normalized_scopes(service_scopes)
        self._require_service_token = require_service_token
        self._demo_login_agent_id = _text(demo_login_agent_id)
        self._required_service_token_error = required_service_token_error
        self._timeout = timeout
        self._service_token_attempted = False
        self._demo_login_attempted = False
        self._auth_context = self._initial_auth_context()

    def get(self, path: str) -> Any:
        request = urllib.request.Request(
            self._url(path),
            headers=self.headers(),
            method="GET",
        )
        return self._open_json(request)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        request = urllib.request.Request(
            self._url(path),
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=self.headers(content_type=True),
            method="POST",
        )
        return self._open_json(request)

    def headers(self, *, content_type: bool = False) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = "application/json"
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        token = self.bearer_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def bearer_token(self) -> str:
        self._ensure_auth()
        return self._bearer_token

    def auth_context(self) -> dict[str, Any]:
        return dict(self._auth_context)

    def auth_session(self) -> AuthSession:
        return AuthSession(token=self.bearer_token(), context=self.auth_context())

    def _ensure_auth(self) -> None:
        if self._require_service_token:
            if not self._service_token_secret:
                raise RuntimeError(self._required_service_token_error)
            if not self._service_token_attempted:
                self._bootstrap_service_token()
            return
        if self._bearer_token or self._api_key:
            return
        if self._service_token_secret and not self._service_token_attempted:
            self._bootstrap_service_token()
            return
        if self._demo_login_attempted:
            return
        self._demo_login_attempted = True
        if self._demo_login_agent_id:
            self._bootstrap_demo_login()

    def _bootstrap_service_token(self) -> None:
        self._service_token_attempted = True
        payload = self._open_json(
            urllib.request.Request(
                self._url("/api/v1/auth/service-token"),
                data=json.dumps(
                    {
                        "service_id": self._service_id,
                        "secret": self._service_token_secret,
                        "scopes": self._service_scopes,
                    }
                ).encode("utf-8"),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                method="POST",
            )
        )
        token, data = _token_and_data(payload, "service-token")
        self._bearer_token = token
        self._auth_context = {
            "schema_version": AUTH_CONTEXT_SCHEMA,
            "auth_method": _text(data.get("auth_method")) or "service_token",
            "service_id": _text(data.get("service_id")) or self._service_id,
            "scopes": data.get("scopes") if isinstance(data.get("scopes"), list) else self._service_scopes,
            "production_allowed": bool(data.get("production_allowed", False)),
            "evidence_allowed": bool(data.get("evidence_allowed", False)),
            "non_claims": data.get(
                "non_claims",
                [
                    "service_token_is_controlled_operator_automation_only",
                    "service_token_is_not_runtime_behavior_evidence",
                ],
            ),
        }

    def _bootstrap_demo_login(self) -> None:
        payload = self._open_json(
            urllib.request.Request(
                self._url("/api/v1/auth/demo-login"),
                data=json.dumps({"agent_id": self._demo_login_agent_id}).encode("utf-8"),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                method="POST",
            )
        )
        token, data = _token_and_data(payload, "demo-login")
        self._bearer_token = token
        self._auth_context = {
            "schema_version": AUTH_CONTEXT_SCHEMA,
            "auth_method": _text(data.get("auth_method")) or "demo_login",
            "production_allowed": bool(data.get("production_allowed", False)),
            "evidence_allowed": bool(data.get("evidence_allowed", False)),
            "non_claims": data.get(
                "non_claims",
                [
                    "demo_login_is_dev_test_only",
                    "demo_login_must_not_be_used_as_production_evidence",
                ],
            ),
        }

    def _initial_auth_context(self) -> dict[str, Any]:
        base = {
            "schema_version": AUTH_CONTEXT_SCHEMA,
            "production_allowed": False,
            "evidence_allowed": False,
        }
        if self._require_service_token:
            return {
                **base,
                "auth_method": (
                    "pending_service_token"
                    if self._service_token_secret
                    else "missing_required_service_token"
                ),
                "service_id": self._service_id,
                "scopes": self._service_scopes,
                "require_service_token": True,
            }
        if self._api_key:
            return {**base, "auth_method": "api_key"}
        if self._bearer_token:
            return {
                **base,
                "auth_method": "provided_bearer_token",
                "production_allowed": None,
                "evidence_allowed": None,
            }
        if self._service_token_secret:
            return {
                **base,
                "auth_method": "pending_service_token",
                "service_id": self._service_id,
                "scopes": self._service_scopes,
            }
        return {
            **base,
            "auth_method": "pending_demo_login" if self._demo_login_agent_id else "none",
        }

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path if path.startswith('/') else '/' + path}"

    def _open_json(self, request: urllib.request.Request) -> Any:
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {request.full_url}: {detail}") from exc
        if not raw:
            return None
        return json.loads(raw)


def resolve_auth_session(
    *,
    base_url: str,
    auth_mode: str,
    bearer_token: str | None = None,
    bearer_token_files: Iterable[Path] = (),
    bearer_token_env_values: Iterable[str | None] = (),
    service_token_secret: str | None = None,
    service_id: str,
    service_scopes: Iterable[str],
    demo_login_agent_id: str | None = None,
    timeout: float = 10,
) -> AuthSession:
    """Resolve one auth mode without silently crossing policy boundaries."""

    if auth_mode not in AUTH_MODES:
        raise ValueError(f"unsupported auth mode: {auth_mode}")
    configured_bearer = first_token(
        [bearer_token, *bearer_token_env_values],
        bearer_token_files,
    )
    if auth_mode in {"auto", "bearer-token"} and configured_bearer:
        return AuthSession(
            token=configured_bearer,
            context={
                "schema_version": AUTH_CONTEXT_SCHEMA,
                "auth_method": "bearer_token",
                "source": "argument_env_or_file",
                "production_allowed": None,
                "evidence_allowed": None,
            },
        )
    if auth_mode == "bearer-token":
        raise RuntimeError("bearer-token mode requires a bearer token")

    secret = _text(service_token_secret)
    if auth_mode in {"auto", "service-token"} and secret:
        client = CivitasHttpClient(
            base_url,
            service_token_secret=secret,
            service_id=service_id,
            service_scopes=service_scopes,
            require_service_token=True,
            required_service_token_error="service-token mode requires a service token secret",
            timeout=timeout,
        )
        return client.auth_session()
    if auth_mode == "service-token":
        raise RuntimeError("service-token mode requires a service token secret")

    agent_id = _text(demo_login_agent_id)
    if not agent_id:
        raise RuntimeError("demo-login mode requires a demo login agent id")
    client = CivitasHttpClient(
        base_url,
        demo_login_agent_id=agent_id,
        timeout=timeout,
    )
    return client.auth_session()


def first_token(values: Iterable[str | None], files: Iterable[Path]) -> str:
    for value in values:
        token = _text(value)
        if token:
            return token
    for path in files:
        if path and path.is_file():
            token = path.read_text(encoding="utf-8").strip()
            if token:
                return token
    return ""


def _token_and_data(payload: Any, label: str) -> tuple[str, dict[str, Any]]:
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} response must be an object: {payload}")
    nested = payload.get("data")
    data = nested if isinstance(nested, dict) else payload
    token = _text(payload.get("token")) or _text(data.get("token"))
    if not token:
        raise RuntimeError(f"{label} response missing token: {payload}")
    return token, data


def _normalized_scopes(scopes: Iterable[str]) -> list[str]:
    return [scope for scope in (_text(item) for item in scopes) if scope]


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""
