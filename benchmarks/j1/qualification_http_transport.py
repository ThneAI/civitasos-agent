"""Explicit pre-dispatch HTTPS transport for J1-D provider calls."""

from __future__ import annotations

import http.client
import json
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import SplitResult, urlsplit

from .qualification_provider_broker import sanitized_provider_failure


MAX_RESPONSE_BYTES = 1_048_576


class HTTPSConnectionLike(Protocol):
    def connect(self) -> None: ...

    def request(
        self,
        method: str,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> None: ...

    def getresponse(self) -> Any: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[
    [str, int | None, float, ssl.SSLContext], HTTPSConnectionLike
]


@dataclass(frozen=True)
class HTTPSPostPolicy:
    connect_attempts: int = 3
    connect_timeout_seconds: float = 10.0
    response_timeout_seconds: float = 30.0
    connect_backoff_seconds: tuple[float, ...] = (0.25, 1.0)
    max_response_bytes: int = MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if (
            self.connect_attempts < 1
            or self.connect_timeout_seconds <= 0
            or self.response_timeout_seconds <= 0
            or len(self.connect_backoff_seconds) != self.connect_attempts - 1
            or any(delay < 0 for delay in self.connect_backoff_seconds)
            or self.max_response_bytes < 1
        ):
            raise ValueError("HTTPS transport policy is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "connect_attempts": self.connect_attempts,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "response_timeout_seconds": self.response_timeout_seconds,
            "connect_backoff_seconds": list(self.connect_backoff_seconds),
            "max_response_bytes": self.max_response_bytes,
            "pre_dispatch_connect_retry_allowed": True,
            "http_request_retry_allowed": False,
            "ambiguous_dispatch_retry_allowed": False,
        }


class PreparedHTTPSPost:
    """Connect first, then permit exactly one HTTP request on that connection."""

    def __init__(
        self,
        url: str,
        *,
        policy: HTTPSPostPolicy | None = None,
        connection_factory: ConnectionFactory | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.url = _validated_https_url(url)
        self.policy = policy or HTTPSPostPolicy()
        self._connection_factory = connection_factory or _https_connection
        self._sleeper = sleeper
        self._connection: HTTPSConnectionLike | None = None
        self.connect_attempt_count = 0
        self.http_request_count = 0
        self._consumed = False

    @property
    def prepared(self) -> bool:
        return self._connection is not None and not self._consumed

    def prepare(self) -> None:
        if self.prepared:
            return
        if self._consumed:
            raise ValueError("HTTPS transport is already consumed")
        last_error: BaseException | None = None
        last_stage = "http_pre_dispatch_connect"
        context = ssl.create_default_context()
        for attempt in range(self.policy.connect_attempts):
            self.connect_attempt_count += 1
            connection = self._connection_factory(
                str(self.url.hostname),
                self.url.port,
                self.policy.connect_timeout_seconds,
                context,
            )
            try:
                connection.connect()
            except Exception as error:
                last_error = error
                last_stage = (
                    "http_pre_dispatch_tls"
                    if isinstance(error, ssl.SSLError)
                    else "http_pre_dispatch_connect"
                )
                connection.close()
                if attempt < len(self.policy.connect_backoff_seconds):
                    self._sleeper(self.policy.connect_backoff_seconds[attempt])
                continue
            self._set_response_timeout(connection)
            self._connection = connection
            return
        raise sanitized_provider_failure(
            category="http",
            stage=last_stage,
            error=last_error,
        )

    def post_json_once(
        self,
        *,
        api_key: str,
        body: dict[str, Any],
        user_agent: str,
    ) -> tuple[int, bytes]:
        if not self.prepared or self._connection is None:
            raise ValueError("HTTPS transport was not prepared")
        if self.http_request_count != 0:
            raise ValueError("HTTPS request is single-use")
        encoded = json.dumps(
            body,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": user_agent,
        }
        connection = self._connection
        self._connection = None
        self._consumed = True
        self.http_request_count = 1
        try:
            connection.request(
                "POST",
                _request_target(self.url),
                body=encoded,
                headers=headers,
            )
            response = connection.getresponse()
            status = int(response.status)
            result = response.read(self.policy.max_response_bytes + 1)
        except Exception as error:
            raise sanitized_provider_failure(
                category="http",
                stage="http_dispatch_ambiguous",
                error=error,
            ) from None
        finally:
            connection.close()
        if len(result) > self.policy.max_response_bytes:
            raise sanitized_provider_failure(
                category="http",
                stage="http_response_too_large",
                source_exception_type="ProviderResponseSizeError",
            )
        return status, result

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _set_response_timeout(self, connection: HTTPSConnectionLike) -> None:
        sock = getattr(connection, "sock", None)
        if sock is not None:
            sock.settimeout(self.policy.response_timeout_seconds)


def _https_connection(
    host: str,
    port: int | None,
    timeout: float,
    context: ssl.SSLContext,
) -> HTTPSConnectionLike:
    return http.client.HTTPSConnection(
        host,
        port=port,
        timeout=timeout,
        context=context,
    )


def _validated_https_url(value: str) -> SplitResult:
    parsed = urlsplit(value)
    if not (
        parsed.scheme == "https"
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
    ):
        raise ValueError("provider transport URL must be credential-free HTTPS")
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("provider transport URL port is invalid") from error
    return parsed


def _request_target(url: SplitResult) -> str:
    path = url.path or "/"
    return f"{path}?{url.query}" if url.query else path
