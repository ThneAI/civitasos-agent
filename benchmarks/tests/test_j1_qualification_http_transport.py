from __future__ import annotations

import ssl
from collections.abc import Callable
from typing import Any

import pytest

from benchmarks.j1.qualification_http_transport import (
    HTTPSPostPolicy,
    PreparedHTTPSPost,
)
from benchmarks.j1.qualification_provider_broker import SanitizedProviderFailure


class _Socket:
    def __init__(self) -> None:
        self.timeout: float | None = None

    def settimeout(self, value: float) -> None:
        self.timeout = value


class _Response:
    status = 200

    def __init__(self, body: bytes = b'{"ok":true}', error: Exception | None = None):
        self.body = body
        self.error = error

    def read(self, _: int) -> bytes:
        if self.error is not None:
            raise self.error
        return self.body


class _Connection:
    def __init__(
        self,
        *,
        connect_error: Exception | None = None,
        request_error: Exception | None = None,
        response: _Response | None = None,
    ) -> None:
        self.connect_error = connect_error
        self.request_error = request_error
        self.response = response or _Response()
        self.sock = _Socket()
        self.connect_count = 0
        self.request_count = 0
        self.closed = False
        self.captured_request: dict[str, Any] | None = None

    def connect(self) -> None:
        self.connect_count += 1
        if self.connect_error is not None:
            raise self.connect_error

    def request(
        self,
        method: str,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        self.request_count += 1
        self.captured_request = {
            "method": method,
            "url": url,
            "body": body,
            "headers": headers,
        }
        if self.request_error is not None:
            raise self.request_error

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


def _factory(
    connections: list[_Connection],
) -> Callable[[str, int | None, float, ssl.SSLContext], _Connection]:
    def build(
        host: str,
        port: int | None,
        timeout: float,
        context: ssl.SSLContext,
    ) -> _Connection:
        assert host == "provider.invalid"
        assert port is None
        assert timeout == 10.0
        assert isinstance(context, ssl.SSLContext)
        return connections.pop(0)

    return build


def test_transport_retries_only_pre_dispatch_connect_and_posts_once() -> None:
    first = _Connection(connect_error=OSError("private-connect-detail"))
    second = _Connection(connect_error=TimeoutError("private-timeout-detail"))
    third = _Connection()
    sleeps: list[float] = []
    transport = PreparedHTTPSPost(
        "https://provider.invalid/chat/completions",
        connection_factory=_factory([first, second, third]),
        sleeper=sleeps.append,
    )

    transport.prepare()
    status, body = transport.post_json_once(
        api_key="private-api-key",
        body={"synthetic": True},
        user_agent="bounded-test/1",
    )

    assert (status, body) == (200, b'{"ok":true}')
    assert transport.connect_attempt_count == 3
    assert transport.http_request_count == 1
    assert sleeps == [0.25, 1.0]
    assert first.request_count == second.request_count == 0
    assert third.request_count == 1
    assert third.sock.timeout == 30.0
    assert third.closed is True
    assert third.captured_request is not None
    assert third.captured_request["url"] == "/chat/completions"
    assert (
        third.captured_request["headers"]["Authorization"]
        == "Bearer private-api-key"
    )


def test_transport_connect_exhaustion_is_proven_pre_dispatch() -> None:
    connections = [
        _Connection(connect_error=OSError("private-detail")) for _ in range(3)
    ]
    transport = PreparedHTTPSPost(
        "https://provider.invalid/chat/completions",
        connection_factory=_factory(connections.copy()),
        sleeper=lambda _: None,
    )

    with pytest.raises(SanitizedProviderFailure) as raised:
        transport.prepare()

    assert raised.value.failure_category == "http"
    assert raised.value.failure_stage == "http_pre_dispatch_connect"
    assert raised.value.source_exception_type == "OSError"
    assert transport.http_request_count == 0
    assert all(connection.request_count == 0 for connection in connections)
    assert "private-detail" not in str(raised.value)


def test_transport_tls_exhaustion_is_proven_pre_dispatch() -> None:
    connections = [
        _Connection(connect_error=ssl.SSLError("private-tls-detail"))
        for _ in range(3)
    ]
    transport = PreparedHTTPSPost(
        "https://provider.invalid/chat/completions",
        connection_factory=_factory(connections),
        sleeper=lambda _: None,
    )

    with pytest.raises(SanitizedProviderFailure) as raised:
        transport.prepare()

    assert raised.value.failure_stage == "http_pre_dispatch_tls"
    assert raised.value.source_exception_type == "SSLError"
    assert transport.http_request_count == 0


def test_transport_never_retries_after_request_start() -> None:
    connection = _Connection(request_error=TimeoutError("private-write-detail"))
    transport = PreparedHTTPSPost(
        "https://provider.invalid/chat/completions",
        connection_factory=_factory([connection]),
        sleeper=lambda _: None,
    )
    transport.prepare()

    with pytest.raises(SanitizedProviderFailure) as raised:
        transport.post_json_once(
            api_key="private-api-key",
            body={"synthetic": True},
            user_agent="bounded-test/1",
        )

    assert raised.value.failure_stage == "http_dispatch_ambiguous"
    assert raised.value.source_exception_type == "TimeoutError"
    assert transport.connect_attempt_count == 1
    assert transport.http_request_count == 1
    assert connection.request_count == 1
    assert connection.closed is True
    assert "private-write-detail" not in str(raised.value)


def test_transport_read_failure_is_ambiguous_and_single_use() -> None:
    connection = _Connection(
        response=_Response(error=TimeoutError("private-read-detail"))
    )
    transport = PreparedHTTPSPost(
        "https://provider.invalid/chat/completions",
        connection_factory=_factory([connection]),
    )
    transport.prepare()

    with pytest.raises(SanitizedProviderFailure) as raised:
        transport.post_json_once(
            api_key="private-api-key",
            body={"synthetic": True},
            user_agent="bounded-test/1",
        )

    assert raised.value.failure_stage == "http_dispatch_ambiguous"
    assert transport.http_request_count == 1
    with pytest.raises(ValueError, match="not prepared"):
        transport.post_json_once(
            api_key="private-api-key",
            body={"synthetic": True},
            user_agent="bounded-test/1",
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://provider.invalid/chat/completions",
        "https://user:secret@provider.invalid/chat/completions",
        "https://provider.invalid/chat/completions#fragment",
    ],
)
def test_transport_rejects_non_https_or_credentialed_url(url: str) -> None:
    with pytest.raises(ValueError, match="credential-free HTTPS"):
        PreparedHTTPSPost(url)


def test_transport_policy_freezes_retry_boundary() -> None:
    assert HTTPSPostPolicy().as_dict() == {
        "connect_attempts": 3,
        "connect_timeout_seconds": 10.0,
        "response_timeout_seconds": 30.0,
        "connect_backoff_seconds": [0.25, 1.0],
        "max_response_bytes": 1_048_576,
        "pre_dispatch_connect_retry_allowed": True,
        "http_request_retry_allowed": False,
        "ambiguous_dispatch_retry_allowed": False,
    }
