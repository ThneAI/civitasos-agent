from __future__ import annotations

import json
from typing import Any

import pytest

from benchmarks.j1 import qualification_live_boundaries_v4 as boundaries
from benchmarks.j1.qualification_provider_broker import SanitizedProviderFailure


@pytest.mark.parametrize(
    ("wire_result", "category", "stage"),
    [
        ((503, b"private-response-content"), "http", "http_status"),
        ((200, b"{private-response-content"), "parse", "response_json_parse"),
        (
            (
                200,
                json.dumps(
                    {
                        "model": "wrong-model",
                        "private": "private-response-content",
                    }
                ).encode(),
            ),
            "schema",
            "response_model",
        ),
        (
            (
                200,
                json.dumps(
                    {
                        "model": "reviewed-model",
                        "choices": [
                            {"message": {"content": "private-response-content"}}
                        ],
                        "usage": {
                            "prompt_tokens": 3,
                            "completion_tokens": "invalid",
                        },
                    }
                ).encode(),
            ),
            "usage",
            "response_usage",
        ),
    ],
)
def test_provider_boundary_emits_only_sanitized_failure_taxonomy(
    monkeypatch: pytest.MonkeyPatch,
    wire_result: tuple[int, bytes],
    category: str,
    stage: str,
) -> None:
    monkeypatch.setattr(boundaries, "_https_post_once", lambda *_: wire_result)

    with pytest.raises(SanitizedProviderFailure) as raised:
        boundaries.OpenAICompatibleQualificationProvider._post_once(
            base_url="https://provider.invalid",
            api_key="private-api-key",
            model="reviewed-model",
            prompt='{"system":"bounded","user":"bounded"}',
            max_tokens=8,
            temperature=0,
        )

    assert raised.value.failure_category == category
    assert raised.value.failure_stage == stage
    diagnostic = {
        "error": str(raised.value),
        "category": raised.value.failure_category,
        "stage": raised.value.failure_stage,
        "source_exception_type": raised.value.source_exception_type,
    }
    assert "private-response-content" not in str(diagnostic)
    assert "private-api-key" not in str(diagnostic)


def test_provider_transport_failure_does_not_persist_exception_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispatch_count = 0

    def fail_transport(*_: Any) -> tuple[int, bytes]:
        nonlocal dispatch_count
        dispatch_count += 1
        raise RuntimeError("private-response-content")

    monkeypatch.setattr(boundaries, "_https_post_once", fail_transport)

    with pytest.raises(SanitizedProviderFailure) as raised:
        boundaries.OpenAICompatibleQualificationProvider._post_once(
            base_url="https://provider.invalid",
            api_key="private-api-key",
            model="reviewed-model",
            prompt='{"system":"bounded","user":"bounded"}',
            max_tokens=8,
            temperature=0,
        )

    assert dispatch_count == 1
    assert raised.value.failure_category == "http"
    assert raised.value.failure_stage == "http_transport"
    assert raised.value.source_exception_type == "RuntimeError"
    assert "private-response-content" not in str(raised.value)


def test_provider_boundary_rejects_invalid_request_before_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_dispatch(*_: Any) -> tuple[int, bytes]:
        raise AssertionError("HTTP dispatch must not occur")

    monkeypatch.setattr(boundaries, "_https_post_once", must_not_dispatch)

    with pytest.raises(SanitizedProviderFailure) as raised:
        boundaries.OpenAICompatibleQualificationProvider._post_once(
            base_url="https://provider.invalid",
            api_key="private-api-key",
            model="reviewed-model",
            prompt="{invalid",
            max_tokens=8,
            temperature=0,
        )

    assert raised.value.failure_category == "parse"
    assert raised.value.failure_stage == "request_parse"
