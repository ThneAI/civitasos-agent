from __future__ import annotations

import json
from typing import Any

import pytest

from benchmarks.j1 import qualification_live_boundaries_v4 as boundaries
from benchmarks.j1.qualification_provider_broker import SanitizedProviderFailure


def _prompt() -> str:
    return boundaries._decision_prompt(system="bounded", user="bounded")


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
                            {
                                "finish_reason": "stop",
                                "message": {
                                    "content": json.dumps(
                                        {"decision": "private-response-content"}
                                    )
                                },
                            }
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
            prompt=_prompt(),
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
            prompt=_prompt(),
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


def test_provider_boundary_binds_and_extracts_json_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def post_once(url: str, api_key: str, body: dict[str, Any]) -> tuple[int, bytes]:
        captured.update({"url": url, "api_key": api_key, "body": body})
        return (
            200,
            json.dumps(
                {
                    "model": "reviewed-model",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {
                                "content": json.dumps(
                                    {"decision": "bounded participant decision"}
                                )
                            },
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 12,
                        "completion_tokens": 7,
                        "prompt_cache_hit_tokens": 2,
                        "prompt_cache_miss_tokens": 10,
                    },
                }
            ).encode(),
        )

    monkeypatch.setattr(boundaries, "_https_post_once", post_once)

    result = boundaries.OpenAICompatibleQualificationProvider._post_once(
        base_url="https://provider.invalid",
        api_key="private-api-key",
        model="reviewed-model",
        prompt=_prompt(),
        max_tokens=1000,
        temperature=0,
    )

    assert result == {
        "content": "bounded participant decision",
        "usage": {
            "input_cache_hit": 2,
            "input_cache_miss": 10,
            "output": 7,
        },
    }
    assert captured["body"]["thinking"] == {"type": "disabled"}
    assert captured["body"]["response_format"] == {"type": "json_object"}
    assert (
        boundaries.DECISION_SYSTEM_SUFFIX in captured["body"]["messages"][0]["content"]
    )


@pytest.mark.parametrize(
    ("finish_reason", "content", "category", "stage"),
    [
        (
            "length",
            json.dumps({"decision": "private-response-content"}),
            "schema",
            "response_finish_reason",
        ),
        ("stop", "", "schema", "response_decision"),
        ("stop", "{private-response-content", "parse", "response_decision_json_parse"),
        (
            "stop",
            json.dumps({"unexpected": "private-response-content"}),
            "schema",
            "response_decision",
        ),
    ],
)
def test_provider_boundary_fail_closes_sanitized_decision_contract_drift(
    monkeypatch: pytest.MonkeyPatch,
    finish_reason: str,
    content: str,
    category: str,
    stage: str,
) -> None:
    monkeypatch.setattr(
        boundaries,
        "_https_post_once",
        lambda *_: (
            200,
            json.dumps(
                {
                    "model": "reviewed-model",
                    "choices": [
                        {
                            "finish_reason": finish_reason,
                            "message": {"content": content},
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 3,
                        "completion_tokens": 2,
                    },
                }
            ).encode(),
        ),
    )

    with pytest.raises(SanitizedProviderFailure) as raised:
        boundaries.OpenAICompatibleQualificationProvider._post_once(
            base_url="https://provider.invalid",
            api_key="private-api-key",
            model="reviewed-model",
            prompt=_prompt(),
            max_tokens=1000,
            temperature=0,
        )

    assert raised.value.failure_category == category
    assert raised.value.failure_stage == stage
    assert "private-response-content" not in str(raised.value)


def test_provider_boundary_rejects_unbound_decision_contract_before_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispatched = False

    def must_not_dispatch(*_: Any) -> tuple[int, bytes]:
        nonlocal dispatched
        dispatched = True
        raise AssertionError("HTTP dispatch must not occur")

    monkeypatch.setattr(boundaries, "_https_post_once", must_not_dispatch)

    with pytest.raises(SanitizedProviderFailure) as raised:
        boundaries.OpenAICompatibleQualificationProvider._post_once(
            base_url="https://provider.invalid",
            api_key="private-api-key",
            model="reviewed-model",
            prompt='{"system":"bounded","user":"bounded"}',
            max_tokens=1000,
            temperature=0,
        )

    assert dispatched is False
    assert raised.value.failure_category == "schema"
    assert raised.value.failure_stage == "request_decision_contract"
