from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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


def test_live_provider_uses_prepared_single_use_transport(tmp_path: Path) -> None:
    transports: list[Any] = []

    class Transport:
        def __init__(self, url: str) -> None:
            self.url = urlsplit(url)
            self.prepare_count = 0
            self.post_count = 0
            self.close_count = 0
            transports.append(self)

        def prepare(self) -> None:
            self.prepare_count += 1

        def post_json_once(
            self,
            *,
            api_key: str,
            body: dict[str, Any],
            user_agent: str,
        ) -> tuple[int, bytes]:
            assert api_key == "private-api-key"
            assert body["model"] == "reviewed-model"
            assert user_agent == "civitasos-j1d-live-execution/1"
            self.post_count += 1
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
                                        {"decision": "bounded decision"}
                                    )
                                },
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 3,
                            "completion_tokens": 2,
                            "prompt_cache_hit_tokens": 0,
                            "prompt_cache_miss_tokens": 3,
                        },
                    }
                ).encode(),
            )

        def close(self) -> None:
            self.close_count += 1

    provider = boundaries.OpenAICompatibleQualificationProvider(
        run_id="run-1",
        api_key="private-api-key",
        authorization_sha256="a" * 64,
        amended_design={
            "provider_call": {
                "provider_id": "openai_compatible",
                "base_url": "https://provider.invalid",
                "model_id": "reviewed-model",
                "temperature": 0,
                "max_output_tokens": 8,
                "max_input_utf8_bytes": 65_536,
                "reserved_total_tokens_per_call": 32,
            },
            "budget_reservation": {
                "per_call_max_microunits": 100,
                "per_participant_reserved_tokens": 32,
                "per_participant_reserved_microunits": 100,
                "aggregate_reserved_tokens": 32,
                "aggregate_reserved_microunits": 100,
            },
            "pricing": {
                "rate_basis_tokens": 1_000_000,
                "rates_microunits": {
                    "input_cache_hit": 3625,
                    "input_cache_miss": 435000,
                    "output": 870000,
                },
            },
        },
        budget_path=tmp_path / "budget.sqlite3",
        transport_factory=Transport,
    )
    task = {
        "call_id": "call-1",
        "participant_id": "participant-1",
        "task": {"task_id": "task-1"},
    }
    provider.prepare(task=task)
    provider.prepare(task=task)

    result = provider.call(
        task=task,
        request={"system": "bounded", "user": "bounded"},
    )

    assert result["decision"] == "bounded decision"
    assert result["usage"]["cost_microunits"] == 4
    assert len(transports) == 1
    assert transports[0].prepare_count == 1
    assert transports[0].post_count == 1
    assert provider.budget.status("call-1") == "reconciled"


def test_live_provider_discards_unused_prepared_transport(tmp_path: Path) -> None:
    transports: list[Any] = []

    class Transport:
        def __init__(self, url: str) -> None:
            self.url = urlsplit(url)
            self.close_count = 0
            transports.append(self)

        def prepare(self) -> None:
            return None

        def close(self) -> None:
            self.close_count += 1

    provider = boundaries.OpenAICompatibleQualificationProvider(
        run_id="run-1",
        api_key="private-api-key",
        authorization_sha256="a" * 64,
        amended_design={
            "provider_call": {
                "provider_id": "openai_compatible",
                "base_url": "https://provider.invalid",
                "model_id": "reviewed-model",
                "temperature": 0,
                "max_output_tokens": 8,
                "max_input_utf8_bytes": 65_536,
                "reserved_total_tokens_per_call": 32,
            },
            "budget_reservation": {
                "per_call_max_microunits": 100,
                "per_participant_reserved_tokens": 32,
                "per_participant_reserved_microunits": 100,
                "aggregate_reserved_tokens": 32,
                "aggregate_reserved_microunits": 100,
            },
            "pricing": {
                "rate_basis_tokens": 1_000_000,
                "rates_microunits": {
                    "input_cache_hit": 3625,
                    "input_cache_miss": 435000,
                    "output": 870000,
                },
            },
        },
        budget_path=tmp_path / "budget.sqlite3",
        transport_factory=Transport,
    )
    task = {
        "call_id": "call-1",
        "participant_id": "participant-1",
        "task": {"task_id": "task-1"},
    }
    provider.prepare(task=task)
    provider.discard(task=task)

    assert transports[0].close_count == 1


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
