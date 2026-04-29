"""Tests for benchmarks/backend_task_client.py (F.1.b §3.3.2 contract)."""
from __future__ import annotations

import time
from typing import Any

import pytest

from benchmarks.backend_task_client import (
    BackendTaskClient,
    BackendTaskState,
    state_to_sentinel,
)


class FakeSDK:
    """In-memory _SDKLike implementation for unit testing."""

    def __init__(self) -> None:
        self.tasks: list[dict[str, Any]] = []
        self.post_calls: list[dict[str, Any]] = []
        self.confirm_calls: list[str] = []
        self.fail_calls: list[str] = []
        self._next_id = 1
        self.confirm_should_raise: bool = False
        self.fail_should_raise: bool = False
        self.list_wrap: bool = False  # if True, pool_list returns {"tasks":[...]}

    def pool_post(self, **kwargs: Any) -> dict[str, Any]:
        self.post_calls.append(kwargs)
        tid = f"task_{self._next_id}"
        self._next_id += 1
        self.tasks.append({
            "id": tid,
            "status": "Open",
            "output": None,
            "required_capability": kwargs["required_capability"],
            "allowed_agents": kwargs["allowed_agents"],
        })
        return {"task_id": tid}

    def pool_list(self) -> Any:
        if self.list_wrap:
            return {"tasks": list(self.tasks)}
        return list(self.tasks)

    def pool_confirm(self, task_id: str) -> dict[str, Any]:
        if self.confirm_should_raise:
            raise RuntimeError("backend confirm failed")
        self.confirm_calls.append(task_id)
        return {"ok": True}

    def pool_fail(self, task_id: str) -> dict[str, Any]:
        if self.fail_should_raise:
            raise RuntimeError("backend fail failed")
        self.fail_calls.append(task_id)
        return {"ok": True}

    # test helpers
    def _set_status(self, task_id: str, status: str, *, output: Any = None) -> None:
        for t in self.tasks:
            if t["id"] == task_id:
                t["status"] = status
                t["output"] = output
                return
        raise AssertionError(f"task {task_id} not found")


class RateLimitError(RuntimeError):
    def __init__(self, message: str = "HTTP 429: rate limit exceeded") -> None:
        super().__init__(message)
        self.status_code = 429


# ── create ───────────────────────────────────────────────────────────

def test_create_passes_allowed_agents_and_returns_task_id():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk, default_capability="bench")
    tid = client.create(briefing="do X", target_agent_id="alpha-bench", reward=42, deadline_secs=99)
    assert tid == "task_1"
    call = sdk.post_calls[0]
    assert call["allowed_agents"] == ["alpha-bench"]
    assert call["required_capability"] == "bench"
    assert call["reward"] == 42
    assert call["deadline_secs"] == 99
    assert call["input_data"] == {"description": "do X"}


def test_create_uses_explicit_capability_over_default():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk, default_capability="general")
    client.create(briefing="x", target_agent_id="a", capability="reasoning")
    assert sdk.post_calls[0]["required_capability"] == "reasoning"


def test_create_accepts_id_field_when_no_task_id():
    class WeirdSDK(FakeSDK):
        def pool_post(self, **kwargs):
            super().pool_post(**kwargs)
            return {"id": "weird_task"}
    sdk = WeirdSDK()
    client = BackendTaskClient(sdk)
    assert client.create(briefing="x", target_agent_id="a") == "weird_task"


def test_create_raises_when_response_missing_id():
    class BrokenSDK(FakeSDK):
        def pool_post(self, **kwargs):
            return {}
    with pytest.raises(ValueError, match="task_id"):
        BackendTaskClient(BrokenSDK()).create(briefing="x", target_agent_id="a")


def test_create_retries_when_pool_post_is_rate_limited(monkeypatch):
    calls = {"n": 0}

    class RetrySDK(FakeSDK):
        def pool_post(self, **kwargs):  # type: ignore[override]
            calls["n"] += 1
            if calls["n"] < 3:
                raise RateLimitError()
            return super().pool_post(**kwargs)

    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(float(s)))

    client = BackendTaskClient(
        RetrySDK(),
        create_max_retries=4,
        create_retry_base_s=0.01,
        create_retry_max_s=0.02,
    )
    tid = client.create(briefing="x", target_agent_id="a")
    assert tid == "task_1"
    assert calls["n"] == 3
    assert sleeps == [0.01, 0.02]


def test_create_raises_after_rate_limit_retry_exhausted(monkeypatch):
    class AlwaysRateLimitSDK(FakeSDK):
        def pool_post(self, **kwargs):  # type: ignore[override]
            raise RateLimitError()

    monkeypatch.setattr(time, "sleep", lambda _s: None)
    client = BackendTaskClient(AlwaysRateLimitSDK(), create_max_retries=2, create_retry_base_s=0.01)
    with pytest.raises(RateLimitError):
        client.create(briefing="x", target_agent_id="a")


# ── get_state ────────────────────────────────────────────────────────

def test_get_state_returns_state_for_listed_task():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk)
    tid = client.create(briefing="x", target_agent_id="a")
    state = client.get_state(tid)
    assert state.task_id == tid
    assert state.status == "Open"
    assert not state.is_terminal


def test_get_state_handles_dict_wrap():
    sdk = FakeSDK()
    sdk.list_wrap = True
    client = BackendTaskClient(sdk)
    tid = client.create(briefing="x", target_agent_id="a")
    assert client.get_state(tid).status == "Open"


def test_get_state_raises_lookuperror_when_missing():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk)
    with pytest.raises(LookupError):
        client.get_state("nonexistent")


def test_get_state_terminal_flag():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk)
    tid = client.create(briefing="x", target_agent_id="a")
    sdk._set_status(tid, "Delivered", output="result")
    state = client.get_state(tid)
    assert state.is_terminal
    assert state.output == "result"


# ── wait_terminal ────────────────────────────────────────────────────

def test_wait_terminal_returns_terminal_state():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk)
    tid = client.create(briefing="x", target_agent_id="a")
    sdk._set_status(tid, "Completed", output="done")
    state = client.wait_terminal(
        tid, deadline_monotonic=time.monotonic() + 5.0, poll_interval_s=0.01,
    )
    assert state is not None
    assert state.status == "Completed"


def test_wait_terminal_returns_none_on_deadline():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk)
    tid = client.create(briefing="x", target_agent_id="a")
    # leave Open forever
    state = client.wait_terminal(
        tid, deadline_monotonic=time.monotonic() + 0.05, poll_interval_s=0.01,
    )
    assert state is None


def test_wait_terminal_returns_synthetic_cancelled_on_lookuperror():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk)
    tid = client.create(briefing="x", target_agent_id="a")
    sdk.tasks.clear()  # task vanishes
    state = client.wait_terminal(
        tid, deadline_monotonic=time.monotonic() + 5.0, poll_interval_s=0.01,
    )
    assert state is not None
    assert state.status == "Cancelled"


def test_wait_terminal_invokes_on_tick():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk)
    tid = client.create(briefing="x", target_agent_id="a")
    seen: list[str] = []
    sdk._set_status(tid, "Delivered", output="ok")
    client.wait_terminal(
        tid, deadline_monotonic=time.monotonic() + 5.0, poll_interval_s=0.01,
        on_tick=lambda s: seen.append(s.status),
    )
    assert seen == ["Delivered"]


def test_wait_terminal_swallows_on_tick_exceptions():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk)
    tid = client.create(briefing="x", target_agent_id="a")
    sdk._set_status(tid, "Completed", output="ok")
    # on_tick raising must not break the wait
    state = client.wait_terminal(
        tid, deadline_monotonic=time.monotonic() + 5.0, poll_interval_s=0.01,
        on_tick=lambda s: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert state is not None and state.status == "Completed"


# ── confirm / force_fail ──────────────────────────────────────────────

def test_confirm_returns_true_on_success():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk)
    assert client.confirm("task_x") is True
    assert sdk.confirm_calls == ["task_x"]


def test_confirm_swallows_exception_returns_false():
    sdk = FakeSDK()
    sdk.confirm_should_raise = True
    client = BackendTaskClient(sdk)
    assert client.confirm("task_x") is False


def test_force_fail_swallows_exception_returns_false():
    sdk = FakeSDK()
    sdk.fail_should_raise = True
    client = BackendTaskClient(sdk)
    assert client.force_fail("task_x") is False


def test_force_fail_returns_true_on_success():
    sdk = FakeSDK()
    client = BackendTaskClient(sdk)
    assert client.force_fail("task_y") is True
    assert sdk.fail_calls == ["task_y"]


# ── state_to_sentinel (the 5-row table) ──────────────────────────────

def test_state_to_sentinel_delivered():
    s = BackendTaskState(task_id="t", status="Delivered", output="ok", raw={})
    kind, _ = state_to_sentinel(s)
    assert kind == "done"


def test_state_to_sentinel_completed():
    s = BackendTaskState(task_id="t", status="Completed", output="ok", raw={})
    assert state_to_sentinel(s)[0] == "done"


def test_state_to_sentinel_failed_with_output_is_failed():
    s = BackendTaskState(task_id="t", status="Failed", output="partial", raw={})
    kind, reason = state_to_sentinel(s)
    assert kind == "failed"
    assert "execute(success=False)" in reason


def test_state_to_sentinel_failed_without_output_is_give_up():
    s = BackendTaskState(task_id="t", status="Failed", output=None, raw={})
    kind, reason = state_to_sentinel(s)
    assert kind == "give_up"
    assert "pool_abandon" in reason


def test_state_to_sentinel_failed_empty_string_is_give_up():
    s = BackendTaskState(task_id="t", status="Failed", output="", raw={})
    assert state_to_sentinel(s)[0] == "give_up"


def test_state_to_sentinel_cancelled():
    s = BackendTaskState(task_id="t", status="Cancelled", output=None, raw={})
    assert state_to_sentinel(s)[0] == "give_up"


def test_state_to_sentinel_raises_on_non_terminal():
    s = BackendTaskState(task_id="t", status="Open", output=None, raw={})
    with pytest.raises(ValueError, match="non-terminal"):
        state_to_sentinel(s)
