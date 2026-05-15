from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "l1_pilot_001_contract_runner.py"
spec = importlib.util.spec_from_file_location("l1_pilot_001_contract_runner", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class _Response:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def test_http_client_bootstraps_demo_login_token(monkeypatch) -> None:
    requests = []

    def fake_urlopen(request, timeout=0):  # noqa: ANN001
        requests.append(request)
        if request.full_url == "http://backend/api/v1/auth/demo-login":
            return _Response({"data": {"token": "demo-token"}})
        assert dict(request.header_items()).get("Authorization") == "Bearer demo-token"
        return _Response([])

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)

    client = module.HttpJsonClient("http://backend", demo_login_agent_id="runner")

    assert client.get("/api/v1/a2a/agents") == []
    assert [request.full_url for request in requests] == [
        "http://backend/api/v1/auth/demo-login",
        "http://backend/api/v1/a2a/agents",
    ]


def test_task_collection_accepts_wrapped_and_legacy_list_shapes() -> None:
    wrapped = {"tasks": [{"id": "t1"}, {"id": "t2"}], "total": 2}
    legacy = [{"id": "t3"}]

    assert [task["id"] for task in module._task_collection(wrapped)] == ["t1", "t2"]
    assert [task["id"] for task in module._task_collection(legacy)] == ["t3"]
    assert module._task_collection({"unexpected": []}) == []


def test_latest_matching_agent_requires_synced_capabilities() -> None:
    cards = [
        {
            "did": "old",
            "name": "alpha_planner",
            "updated_at": "2026-05-15T00:00:00Z",
            "capabilities": [{"id": "general"}],
        },
        {
            "did": "new",
            "name": "alpha_planner",
            "updated_at": "2026-05-15T00:01:00Z",
            "capabilities": [
                {"id": "planning"},
                {"id": "documentation"},
                {"id": "boundary_analysis"},
            ],
        },
    ]

    selected = module._latest_matching_agent(
        cards,
        "alpha_planner",
        {"planning", "documentation", "boundary_analysis"},
    )

    assert selected["did"] == "new"


def test_latest_matching_agent_can_exclude_preexisting_dids() -> None:
    cards = [
        {
            "did": "old",
            "name": "beta_implementer",
            "updated_at": "2026-05-15T00:02:00Z",
            "capabilities": [
                {"id": "implementation"},
                {"id": "documentation"},
                {"id": "repair"},
            ],
        },
        {
            "did": "new",
            "name": "beta_implementer",
            "updated_at": "2026-05-15T00:01:00Z",
            "capabilities": [
                {"id": "implementation"},
                {"id": "documentation"},
                {"id": "repair"},
            ],
        },
    ]

    selected = module._latest_matching_agent(
        cards,
        "beta_implementer",
        {"implementation", "documentation", "repair"},
        excluded_dids={"old"},
    )

    assert selected["did"] == "new"


def test_summarise_task_preserves_contract_failure_surface() -> None:
    task = {
        "id": "task-1",
        "status": "Failed",
        "required_capability": "review",
        "claimed_by": "did:gamma",
        "failure_reason": "worker_failed",
        "input": {
            "delivery_contract": {
                "required_sections": ["verdict", "问题清单", "H3"],
                "h3_must_remain_blocked": True,
            }
        },
        "output": None,
    }

    summary = module._summarise_task(task)

    assert summary["id"] == "task-1"
    assert summary["status"] == "Failed"
    assert summary["failure_reason"] == "worker_failed"
    assert summary["delivery_contract"]["h3_must_remain_blocked"] is True
    assert summary["has_output"] is False


def test_split_failed_tasks_separates_chain_from_historical_pool_failures() -> None:
    pool_tasks = [
        {"id": "chain-failed", "status": "Failed", "output": None},
        {"id": "old-failed", "status": "Failed", "output": None},
        {"id": "chain-ok", "status": "Delivered", "output": "ok"},
    ]

    chain_failed, historical_failed = module._split_failed_tasks(
        pool_tasks,
        {"chain-failed", "chain-ok"},
    )

    assert [task["id"] for task in chain_failed] == ["chain-failed"]
    assert [task["id"] for task in historical_failed] == ["old-failed"]


def test_wait_for_task_uses_auto_fallback_once(tmp_path, monkeypatch) -> None:
    class Client:
        calls = 0

        def get(self, _path: str) -> dict:
            self.calls += 1
            status = "Delivered" if self.calls >= 3 else "Open"
            return {"task": {"id": "task-1", "status": status}}

    fallbacks: list[str] = []
    tick = {"value": 0.0}

    def monotonic() -> float:
        current = tick["value"]
        tick["value"] += 1.0
        return current

    monkeypatch.setattr(module.time, "monotonic", monotonic)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    task, wake = module._wait_for_task(
        Client(),
        "task-1",
        timeout=10,
        poll_interval=0,
        snapshots_dir=tmp_path,
        fallback_after=1,
        fallback=lambda: fallbacks.append("restart"),
    )

    assert task["status"] == "Delivered"
    assert wake["fallback_used"] is True
    assert fallbacks == ["restart"]
