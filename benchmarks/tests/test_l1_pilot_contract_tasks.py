from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "l1_pilot_001_contract_tasks.py"
spec = importlib.util.spec_from_file_location("l1_pilot_001_contract_tasks", SCRIPT)
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
    monkeypatch.delenv("CIVITASOS_SERVICE_TOKEN_SECRET", raising=False)
    monkeypatch.delenv("L1_SERVICE_TOKEN_SECRET", raising=False)
    requests = []

    def fake_urlopen(request, timeout=0):  # noqa: ANN001
        requests.append(request)
        if request.full_url == "http://backend/api/v1/auth/demo-login":
            return _Response({"data": {"token": "demo-token"}})
        assert dict(request.header_items()).get("Authorization") == "Bearer demo-token"
        return _Response([])

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)

    client = module.HttpJsonClient("http://backend", demo_login_agent_id="tasks")

    assert client.get("/api/v1/a2a/agents") == []
    assert [request.full_url for request in requests] == [
        "http://backend/api/v1/auth/demo-login",
        "http://backend/api/v1/a2a/agents",
    ]


def test_http_client_requires_service_token_without_demo_login_fallback(monkeypatch) -> None:
    monkeypatch.delenv("CIVITASOS_SERVICE_TOKEN_SECRET", raising=False)
    monkeypatch.delenv("L1_SERVICE_TOKEN_SECRET", raising=False)
    monkeypatch.setenv("L1_REQUIRE_SERVICE_TOKEN", "1")

    def fake_urlopen(_request, timeout=0):  # noqa: ANN001
        raise AssertionError("strict service-token mode must not call demo-login")

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)

    client = module.HttpJsonClient("http://backend", demo_login_agent_id="tasks")

    with pytest.raises(RuntimeError, match="L1_REQUIRE_SERVICE_TOKEN=1"):
        client.get("/api/v1/a2a/agents")


def test_http_client_prefers_scoped_service_token(monkeypatch) -> None:
    requests = []
    monkeypatch.setenv("L1_SERVICE_TOKEN_SECRET", "service-secret")
    monkeypatch.setenv("L1_SERVICE_ID", "l1-tasks")

    def fake_urlopen(request, timeout=0):  # noqa: ANN001
        requests.append(request)
        if request.full_url == "http://backend/api/v1/auth/service-token":
            body = json.loads(request.data.decode("utf-8"))
            assert body["service_id"] == "l1-tasks"
            assert body["secret"] == "service-secret"
            assert body["scopes"] == ["agents:read", "agents:write", "pool:post", "pool:read", "pool:claim", "pool:write", "webhooks:write"]
            return _Response({"data": {"token": "service-token"}})
        assert dict(request.header_items()).get("Authorization") == "Bearer service-token"
        return _Response([])

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)

    client = module.HttpJsonClient("http://backend", demo_login_agent_id="tasks")

    assert client.get("/api/v1/a2a/agents") == []
    assert [request.full_url for request in requests] == [
        "http://backend/api/v1/auth/service-token",
        "http://backend/api/v1/a2a/agents",
    ]


def test_alpha_payload_has_h3_delivery_contract() -> None:
    payload = module.build_alpha_payload(requester="did:req", alpha_did="did:alpha")

    assert payload["requester"] == "did:req"
    assert payload["allowed_agents"] == ["did:alpha"]
    contract = payload["input"]["delivery_contract"]
    assert contract["h3_must_remain_blocked"] is True
    assert "任务边界" in contract["required_sections"]
    assert "H.3 remains blocked" in payload["input"]["boundary"]


def test_beta_payload_carries_alpha_output_and_replay_guard() -> None:
    payload = module.build_beta_payload(
        requester="did:alpha",
        beta_did="did:beta",
        alpha_task_id="task-alpha",
        alpha_output={"result": "alpha plan"},
    )

    assert payload["requester"] == "did:alpha"
    assert payload["required_capability"] == "implementation"
    assert payload["allowed_agents"] == ["did:beta"]
    assert payload["input"]["upstream_task_id"] == "task-alpha"
    assert payload["input"]["alpha_output"] == '{"result": "alpha plan"}'
    assert payload["input"]["delivery_contract"]["forbid_upstream_replay"] is True
    assert "与上游不同之处" in payload["input"]["delivery_contract"]["required_sections"]


def test_gamma_payload_requires_review_issue_list_and_h3_boundary() -> None:
    payload = module.build_gamma_payload(
        requester="did:beta",
        gamma_did="did:gamma",
        alpha_task_id="task-alpha",
        beta_task_id="task-beta",
        alpha_output="alpha",
        beta_output="beta",
    )

    assert payload["requester"] == "did:beta"
    assert payload["required_capability"] == "review"
    assert payload["allowed_agents"] == ["did:gamma"]
    assert payload["input"]["delivery_contract"]["review_must_have_issue_list"] is True
    assert payload["input"]["delivery_contract"]["h3_must_remain_blocked"] is True
    assert "verdict" in payload["input"]["delivery_contract"]["required_sections"]


def test_repair_payload_requires_operator_approval_metadata() -> None:
    payload = module.build_repair_payload(
        requester="did:req",
        repair_did="did:repair",
        failed_task_id="task-failed",
        failed_task={
            "status": "Failed",
            "failure_reason": "delivery_contract_violation",
            "input": {
                "delivery_contract": {
                    "required_sections": ["H3"],
                    "h3_must_remain_blocked": True,
                }
            },
            "delivery_contract_verification": {
                "repair_suggestions": ["Add missing H3 section"],
            },
        },
        operator_id="operator-1",
    )

    assert payload["requester"] == "did:req"
    assert payload["required_capability"] == "repair"
    assert payload["allowed_agents"] == ["did:repair"]
    assert payload["input"]["source_failed_task_id"] == "task-failed"
    assert payload["input"]["repair_suggestions"] == ["Add missing H3 section"]
    assert payload["input"]["operator_approval"]["approved"] is True
    assert payload["input"]["operator_approval"]["approved_by"] == "operator-1"
    assert payload["input"]["delivery_contract"]["forbid_upstream_replay"] is True
    assert payload["input"]["delivery_contract"]["h3_must_remain_blocked"] is True


def test_post_repair_fails_closed_without_operator_approval() -> None:
    args = module.argparse.Namespace(operator_approved_repair=False)
    agents = {
        "requester": module.AgentRef(role="requester", did="did:req", alias=None, name="requester"),
        "beta": module.AgentRef(role="beta", did="did:beta", alias=None, name="beta"),
    }

    with pytest.raises(SystemExit, match="failed tasks are not auto-retried"):
        module._post_repair(object(), args, {}, agents, "task-failed")


def test_extract_repair_suggestions_falls_back_to_failure_reason() -> None:
    suggestions = module._extract_repair_suggestions({
        "status": "Failed",
        "failure_reason": "missing_required_section",
    })

    assert suggestions == [
        "Inspect failure_reason=missing_required_section and produce a contract-shaped repair artifact."
    ]
