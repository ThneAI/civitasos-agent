from __future__ import annotations

import importlib.util
import json
import argparse
import sys
from pathlib import Path

import pytest


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

    client = module.HttpJsonClient("http://backend", demo_login_agent_id="runner")

    assert client.get("/api/v1/a2a/agents") == []
    assert client.auth_context()["auth_method"] == "demo_login"
    assert client.auth_context()["production_allowed"] is False
    assert client.auth_context()["evidence_allowed"] is False
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

    client = module.HttpJsonClient("http://backend", demo_login_agent_id="runner")

    with pytest.raises(RuntimeError, match="L1_REQUIRE_SERVICE_TOKEN=1"):
        client.get("/api/v1/a2a/agents")
    assert client.auth_context()["auth_method"] == "missing_required_service_token"
    assert client.auth_context()["require_service_token"] is True


def test_http_client_prefers_scoped_service_token(monkeypatch) -> None:
    requests = []
    monkeypatch.setenv("L1_SERVICE_TOKEN_SECRET", "service-secret")
    monkeypatch.setenv("L1_SERVICE_ID", "l1-runner")

    def fake_urlopen(request, timeout=0):  # noqa: ANN001
        requests.append(request)
        if request.full_url == "http://backend/api/v1/auth/service-token":
            body = json.loads(request.data.decode("utf-8"))
            assert body["service_id"] == "l1-runner"
            assert body["secret"] == "service-secret"
            assert body["scopes"] == ["agents:read", "agents:write", "pool:post", "pool:read", "pool:claim", "pool:write", "webhooks:write"]
            return _Response({
                "data": {
                    "token": "service-token",
                    "auth_method": "service_token",
                    "service_id": "l1-runner",
                    "scopes": body["scopes"],
                    "production_allowed": False,
                    "evidence_allowed": False,
                }
            })
        assert dict(request.header_items()).get("Authorization") == "Bearer service-token"
        return _Response([])

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)

    client = module.HttpJsonClient("http://backend", demo_login_agent_id="runner")

    assert client.get("/api/v1/a2a/agents") == []
    assert client.auth_context()["auth_method"] == "service_token"
    assert client.auth_context()["service_id"] == "l1-runner"
    assert client.auth_context()["scopes"] == ["agents:read", "agents:write", "pool:post", "pool:read", "pool:claim", "pool:write", "webhooks:write"]
    assert [request.full_url for request in requests] == [
        "http://backend/api/v1/auth/service-token",
        "http://backend/api/v1/a2a/agents",
    ]


def test_evidence_includes_auth_context(tmp_path) -> None:
    class Client:
        def auth_context(self) -> dict:
            return {
                "auth_method": "demo_login",
                "production_allowed": False,
                "evidence_allowed": False,
            }

        def get(self, path: str) -> dict:
            if path == "/api/v1/a2a/pool/tasks":
                return {"tasks": []}
            task_id = path.rsplit("/", 1)[-1]
            status = "Completed" if task_id == "a" else "Delivered"
            return {"task": {"id": task_id, "status": status, "output": "ok"}}

    (tmp_path / "task_chain.json").write_text(
        '{"alpha_task_id":"a","beta_task_id":"b","gamma_task_id":"c"}',
        encoding="utf-8",
    )
    agents = {
        "requester": module.AgentRef(did="did:req", alias=None, name="requester"),
        "alpha": module.AgentRef(did="did:a", alias=None, name="alpha"),
        "beta": module.AgentRef(did="did:b", alias=None, name="beta"),
        "gamma": module.AgentRef(did="did:g", alias=None, name="gamma"),
    }

    wake_security = {
        "require_signed_wake": True,
        "callback_secret_configured": True,
    }

    evidence = module._collect_evidence(Client(), tmp_path, agents, [], wake_security)

    assert evidence["auth_context"]["auth_method"] == "demo_login"
    assert evidence["auth_context"]["production_allowed"] is False
    assert evidence["auth_context"]["evidence_allowed"] is False
    assert evidence["wake_security"]["require_signed_wake"] is True
    assert evidence["wake_security"]["callback_secret_configured"] is True
    assert evidence["event_wake_evidence"]["schema_version"] == "l1-event-wake-evidence:v1"
    assert evidence["chain_passed"] is True


def test_wake_security_context_records_signed_wake_requirements(monkeypatch) -> None:
    args = argparse.Namespace(wake_mode="event", require_signed_wake=True)
    monkeypatch.setenv("CIVITASOS_WAKE_CALLBACK_SECRET", "secret")

    context = module._wake_security_context(args)

    assert context["wake_mode"] == "event"
    assert context["require_signed_wake"] is True
    assert context["callback_secret_configured"] is True
    assert context["compatibility_mode"] is False
    assert context["signature_scheme"] == "hmac-sha256(issuer.timestamp.raw_body)"
    assert context["expected_issuer"] == "civitasos-backend"


def test_event_wake_evidence_summarises_role_logs(tmp_path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "alpha_planner.log").write_text(
        "\n".join([
            "Service-token bootstrap token acquired",
            "DID auth token bootstrapped",
            "WAKE received: event=task.posted task_id=t-alpha issuer=civitasos-backend",
            "Wake action bias accepted: action=pool_claim task_id=t-alpha source_event=task.posted",
            "Rule 'auto_claim_matching' fired: pool_claim",
            "WAKE received: event=task.claimed task_id=t-alpha issuer=civitasos-backend",
            "WAKE received: event=task.delivered task_id=t-alpha issuer=civitasos-backend",
        ]),
        encoding="utf-8",
    )

    evidence = module._event_wake_evidence(
        tmp_path,
        [{
            "role": "alpha",
            "task_id": "t-alpha",
            "terminal_status": "Delivered",
            "claimed_by": "did:alpha",
            "wake": {"fallback_used": False},
        }],
    )

    assert evidence["wake_event_counts"] == {
        "task_posted": 1,
        "task_claimed": 1,
        "task_delivered": 1,
    }
    assert evidence["rule_pool_claim_count"] == 1
    assert evidence["wake_action_bias_pool_claim_count"] == 1
    assert evidence["service_token_bootstrap_count"] == 1
    assert evidence["did_auth_bootstrap_count"] == 1
    stage = evidence["stage_evidence"][0]
    assert stage["task_posted_wake_observed"] is True
    assert stage["task_claimed_wake_observed"] is True
    assert stage["task_delivered_wake_observed"] is True
    assert stage["rule_pool_claim_observed"] is True
    assert stage["wake_action_bias_pool_claim_observed"] is True
    assert stage["fallback_used"] is False


def test_task_collection_accepts_wrapped_and_legacy_list_shapes() -> None:
    wrapped = {"tasks": [{"id": "t1"}, {"id": "t2"}], "total": 2}
    legacy = [{"id": "t3"}]

    assert [task["id"] for task in module._task_collection(wrapped)] == ["t1", "t2"]
    assert [task["id"] for task in module._task_collection(legacy)] == ["t3"]
    assert module._task_collection({"unexpected": []}) == []


def test_repair_suggestion_audit_refs_collects_failed_task_hints() -> None:
    refs = module._repair_suggestion_audit_refs(
        {
            "beta_task_id": {
                "id": "task-beta",
                "failure_reason": "delivery_contract_violation",
                "repair_suggestions": ["Add missing H3 section"],
            }
        },
        [],
        [],
    )

    assert refs["schema_version"] == "l1-repair-suggestion-audit-refs:v1"
    assert refs["record_count"] == 1
    assert refs["records"][0]["task_id"] == "task-beta"
    assert refs["records"][0]["repair_suggestions"] == ["Add missing H3 section"]
    assert refs["records"][0]["audit_ref_kind"] == "delivery_contract_repair_suggestions"


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
