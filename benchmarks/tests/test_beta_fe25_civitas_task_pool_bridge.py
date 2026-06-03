from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load("beta_fe25_civitas_task_pool_bridge", SCRIPTS / "beta_fe25_civitas_task_pool_bridge.py")


def test_beta_fe25_bridge_posts_claims_and_delivers_tasks(tmp_path: Path) -> None:
    responses = []
    for participant_id in ("deepseek-api-agent", "hermes-cli-agent", "local-gpu-agent"):
        response_file = _write_response(tmp_path / f"{participant_id}.md", f"{participant_id} proposal")
        record_path = _write_response_record(tmp_path / f"{participant_id}.record.json", participant_id, response_file)
        responses.append({"path": str(record_path), "sha256": _sha256(record_path)})
    fe2_path = _write_fe2_reconciliation(tmp_path / "fe2.json", responses)
    client = FakeClient()

    summary = module.run_bridge(
        client=client,
        fe2_reconciliation_path=fe2_path,
        output_root=tmp_path / "run",
        confirm_deliveries=True,
        backend_url="http://backend",
    )

    assert summary["passed"] is True
    assert summary["task_receipt_count"] == 3
    assert summary["claim_observed_count"] == 3
    assert summary["delivery_observed_count"] == 3
    assert summary["full_autonomous_agent_runner_execution_observed"] is False
    assert summary["boundary"]["frontend_code_modified"] is False
    assert client.calls.count("healthz") == 1
    assert client.call_kinds["/api/v1/a2a/quickstart"] == 4
    assert client.call_kinds["/api/v1/a2a/pool/post"] == 3
    assert client.call_kinds["/api/v1/a2a/pool/claim"] == 3
    assert client.call_kinds["/api/v1/a2a/task/execute"] == 3
    assert client.call_kinds["/api/v1/a2a/pool/confirm"] == 3


def test_beta_fe25_bridge_blocks_non_ready_fe2(tmp_path: Path) -> None:
    fe2_path = _write_fe2_reconciliation(tmp_path / "fe2.json", [])
    payload = json.loads(fe2_path.read_text(encoding="utf-8"))
    payload["passed"] = False
    fe2_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    try:
        module.run_bridge(
            client=FakeClient(),
            fe2_reconciliation_path=fe2_path,
            output_root=tmp_path / "run",
        )
    except ValueError as exc:
        assert "FE-2 reconciliation must be passed" in str(exc)
    else:
        raise AssertionError("expected FE-2.5 bridge to block non-ready FE-2 evidence")


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.call_kinds: dict[str, int] = {}
        self.did_count = 0
        self.task_count = 0
        self.tasks: dict[str, dict[str, Any]] = {}

    def healthz(self) -> None:
        self.calls.append("healthz")

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        kind = path if not path.startswith("/api/v1/a2a/pool/confirm/") else "/api/v1/a2a/pool/confirm"
        self.call_kinds[kind] = self.call_kinds.get(kind, 0) + 1
        if path == "/api/v1/a2a/quickstart":
            self.did_count += 1
            alias = payload.get("alias") or f"agent-{self.did_count}"
            did = f"did:civ:test:{alias}"
            return {"agent": {"did": did, "alias": alias, "name": payload.get("name")}}
        if path == "/api/v1/a2a/pool/post":
            self.task_count += 1
            task_id = f"task-{self.task_count}"
            self.tasks[task_id] = {
                "id": task_id,
                "requester": payload["requester"],
                "required_capability": payload["required_capability"],
                "status": "Open",
                "claimed_by": None,
                "posted_at": "2026-06-03T00:00:00Z",
                "claimed_at": None,
                "delivered_at": None,
                "challenge_deadline_at": None,
                "challenge_window_secs": None,
                "output": None,
            }
            return {"task_id": task_id, "status": "open"}
        if path == "/api/v1/a2a/pool/claim":
            task = self.tasks[payload["task_id"]]
            task["status"] = "Claimed"
            task["claimed_by"] = payload["agent_id"]
            task["claimed_at"] = "2026-06-03T00:00:01Z"
            return {"claimed": True, "task": task}
        if path == "/api/v1/a2a/task/execute":
            task = self.tasks[payload["task_id"]]
            task["status"] = "Delivered"
            task["output"] = payload["output"]
            task["delivered_at"] = "2026-06-03T00:00:02Z"
            task["challenge_deadline_at"] = "2026-06-03T00:01:02Z"
            task["challenge_window_secs"] = 60
            return {"task_id": payload["task_id"], "status": "delivered"}
        if path.startswith("/api/v1/a2a/pool/confirm/"):
            task_id = path.rsplit("/", 1)[-1]
            self.tasks[task_id]["status"] = "Completed"
            return {"task_id": task_id, "status": "completed"}
        raise AssertionError(f"unexpected POST {path}")

    def get(self, path: str) -> dict[str, Any]:
        if path.startswith("/api/v1/a2a/pool/tasks/"):
            task_id = path.rsplit("/", 1)[-1]
            return {"task": self.tasks[task_id]}
        raise AssertionError(f"unexpected GET {path}")


def _write_fe2_reconciliation(path: Path, response_refs: list[dict[str, str]]) -> Path:
    payload = {
        "schema_version": "beta-fe2-patch-proposal-reconciliation:v1",
        "passed": True,
        "decision": "beta_fe2_operator_decision_ready",
        "patch_slice_id": "task_read_adapter_extraction",
        "unique_participant_count": 3,
        "hard_reject_observed": False,
        "response_records": response_refs,
        "collaboration_boundary": {
            "direct_mutation_allowed": False,
            "apply_allowed": False,
            "commit_allowed": False,
            "push_allowed": False,
            "merge_allowed": False,
            "deploy_allowed": False,
            "production_runtime_execution_allowed": False,
            "production_receipt_write_allowed": False,
        },
        "h3_boundary": {"h3_remains_blocked": True, "h3_production_readiness_claimed": False},
    }
    return _write_json(path, payload)


def _write_response_record(path: Path, participant_id: str, response_file: Path) -> Path:
    payload = {
        "schema_version": "beta-fe2-agent-proposal-response-record:v1",
        "participant_id": participant_id,
        "recommendation": "proceed",
        "response_file": {"path": str(response_file), "sha256": _sha256(response_file)},
    }
    return _write_json(path, payload)


def _write_response(path: Path, content: str) -> Path:
    path.write_text(f"# Response\n\n{content}\n", encoding="utf-8")
    return path


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()
