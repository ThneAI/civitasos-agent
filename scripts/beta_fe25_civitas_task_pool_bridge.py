#!/usr/bin/env python3
"""Bridge Beta-FE-2 proposal evidence through the CivitasOS task pool.

Beta-FE-2.5 is a correction step: previous FE-1/FE-2 evidence was collected by
terminal orchestration. This runner replays accepted FE-2 Agent responses through
real CivitasOS A2A task-pool state transitions: quickstart identity, task post,
claim, execute/deliver, task readback, and optional requester confirmation.

It still does not modify civitasos-frontend and does not claim full autonomous
Agent-runner execution. The mediation level is task-pool delivery bridge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SUMMARY_SCHEMA = "beta-fe25-civitas-task-pool-bridge-summary:v1"
TASK_RECEIPT_SCHEMA = "beta-fe25-civitas-task-pool-delivery-receipt:v1"
FE2_RECONCILIATION_SCHEMA = "beta-fe2-patch-proposal-reconciliation:v1"
DEFAULT_BACKEND_URL = "http://127.0.0.1:8099"
DEFAULT_REQUESTER_ALIAS = "beta_fe25_frontend_operator"
PARTICIPANT_ALIASES = {
    "deepseek-api-agent": "beta_fe25_deepseek_worker",
    "hermes-cli-agent": "beta_fe25_hermes_worker",
    "local-gpu-agent": "beta_fe25_local_gpu_worker",
    "claude-cli-agent": "beta_fe25_claude_worker",
}
NON_CLAIMS = (
    "beta_fe25_bridge_uses_civitasos_task_pool_state",
    "beta_fe25_bridge_does_not_modify_frontend_repo",
    "beta_fe25_bridge_does_not_claim_full_autonomous_agent_runner_execution",
    "beta_fe25_bridge_does_not_authorize_apply_commit_push_merge_or_deploy",
    "beta_fe25_bridge_does_not_claim_h3_production_readiness",
    "beta_fe25_bridge_does_not_write_production_receipts",
)
FALSE_BOUNDARY_FIELDS = (
    "frontend_code_modified",
    "apply_allowed",
    "commit_allowed",
    "push_allowed",
    "merge_allowed",
    "deploy_allowed",
    "production_runtime_execution_allowed",
    "production_receipt_write_allowed",
)


class HttpJsonClient:
    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str | None = None,
        demo_login_agent_id: str = "beta_fe25_bridge",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token or os.getenv("CIVITASOS_BEARER_TOKEN") or None
        self.demo_login_agent_id = demo_login_agent_id
        self.demo_login_attempted = False

    def healthz(self) -> None:
        request = urllib.request.Request(self._url("/healthz"), method="GET")
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()

    def get(self, path: str) -> Any:
        request = urllib.request.Request(self._url(path), headers=self._headers(), method="GET")
        return self._open_json(request)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self._url(path),
            data=body,
            headers=self._headers(content_type=True),
            method="POST",
        )
        return self._open_json(request)

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path if path.startswith('/') else '/' + path}"

    def _headers(self, *, content_type: bool = False) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = "application/json"
        token = self._auth_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _auth_token(self) -> str | None:
        if self.bearer_token:
            return self.bearer_token
        if self.demo_login_attempted:
            return None
        self.demo_login_attempted = True
        payload = self._open_json(
            urllib.request.Request(
                self._url("/api/v1/auth/demo-login"),
                data=json.dumps({"agent_id": self.demo_login_agent_id}).encode("utf-8"),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                method="POST",
            )
        )
        token = payload.get("token") if isinstance(payload, dict) else None
        data = payload.get("data") if isinstance(payload, dict) else None
        if not token and isinstance(data, dict):
            token = data.get("token")
        if token:
            self.bearer_token = str(token)
        return self.bearer_token

    @staticmethod
    def _open_json(request: urllib.request.Request) -> Any:
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {request.full_url}: {detail}") from exc
        if not raw:
            return None
        return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--fe2-reconciliation", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--confirm-deliveries", action="store_true")
    parser.add_argument("--demo-login-agent-id", default="beta_fe25_bridge")
    args = parser.parse_args(argv)

    client = HttpJsonClient(args.backend_url, demo_login_agent_id=args.demo_login_agent_id)
    summary = run_bridge(
        client=client,
        fe2_reconciliation_path=Path(args.fe2_reconciliation),
        output_root=Path(args.output_root),
        confirm_deliveries=bool(args.confirm_deliveries),
        backend_url=args.backend_url,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary.get("passed") is True else 1


def run_bridge(
    *,
    client: HttpJsonClient,
    fe2_reconciliation_path: Path,
    output_root: Path,
    confirm_deliveries: bool = False,
    backend_url: str = DEFAULT_BACKEND_URL,
) -> dict[str, Any]:
    failures: list[str] = []
    output_root.mkdir(parents=True, exist_ok=True)
    fe2 = _read_json(fe2_reconciliation_path, failures, "FE-2 reconciliation")
    _validate_fe2_reconciliation(fe2, failures)
    if failures:
        raise ValueError(f"Beta-FE-2.5 bridge blocked: {failures}")

    client.healthz()
    alias_suffix = _safe_alias(output_root.name)[-20:]
    requester = _quickstart_agent(
        client,
        alias=f"{DEFAULT_REQUESTER_ALIAS}_{alias_suffix}",
        name="Beta FE2.5 Frontend Operator",
        description="Requester identity for CivitasOS-mediated frontend patch proposal tasks",
        output_path=output_root / "requester_quickstart.json",
    )

    receipts: list[dict[str, Any]] = []
    for response_ref in fe2.get("response_records", []):
        record_path = Path(str(response_ref.get("path") or ""))
        record = _read_json(record_path, failures, f"response record {record_path}")
        participant_id = str(record.get("participant_id") or "")
        base_alias = PARTICIPANT_ALIASES.get(participant_id, _safe_alias(f"beta_fe25_{participant_id}"))
        alias = f"{base_alias}_{alias_suffix}"
        worker = _quickstart_agent(
            client,
            alias=alias,
            name=f"Beta FE2.5 Worker {participant_id}",
            description=f"CivitasOS task-pool worker identity for {participant_id}",
            output_path=output_root / f"{participant_id}.quickstart.json",
        )
        receipt = _post_claim_deliver(
            client=client,
            requester=requester,
            worker=worker,
            fe2_reconciliation_path=fe2_reconciliation_path,
            fe2=fe2,
            response_record_path=record_path,
            response_record=record,
            output_root=output_root,
            confirm_delivery=confirm_deliveries,
        )
        receipts.append(receipt)
        _write_json(output_root / f"{participant_id}.task_receipt.json", receipt)

    statuses = [str(receipt.get("final_task", {}).get("status") or "") for receipt in receipts]
    passed = bool(receipts) and all(status in {"Delivered", "Completed"} for status in statuses)
    summary = {
        "schema_version": SUMMARY_SCHEMA,
        "checked_at": _now(),
        "passed": passed,
        "decision": "beta_fe25_civitas_task_pool_bridge_passed" if passed else "blocked",
        "failure_reasons": [] if passed else ["all task receipts must end in Delivered or Completed"],
        "backend_url": backend_url,
        "mediation_level": "civitasos_task_pool_delivery_bridge",
        "full_autonomous_agent_runner_execution_observed": False,
        "source_fe2_reconciliation": _artifact_ref(fe2_reconciliation_path),
        "requester": requester,
        "task_receipt_count": len(receipts),
        "task_receipts": [_artifact_ref(output_root / f"{receipt['participant_id']}.task_receipt.json") for receipt in receipts],
        "task_ids": [receipt.get("task_id") for receipt in receipts],
        "final_statuses": statuses,
        "claim_observed_count": sum(1 for receipt in receipts if receipt.get("claim_observed") is True),
        "delivery_observed_count": sum(1 for receipt in receipts if receipt.get("delivery_observed") is True),
        "challenge_window_observed_count": sum(1 for receipt in receipts if receipt.get("challenge_window_observed") is True),
        "confirm_deliveries": confirm_deliveries,
        "boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    _write_json(output_root / "beta_fe25_civitas_task_pool_bridge_summary.json", summary)
    return summary


def _validate_fe2_reconciliation(fe2: Any, failures: list[str]) -> None:
    if not isinstance(fe2, dict):
        failures.append("FE-2 reconciliation must be an object")
        return
    if fe2.get("schema_version") != FE2_RECONCILIATION_SCHEMA:
        failures.append(f"FE-2 reconciliation schema_version must be {FE2_RECONCILIATION_SCHEMA}")
    if fe2.get("passed") is not True:
        failures.append("FE-2 reconciliation must be passed")
    if fe2.get("decision") != "beta_fe2_operator_decision_ready":
        failures.append("FE-2 reconciliation must be operator-decision-ready")
    if int(fe2.get("unique_participant_count") or 0) < 3:
        failures.append("FE-2 unique participant count must be >= 3")
    if fe2.get("hard_reject_observed") is not False:
        failures.append("FE-2 hard_reject_observed must be false")
    _validate_boundary(fe2.get("collaboration_boundary"), failures, "FE-2 collaboration_boundary")
    h3 = fe2.get("h3_boundary")
    if not isinstance(h3, dict) or h3.get("h3_remains_blocked") is not True:
        failures.append("FE-2 h3_boundary must keep H.3 blocked")


def _quickstart_agent(
    client: HttpJsonClient,
    *,
    alias: str,
    name: str,
    description: str,
    output_path: Path,
) -> dict[str, Any]:
    result = client.post(
        "/api/v1/a2a/quickstart",
        {
            "public_key": _generate_public_key_hex(),
            "alias": alias,
            "name": name,
            "endpoint": f"http://127.0.0.1:65535/{alias}",
            "description": description,
        },
    )
    _write_json(output_path, result if isinstance(result, dict) else {"result": result})
    agent = result.get("agent", {}) if isinstance(result, dict) else {}
    did = str(agent.get("did") or "")
    if not did:
        raise RuntimeError(f"quickstart response missing DID for {alias}: {result}")
    return {
        "did": did,
        "alias": agent.get("alias") or alias,
        "name": agent.get("name") or name,
        "quickstart_ref": _artifact_ref(output_path),
    }


def _generate_public_key_hex() -> str:
    try:
        from civitasos import CivitasAgent  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("civitasos SDK is required to generate a valid Ed25519 public key") from exc
    agent = CivitasAgent(auto_discover=False)
    return str(agent.generate_keys())


def _post_claim_deliver(
    *,
    client: HttpJsonClient,
    requester: dict[str, Any],
    worker: dict[str, Any],
    fe2_reconciliation_path: Path,
    fe2: dict[str, Any],
    response_record_path: Path,
    response_record: dict[str, Any],
    output_root: Path,
    confirm_delivery: bool,
) -> dict[str, Any]:
    participant_id = str(response_record.get("participant_id") or "unknown")
    response_file = Path(str((response_record.get("response_file") or {}).get("path") or ""))
    response_text = response_file.read_text(encoding="utf-8") if response_file.is_file() else ""
    task_payload = {
        "requester": requester["did"],
        "required_capability": "general",
        "reward": 10,
        "min_reputation": 0.0,
        "deadline_secs": 3600,
        "allowed_agents": [worker["did"]],
        "blocked_agents": [],
        "required_stake": 0,
        "input": {
            "civitasos_task_kind": "beta_fe25_frontend_patch_proposal_review",
            "participant_id": participant_id,
            "patch_slice_id": fe2.get("patch_slice_id"),
            "instruction": (
                "Deliver the FE-2 patch proposal/review as a CivitasOS task output. "
                "Preserve no-apply/no-deploy/H3-blocked boundaries."
            ),
            "source_fe2_reconciliation": _artifact_ref(fe2_reconciliation_path),
            "source_response_record": _artifact_ref(response_record_path),
            "expected_boundary": _boundary(),
            "h3_boundary": _h3_boundary(),
        },
    }
    post = client.post("/api/v1/a2a/pool/post", task_payload)
    task_id = str((post or {}).get("task_id") or "")
    if not task_id:
        raise RuntimeError(f"pool post missing task_id for {participant_id}: {post}")
    claim = client.post("/api/v1/a2a/pool/claim", {"agent_id": worker["did"], "task_id": task_id, "stake_amount": 0})
    delivery_output = {
        "schema_version": "beta-fe25-agent-delivery-output:v1",
        "participant_id": participant_id,
        "recommendation": response_record.get("recommendation"),
        "patch_slice_id": fe2.get("patch_slice_id"),
        "response_file": _artifact_ref(response_file) if response_file.is_file() else None,
        "response_record": _artifact_ref(response_record_path),
        "response_excerpt": response_text[:4000],
        "boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    execute = client.post(
        "/api/v1/a2a/task/execute",
        {
            "agent_id": worker["did"],
            "task_id": task_id,
            "output": delivery_output,
            "success": True,
            "metadata": {
                "runner": "beta_fe25_civitas_task_pool_bridge",
                "participant_id": participant_id,
            },
        },
    )
    delivered_task = _get_task(client, task_id)
    confirm = None
    final_task = delivered_task
    if confirm_delivery and delivered_task.get("status") == "Delivered":
        try:
            confirm = client.post(f"/api/v1/a2a/pool/confirm/{task_id}", {})
            final_task = _get_task(client, task_id)
        except RuntimeError as exc:
            confirm = {
                "blocked": True,
                "reason": "confirm_blocked_or_unavailable",
                "error": str(exc),
            }
    receipt = {
        "schema_version": TASK_RECEIPT_SCHEMA,
        "checked_at": _now(),
        "participant_id": participant_id,
        "task_id": task_id,
        "requester": requester,
        "worker": worker,
        "post_response": post,
        "claim_response": claim,
        "execute_response": execute,
        "confirm_response": confirm,
        "final_task": _task_summary(final_task),
        "claim_observed": bool(final_task.get("claimed_by") or delivered_task.get("claimed_by")),
        "delivery_observed": final_task.get("status") in {"Delivered", "Completed"} or delivered_task.get("status") == "Delivered",
        "challenge_window_observed": bool(delivered_task.get("challenge_deadline_at") or delivered_task.get("challenge_window_secs")),
        "source_response_record": _artifact_ref(response_record_path),
        "boundary": _boundary(),
        "h3_boundary": _h3_boundary(),
        "non_claims": list(NON_CLAIMS),
    }
    return receipt


def _get_task(client: HttpJsonClient, task_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/a2a/pool/tasks/{task_id}")
    if isinstance(response, dict) and isinstance(response.get("task"), dict):
        return response["task"]
    raise RuntimeError(f"unexpected task response for {task_id}: {response}")


def _task_summary(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": task.get("id"),
        "requester": task.get("requester"),
        "required_capability": task.get("required_capability"),
        "status": task.get("status"),
        "claimed_by": task.get("claimed_by"),
        "posted_at": task.get("posted_at"),
        "claimed_at": task.get("claimed_at"),
        "delivered_at": task.get("delivered_at"),
        "challenge_deadline_at": task.get("challenge_deadline_at"),
        "challenge_window_secs": task.get("challenge_window_secs"),
        "has_output": task.get("output") not in (None, "", {}, []),
    }


def _read_json(path: Path, failures: list[str], label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"{label} not found: {path}")
    except json.JSONDecodeError as exc:
        failures.append(f"{label} is not valid JSON: {exc}")
    return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _artifact_ref(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"artifact path is not a file: {path}")
    return {"path": str(path.resolve()), "sha256": _sha256(path)}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_boundary(value: Any, failures: list[str], label: str) -> None:
    if not isinstance(value, dict):
        failures.append(f"{label} must be an object")
        return
    for field in FALSE_BOUNDARY_FIELDS:
        expected_key = "direct_mutation_allowed" if field == "frontend_code_modified" else field
        if expected_key in value and value.get(expected_key) is not False:
            failures.append(f"{label}.{expected_key} must be false")


def _boundary() -> dict[str, bool]:
    return {field: False for field in FALSE_BOUNDARY_FIELDS}


def _h3_boundary() -> dict[str, bool]:
    return {"h3_remains_blocked": True, "h3_production_readiness_claimed": False}


def _safe_alias(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in value).strip("_")[:48] or "beta_fe25_worker"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
