#!/usr/bin/env python3
"""Post L1 Pilot 001 tasks with structured delivery contracts.

This script is intentionally small and HTTP-only. It publishes the alpha,
beta, and gamma tasks as real backend pool tasks while carrying machine-readable
delivery contracts in ``input.delivery_contract``. Runtime and backend verifiers
then decide delivery eligibility; prompt text is no longer the only guardrail.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from civitasos_contracts.auth import CivitasHttpClient
except ModuleNotFoundError:
    from scripts.civitasos_contracts.auth import CivitasHttpClient


DEFAULT_BASE_URL = "http://localhost:8099"
DEFAULT_ROOT = "runs/l1_pilot_001_contract_tasks"
DEFAULT_DEMO_LOGIN_AGENT_ID = "l1_pilot_contract_tasks"
DEFAULT_REWARD = 25
DEFAULT_DEADLINE_SECS = 3600
ROLE_DEFAULTS = {
    "requester": "pilot-guardian",
    "alpha": "alpha-planner",
    "beta": "beta-implementer",
    "gamma": "gamma-reviewer",
}


@dataclass(frozen=True)
class AgentRef:
    role: str
    did: str
    alias: str | None
    name: str


def _scope_list(raw: str) -> list[str]:
    return [scope.strip() for scope in raw.split(",") if scope.strip()]


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class HttpJsonClient(CivitasHttpClient):
    """L1 compatibility adapter over the canonical auth client."""

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str | None = None,
        api_key: str | None = None,
        demo_login_agent_id: str | None = None,
    ) -> None:
        super().__init__(
            base_url,
            bearer_token=bearer_token or os.getenv("CIVITASOS_BEARER_TOKEN"),
            api_key=api_key or os.getenv("CIVITASOS_API_KEY"),
            service_token_secret=(
                os.getenv("L1_SERVICE_TOKEN_SECRET")
                or os.getenv("CIVITASOS_SERVICE_TOKEN_SECRET")
            ),
            service_id=os.getenv("L1_SERVICE_ID", "l1_contract_tasks"),
            service_scopes=_scope_list(
                os.getenv(
                    "L1_SERVICE_TOKEN_SCOPES",
                    "agents:read,agents:write,pool:post,pool:read,pool:claim,pool:write,webhooks:write",
                )
            ),
            require_service_token=_env_flag("L1_REQUIRE_SERVICE_TOKEN"),
            demo_login_agent_id=(
                demo_login_agent_id
                if demo_login_agent_id is not None
                else os.getenv("L1_DEMO_LOGIN_AGENT_ID", DEFAULT_DEMO_LOGIN_AGENT_ID)
            ),
            required_service_token_error=(
                "L1_REQUIRE_SERVICE_TOKEN=1 requires L1_SERVICE_TOKEN_SECRET "
                "or CIVITASOS_SERVICE_TOKEN_SECRET"
            ),
        )


def build_alpha_payload(
    *,
    requester: str,
    alpha_did: str,
    reward: int = DEFAULT_REWARD,
    deadline_secs: int = DEFAULT_DEADLINE_SECS,
) -> dict[str, Any]:
    instruction = (
        "Create the L1 Pilot 001 execution plan update. Scope: controlled pilot "
        "only. H.3 must remain blocked. Output must separate task boundary, "
        "execution plan, and H.3 non-readiness. Use these exact headings: "
        "任务边界, 执行计划, H3. The H3 section must contain only blocked-state "
        "claims: H.3 remains blocked; no production readiness; no production "
        "runtime execution; no production receipt writes. Do not use ready, "
        "passed, approved, authorized, allowed, unblocked, 通过, 就绪, 授权, 允许, "
        "or 解锁 on any line that also mentions H3, H.3, production, or 生产. "
        "Use 采用 instead of 通过 when you mean 'by means of'."
        + _h3_output_wording_rule()
    )
    return _pool_post_payload(
        requester=requester,
        required_capability="planning",
        allowed_agent=alpha_did,
        reward=reward,
        deadline_secs=deadline_secs,
        input_data={
            "description": instruction,
            "instruction": instruction,
            "expected_artifact_name": "alpha_l1_pilot_plan.md",
            "boundary": _h3_blocked_boundary(),
            "delivery_contract": {
                "required_sections": ["任务边界", "执行计划", "H3"],
                "forbid_upstream_replay": False,
                "h3_must_remain_blocked": True,
                "canonical_h3_boundary": True,
            },
        },
    )


def build_beta_payload(
    *,
    requester: str,
    beta_did: str,
    alpha_task_id: str,
    alpha_output: Any,
    reward: int = DEFAULT_REWARD,
    deadline_secs: int = DEFAULT_DEADLINE_SECS,
) -> dict[str, Any]:
    instruction = (
        "Implement a repair/delta artifact based on alpha's plan. Do not replay "
        "alpha. Output must identify concrete changes, differences from alpha, "
        "and H.3 blocked boundary preservation. Use these exact headings: "
        "变更摘要, 与上游不同之处, H3. The H3 section must contain only blocked-state "
        "claims: H.3 remains blocked; no production readiness; no production "
        "runtime execution; no production receipt writes. Do not use ready, "
        "passed, approved, authorized, allowed, unblocked, 通过, 就绪, 授权, 允许, "
        "or 解锁 on any line that also mentions H3, H.3, production, or 生产. "
        "Use 采用 instead of 通过 when you mean 'by means of'."
        + _h3_output_wording_rule()
    )
    return _pool_post_payload(
        requester=requester,
        required_capability="implementation",
        allowed_agent=beta_did,
        reward=reward,
        deadline_secs=deadline_secs,
        input_data={
            "description": instruction,
            "instruction": instruction,
            "expected_artifact_name": "beta_l1_pilot_delta.md",
            "upstream_task_id": alpha_task_id,
            "alpha_output": _stable_text(alpha_output),
            "boundary": _h3_blocked_boundary(),
            "delivery_contract": {
                "required_sections": ["变更摘要", "与上游不同之处", "H3"],
                "forbid_upstream_replay": True,
                "h3_must_remain_blocked": True,
                "canonical_h3_boundary": True,
            },
        },
    )


def build_gamma_payload(
    *,
    requester: str,
    gamma_did: str,
    alpha_task_id: str,
    beta_task_id: str,
    alpha_output: Any,
    beta_output: Any,
    reward: int = DEFAULT_REWARD,
    deadline_secs: int = DEFAULT_DEADLINE_SECS,
) -> dict[str, Any]:
    instruction = (
        "Review beta's L1 Pilot 001 delta against alpha's plan. Give an explicit "
        "L1 verdict, list issues, and preserve the H.3 blocked boundary. Do not "
        "claim production readiness, production runtime execution, or production "
        "receipt write permission. Use these exact headings: verdict, 问题清单, "
        "H3. In the verdict section say whether the L1 controlled pilot delta is "
        "accepted or blocked. In the H3 section state only blocked-state claims: "
        "H.3 remains blocked; no production readiness; no production runtime "
        "execution; no production receipt writes. Do not use ready, passed, "
        "approved, authorized, allowed, unblocked, 通过, 就绪, 授权, 允许, or 解锁 "
        "on any line that also mentions H3, H.3, production, or 生产. Use 采用 "
        "instead of 通过 when you mean 'by means of'."
        + _h3_output_wording_rule()
    )
    return _pool_post_payload(
        requester=requester,
        required_capability="review",
        allowed_agent=gamma_did,
        reward=reward,
        deadline_secs=deadline_secs,
        input_data={
            "description": instruction,
            "instruction": instruction,
            "expected_artifact_name": "gamma_l1_pilot_review.md",
            "alpha_task_id": alpha_task_id,
            "beta_task_id": beta_task_id,
            "alpha_output": _stable_text(alpha_output),
            "beta_output": _stable_text(beta_output),
            "boundary": _h3_blocked_boundary(),
            "delivery_contract": {
                "required_sections": ["verdict", "问题清单", "H3"],
                "forbid_upstream_replay": True,
                "h3_must_remain_blocked": True,
                "canonical_h3_boundary": True,
                "review_must_have_issue_list": True,
            },
        },
    )


def build_repair_payload(
    *,
    requester: str,
    repair_did: str,
    failed_task_id: str,
    failed_task: dict[str, Any],
    operator_id: str,
    repair_suggestions: list[str] | None = None,
    reward: int = DEFAULT_REWARD,
    deadline_secs: int = DEFAULT_DEADLINE_SECS,
) -> dict[str, Any]:
    """Build an explicit operator-approved repair task.

    This is deliberately not used by post-next/run-chain. A failed task may only
    enter this path after an operator records an approval.
    """
    suggestions = repair_suggestions or _extract_repair_suggestions(failed_task)
    instruction = (
        "Create an explicit repair artifact for the failed L1 controlled pilot "
        "task. Do not retry automatically and do not replay the failed output. "
        "Use these exact headings: 失败原因, 修复计划, 验证步骤, H3. The H3 section "
        "must contain only blocked-state claims: H.3 remains blocked; no "
        "production readiness; no production runtime execution; no production "
        "receipt writes."
        + _h3_output_wording_rule()
    )
    return _pool_post_payload(
        requester=requester,
        required_capability="repair",
        allowed_agent=repair_did,
        reward=reward,
        deadline_secs=deadline_secs,
        input_data={
            "description": instruction,
            "instruction": instruction,
            "expected_artifact_name": "l1_operator_approved_repair.md",
            "source_failed_task_id": failed_task_id,
            "source_failure_reason": failed_task.get("failure_reason"),
            "source_task_status": failed_task.get("status"),
            "source_task_contract": (failed_task.get("input") or {}).get("delivery_contract")
            if isinstance(failed_task.get("input"), dict) else None,
            "repair_suggestions": suggestions,
            "operator_approval": {
                "schema_version": "l1-operator-approved-repair:v1",
                "approved": True,
                "approved_by": operator_id,
                "approved_at": _now(),
                "source_failed_task_id": failed_task_id,
                "non_claims": [
                    "operator_approval_does_not_authorize_production_runtime_execution",
                    "operator_approval_does_not_write_production_receipts",
                    "repair_task_is_not_an_automatic_retry",
                ],
            },
            "boundary": _h3_blocked_boundary(),
            "delivery_contract": {
                "required_sections": ["失败原因", "修复计划", "验证步骤", "H3"],
                "forbid_upstream_replay": True,
                "h3_must_remain_blocked": True,
                "canonical_h3_boundary": True,
            },
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.getenv("CIVITASOS_URL", DEFAULT_BASE_URL),
        help="CivitasOS backend base URL",
    )
    parser.add_argument(
        "--root",
        default=os.getenv("L1_PILOT_ROOT", DEFAULT_ROOT),
        help="Run root for task_chain.json",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print payload without posting")
    parser.add_argument("--reward", type=int, default=DEFAULT_REWARD)
    parser.add_argument("--deadline-secs", type=int, default=DEFAULT_DEADLINE_SECS)
    parser.add_argument(
        "--operator-approved-repair",
        action="store_true",
        default=_env_flag("L1_OPERATOR_APPROVED_REPAIR"),
        help="Required for post-repair; also accepted through L1_OPERATOR_APPROVED_REPAIR=1.",
    )
    parser.add_argument(
        "--operator-id",
        default=os.getenv("L1_OPERATOR_ID", "l1-controlled-pilot-operator"),
        help="Operator id written into repair task approval metadata.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("resolve-agents")
    sub.add_parser("post-alpha")
    beta = sub.add_parser("post-beta")
    beta.add_argument("--alpha-task-id")
    gamma = sub.add_parser("post-gamma")
    gamma.add_argument("--alpha-task-id")
    gamma.add_argument("--beta-task-id")
    repair = sub.add_parser("post-repair")
    repair.add_argument("--failed-task-id", required=True)
    repair.add_argument(
        "--repair-agent",
        default=os.getenv("L1_REPAIR_AGENT"),
        help="Repair agent DID/alias/name. Defaults to the beta implementer.",
    )
    sub.add_parser("post-next")
    sub.add_parser("status")
    args = parser.parse_args(argv)

    client = HttpJsonClient(args.base_url)
    root = Path(args.root)
    state_path = root / "task_chain.json"

    if args.command == "resolve-agents":
        print(json.dumps(_agent_state(client), ensure_ascii=False, indent=2))
        return 0
    if args.command == "status":
        print(json.dumps(_status(client, state_path), ensure_ascii=False, indent=2))
        return 0

    agents = _resolve_required_agents(client)
    state = _read_state(state_path)

    if args.command == "post-alpha":
        task_id = _post_alpha(client, args, state, agents)
    elif args.command == "post-beta":
        alpha_task_id = args.alpha_task_id or state.get("alpha_task_id")
        if not alpha_task_id:
            raise SystemExit("missing --alpha-task-id and state has no alpha_task_id")
        task_id = _post_beta(client, args, state, agents, str(alpha_task_id))
    elif args.command == "post-gamma":
        alpha_task_id = args.alpha_task_id or state.get("alpha_task_id")
        beta_task_id = args.beta_task_id or state.get("beta_task_id")
        if not alpha_task_id or not beta_task_id:
            raise SystemExit("missing alpha/beta task ids")
        task_id = _post_gamma(
            client,
            args,
            state,
            agents,
            str(alpha_task_id),
            str(beta_task_id),
        )
    elif args.command == "post-repair":
        task_id = _post_repair(client, args, state, agents, str(args.failed_task_id))
    else:
        task_id = _post_next(client, args, state, agents)

    if args.dry_run:
        return 0
    _write_state(state_path, state)
    print(json.dumps({"posted_task_id": task_id, "state_path": str(state_path)}, ensure_ascii=False, indent=2))
    return 0


def _pool_post_payload(
    *,
    requester: str,
    required_capability: str,
    allowed_agent: str,
    input_data: dict[str, Any],
    reward: int,
    deadline_secs: int,
) -> dict[str, Any]:
    return {
        "requester": requester,
        "required_capability": required_capability,
        "input": input_data,
        "deadline_secs": deadline_secs,
        "reward": reward,
        "min_reputation": 0.0,
        "allowed_agents": [allowed_agent],
        "blocked_agents": [],
        "required_stake": 0,
    }


def _h3_blocked_boundary() -> str:
    return (
        "L1 controlled pilot only. H.3 remains blocked. No production readiness, "
        "no production runtime execution, no production receipt write permission, "
        "no external production mutation."
    )


def _h3_output_wording_rule() -> str:
    return (
        " In non-H3 sections, do not mention H3, H.3, production, 生产, 准入, "
        "通过, 授权, 允许, 就绪, 解锁, ready, passed, approved, authorized, "
        "allowed, or unblocked. Put all H.3 boundary wording only in the H3 "
        "section. The H3 section should be short and use only blocked/no-"
        "authorization wording."
    )


def _post_alpha(client: HttpJsonClient, args: argparse.Namespace, state: dict[str, Any], agents: dict[str, AgentRef]) -> str:
    payload = build_alpha_payload(
        requester=agents["requester"].did,
        alpha_did=agents["alpha"].did,
        reward=args.reward,
        deadline_secs=args.deadline_secs,
    )
    task_id = _post_or_print(client, args, payload)
    if not args.dry_run:
        state["agents"] = _agents_as_dict(agents)
        state["alpha_task_id"] = task_id
        state["updated_at"] = _now()
    return task_id


def _post_beta(
    client: HttpJsonClient,
    args: argparse.Namespace,
    state: dict[str, Any],
    agents: dict[str, AgentRef],
    alpha_task_id: str,
) -> str:
    alpha_task = _require_delivered_task(client, alpha_task_id, "alpha")
    payload = build_beta_payload(
        requester=agents["alpha"].did,
        beta_did=agents["beta"].did,
        alpha_task_id=alpha_task_id,
        alpha_output=alpha_task["output"],
        reward=args.reward,
        deadline_secs=args.deadline_secs,
    )
    task_id = _post_or_print(client, args, payload)
    if not args.dry_run:
        state["agents"] = _agents_as_dict(agents)
        state["alpha_task_id"] = alpha_task_id
        state["beta_task_id"] = task_id
        state["updated_at"] = _now()
    return task_id


def _post_gamma(
    client: HttpJsonClient,
    args: argparse.Namespace,
    state: dict[str, Any],
    agents: dict[str, AgentRef],
    alpha_task_id: str,
    beta_task_id: str,
) -> str:
    alpha_task = _require_delivered_task(client, alpha_task_id, "alpha")
    beta_task = _require_delivered_task(client, beta_task_id, "beta")
    payload = build_gamma_payload(
        requester=agents["beta"].did,
        gamma_did=agents["gamma"].did,
        alpha_task_id=alpha_task_id,
        beta_task_id=beta_task_id,
        alpha_output=alpha_task["output"],
        beta_output=beta_task["output"],
        reward=args.reward,
        deadline_secs=args.deadline_secs,
    )
    task_id = _post_or_print(client, args, payload)
    if not args.dry_run:
        state["agents"] = _agents_as_dict(agents)
        state["alpha_task_id"] = alpha_task_id
        state["beta_task_id"] = beta_task_id
        state["gamma_task_id"] = task_id
        state["updated_at"] = _now()
    return task_id


def _post_repair(
    client: HttpJsonClient,
    args: argparse.Namespace,
    state: dict[str, Any],
    agents: dict[str, AgentRef],
    failed_task_id: str,
) -> str:
    if not args.operator_approved_repair:
        raise SystemExit(
            "post-repair requires --operator-approved-repair or "
            "L1_OPERATOR_APPROVED_REPAIR=1; failed tasks are not auto-retried"
        )
    failed_task = _require_failed_task(client, failed_task_id)
    repair_agent = _resolve_repair_agent(client, args, agents)
    payload = build_repair_payload(
        requester=agents["requester"].did,
        repair_did=repair_agent.did,
        failed_task_id=failed_task_id,
        failed_task=failed_task,
        operator_id=str(args.operator_id),
        reward=args.reward,
        deadline_secs=args.deadline_secs,
    )
    task_id = _post_or_print(client, args, payload)
    if not args.dry_run:
        state["agents"] = _agents_as_dict({**agents, "repair": repair_agent})
        state.setdefault("repair_tasks", []).append({
            "source_failed_task_id": failed_task_id,
            "repair_task_id": task_id,
            "operator_approved": True,
            "operator_id": str(args.operator_id),
            "updated_at": _now(),
        })
        state["updated_at"] = _now()
    return task_id


def _post_next(client: HttpJsonClient, args: argparse.Namespace, state: dict[str, Any], agents: dict[str, AgentRef]) -> str:
    if not state.get("alpha_task_id"):
        return _post_alpha(client, args, state, agents)
    if not state.get("beta_task_id"):
        return _post_beta(client, args, state, agents, str(state["alpha_task_id"]))
    if not state.get("gamma_task_id"):
        return _post_gamma(
            client,
            args,
            state,
            agents,
            str(state["alpha_task_id"]),
            str(state["beta_task_id"]),
        )
    raise SystemExit("all alpha/beta/gamma tasks already posted")


def _post_or_print(client: HttpJsonClient, args: argparse.Namespace, payload: dict[str, Any]) -> str:
    if args.dry_run:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return "dry-run"
    response = client.post("/api/v1/a2a/pool/post", payload)
    task_id = response.get("task_id") or response.get("id") if isinstance(response, dict) else None
    if not task_id:
        raise RuntimeError(f"pool post response missing task_id: {response}")
    return str(task_id)


def _require_delivered_task(client: HttpJsonClient, task_id: str, label: str) -> dict[str, Any]:
    task = _get_task(client, task_id)
    status = task.get("status")
    if status not in {"Delivered", "Completed"}:
        raise SystemExit(f"{label} task {task_id} is {status}; wait for Delivered/Completed")
    if task.get("output") in (None, "", {}, []):
        raise SystemExit(f"{label} task {task_id} has no output")
    return task


def _require_failed_task(client: HttpJsonClient, task_id: str) -> dict[str, Any]:
    task = _get_task(client, task_id)
    status = task.get("status")
    if status not in {"Failed", "Disputed", "Cancelled"}:
        raise SystemExit(f"task {task_id} is {status}; repair requires Failed/Disputed/Cancelled")
    return task


def _get_task(client: HttpJsonClient, task_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/a2a/pool/tasks/{task_id}")
    if isinstance(response, dict) and isinstance(response.get("task"), dict):
        return response["task"]
    raise RuntimeError(f"unexpected task response for {task_id}: {response}")


def _extract_repair_suggestions(task: dict[str, Any]) -> list[str]:
    candidates = [
        (task.get("delivery_contract_verification") or {}).get("repair_suggestions")
        if isinstance(task.get("delivery_contract_verification"), dict) else None,
        (task.get("input") or {}).get("repair_suggestions") if isinstance(task.get("input"), dict) else None,
        (task.get("metadata") or {}).get("repair_suggestions") if isinstance(task.get("metadata"), dict) else None,
    ]
    for value in candidates:
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
    reason = str(task.get("failure_reason") or "").strip()
    if reason:
        return [f"Inspect failure_reason={reason} and produce a contract-shaped repair artifact."]
    return ["Inspect failed task evidence and produce a contract-shaped repair artifact."]


def _resolve_repair_agent(
    client: HttpJsonClient,
    args: argparse.Namespace,
    agents: dict[str, AgentRef],
) -> AgentRef:
    if not args.repair_agent:
        beta = agents["beta"]
        return AgentRef(role="repair", did=beta.did, alias=beta.alias, name=beta.name)
    return _resolve_agent(_list_agent_cards(client), "repair", str(args.repair_agent))


def _status(client: HttpJsonClient, state_path: Path) -> dict[str, Any]:
    state = _read_state(state_path)
    tasks: dict[str, Any] = {}
    for key in ("alpha_task_id", "beta_task_id", "gamma_task_id"):
        task_id = state.get(key)
        if not task_id:
            continue
        try:
            task = _get_task(client, str(task_id))
            tasks[key] = {
                "task_id": task_id,
                "status": task.get("status"),
                "claimed_by": task.get("claimed_by"),
                "has_output": task.get("output") not in (None, "", {}, []),
                "delivery_contract": task.get("input", {}).get("delivery_contract"),
            }
        except Exception as exc:  # noqa: BLE001
            tasks[key] = {"task_id": task_id, "error": str(exc)}
    return {"state_path": str(state_path), "state": state, "tasks": tasks}


def _resolve_required_agents(client: HttpJsonClient) -> dict[str, AgentRef]:
    cards = _list_agent_cards(client)
    return {
        role: _resolve_agent(
            cards,
            role,
            os.getenv(f"L1_{role.upper()}_AGENT", ROLE_DEFAULTS[role]),
        )
        for role in ("requester", "alpha", "beta", "gamma")
    }


def _agent_state(client: HttpJsonClient) -> dict[str, Any]:
    agents = _resolve_required_agents(client)
    return {"agents": _agents_as_dict(agents)}


def _list_agent_cards(client: HttpJsonClient) -> list[dict[str, Any]]:
    response = client.get("/api/v1/a2a/agents")
    if not isinstance(response, list):
        raise RuntimeError(f"unexpected agents response: {response}")
    return [card for card in response if isinstance(card, dict)]


def _resolve_agent(cards: list[dict[str, Any]], role: str, spec: str) -> AgentRef:
    wanted = spec.strip()
    for card in cards:
        candidates = {
            str(card.get("did") or ""),
            str(card.get("alias") or ""),
            str(card.get("name") or ""),
        }
        if wanted in candidates:
            return AgentRef(
                role=role,
                did=str(card["did"]),
                alias=card.get("alias"),
                name=str(card.get("name") or ""),
            )
    available = [
        {"did": c.get("did"), "alias": c.get("alias"), "name": c.get("name")}
        for c in cards
    ]
    raise SystemExit(
        f"cannot resolve {role} agent '{wanted}'. "
        f"Set L1_{role.upper()}_AGENT to a registered DID/alias/name. "
        f"Available: {json.dumps(available, ensure_ascii=False)}"
    )


def _agents_as_dict(agents: dict[str, AgentRef]) -> dict[str, Any]:
    return {
        role: {"did": ref.did, "alias": ref.alias, "name": ref.name}
        for role, ref in agents.items()
    }


def _read_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise RuntimeError(f"state file must contain a JSON object: {path}")
    return data


def _write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _stable_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
