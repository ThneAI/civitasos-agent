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


DEFAULT_BASE_URL = "http://localhost:8099"
DEFAULT_ROOT = "runs/l1_pilot_001_contract_tasks"
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


class HttpJsonClient:
    def __init__(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")

    def get(self, path: str) -> Any:
        request = urllib.request.Request(self._url(path), method="GET")
        return self._open_json(request)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self._url(path),
            data=body,
            headers={"content-type": "application/json"},
            method="POST",
        )
        return self._open_json(request)

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path if path.startswith('/') else '/' + path}"

    @staticmethod
    def _open_json(request: urllib.request.Request) -> Any:
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} {request.full_url}: {detail}") from exc
        if not raw:
            return None
        return json.loads(raw)


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
        "execution plan, and H.3 non-readiness."
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
        "and H.3 blocked boundary preservation."
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
        "receipt write permission."
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
                "required_sections": ["通过/不通过", "问题清单", "H3"],
                "forbid_upstream_replay": True,
                "h3_must_remain_blocked": True,
                "review_must_have_issue_list": True,
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
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("resolve-agents")
    sub.add_parser("post-alpha")
    beta = sub.add_parser("post-beta")
    beta.add_argument("--alpha-task-id")
    gamma = sub.add_parser("post-gamma")
    gamma.add_argument("--alpha-task-id")
    gamma.add_argument("--beta-task-id")
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


def _get_task(client: HttpJsonClient, task_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/a2a/pool/tasks/{task_id}")
    if isinstance(response, dict) and isinstance(response.get("task"), dict):
        return response["task"]
    raise RuntimeError(f"unexpected task response for {task_id}: {response}")


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
