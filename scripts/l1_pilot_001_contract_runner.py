#!/usr/bin/env python3
"""Run the L1 Pilot 001 contract task chain end-to-end.

The runner is intentionally operator-facing glue around the existing local
agent launcher and contract task publisher. It does not claim production
readiness. It runs a controlled L1 pilot only and writes evidence files into
the selected run root.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "http://localhost:8099"
DEFAULT_ROOT = "runs/l1_pilot_001_contract_runner"
DEFAULT_DEMO_LOGIN_AGENT_ID = "l1_pilot_contract_runner"
ROLE_NAMES = {
    "alpha": "alpha_planner",
    "beta": "beta_implementer",
    "gamma": "gamma_reviewer",
}
ROLE_CAPABILITIES = {
    "alpha": {"planning", "documentation", "boundary_analysis"},
    "beta": {"implementation", "documentation", "repair"},
    "gamma": {"review", "boundary_check", "audit"},
}
SUCCESS_STATUSES = {"Delivered", "Completed"}
TERMINAL_STATUSES = {"Delivered", "Completed", "Failed"}


@dataclass(frozen=True)
class AgentRef:
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


class HttpJsonClient:
    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str | None = None,
        api_key: str | None = None,
        demo_login_agent_id: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._bearer_token = bearer_token or os.getenv("CIVITASOS_BEARER_TOKEN") or None
        self._api_key = api_key or os.getenv("CIVITASOS_API_KEY") or None
        self._service_token_secret = (
            os.getenv("L1_SERVICE_TOKEN_SECRET")
            or os.getenv("CIVITASOS_SERVICE_TOKEN_SECRET")
            or None
        )
        self._service_id = os.getenv("L1_SERVICE_ID", "l1_contract_runner")
        self._service_scopes = _scope_list(
            os.getenv("L1_SERVICE_TOKEN_SCOPES", "agents:read,agents:write,pool:post,pool:read,pool:claim,pool:write,webhooks:write")
        )
        self._require_service_token = _env_flag("L1_REQUIRE_SERVICE_TOKEN")
        self._demo_login_agent_id = (
            demo_login_agent_id
            if demo_login_agent_id is not None
            else os.getenv("L1_DEMO_LOGIN_AGENT_ID", DEFAULT_DEMO_LOGIN_AGENT_ID)
        )
        self._service_token_attempted = False
        self._demo_login_attempted = False
        self._auth_context: dict[str, Any] = self._initial_auth_context()

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
        return f"{self._base_url}{path if path.startswith('/') else '/' + path}"

    def _headers(self, *, content_type: bool = False) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = "application/json"
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        token = self._auth_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _auth_token(self) -> str | None:
        if self._require_service_token:
            if not self._service_token_secret:
                raise RuntimeError(
                    "L1_REQUIRE_SERVICE_TOKEN=1 requires L1_SERVICE_TOKEN_SECRET "
                    "or CIVITASOS_SERVICE_TOKEN_SECRET"
                )
            if not self._service_token_attempted:
                return self._service_token()
            return self._bearer_token
        if self._bearer_token or self._api_key:
            return self._bearer_token
        if self._service_token_secret and not self._service_token_attempted:
            return self._service_token()
        if self._demo_login_attempted:
            return self._bearer_token
        agent_id = str(self._demo_login_agent_id or "").strip()
        if not agent_id:
            self._demo_login_attempted = True
            return None
        self._demo_login_attempted = True
        payload = self._open_json(
            urllib.request.Request(
                self._url("/api/v1/auth/demo-login"),
                data=json.dumps({"agent_id": agent_id}).encode("utf-8"),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                method="POST",
            )
        )
        if not isinstance(payload, dict):
            raise RuntimeError(f"demo-login response must be an object: {payload}")
        token = payload.get("token")
        data = payload.get("data")
        if not token and isinstance(data, dict):
            token = data.get("token")
        if not token:
            raise RuntimeError(f"demo-login response missing token: {payload}")
        self._bearer_token = str(token)
        data = data if isinstance(data, dict) else payload
        self._auth_context = {
            "auth_method": str(data.get("auth_method") or "demo_login"),
            "production_allowed": bool(data.get("production_allowed", False)),
            "evidence_allowed": bool(data.get("evidence_allowed", False)),
            "non_claims": data.get("non_claims", [
                "demo_login_is_dev_test_only",
                "demo_login_must_not_be_used_as_production_evidence",
            ]),
        }
        return self._bearer_token

    def _service_token(self) -> str | None:
        self._service_token_attempted = True
        payload = self._open_json(
            urllib.request.Request(
                self._url("/api/v1/auth/service-token"),
                data=json.dumps({
                    "service_id": self._service_id,
                    "secret": self._service_token_secret,
                    "scopes": self._service_scopes,
                }).encode("utf-8"),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                method="POST",
            )
        )
        if not isinstance(payload, dict):
            raise RuntimeError(f"service-token response must be an object: {payload}")
        token = payload.get("token")
        data = payload.get("data")
        if not token and isinstance(data, dict):
            token = data.get("token")
        if not token:
            raise RuntimeError(f"service-token response missing token: {payload}")
        self._bearer_token = str(token)
        data = data if isinstance(data, dict) else payload
        self._auth_context = {
            "auth_method": str(data.get("auth_method") or "service_token"),
            "service_id": str(data.get("service_id") or self._service_id),
            "scopes": data.get("scopes", self._service_scopes),
            "production_allowed": bool(data.get("production_allowed", False)),
            "evidence_allowed": bool(data.get("evidence_allowed", False)),
            "non_claims": data.get("non_claims", [
                "service_token_is_controlled_operator_automation_only",
                "service_token_must_not_be_used_as_production_evidence",
            ]),
        }
        return self._bearer_token

    def auth_context(self) -> dict[str, Any]:
        return dict(self._auth_context)

    def _initial_auth_context(self) -> dict[str, Any]:
        if self._require_service_token:
            if self._service_token_secret:
                return {
                    "auth_method": "pending_service_token",
                    "service_id": self._service_id,
                    "scopes": self._service_scopes,
                    "production_allowed": False,
                    "evidence_allowed": False,
                    "require_service_token": True,
                }
            return {
                "auth_method": "missing_required_service_token",
                "production_allowed": False,
                "evidence_allowed": False,
                "require_service_token": True,
            }
        if self._api_key:
            return {
                "auth_method": "api_key",
                "production_allowed": False,
                "evidence_allowed": False,
                "scopes": _scope_list(os.getenv("CIVITASOS_API_KEY_SCOPES", "")),
            }
        if self._bearer_token:
            return {
                "auth_method": "provided_bearer_token",
                "production_allowed": None,
                "evidence_allowed": None,
            }
        if self._service_token_secret:
            return {
                "auth_method": "pending_service_token",
                "service_id": self._service_id,
                "scopes": self._service_scopes,
                "production_allowed": False,
                "evidence_allowed": False,
            }
        return {
            "auth_method": "pending_demo_login" if self._demo_login_agent_id else "none",
            "production_allowed": False,
            "evidence_allowed": False,
        }

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.getenv("CIVITASOS_URL", DEFAULT_BASE_URL))
    parser.add_argument("--root", default=os.getenv("L1_PILOT_ROOT", DEFAULT_ROOT))
    parser.add_argument("--python", default=os.getenv("PYTHON", "./.venv/bin/python"))
    parser.add_argument("--agent-script", default="scripts/l1_pilot_001_local_agents.sh")
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument("--stage-timeout", type=float, default=180.0)
    parser.add_argument(
        "--wake-mode",
        choices=("auto", "event", "restart"),
        default=os.getenv("L1_WAKE_MODE", "auto"),
        help="How to wake agents after posting each task. auto uses event wake and falls back to one restart.",
    )
    parser.add_argument(
        "--event-wake-grace",
        type=float,
        default=float(os.getenv("L1_EVENT_WAKE_GRACE", "25")),
        help="Seconds to wait before auto wake fallback restarts local agents.",
    )
    parser.add_argument(
        "--require-signed-wake",
        action="store_true",
        default=os.getenv("L1_REQUIRE_SIGNED_WAKE", "0").strip().lower()
        in {"1", "true", "yes", "on"},
        help="Fail closed unless CIVITASOS_WAKE_CALLBACK_SECRET is configured for signed wake callbacks.",
    )
    parser.add_argument("--no-stop-agents", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)
    client = HttpJsonClient(args.base_url)
    wake_security = _wake_security_context(args)
    if args.require_signed_wake and not wake_security["callback_secret_configured"]:
        raise SystemExit(
            "signed wake required but CIVITASOS_WAKE_CALLBACK_SECRET is not configured"
        )

    _write_json(root / "runner_start.json", {
        "started_at": _now(),
        "base_url": args.base_url,
        "root": str(root),
        "wake_mode": args.wake_mode,
        "event_wake_grace": args.event_wake_grace,
        "wake_security": wake_security,
        "non_claims": [
            "l1_controlled_pilot_only",
            "does_not_claim_h3_readiness",
            "does_not_claim_production_runtime_execution",
            "does_not_write_production_receipts",
        ],
    })

    _assert_backend_ready(client)
    requester = _ensure_requester(client, root)
    existing_role_dids = _existing_role_dids(client)
    _run_agent_script(args, root, "start")
    try:
        agents = _wait_for_agents(
            client,
            timeout=args.stage_timeout,
            excluded_dids=existing_role_dids,
        )
        agents["requester"] = requester
        _write_agent_refs(root, agents)
        _write_json(root / "resolved_agents.json", {"agents": _agents_as_dict(agents)})

        stages = (
            ("alpha", "post-alpha", "alpha_task_id"),
            ("beta", "post-beta", "beta_task_id"),
            ("gamma", "post-gamma", "gamma_task_id"),
        )
        stage_reports = []
        for role, command, state_key in stages:
            posted = _run_contract_command(args, root, command, agents)
            _write_json(root / f"post_{role}.json", posted)
            task_id = str(posted["posted_task_id"])
            fallback = _restart_agents if args.wake_mode == "auto" else None
            if args.wake_mode == "restart":
                _restart_agents(args, root)
            terminal, wake_report = _wait_for_task(
                client,
                task_id,
                timeout=args.stage_timeout,
                poll_interval=args.poll_interval,
                snapshots_dir=root / "task_status_polls" / role,
                fallback_after=args.event_wake_grace if fallback else None,
                fallback=lambda: fallback(args, root) if fallback else None,
            )
            stage_report = {
                "role": role,
                "post_command": command,
                "state_key": state_key,
                "task_id": task_id,
                "terminal_status": terminal.get("status"),
                "claimed_by": terminal.get("claimed_by"),
                "has_output": terminal.get("output") not in (None, "", {}, []),
                "wake": wake_report,
                "wake_security": wake_security,
            }
            stage_reports.append(stage_report)
            _write_json(root / f"{role}_stage_report.json", stage_report)
            if terminal.get("status") not in SUCCESS_STATUSES:
                break

        evidence = _collect_evidence(client, root, agents, stage_reports, wake_security)
        _write_json(root / "contract_runner_evidence.json", evidence)
        return 0 if evidence["chain_passed"] else 1
    finally:
        if not args.no_stop_agents:
            _run_agent_script(args, root, "stop", check=False)


def _assert_backend_ready(client: HttpJsonClient) -> None:
    # healthz is empty on success in current backend; any exception is enough.
    request = urllib.request.Request(client._url("/healthz"), method="GET")
    try:
        urllib.request.urlopen(request, timeout=5).close()
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"backend healthz failed: {exc}") from exc


def _ensure_requester(client: HttpJsonClient, root: Path) -> AgentRef:
    existing = _find_requester(client)
    if existing:
        return existing

    public_key = _generate_public_key_hex()
    result = client.post(
        "/api/v1/a2a/quickstart",
        {
            "public_key": public_key,
            "alias": "pilot_guardian",
            "name": "Pilot Guardian",
            "endpoint": "http://127.0.0.1:65535/pilot_guardian",
            "description": "Controlled L1 pilot requester identity",
        },
    )
    _write_json(root / "requester_quickstart.json", result)
    agent = result.get("agent", {}) if isinstance(result, dict) else {}
    did = str(agent.get("did") or "")
    if not did:
        raise RuntimeError(f"quickstart requester response missing DID: {result}")
    return AgentRef(did=did, alias=agent.get("alias"), name=str(agent.get("name") or "Pilot Guardian"))


def _generate_public_key_hex() -> str:
    try:
        from civitasos import CivitasAgent  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("civitasos SDK is required to generate a requester key") from exc
    agent = CivitasAgent(auto_discover=False)
    return str(agent.generate_keys())


def _find_requester(client: HttpJsonClient) -> AgentRef | None:
    for card in _list_agents(client):
        if card.get("alias") == "pilot_guardian" or card.get("name") == "Pilot Guardian":
            return _agent_ref_from_card(card)
    return None


def _existing_role_dids(client: HttpJsonClient) -> dict[str, set[str]]:
    cards = _list_agents(client)
    existing: dict[str, set[str]] = {role: set() for role in ROLE_NAMES}
    for role, name in ROLE_NAMES.items():
        for card in cards:
            did = str(card.get("did") or "")
            if did and card.get("name") == name:
                existing[role].add(did)
    return existing


def _wait_for_agents(
    client: HttpJsonClient,
    *,
    timeout: float,
    excluded_dids: dict[str, set[str]] | None = None,
) -> dict[str, AgentRef]:
    deadline = time.monotonic() + timeout
    last_seen: list[dict[str, Any]] = []
    excluded_dids = excluded_dids or {}
    while time.monotonic() < deadline:
        cards = _list_agents(client)
        last_seen = cards
        resolved: dict[str, AgentRef] = {}
        for role, name in ROLE_NAMES.items():
            card = _latest_matching_agent(
                cards,
                name,
                ROLE_CAPABILITIES[role],
                excluded_dids=excluded_dids.get(role, set()),
            )
            if card:
                resolved[role] = _agent_ref_from_card(card)
        if set(resolved) == set(ROLE_NAMES):
            return resolved
        time.sleep(1)
    raise TimeoutError(
        "timed out waiting for L1 agents with synced capabilities. "
        f"Last seen: {json.dumps(_agent_cards_summary(last_seen), ensure_ascii=False)}"
    )


def _latest_matching_agent(
    cards: list[dict[str, Any]],
    name: str,
    required_caps: set[str],
    *,
    excluded_dids: set[str] | None = None,
) -> dict[str, Any] | None:
    excluded_dids = excluded_dids or set()
    matches = [
        card for card in cards
        if card.get("name") == name
        and str(card.get("did") or "") not in excluded_dids
        and required_caps.issubset(_capability_ids(card))
    ]
    if not matches:
        return None
    return sorted(matches, key=_agent_sort_key)[-1]


def _agent_sort_key(card: dict[str, Any]) -> str:
    return str(card.get("updated_at") or card.get("genesis_time") or "")


def _capability_ids(card: dict[str, Any]) -> set[str]:
    return {
        str(cap.get("id"))
        for cap in card.get("capabilities", [])
        if isinstance(cap, dict) and cap.get("id")
    }


def _agent_ref_from_card(card: dict[str, Any]) -> AgentRef:
    did = str(card.get("did") or "")
    if not did:
        raise RuntimeError(f"agent card missing DID: {card}")
    return AgentRef(did=did, alias=card.get("alias"), name=str(card.get("name") or ""))


def _agent_cards_summary(cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "did": card.get("did"),
            "alias": card.get("alias"),
            "name": card.get("name"),
            "capabilities": sorted(_capability_ids(card)),
        }
        for card in cards
    ]


def _list_agents(client: HttpJsonClient) -> list[dict[str, Any]]:
    response = client.get("/api/v1/a2a/agents")
    if not isinstance(response, list):
        raise RuntimeError(f"unexpected agents response: {response}")
    return [card for card in response if isinstance(card, dict)]


def _write_agent_refs(root: Path, agents: dict[str, AgentRef]) -> None:
    lines = [
        f'export L1_REQUESTER_AGENT="{agents["requester"].did}"',
        f'export L1_ALPHA_AGENT="{agents["alpha"].did}"',
        f'export L1_BETA_AGENT="{agents["beta"].did}"',
        f'export L1_GAMMA_AGENT="{agents["gamma"].did}"',
    ]
    (root / "agent_refs.env").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _agents_as_dict(agents: dict[str, AgentRef]) -> dict[str, Any]:
    return {
        role: {"did": agent.did, "alias": agent.alias, "name": agent.name}
        for role, agent in agents.items()
    }


def _run_agent_script(
    args: argparse.Namespace,
    root: Path,
    command: str,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    env = _base_env(args, root)
    result = subprocess.run(
        ["bash", args.agent_script, command],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    _write_text(root / "runner_logs" / f"agent_{command}_{int(time.time())}.log", result.stdout + result.stderr)
    if check and result.returncode != 0:
        raise RuntimeError(f"agent script {command} failed: {result.stdout}{result.stderr}")
    return result


def _restart_agents(args: argparse.Namespace, root: Path) -> None:
    # Restart wake is a controlled-pilot fallback only. Event wake is the
    # preferred path because it preserves long-running agent process identity.
    _run_agent_script(args, root, "stop", check=False)
    _run_agent_script(args, root, "start")


def _run_contract_command(
    args: argparse.Namespace,
    root: Path,
    command: str,
    agents: dict[str, AgentRef],
) -> dict[str, Any]:
    env = _base_env(args, root)
    env.update({
        "L1_REQUESTER_AGENT": agents["requester"].did,
        "L1_ALPHA_AGENT": agents["alpha"].did,
        "L1_BETA_AGENT": agents["beta"].did,
        "L1_GAMMA_AGENT": agents["gamma"].did,
    })
    result = subprocess.run(
        [args.python, "scripts/l1_pilot_001_contract_tasks.py", "--base-url", args.base_url, "--root", str(root), command],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    _write_text(root / "runner_logs" / f"contract_{command}_{int(time.time())}.log", result.stdout + result.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"contract command {command} failed: {result.stdout}{result.stderr}")
    return json.loads(result.stdout)


def _base_env(args: argparse.Namespace, root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "L1_PILOT_ROOT": str(root),
        "CIVITASOS_URL": args.base_url,
        "PYTHON": args.python,
    })
    if _env_flag("L1_REQUIRE_SERVICE_TOKEN"):
        env.setdefault("CIVITASOS_RUNTIME_REQUIRE_SERVICE_TOKEN_BOOTSTRAP", "1")
    return env


def _wake_security_context(args: argparse.Namespace) -> dict[str, Any]:
    secret = os.getenv("CIVITASOS_WAKE_CALLBACK_SECRET", "").strip()
    return {
        "schema_version": "l1-wake-security-context:v1",
        "wake_mode": args.wake_mode,
        "require_signed_wake": bool(args.require_signed_wake),
        "callback_secret_configured": bool(secret),
        "signature_scheme": "hmac-sha256(issuer.timestamp.raw_body)" if secret else None,
        "expected_issuer": "civitasos-backend" if secret else None,
        "compatibility_mode": not bool(secret),
        "non_claims": [
            "secret_presence_does_not_prove_backend_was_started_with_same_secret",
            "signed_wake_does_not_authorize_production_runtime_execution",
        ],
    }


def _wait_for_task(
    client: HttpJsonClient,
    task_id: str,
    *,
    timeout: float,
    poll_interval: float,
    snapshots_dir: Path,
    fallback_after: float | None = None,
    fallback: Any = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = time.monotonic() + timeout
    poll = 0
    last_task: dict[str, Any] | None = None
    fallback_used = False
    while time.monotonic() < deadline:
        poll += 1
        task = _get_task(client, task_id)
        last_task = task
        _write_json(snapshots_dir / f"{poll:03d}.json", task)
        if task.get("status") in TERMINAL_STATUSES:
            return task, {
                "poll_count": poll,
                "fallback_used": fallback_used,
                "fallback_after_secs": fallback_after,
            }
        if (
            fallback is not None
            and fallback_after is not None
            and not fallback_used
            and time.monotonic() - started >= fallback_after
        ):
            fallback()
            fallback_used = True
        time.sleep(poll_interval)
    raise TimeoutError(f"task {task_id} did not reach terminal state; last={last_task}")


def _get_task(client: HttpJsonClient, task_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/a2a/pool/tasks/{task_id}")
    if isinstance(response, dict) and isinstance(response.get("task"), dict):
        return response["task"]
    raise RuntimeError(f"unexpected task response for {task_id}: {response}")


def _collect_evidence(
    client: HttpJsonClient,
    root: Path,
    agents: dict[str, AgentRef],
    stage_reports: list[dict[str, Any]],
    wake_security: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state_path = root / "task_chain.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    tasks: dict[str, Any] = {}
    for key in ("alpha_task_id", "beta_task_id", "gamma_task_id"):
        task_id = state.get(key)
        if task_id:
            tasks[key] = _summarise_task(_get_task(client, str(task_id)))

    pool_response = client.get("/api/v1/a2a/pool/tasks")
    pool_tasks = _task_collection(pool_response)
    chain_task_ids = {str(task.get("id")) for task in tasks.values() if task.get("id")}
    chain_failed_tasks, historical_failed_tasks = _split_failed_tasks(pool_tasks, chain_task_ids)
    delivered_tasks = [_summarise_task(task) for task in pool_tasks if task.get("status") == "Delivered"]
    contract_log_hits = _contract_log_hits(root)
    event_wake_evidence = _event_wake_evidence(root, stage_reports)
    repair_suggestion_audit_refs = _repair_suggestion_audit_refs(
        tasks,
        chain_failed_tasks,
        contract_log_hits,
    )
    return {
        "schema_version": "l1-pilot-001-contract-runner-evidence:v1",
        "generated_at": _now(),
        "chain_passed": all(
            tasks.get(key, {}).get("status") in SUCCESS_STATUSES
            for key in ("alpha_task_id", "beta_task_id", "gamma_task_id")
        ),
        "root": str(root),
        "auth_context": client.auth_context(),
        "wake_security": wake_security or {},
        "agents": _agents_as_dict(agents),
        "stage_reports": stage_reports,
        "event_wake_evidence": event_wake_evidence,
        "task_chain": state,
        "tasks": tasks,
        "pool_summary": {
            "total": len(pool_tasks),
            "delivered_count": len(delivered_tasks),
            "failed_count": len(chain_failed_tasks) + len(historical_failed_tasks),
            "chain_failed_count": len(chain_failed_tasks),
            "historical_failed_count": len(historical_failed_tasks),
            "open_count": sum(1 for task in pool_tasks if task.get("status") == "Open"),
        },
        "failed_tasks": chain_failed_tasks,
        "historical_pool_failed_tasks": historical_failed_tasks,
        "contract_log_hits": contract_log_hits,
        "repair_suggestion_audit_refs": repair_suggestion_audit_refs,
        "non_claims": [
            "l1_controlled_pilot_only",
            "h3_remains_blocked",
            "no_production_runtime_execution",
            "no_production_receipt_write",
        ],
    }


def _event_wake_evidence(root: Path, stage_reports: list[dict[str, Any]]) -> dict[str, Any]:
    logs_by_role = {
        role: _read_text_if_exists(root / "logs" / f"{ROLE_NAMES[role]}.log")
        for role in ROLE_NAMES
    }
    all_logs = "\n".join(logs_by_role.values())
    per_stage = []
    for stage in stage_reports:
        role = str(stage.get("role") or "")
        task_id = str(stage.get("task_id") or "")
        role_log = logs_by_role.get(role, "")
        per_stage.append({
            "role": role,
            "task_id": task_id,
            "fallback_used": bool((stage.get("wake") or {}).get("fallback_used")),
            "terminal_status": stage.get("terminal_status"),
            "claimed_by": stage.get("claimed_by"),
            "task_posted_wake_observed": _log_has_event(role_log, "task.posted", task_id),
            "task_claimed_wake_observed": _log_has_event(role_log, "task.claimed", task_id),
            "task_delivered_wake_observed": _log_has_event(role_log, "task.delivered", task_id),
            "rule_pool_claim_observed": "Rule 'auto_claim_matching' fired: pool_claim" in role_log,
            "wake_action_bias_pool_claim_observed": (
                "Wake action bias accepted: action=pool_claim" in role_log
                and (not task_id or task_id in role_log)
            ),
        })
    return {
        "schema_version": "l1-event-wake-evidence:v1",
        "wake_event_counts": {
            "task_posted": all_logs.count("WAKE received: event=task.posted"),
            "task_claimed": all_logs.count("WAKE received: event=task.claimed"),
            "task_delivered": all_logs.count("WAKE received: event=task.delivered"),
        },
        "rule_pool_claim_count": all_logs.count("Rule 'auto_claim_matching' fired: pool_claim"),
        "wake_action_bias_pool_claim_count": all_logs.count(
            "Wake action bias accepted: action=pool_claim"
        ),
        "service_token_bootstrap_count": all_logs.count("Service-token bootstrap token acquired"),
        "did_auth_bootstrap_count": all_logs.count("DID auth token bootstrapped"),
        "stage_evidence": per_stage,
        "non_claims": [
            "log_evidence_is_local_controlled_pilot_observability",
            "wake_action_bias_does_not_bypass_scope_or_backend_claim_checks",
            "event_wake_evidence_does_not_claim_h3_production_readiness",
        ],
    }


def _log_has_event(log_text: str, event: str, task_id: str) -> bool:
    marker = f"WAKE received: event={event}"
    return marker in log_text and (not task_id or task_id in log_text)


def _read_text_if_exists(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _task_collection(pool_response: Any) -> list[dict[str, Any]]:
    if isinstance(pool_response, dict) and isinstance(pool_response.get("tasks"), list):
        return [task for task in pool_response["tasks"] if isinstance(task, dict)]
    if isinstance(pool_response, list):
        return [task for task in pool_response if isinstance(task, dict)]
    return []


def _split_failed_tasks(
    pool_tasks: list[dict[str, Any]],
    chain_task_ids: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    chain_failed_tasks: list[dict[str, Any]] = []
    historical_failed_tasks: list[dict[str, Any]] = []
    for task in pool_tasks:
        if task.get("status") != "Failed":
            continue
        summary = _summarise_task(task)
        if str(task.get("id") or "") in chain_task_ids:
            chain_failed_tasks.append(summary)
        else:
            historical_failed_tasks.append(summary)
    return chain_failed_tasks, historical_failed_tasks


def _summarise_task(task: dict[str, Any]) -> dict[str, Any]:
    output = task.get("output")
    output_text = output if isinstance(output, str) else json.dumps(output, ensure_ascii=False, sort_keys=True) if output is not None else ""
    return {
        "id": task.get("id"),
        "status": task.get("status"),
        "required_capability": task.get("required_capability"),
        "claimed_by": task.get("claimed_by"),
        "failure_reason": task.get("failure_reason"),
        "delivery_contract": (task.get("input") or {}).get("delivery_contract") if isinstance(task.get("input"), dict) else None,
        "repair_suggestions": _task_repair_suggestions(task),
        "has_output": output not in (None, "", {}, []),
        "output_chars": len(output_text),
        "output_preview": output_text[:500],
    }


def _task_repair_suggestions(task: dict[str, Any]) -> list[str]:
    candidates = [
        (task.get("delivery_contract_verification") or {}).get("repair_suggestions")
        if isinstance(task.get("delivery_contract_verification"), dict) else None,
        (task.get("input") or {}).get("repair_suggestions") if isinstance(task.get("input"), dict) else None,
        (task.get("metadata") or {}).get("repair_suggestions") if isinstance(task.get("metadata"), dict) else None,
    ]
    for value in candidates:
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
    return []


def _repair_suggestion_audit_refs(
    tasks: dict[str, Any],
    failed_tasks: list[dict[str, Any]],
    contract_log_hits: list[dict[str, str]],
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for source, task in [*tasks.items(), *[(f"failed_{index}", task) for index, task in enumerate(failed_tasks, start=1)]]:
        suggestions = task.get("repair_suggestions") if isinstance(task, dict) else None
        if not isinstance(suggestions, list) or not suggestions:
            continue
        records.append({
            "source": source,
            "task_id": task.get("id"),
            "failure_reason": task.get("failure_reason"),
            "repair_suggestions": suggestions,
            "audit_ref_kind": "delivery_contract_repair_suggestions",
        })
    for index, hit in enumerate(contract_log_hits, start=1):
        records.append({
            "source": f"contract_log_hit_{index}",
            "task_id": None,
            "failure_reason": "delivery_contract_blocked",
            "repair_suggestions": [
                "Inspect delivery contract violation and create an operator-approved repair task when needed."
            ],
            "audit_ref_kind": "delivery_contract_block_log",
            "log": hit.get("log"),
            "line": hit.get("line"),
        })
    return {
        "schema_version": "l1-repair-suggestion-audit-refs:v1",
        "record_count": len(records),
        "records": records,
        "non_claims": [
            "repair_suggestion_audit_refs_do_not_auto_retry_failed_tasks",
            "repair_suggestion_audit_refs_do_not_authorize_h3_production_readiness",
        ],
    }


def _contract_log_hits(root: Path) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for log_path in sorted((root / "logs").glob("*.log")):
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "Delivery contract blocked" in line:
                hits.append({"log": str(log_path), "line": line})
    return hits


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
