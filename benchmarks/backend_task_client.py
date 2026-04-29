"""BackendTaskClient — orchestrator-side wrapper around CivitasAgent SDK.

Implements F1_BASELINE_DESIGN §3.3.2 contract. The orchestrator plays the
"requester" role: it creates the real backend task before spawning the agent,
polls its state, and performs settlement cleanup after a terminal state.

The client is intentionally thin: it translates the 5-method contract
(create / get_state / confirm / force_fail / wait_terminal) onto the SDK
calls confirmed by the R2' audit (F1_BASELINE_DESIGN §3.3.1).

Backend `PooledTaskStatus` (Rust enum, 7 variants) is observed as a
JSON string in the `status` field. Orchestrator-relevant terminal states:
    Delivered, Completed, Failed, Cancelled
Non-terminal states the orchestrator treats as "still running":
    Open, Claimed, Disputed (Disputed is a requester-controlled state and
    should not appear in F.1 because we never call pool_dispute).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)


# Mirrors backend src/api/api_a2a.rs PooledTaskStatus serialization.
TERMINAL_STATES = frozenset({"Delivered", "Completed", "Failed", "Cancelled"})


class _SDKLike(Protocol):
    """Minimal surface we use from civitasos.CivitasAgent.

    Declared as a Protocol so unit tests can pass a hand-rolled fake without
    importing the full SDK (which requires a running backend for some calls).
    """

    def pool_post(  # noqa: D401 — interface stub
        self, *, required_capability: str, input_data: Any, reward: int,
        deadline_secs: int, allowed_agents: list[str],
    ) -> dict[str, Any]: ...

    def pool_list(self) -> list[dict[str, Any]] | dict[str, Any]: ...

    def pool_confirm(self, task_id: str) -> dict[str, Any]: ...

    def pool_fail(self, task_id: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class BackendTaskState:
    """Snapshot of a single backend task at one polling instant."""

    task_id: str
    status: str                      # raw backend status string
    output: Any | None               # PooledTask.output; None ↔ no execute submission
    raw: dict[str, Any]              # full record (forward compat)

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATES


class BackendTaskClient:
    """Orchestrator-side requester client; stateless apart from injected SDK."""

    def __init__(
        self,
        sdk: _SDKLike,
        *,
        default_capability: str = "general",
        create_max_retries: int = 6,
        create_retry_base_s: float = 0.5,
        create_retry_max_s: float = 8.0,
    ) -> None:
        self._sdk = sdk
        self._default_capability = default_capability
        self._create_max_retries = max(0, int(create_max_retries))
        self._create_retry_base_s = max(0.0, float(create_retry_base_s))
        self._create_retry_max_s = max(self._create_retry_base_s, float(create_retry_max_s))

    # -- create ---------------------------------------------------------

    def create(
        self,
        *,
        briefing: str,
        target_agent_id: str,
        capability: str | None = None,
        reward: int = 100,
        deadline_secs: int = 3600,
    ) -> str:
        """Post a benchmark task locked to ``target_agent_id`` (D3).

        Returns the backend-assigned ``task_id`` string. Raises whatever
        the SDK raises on backend errors — orchestrator decides retry policy.
        """
        cap = capability or self._default_capability
        resp: dict[str, Any] | Any
        for attempt in range(self._create_max_retries + 1):
            try:
                resp = self._sdk.pool_post(
                    required_capability=cap,
                    input_data={"description": briefing},
                    reward=reward,
                    deadline_secs=deadline_secs,
                    allowed_agents=[target_agent_id],
                )
                break
            except Exception as exc:  # noqa: BLE001
                if attempt >= self._create_max_retries or not _is_rate_limited(exc):
                    raise
                backoff_s = min(
                    self._create_retry_max_s,
                    self._create_retry_base_s * (2 ** attempt),
                )
                logger.warning(
                    "pool_post rate-limited (attempt %d/%d), retry in %.1fs: %s",
                    attempt + 1,
                    self._create_max_retries + 1,
                    backoff_s,
                    exc,
                )
                time.sleep(backoff_s)
        # Backend serializes as {"task_id": "..."}; some test fakes may wrap.
        if not isinstance(resp, dict):
            raise ValueError(f"pool_post returned non-dict: {type(resp).__name__}")
        task_id = resp.get("task_id") or resp.get("id")
        if not task_id:
            raise ValueError(f"pool_post response missing task_id: {resp}")
        return str(task_id)

    # -- read -----------------------------------------------------------

    def get_state(self, task_id: str) -> BackendTaskState:
        """Return current state by scanning ``pool_list``.

        v1.1.1 §3.3.2 acknowledges this is O(n_tasks) per poll; if profiling
        shows pressure under F.1.c (3 agents × 60 tasks) the G-stage backlog
        item ``pool_get_task(task_id)`` will replace this.
        """
        records = self._sdk.pool_list()
        # SDK returns either bare list or {"tasks": [...]}; tolerate both.
        if isinstance(records, dict):
            records = records.get("tasks") or records.get("data") or []
        if not isinstance(records, list):
            raise ValueError(
                f"pool_list returned unexpected type: {type(records).__name__}"
            )
        for rec in records:
            if not isinstance(rec, dict):
                continue
            if rec.get("id") == task_id or rec.get("task_id") == task_id:
                return BackendTaskState(
                    task_id=task_id,
                    status=str(rec.get("status", "Unknown")),
                    output=rec.get("output"),
                    raw=rec,
                )
        raise LookupError(f"backend task {task_id!r} not present in pool_list")

    # -- terminal-state polling ----------------------------------------

    def wait_terminal(
        self,
        task_id: str,
        *,
        deadline_monotonic: float,
        poll_interval_s: float = 1.0,
        on_tick: "callable | None" = None,
    ) -> BackendTaskState | None:
        """Poll until terminal state or deadline (monotonic clock) reached.

        ``on_tick(state)`` (if provided) is invoked once per poll with the
        latest snapshot; orchestrator uses this to interleave its own
        agent-process / wall-clock checks. Returns the terminal state on
        success; ``None`` if deadline elapsed first.
        """
        while True:
            try:
                state = self.get_state(task_id)
            except LookupError:
                # Task gone before we could observe terminal state — treat as
                # cancelled-equivalent so the caller writes a give_up sentinel.
                logger.warning("task %s vanished from pool_list", task_id)
                return BackendTaskState(
                    task_id=task_id, status="Cancelled", output=None, raw={},
                )
            if on_tick is not None:
                try:
                    on_tick(state)
                except Exception:  # noqa: BLE001 — observer failures must not break loop
                    logger.exception("on_tick observer raised; ignored")
            if state.is_terminal:
                return state
            if time.monotonic() >= deadline_monotonic:
                return None
            time.sleep(poll_interval_s)

    # -- cleanup --------------------------------------------------------

    def confirm(self, task_id: str) -> bool:
        """Best-effort settlement (D1). Returns True iff backend accepted."""
        try:
            self._sdk.pool_confirm(task_id)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("pool_confirm cleanup failed for %s: %s", task_id, exc)
            return False

    def force_fail(self, task_id: str) -> bool:
        """Best-effort cleanup when orchestrator gave up (timeout).

        Backend rejects pool_fail unless the task is currently Claimed; that's
        the common case here (task is already Open, Failed by deadline, or
        terminal) so we downgrade those benign rejections to debug.
        """
        try:
            self._sdk.pool_fail(task_id)
            return True
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "not Claimed" in msg or "Task must be in Claimed state" in msg:
                logger.debug("pool_fail noop for %s (state already terminal): %s", task_id, msg)
            else:
                logger.warning("pool_fail cleanup failed for %s: %s", task_id, exc)
            return False


# ─── sentinel mapping (§3.3 v1.1.1) ────────────────────────────────────

def state_to_sentinel(state: BackendTaskState) -> tuple[str, str]:
    """Map terminal backend state to (sentinel_kind, reason).

    Implements the 5-row table in F1_BASELINE_DESIGN §3.3:
        Delivered/Completed                            -> done
        Failed   AND task.output is non-None/non-empty -> failed (D2)
        Failed   AND task.output is None/empty         -> give_up (D2)
        Cancelled                                       -> give_up

    Caller (orchestrator) is responsible for non-terminal cases:
        - tick limit  -> EXIT_TICK_LIMIT
        - wall_clock  -> EXIT_WALL_CLOCK
    """
    s = state.status
    if s in ("Delivered", "Completed"):
        return "done", f"backend status={s}"
    if s == "Failed":
        # D2: distinguish failed vs give_up by output presence
        if state.output is None or state.output == "":
            return "give_up", "backend status=Failed; task.output empty (≈pool_abandon)"
        return "failed", "backend status=Failed; task.output non-empty (≈execute(success=False))"
    if s == "Cancelled":
        return "give_up", "backend status=Cancelled"
    raise ValueError(f"state_to_sentinel called on non-terminal state: {s}")


def _is_rate_limited(exc: Exception) -> bool:
    """Best-effort check for backend 429 responses."""
    status_code = int(getattr(exc, "status_code", 0) or 0)
    if status_code == 429:
        return True
    msg = str(exc).lower()
    return "http 429" in msg or "rate limit" in msg
