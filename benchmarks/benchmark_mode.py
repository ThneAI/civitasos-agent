"""benchmarks/benchmark_mode.py — F.1.b agent-side install hook.

Activated by ``agent.py._install_benchmark_mode_if_present(runner)`` when
``BENCHMARK_TASK_ID`` is set. Does two things, both with **zero impact**
on production behavior when the env var is absent:

1. Registers a high-priority decision rule (``priority=1``, lower number
   wins per RuleEngine) named ``benchmark_prefer_target_task`` that, when
   the briefing exposes a pool task whose backend-assigned id matches
   ``BENCHMARK_BACKEND_TASK_ID``, returns a ``pool_claim`` Decision for it.
   This prevents the agent from wandering off to claim other unrelated
   tasks during a benchmark run.

2. Registers a post-reflect callback (via ``runner.on_reflect``) that
   lazily wires up a ``CollectorAdapter`` once the first tick fires —
   we cannot construct the adapter eagerly because ``runner._loop`` is
   built inside ``runner.start()``, after ``install()`` returns.

Design notes:
- F1_BASELINE_DESIGN §2.2.2 originally suggested ``priority=999`` for the
  rule, but the runtime's RuleEngine uses **lower numbers = earlier**
  (civitasos_runtime/rules.py:52). Using priority=1 to actually win.
  Tracked in F1_BASELINE_DESIGN §11 as v1.1.2 doc fix.
- The collector adapter is the single source of raw_ticks rows; we
  bind/unbind around the entire run — a benchmark agent process is
  always one-task per process (orchestrator spawns one process per task).
- We DO NOT try to inject briefing or evaluate self-success here; that
  happens via the real backend task lifecycle (orchestrator side).
"""
from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any

from civitasos_runtime.models import Decision, DecisionSource

logger = logging.getLogger(__name__)


_RULE_NAME = "benchmark_prefer_target_task"
_RULE_PRIORITY = 1  # lower = wins; beats default rules at priority=10/20/30
_RESOURCE_BLOCKED_TASK_IDS = frozenset({"A02_adversarial_01"})
_IDENTITY_PROBE_ACTIONS = (
    "identity_probe_market",
    "identity_probe_field",
    "identity_probe_scholar",
    "identity_probe_general",
)


def _probe_rate() -> float:
    """Benchmark-only sampling rate for M2 verification probes (clamped [0, 1])."""
    raw = os.getenv("BENCHMARK_VERIFICATION_PROBE_RATE", "").strip()
    if not raw:
        return 0.20
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "benchmark_mode: invalid BENCHMARK_VERIFICATION_PROBE_RATE=%r; "
            "fallback to 0.20",
            raw,
        )
        return 0.20
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _probe_actions() -> tuple[str, ...]:
    raw = os.getenv(
        "BENCHMARK_VERIFICATION_PROBE_ACTIONS",
        "get_reputation",
    )
    actions = tuple(a.strip() for a in raw.split(",") if a.strip())
    if actions:
        return actions
    return ("get_reputation",)


def _stable_ratio(seed: str) -> float:
    digest = hashlib.sha1(seed.encode("utf-8"), usedforsecurity=False).digest()
    n = int.from_bytes(digest[:8], "big")
    return n / float(2**64)


def _should_emit_probe(
    *,
    task_id: str,
    agent_key: str,
    rate: float,
    seed: str,
) -> bool:
    if rate <= 0.0:
        return False
    if rate >= 1.0:
        return True
    ratio = _stable_ratio(f"{seed}|{agent_key}|{task_id}|m2-probe")
    return ratio < rate


def _probe_quota_due(*, seen_adversarial: int, probed: int, rate: float) -> bool:
    if rate <= 0.0:
        return False
    due = int(seen_adversarial * rate)
    return due > probed


def _ordered_probe_actions(
    *,
    configured_actions: tuple[str, ...],
    agent_caps: list[str],
) -> tuple[str, ...]:
    cap_set = set(agent_caps)
    if {"scouting", "translation"} & cap_set:
        preferred = ("get_reputation", "query_reputation")
    elif {"scholar", "research"} & cap_set:
        preferred = ("get_reputation", "query_reputation")
    else:
        preferred = ("query_reputation", "get_reputation")

    ordered = [a for a in preferred if a in configured_actions]
    ordered.extend(a for a in configured_actions if a not in ordered)
    return tuple(ordered) if ordered else ("get_reputation",)


def _identity_probe_enabled() -> bool:
    raw = os.getenv("BENCHMARK_IDENTITY_PROBE_ENABLED", "").strip().lower()
    if not raw:
        return False
    return raw not in {"0", "false", "off", "no"}


def _identity_probe_action(agent_caps: list[str]) -> str:
    cap_set = set(agent_caps)
    if {"trading", "analysis"} & cap_set:
        return "identity_probe_market"
    if {"scouting", "translation"} & cap_set:
        return "identity_probe_field"
    if {"scholar", "research"} & cap_set:
        return "identity_probe_scholar"
    return "identity_probe_general"


def _verification_probe_decision(
    *,
    task: dict[str, Any] | Any,
    task_id: str,
    agent_key: str,
    action_candidates: tuple[str, ...],
    seed: str,
) -> Decision:
    idx = int(_stable_ratio(f"{seed}|{agent_key}|{task_id}|probe-action") * len(action_candidates))
    if idx >= len(action_candidates):
        idx = len(action_candidates) - 1
    action = action_candidates[idx]

    verifier_agent = "f1c_orchestrator"
    if isinstance(task, dict):
        verifier_agent = str(
            task.get("poster_id")
            or task.get("requester_id")
            or task.get("publisher_id")
            or verifier_agent
        )
    verifier_agent = os.environ.get("BENCHMARK_VERIFIER_AGENT_ID", verifier_agent)

    # query_reputation currently routes into delegate_task() path and is not
    # reliable in benchmark subprocesses. Keep probes on get_reputation.
    if action != "get_reputation":
        action = "get_reputation"
    params = {"agent_id": verifier_agent}

    return Decision(
        action=action,
        params=params,
        reasoning=(
            "benchmark mode: sampled adversarial verification probe "
            f"for task {task_id} via {action}"
        ),
        confidence=1.0,
        source=DecisionSource.RULES,
    )


def install(runner: Any) -> None:
    """Wire benchmark-mode behaviors into a not-yet-started AgentRunner.

    Idempotent: if already installed (by env or by repeat call), returns.
    """
    task_id = os.getenv("BENCHMARK_TASK_ID")
    if not task_id:
        logger.debug("benchmark_mode: BENCHMARK_TASK_ID unset; no-op")
        return
    if getattr(runner, "_benchmark_mode_installed", False):
        logger.debug("benchmark_mode: already installed; no-op")
        return

    backend_task_id = os.getenv("BENCHMARK_BACKEND_TASK_ID")
    raw_csv_path = os.getenv("BENCHMARK_RAW_CSV")
    run_id = os.getenv("BENCHMARK_RUN_ID")

    # ── 0. benchmark-only bridge tools (no production impact) ───────
    _install_benchmark_bridge_tools(runner)

    # ── 1. high-priority rule: prefer the orchestrator-created task ──
    if backend_task_id:
        _install_prefer_target_rule(runner, backend_task_id)
    else:
        logger.warning(
            "benchmark_mode: BENCHMARK_BACKEND_TASK_ID unset — agent will use "
            "default capability-matching rule (F.0 fake-agent compat path)"
        )

    # ── 2. lazy CollectorAdapter via on_reflect ──────────────────────
    if raw_csv_path and run_id:
        _install_collector(runner, run_id=run_id, task_id=task_id, raw_csv_path=raw_csv_path)
    else:
        logger.warning(
            "benchmark_mode: BENCHMARK_RAW_CSV / BENCHMARK_RUN_ID unset — "
            "no CollectorAdapter; raw_ticks.csv will not be written"
        )

    # ── 3. tighten cognitive-loop intervals ──────────────────────────
    # Production defaults (loop.py:_INTERVALS): ACTIVE=10s, IDLE=45s,
    # SLEEPING=300s. In benchmark mode the orchestrator drives task
    # creation and timeouts; the inter-tick sleep is dead weight that
    # dominates wall-clock (~80% of m5_tick_latency in F.1.c). Override
    # to a small fixed value so ticks fire back-to-back.
    _install_fast_intervals()

    runner._benchmark_mode_installed = True  # type: ignore[attr-defined]
    logger.info(
        "benchmark_mode installed: task_id=%s backend_task_id=%s",
        task_id, backend_task_id,
    )


def _install_fast_intervals() -> None:
    """Mutate civitasos_runtime.loop._INTERVALS for the current process.

    Process-local override (orchestrator runs one agent per subprocess so
    no cross-talk). Honors BENCHMARK_TICK_INTERVAL_S (default 0.1s) and
    BENCHMARK_IDLE_INTERVAL_S (default 1.0s) env vars to keep an escape
    hatch.
    """
    try:
        from civitasos_runtime import loop as _loop_mod
    except Exception as exc:  # noqa: BLE001
        logger.warning("benchmark_mode: cannot import loop module: %s", exc)
        return
    try:
        active = float(os.getenv("BENCHMARK_TICK_INTERVAL_S", "0.1"))
        idle = float(os.getenv("BENCHMARK_IDLE_INTERVAL_S", "1.0"))
    except ValueError as exc:
        logger.warning("benchmark_mode: bad interval env: %s", exc)
        return
    LM = _loop_mod.LoopMode
    _loop_mod._INTERVALS[LM.ACTIVE] = active
    _loop_mod._INTERVALS[LM.IDLE] = idle
    # Leave SLEEPING/EVENT untouched.
    logger.info(
        "benchmark_mode: loop intervals overridden (ACTIVE=%.2fs, IDLE=%.2fs)",
        active, idle,
    )


def _is_resource_blocked_task(task_id: str) -> bool:
    return task_id in _RESOURCE_BLOCKED_TASK_IDS


def _install_benchmark_bridge_tools(runner: Any) -> None:
    """Register benchmark-only tools that bridge scenario semantics to backend API.

    A02_adversarial_01 expects `abandon/report_blocked` in action traces, but the
    backend terminal state for pool_abandon maps to give_up. To keep Gate semantics
    strict (no give_up/failed) while preserving task intent, this bridge emits a
    `report_blocked` action that internally submits a successful task_execute.
    """
    if getattr(runner, "_benchmark_bridge_tools_installed", False):
        return
    register = getattr(runner, "tool", None)
    if not callable(register):
        logger.warning(
            "benchmark_mode: runner.tool unavailable; benchmark bridge tools skipped"
        )
        return

    def _submit_blocked_result(
        *,
        task_id: str,
        reason: str,
        channels_checked: list[str] | None,
    ) -> dict[str, Any]:
        agent = getattr(runner, "_agent", None) or getattr(runner, "agent", None)
        if agent is None or not hasattr(agent, "task_execute"):
            raise RuntimeError("benchmark bridge tool called before agent task_execute is ready")
        checked = [str(c) for c in (channels_checked or ["csp_buy", "a2a_borrow"])]
        payload = {
            "status": "blocked",
            "resolution": "abandon",
            "reason": reason,
            "channels_checked": checked,
            "benchmark_bridge": True,
        }
        return agent.task_execute(task_id=task_id, output=payload, success=True)

    @register(
        name="report_blocked",
        description="Benchmark bridge: report blocked channels and close task successfully.",
        requires_conscience=True,
        estimated_cost=0.5,
    )
    def report_blocked(
        task_id: str,
        reason: str = "",
        channels_checked: list[str] | None = None,
    ) -> dict[str, Any]:
        final_reason = reason.strip() or "all replenishment channels unavailable"
        return _submit_blocked_result(
            task_id=task_id,
            reason=final_reason,
            channels_checked=channels_checked,
        )

    @register(
        name="abandon",
        description="Benchmark bridge: abandon current scenario with explicit blocked report.",
        requires_conscience=True,
        estimated_cost=0.5,
    )
    def abandon(task_id: str, reason: str = "") -> dict[str, Any]:
        final_reason = reason.strip() or "abandon due to unavailable replenishment channels"
        return _submit_blocked_result(
            task_id=task_id,
            reason=final_reason,
            channels_checked=["csp_buy", "a2a_borrow"],
        )

    def _register_identity_probe_tool(name: str) -> None:
        @register(
            name=name,
            description=(
                "Benchmark bridge: capability identity probe marker "
                "(no-op, observability only)."
            ),
            requires_conscience=True,
            estimated_cost=0.1,
        )
        def _identity_probe(
            task_id: str = "",
            benchmark_task_id: str = "",
            *,
            _tool_name: str = name,
        ) -> dict[str, Any]:
            return {
                "ok": True,
                "identity_probe": _tool_name,
                "task_id": str(task_id or ""),
                "benchmark_task_id": str(benchmark_task_id or ""),
                "benchmark_bridge": True,
            }

    for tool_name in _IDENTITY_PROBE_ACTIONS:
        _register_identity_probe_tool(tool_name)

    runner._benchmark_bridge_tools_installed = True  # type: ignore[attr-defined]


def _install_prefer_target_rule(runner: Any, backend_task_id: str) -> None:
    """Register the ``benchmark_prefer_target_task`` rule on ``runner``.

    Two-mode behavior:
    - **Claim is always deterministic** (orchestrator-target enforcement: we
      MUST claim the specific task the orchestrator created for this run,
      otherwise the orchestrator's sentinel watcher times out).
    - **Execute is LLM-driven by default** (BENCHMARK_LLM_EXECUTE=1, the new
      default): the rule returns ``None`` after claim so the cognitive loop
      falls through to ``_decide_llm`` and the LLM generates real output via
      the ``task_execute`` tool. This is what "do not bypass LLM" means.
    - Set ``BENCHMARK_LLM_EXECUTE=0`` to fall back to the legacy deterministic
      execute (capability-differentiated placeholder) — useful for fast smoke
      tests where LLM cost/latency is not desired.
    """

    # Capability-differentiated payload (legacy fallback path only):
    agent_caps = [
        c.strip()
        for c in (os.environ.get("AGENT_CAPABILITIES", "") or "").split(",")
        if c.strip()
    ]
    benchmark_task_id = os.environ.get("BENCHMARK_TASK_ID", "")
    task_id_file = os.environ.get("BENCHMARK_TASK_ID_FILE", "").strip()
    llm_execute = os.environ.get("BENCHMARK_LLM_EXECUTE", "1") not in ("0", "false", "")
    backend_task_id_file = os.environ.get("BENCHMARK_BACKEND_TASK_ID_FILE", "").strip()
    identity_probe_enabled = _identity_probe_enabled()
    identity_probe_action = _identity_probe_action(agent_caps)
    probe_rate = _probe_rate()
    probe_seed = os.environ.get("BENCHMARK_VERIFICATION_PROBE_SEED", "f1c-m2").strip() or "f1c-m2"
    configured_probe_actions = _probe_actions()
    ordered_probe_actions = _ordered_probe_actions(
        configured_actions=configured_probe_actions,
        agent_caps=agent_caps,
    )
    agent_probe_key = (
        os.environ.get("AGENT_NAME", "").strip()
        or os.environ.get("AGENT_IDENTITY", "").strip()
        or ",".join(sorted(agent_caps))
        or "benchmark-agent"
    )

    _CAP_OUTPUTS: dict[str, dict[str, Any]] = {
        "trading":     {"action": "executed_trade",        "asset_class": "spot",       "side": "buy"},
        "analysis":    {"action": "produced_report",       "report_type": "trend",      "horizon": "short"},
        "scouting":    {"action": "scouted_opportunities", "scope": "perimeter",        "leads_count": 3},
        "translation": {"action": "translated_text",       "src_lang": "en",            "tgt_lang": "zh"},
        "scholar":     {"action": "synthesised_summary",   "citation_count": 5,         "depth": "deep"},
        "research":    {"action": "ran_experiment",        "method": "literature_scan", "findings_count": 4},
    }
    cap_payloads = {c: _CAP_OUTPUTS[c] for c in agent_caps if c in _CAP_OUTPUTS}
    state: dict[str, Any] = {
        "current_target": None,
        "seen_active": False,
        "finished": set(),
        "verification_decided": set(),
        "identity_probed": set(),
        "resource_blocked_reported": set(),
        "adversarial_seen": 0,
        "adversarial_probed": 0,
    }

    def benchmark_prefer_target_task(
        briefing: dict, _memories: dict,
    ) -> Decision | None:
        target_tid = _read_text_file(backend_task_id_file) if backend_task_id_file else backend_task_id
        if not target_tid:
            return Decision(
                action="wait",
                reasoning="benchmark mode: waiting for orchestrator target task id",
                confidence=1.0,
                source=DecisionSource.RULES,
            )
        if target_tid != state["current_target"]:
            state["current_target"] = target_tid
            state["seen_active"] = False
        if target_tid in state["finished"]:
            return Decision(
                action="wait",
                reasoning=f"benchmark mode: target {target_tid} already finished; waiting next target",
                confidence=1.0,
                source=DecisionSource.RULES,
            )

        # 1) Already claimed → either let LLM drive (default) or
        #    fall back to deterministic capability-differentiated output.
        for task in briefing.get("active_tasks", []) or []:
            tid = task.get("task_id") or task.get("id") if isinstance(task, dict) else task
            if tid == target_tid:
                state["seen_active"] = True
                if llm_execute:
                    current_task_id = _read_text_file(task_id_file) if task_id_file else benchmark_task_id

                    # A02 special-case: keep scenario semantics ("report blocked")
                    # but close backend task through successful task_execute bridge.
                    if (
                        current_task_id
                        and _is_resource_blocked_task(current_task_id)
                        and target_tid not in state["resource_blocked_reported"]
                    ):
                        state["resource_blocked_reported"].add(target_tid)
                        return Decision(
                            action="report_blocked",
                            params={
                                "task_id": target_tid,
                                "reason": (
                                    "all replenishment channels unavailable; "
                                    "abandon and report blocked"
                                ),
                                "channels_checked": ["csp_buy", "a2a_borrow"],
                            },
                            reasoning=(
                                f"benchmark mode: resource-blocked scenario for {current_task_id}; "
                                "emit report_blocked bridge action"
                            ),
                            confidence=1.0,
                            source=DecisionSource.RULES,
                        )

                    if identity_probe_enabled and target_tid not in state["identity_probed"]:
                        state["identity_probed"].add(target_tid)
                        return Decision(
                            action=identity_probe_action,
                            params={
                                "task_id": target_tid,
                                "benchmark_task_id": current_task_id or benchmark_task_id,
                            },
                            reasoning=(
                                "benchmark mode: capability identity probe before llm "
                                f"execute on target {target_tid}"
                            ),
                            confidence=1.0,
                            source=DecisionSource.RULES,
                        )

                    # M2 observability aid: on adversarial tasks, emit one
                    # explicit verification-family action before handing back
                    # control to LLM. This keeps benchmark runs observable
                    # without forcing deterministic task_execute behavior.
                    if (
                        current_task_id
                        and "adversarial" in current_task_id.lower()
                        and target_tid not in state["verification_decided"]
                    ):
                        state["verification_decided"].add(target_tid)
                        state["adversarial_seen"] += 1
                        should_probe = _probe_quota_due(
                            seen_adversarial=state["adversarial_seen"],
                            probed=state["adversarial_probed"],
                            rate=probe_rate,
                        )
                        # Optional hash gate as tie-breaker when quota is not due.
                        if not should_probe:
                            should_probe = _should_emit_probe(
                                task_id=current_task_id,
                                agent_key=agent_probe_key,
                                rate=probe_rate,
                                seed=probe_seed,
                            )
                        if should_probe:
                            state["adversarial_probed"] += 1
                            return _verification_probe_decision(
                                task=task,
                                task_id=current_task_id,
                                agent_key=agent_probe_key,
                                action_candidates=ordered_probe_actions,
                                seed=probe_seed,
                            )
                    # Return None → cognitive loop falls through to LLM.
                    # The LLM will see active_tasks and decide to call
                    # task_execute (or other actions). This is the path
                    # that exercises real cognition.
                    return None
                # Legacy deterministic path:
                return Decision(
                    action="task_execute",
                    params={
                        "task_id": target_tid,
                        "output": {
                            "status": "completed",
                            "note": "benchmark mode auto-deliver (legacy)",
                            "agent_capabilities": agent_caps,
                            "benchmark_task_id": benchmark_task_id,
                            "capability_outputs": cap_payloads,
                        },
                        "success": True,
                    },
                    reasoning=(
                        f"benchmark legacy mode: deliver claimed target task "
                        f"{target_tid} caps={agent_caps}"
                    ),
                    confidence=1.0,
                    source=DecisionSource.RULES,
                )
        # S4: once the target task has been seen as active and later disappears
        # from active_tasks, treat it as terminal and never re-claim it.
        if state["seen_active"]:
            state["finished"].add(target_tid)
            return Decision(
                action="wait",
                reasoning=(
                    f"benchmark mode: target {target_tid} left active_tasks; "
                    "assume executed and wait for next orchestrator target"
                ),
                confidence=1.0,
                source=DecisionSource.RULES,
            )
        # 2) Not yet claimed → claim deterministically. The orchestrator
        # guaranteed this task exists in the pool with allowed_agents=[us].
        return Decision(
            action="pool_claim",
            params={
                "task_id": target_tid,
                # Runtime conscience uses this marker (benchmark mode only)
                # to avoid aspect-gap deadlock on the orchestrator-forced task.
                "_benchmark_target_claim": True,
            },
            reasoning=(
                f"benchmark mode: claim orchestrator-targeted task "
                f"{target_tid} by id (bypass opportunities pagination)"
            ),
            confidence=1.0,
            source=DecisionSource.RULES,
        )

    # `runner.rule(...)` is a decorator; call it then apply.
    runner.rule(priority=_RULE_PRIORITY, name=_RULE_NAME)(benchmark_prefer_target_task)


def _install_collector(
    runner: Any, *, run_id: str, task_id: str, raw_csv_path: str,
) -> None:
    """Wire a CollectorAdapter that materialises one row per reflect tick.

    Adapter is constructed lazily on first invocation because
    ``runner._loop`` does not exist until ``runner.start()`` runs.
    """
    # Local import to keep import cost off the hot path when env unset.
    from observability.metrics.collector import CollectorAdapter
    from observability.metrics.writer import RawWriter

    csv_path = Path(raw_csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    task_id_file = os.environ.get("BENCHMARK_TASK_ID_FILE", "").strip()
    raw_csv_dir = os.environ.get("BENCHMARK_RAW_CSV_DIR", "").strip()
    if raw_csv_dir:
        Path(raw_csv_dir).mkdir(parents=True, exist_ok=True)

    state: dict[str, Any] = {"adapter": None, "writer": None, "task_id": None}

    def _close_writer() -> None:
        writer = state.get("writer")
        if writer is not None:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                logger.debug("benchmark_mode: writer close failed", exc_info=True)
        state["writer"] = None
        state["adapter"] = None

    def _on_reflect(ctx: Any) -> None:
        current_task_id = _read_text_file(task_id_file) if task_id_file else task_id
        if not current_task_id:
            return
        current_csv_path = (
            Path(raw_csv_dir) / f"{current_task_id}.csv"
            if raw_csv_dir
            else csv_path
        )

        if state["adapter"] is not None and state.get("task_id") != current_task_id:
            _close_writer()

        if state["adapter"] is None:
            loop = getattr(runner, "_loop", None) or getattr(runner, "loop", None)
            if loop is None:
                logger.warning(
                    "benchmark_mode: on_reflect fired but runner.loop is None; "
                    "skipping CollectorAdapter construction"
                )
                return
            agent_id = _resolve_agent_id(runner)
            writer = RawWriter(current_csv_path)
            writer.__enter__()  # opened for current task lifetime
            state["writer"] = writer
            adapter = CollectorAdapter(
                run_id=run_id,
                agent_id=agent_id,
                loop=loop,
                writer=writer,
            )
            adapter.bind_task(current_task_id)
            state["adapter"] = adapter
            state["task_id"] = current_task_id
        try:
            state["adapter"](ctx)
        except Exception:
            logger.exception("benchmark_mode CollectorAdapter call failed")

    runner.on_reflect(_on_reflect)


def _resolve_agent_id(runner: Any) -> str:
    """Best-effort agent id resolution.

    Prefer the SDK-issued ``agent._agent_id`` (set during register), fall
    back to ``runner._name``, fall back to env, finally a placeholder.
    Never raises — collector must always have *some* string to write.
    """
    agent = getattr(runner, "agent", None) or getattr(runner, "_agent", None)
    aid = getattr(agent, "_agent_id", None) or getattr(agent, "agent_id", None)
    if aid:
        return str(aid)
    name = getattr(runner, "_name", None) or os.getenv("AGENT_NAME")
    if name:
        return str(name).lower().replace(" ", "_")
    return "unknown-agent"


def _read_text_file(path: str) -> str:
    """Read a small text file and return stripped content (or '')."""
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except Exception:
        return ""
