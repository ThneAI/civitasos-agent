"""agent.py — 生产就绪的 Agent 入口，从环境变量配置。

用法:
    # 直接运行
    python agent.py

    # 或通过 Docker
    docker run --env-file .env civitasos-agent

所有配置通过环境变量注入，参见 .env.example。
"""

import asyncio
import logging
import os

from civitasos_runtime import AgentRunner
from civitasos_runtime.models import Decision, DecisionSource


log = logging.getLogger(__name__)


def _benchmark_target_mode_enabled() -> bool:
    """Return True when benchmark mode owns pool-claim routing."""
    return bool(
        os.getenv("BENCHMARK_BACKEND_TASK_ID")
        or os.getenv("BENCHMARK_BACKEND_TASK_ID_FILE")
    )


def build_runner() -> AgentRunner:
    """从环境变量构建 AgentRunner。"""
    backend = os.getenv("CIVITASOS_URL", "http://localhost:8099")
    name = os.getenv("AGENT_NAME", "CivitasAgent")
    capabilities = [
        c.strip()
        for c in os.getenv("AGENT_CAPABILITIES", "general").split(",")
        if c.strip()
    ]

    # LLM 配置
    llm_spec = os.getenv("AGENT_LLM", "ollama:qwen3:latest")
    llm_kwargs = {}
    if llm_spec.startswith("ollama:"):
        llm_kwargs["base_url"] = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
        llm_kwargs["api_key"] = "ollama"
        llm_spec = f"openai:{llm_spec.split(':', 1)[1]}"
    else:
        api_key = os.getenv("LLM_API_KEY", "")
        if api_key:
            llm_kwargs["api_key"] = api_key
        base_url = os.getenv("LLM_BASE_URL", "")
        if base_url:
            llm_kwargs["base_url"] = base_url

    gateway_port = int(os.getenv("GATEWAY_PORT", "0")) or None
    identity = os.getenv("AGENT_IDENTITY", "") or None

    runner = AgentRunner(
        base_url=backend,
        name=name,
        capabilities=capabilities,
        llm=llm_spec,
        llm_kwargs=llm_kwargs or None,
        stake=int(os.getenv("AGENT_STAKE", "100")),
        heartbeat_interval=int(os.getenv("AGENT_HEARTBEAT", "60")),
        gateway_port=gateway_port,
        identity_file=identity,
        endpoint_url=os.getenv("AGENT_ENDPOINT", "") or None,
        data_dir=os.getenv("AGENT_DATA_DIR", "data"),
    )

    # ── 可在这里添加自定义工具 / 规则 / 良心检查 ──────────

    # 示例: 自动认领匹配 capabilities 的任务
    @runner.rule(priority=30, name="auto_claim_matching")
    def auto_claim_matching(briefing: dict, _memories: dict) -> Decision | None:
        if _benchmark_target_mode_enabled():
            # Benchmark target mode installs a higher-priority rule that owns
            # the claim path. Returning None here lets the claimed target fall
            # through to LLM execution instead of re-claiming and deadlocking.
            return None
        wake_bias = briefing.get("backend_wake_action_bias")
        if isinstance(wake_bias, dict) and wake_bias.get("action") == "pool_claim":
            task_id = str(wake_bias.get("task_id") or "").strip()
            if task_id:
                log.info(
                    "Wake action bias accepted: action=pool_claim task_id=%s source_event=%s",
                    task_id,
                    wake_bias.get("source_event") or "",
                )
                return Decision(
                    action="pool_claim",
                    params={
                        "task_id": task_id,
                        "poster_id": wake_bias.get("requester") or "",
                        "_wake_event_driven": True,
                        "_wake_source_event": wake_bias.get("source_event") or "",
                    },
                    reasoning=str(
                        wake_bias.get("reason")
                        or "backend wake action bias matched this agent"
                    ),
                    confidence=float(wake_bias.get("confidence") or 0.9),
                    source=DecisionSource.RULES,
                )
        cap_set = set(capabilities)
        candidates = []
        candidates.extend(briefing.get("pool_tasks", []) or [])
        candidates.extend(briefing.get("opportunities", []) or [])
        for task in candidates:
            required = set(task.get("required_capabilities", []) or [])
            if not required and task.get("required_capability"):
                required = {task["required_capability"]}
            if not required and task.get("capability"):
                required = {task["capability"]}
            if required and required.issubset(cap_set):
                task_id = task.get("task_id") or task.get("id")
                if not task_id:
                    continue
                return Decision(
                    action="pool_claim",
                    params={"task_id": task_id},
                    reasoning=f"Capabilities match: {required}",
                    confidence=0.9,
                    source=DecisionSource.RULES,
                )
        return None

    return runner


def _install_benchmark_mode_if_present(runner) -> None:
    """F.1.b hook: when BENCHMARK_TASK_ID is set, wire collector + target rule.

    Pure no-op when env var absent — production behavior unchanged.
    Import is local so production agents don't pay the import cost.
    """
    if not os.getenv("BENCHMARK_TASK_ID"):
        return
    from benchmarks.benchmark_mode import install
    install(runner)


def main():
    log_level = os.getenv("LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    runner = build_runner()
    _install_benchmark_mode_if_present(runner)
    logger = logging.getLogger("civitasos_agent")
    logger.info(
        "Starting %s | backend=%s | llm=%s",
        os.getenv("AGENT_NAME", "CivitasAgent"),
        os.getenv("CIVITASOS_URL", "http://localhost:8099"),
        os.getenv("AGENT_LLM", "ollama:qwen3:latest"),
    )

    try:
        asyncio.run(runner.start())
    except KeyboardInterrupt:
        logger.info("Interrupted — shutting down")


if __name__ == "__main__":
    main()
