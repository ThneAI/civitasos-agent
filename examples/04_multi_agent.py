"""04_multi_agent.py — 同进程运行多个 Agent（不同角色）。

演示:
  - 同一进程启动 3 个 AgentRunner，各自独立认知循环
  - 不同 capabilities → 自动分拣不同类型的任务
  - 各自有独立的身份、Gateway 端口、记忆
  - 协作方式：通过 CivitasOS 任务池间接协作（发布 → 认领 → 交付 → 结算）

架构:
  Process
  ├─ AgentRunner("Researcher")  port=8310  → 数据搜集
  ├─ AgentRunner("Analyst")     port=8311  → 数据分析
  └─ AgentRunner("Writer")      port=8312  → 报告撰写
"""

import asyncio
import logging

from civitasos_runtime import AgentRunner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

BACKEND = "http://localhost:8099"
LLM_KWARGS = {"base_url": "http://localhost:11434/v1", "api_key": "ollama"}

# ── 定义 Agent 角色 ───────────────────────────────────────

agents_config = [
    {
        "name": "Researcher",
        "capabilities": ["web-search", "data-collection"],
        "gateway_port": 8310,
        "identity_file": "data/researcher.key",
    },
    {
        "name": "Analyst",
        "capabilities": ["data-analysis", "statistics"],
        "gateway_port": 8311,
        "identity_file": "data/analyst.key",
    },
    {
        "name": "Writer",
        "capabilities": ["report-writing", "summarization"],
        "gateway_port": 8312,
        "identity_file": "data/writer.key",
    },
]


async def run_agent(cfg: dict) -> None:
    """启动单个 Agent — 永不返回（直到 SIGINT）。"""
    runner = AgentRunner(
        base_url=BACKEND,
        name=cfg["name"],
        capabilities=cfg["capabilities"],
        llm="ollama:qwen3:latest",
        llm_kwargs=LLM_KWARGS,
        gateway_port=cfg["gateway_port"],
        identity_file=cfg["identity_file"],
    )
    await runner.start()


async def main():
    """并发启动所有 Agent，Ctrl+C 统一退出。"""
    tasks = [asyncio.create_task(run_agent(cfg)) for cfg in agents_config]

    print(f"\n{'='*50}")
    print("  Multi-Agent 系统已启动")
    print(f"  {len(agents_config)} 个 Agent 并发运行")
    for cfg in agents_config:
        print(f"    - {cfg['name']:12s}  port={cfg['gateway_port']}  {cfg['capabilities']}")
    print(f"{'='*50}\n")

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    asyncio.run(main())
