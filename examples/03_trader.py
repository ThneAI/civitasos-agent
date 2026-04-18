"""03_trader.py — 交易 Agent，演示良心审查 + 能量风控。

亮点:
  - @runner.conscience_check: 注册自定义良心检查
  - 风控逻辑：余额低时拒绝高风险交易
  - 自定义工具 evaluate_opportunity: 评估交易机会

Agent 行为:
  1. 浏览公共池 → 寻找 "data-analysis" / "trading" 类任务
  2. 评估机会 → 良心审查（余额？信誉？风险？）
  3. 通过则执行，否则跳过
"""

import asyncio
import logging

from civitasos_runtime import AgentRunner
from civitasos_runtime.models import ConscienceVerdict, Decision, DecisionSource

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

runner = AgentRunner(
    base_url="http://localhost:8099",
    name="TraderBot",
    capabilities=["trading", "data-analysis", "market-research"],
    llm="ollama:qwen3:latest",
    llm_kwargs={"base_url": "http://localhost:11434/v1", "api_key": "ollama"},
    gateway_port=8302,
    identity_file="data/trader.key",
    stake=200,  # 质押更多以获取更高信誉
)


# ── 自定义工具 ─────────────────────────────────────────────
@runner.tool(
    name="evaluate_opportunity",
    description="评估一个交易/分析任务的预期收益和风险",
    requires_conscience=True,    # 需要过良心审查
    estimated_cost=2.0,
)
def evaluate_opportunity(task_description: str, reward: float = 0.0) -> dict:
    """分析任务风险收益比。"""
    risk = 0.3 if reward < 50 else 0.7  # 简化风控模型
    return {
        "description": task_description,
        "reward": reward,
        "estimated_risk": risk,
        "recommendation": "accept" if risk < 0.5 else "cautious",
    }


@runner.tool(
    name="submit_analysis",
    description="提交数据分析报告作为任务交付物",
    estimated_cost=1.0,
)
def submit_analysis(task_id: str, report: str) -> str:
    """生产中会调用更复杂的分析管线。"""
    return f"Report submitted for {task_id}: {report[:100]}..."


# ── 良心审查：余额低时拒绝高风险 ─────────────────────────
@runner.conscience_check
def risk_budget_check(decision, energy_state, context):
    """Balance < 50 时，不允许 estimated_cost > 3 的工具调用。"""
    if energy_state.balance < 50 and decision.action == "evaluate_opportunity":
        return ConscienceVerdict(
            allowed=False,
            reason=f"余额仅 {energy_state.balance:.1f} CIV，暂缓高消耗操作",
            suggestion="先完成手头低风险任务积累余额",
        )
    return ConscienceVerdict(allowed=True)


# ── 自定义规则：高奖励任务优先 ───────────────────────────
@runner.rule(priority=20, name="high_reward_first")
def high_reward_first(briefing: dict, _memories: dict) -> Decision | None:
    """奖励 > 100 CIV 的任务直接认领。"""
    for task in briefing.get("pool_tasks", []):
        reward = task.get("reward", 0)
        if reward >= 100:
            return Decision(
                action="pool_claim",
                params={"task_id": task["task_id"]},
                reasoning=f"高奖励任务 ({reward} CIV)，立即认领",
                confidence=0.95,
                source=DecisionSource.RULE,
            )
    return None


@runner.on_reflect
def log_trade(ctx):
    d = ctx.decision
    e = ctx.evaluation
    if d and d.action != "wait":
        status = "✓" if (e and e.success) else "✗"
        cost = f"{e.cost:.2f}" if e and e.cost else "0"
        print(f"  [{status}] {d.action} | cost={cost} CIV | {d.reasoning[:60]}")


async def main():
    await runner.start()


if __name__ == "__main__":
    asyncio.run(main())
