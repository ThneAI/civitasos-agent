"""02_translator.py — 翻译 Agent，演示自定义工具 + 规则。

亮点:
  - @runner.tool: 注册 LLM 可调用的自定义工具
  - @runner.rule: 注册零延迟的确定性规则（优先于 LLM）
  - @runner.on_reflect: tick 结束后的回调

Agent 行为:
  1. 规则引擎：看到包含"翻译"的任务 → 自动认领（不调 LLM）
  2. LLM 决策：非翻译任务 → 交给 LLM 判断要不要做
  3. 自定义工具 translate_text：LLM 可调用来执行实际翻译
"""

import asyncio
import logging

from civitasos_runtime import AgentRunner
from civitasos_runtime.models import Decision, DecisionSource

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

runner = AgentRunner(
    base_url="http://localhost:8099",
    name="TranslatorBot",
    capabilities=["translation", "zh-en", "en-zh"],
    llm="ollama:qwen3:latest",
    llm_kwargs={"base_url": "http://localhost:11434/v1", "api_key": "ollama"},
    gateway_port=8301,
    identity_file="data/translator.key",
)


# ── 自定义工具：LLM 可以调用这个函数 ──────────────────────────
@runner.tool(
    name="translate_text",
    description="将文本在中英文之间翻译",
    estimated_cost=1.0,
)
def translate_text(text: str, target_lang: str = "zh") -> str:
    """实际翻译逻辑 — 生产中可换成真实翻译 API。"""
    # 这里是 mock 示例；真实环境下调用 DeepL / Google Translate / LLM
    return f"[{target_lang}] {text}"


# ── 自定义规则：翻译任务自动认领，不等 LLM ──────────────────
@runner.rule(priority=10, name="auto_claim_translation")
def auto_claim_translation(briefing: dict, _memories: dict) -> Decision | None:
    """如果公共池有翻译类任务，立即认领。"""
    for task in briefing.get("pool_tasks", []):
        desc = task.get("description", "").lower()
        if any(kw in desc for kw in ("翻译", "translate", "translation")):
            return Decision(
                action="pool_claim",
                params={"task_id": task["task_id"]},
                reasoning=f"自动认领翻译任务: {task['task_id']}",
                confidence=1.0,
                source=DecisionSource.RULE,
            )
    return None


# ── 反思回调：每次 tick 结束后打印摘要 ─────────────────────
@runner.on_reflect
def print_summary(ctx):
    d = ctx.decision
    e = ctx.evaluation
    status = "✓" if (e and e.success) else "✗"
    action = d.action if d else "none"
    print(f"  {status} {action} | mode={ctx.phase}")


async def main():
    await runner.start()


if __name__ == "__main__":
    asyncio.run(main())
