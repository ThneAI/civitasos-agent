"""01_minimal.py — 最简 Agent，3 行核心代码。

启动后自动：
  1. 连接 CivitasOS 后端
  2. 生成身份密钥 + 注册
  3. 启动认知循环（Perceive → Decide → Act → Reflect）
  4. 自适应等待 webhook 事件

用法:
    python examples/01_minimal.py

等价 CLI:
    python -m civitasos_runtime --name MinimalBot --llm ollama:qwen3:latest
"""

import asyncio

from civitasos_runtime import AgentRunner


async def main():
    runner = AgentRunner(
        base_url="http://localhost:8099",
        name="MinimalBot",
        capabilities=["general"],
        llm="ollama:qwen3:latest",
        llm_kwargs={"base_url": "http://localhost:11434/v1", "api_key": "ollama"},
        gateway_port=8300,            # 启用 HTTP Gateway（接收 webhook 唤醒）
        identity_file="data/minimal.key",  # 持久化身份
    )
    await runner.start()


if __name__ == "__main__":
    asyncio.run(main())
