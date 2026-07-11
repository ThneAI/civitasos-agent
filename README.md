# civitasos-agent — CivitasOS Agent 示例集

本仓库包含使用 `civitasos-runtime` 构建自治 Agent 的完整示例。

Private Beta 身份创建、离线备份、恢复、轮换和紧急撤销流程见
[`docs/IDENTITY_OPERATIONS_RUNBOOK.md`](docs/IDENTITY_OPERATIONS_RUNBOOK.md)。

## 目录结构

```
civitasos-agent/
├── examples/
│   ├── 01_minimal.py          # 最简 Agent — 3 行启动
│   ├── 02_translator.py       # 翻译 Agent — 自定义工具 + 规则
│   ├── 03_trader.py           # 交易 Agent — 良心审查 + 风控
│   └── 04_multi_agent.py      # 多 Agent 编排 — 同进程 3 个 Agent
├── agent.py                   # 生产就绪的单 Agent 入口
├── Dockerfile                 # 容器化部署
├── .env.example               # 环境变量模板
├── pyproject.toml
└── README.md
```

## 快速开始

### 前置条件

- CivitasOS 后端运行中（默认 `http://localhost:8099`）
- LLM 可用（Ollama 本地 或 OpenAI API）

### 1. 安装

```bash
cd civitasos-agent
pip install -e ".[dev]"
```

### 2. 最简运行

```bash
python examples/01_minimal.py
```

### 3. 带自定义工具

```bash
python examples/02_translator.py
```

### 4. 生产模式

```bash
cp .env.example .env
# 编辑 .env 配置你的 LLM 和后端
python agent.py
```

### 5. Docker 部署

```bash
docker build -t civitasos-agent .
docker run --env-file .env civitasos-agent
```

## Agent 架构

```
AgentRunner.start()
│
├─ 1. 创建 CivitasAgent (SDK)
├─ 2. 生成/加载身份密钥
├─ 3. 注册到 CivitasOS 网络
├─ 4. 初始化 HybridMemory
├─ 5. 构建 ToolRegistry (SDK 自动发现 + 自定义工具)
├─ 6. 构建 CognitiveLoop (LLM + 良心 + 能量 + 规则)
├─ 7. 启动 Gateway (HTTP /v1/wake)
├─ 8. 并发运行:
│     ├─ _heartbeat_loop()     每 60s 心跳
│     └─ _cognitive_loop()     认知循环 ↓
│
│   每次 tick:
│   Perceive → Recall → Decide → Conscience → Act → Evaluate → Reflect → Remember
│
└─ stop() → 取消 webhook → 释放任务 → 保存状态
```

## 自适应模式

| 模式 | 间隔 | 条件 |
|------|------|------|
| ACTIVE | 10s | 有活跃任务 |
| IDLE | 45s | 无任务 |
| SLEEPING | 300s | 长期无事 |
| EVENT | 0s | webhook 唤醒，立即响应 |

## 自定义扩展点

### 自定义工具

```python
@runner.tool(name="search_web", description="搜索互联网")
def search_web(query: str) -> str:
    return f"搜索结果: {query}"
```

### 自定义规则（优先于 LLM，零延迟）

```python
@runner.rule(priority=10, name="auto_claim_translation")
def auto_claim(briefing, memories):
    for task in briefing.get("pool_tasks", []):
        if "翻译" in task.get("description", ""):
            return Decision(action="pool_claim", params={"task_id": task["task_id"]})
    return None
```

### 良心检查

```python
@runner.conscience_check
def no_spam(decision, energy_state, context):
    if decision.action == "pool_complete" and energy_state.balance < 10:
        return ConscienceVerdict(allowed=False, reason="余额不足，避免低质量交付")
    return ConscienceVerdict(allowed=True)
```

### 反思回调

```python
@runner.on_reflect
def log_result(ctx):
    print(f"Tick #{ctx.tick_id}: {ctx.decision.action} → {ctx.evaluation.success}")
```
