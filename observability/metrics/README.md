# Observability Metrics — F.0.a 指标采集器

> **关联文档**: [WISDOM_EVOLUTION_ROADMAP.md](../../../civitasos/doc/plan/WISDOM_EVOLUTION_ROADMAP.md) Gate F.0.a
> **状态**: DRAFT design (schema + 接口已定，实现 + 单测待 F.0 实施)

---

## 设计原则

1. **不入侵 civitasos-runtime** — 通过 `CognitiveLoop._on_reflect_fns` 钩子注入，不修改 SDK
2. **不假实现** — 所有指标必须从真实的 `TickContext` 字段计算，禁止 mock
3. **Schema-first** — CSV 列定义先行，写入器只生成符合 schema 的行
4. **任务关联** — 每个 tick 必须能映射回 benchmarks/v1 中的 task_id（通过 briefing 注入）
5. **无副作用** — 采集失败不影响 agent 运行（所有写入 try-except 隔离）

---

## 6 项基线指标

来自 [WISDOM_EVOLUTION_ROADMAP Gate F.1](../../../civitasos/doc/plan/WISDOM_EVOLUTION_ROADMAP.md)：

| ID | 指标 | 计算方式 | 输入字段 |
|---|---|---|---|
| **M1** | `result_deviation_rate` | `agent 自报 success` 但 task 的 `success_criteria` 未全满足 / 总任务数 | `Evaluation.success` + task `success_criteria` 验证 |
| **M2** | `verification_miss_rate` | adversarial task 中未调用 verifier 工具 / adversarial task 总数 | `Decision.action` 序列 + task tool_allowed |
| **M3** | `aspect_gap_response_rate` | `aspect_gap > 0.7` 之后 N 个 tick 内行为模式发生改变 / 触发次数 | `EnergyState.aspect_gap` 时序 + 后续 `Decision` 序列 |
| **M4** | `lessons_impact_rate` | 失败 lesson 后再次遇到同情境时决策变化 / 同情境再现次数 | `agent.lessons_learned` + `Decision.reasoning` |
| **M5** | `reaction_latency_dist` | 从 `briefing` 到达到 `action_result` 的 wall-clock 分布（P50/P95/P99） | `TickContext.timestamp` + `Evaluation.duration_ms` |
| **M6** | `idle_thinking_ratio` | `Decision.action == "wait"` 且 `reasoning` 未引用 telos 的 tick / 总 tick | `Decision.action / reasoning` |

---

## 文件结构

```
observability/metrics/
├── README.md                   # 本文档
├── schema.py                   # CSV schema 常量 + 字段定义
├── collector.py                # CollectorAdapter（通过 _on_reflect_fns 注入）
├── writer.py                   # CSV writer（线程安全，按 task_id 分文件）
├── computers/                  # 6 个指标的计算器（从 raw CSV 算出指标）
│   ├── __init__.py
│   ├── m1_result_deviation.py
│   ├── m2_verification_miss.py
│   ├── m3_aspect_gap_response.py
│   ├── m4_lessons_impact.py
│   ├── m5_reaction_latency.py
│   └── m6_idle_thinking.py
└── tests/
    ├── test_schema.py          # schema 字段完备性
    ├── test_collector.py       # adapter 注入与 tick 解析
    ├── test_writer.py          # 并发写入 + 异常隔离
    └── test_computers/         # 每个指标的单元测试（用 fixture CSV）
```

---

## Schema — Raw Tick CSV

每行一个 tick，按 `runs/{run_id}/{task_id}.csv` 分文件存储。

| 列 | 类型 | 来源 | 必需 |
|---|---|---|---|
| `run_id` | string | run_baseline.sh 启动时生成 | ✅ |
| `agent_id` | string | civitasos-runtime agent name | ✅ |
| `task_id` | string | benchmarks/v1 manifest 中的 task id（通过 briefing.metadata 注入） | ✅ |
| `tick_seq` | int | tick 在该 task 内的序号（从 1 开始） | ✅ |
| `tick_id` | string | TickContext.tick_id | ✅ |
| `timestamp` | ISO8601 | TickContext.timestamp | ✅ |
| `phase_reached` | enum | 该 tick 走到的最后阶段（perceive..remember） | ✅ |
| `decision_action` | string | Decision.action | optional |
| `decision_source` | enum | rules / llm / hybrid | optional |
| `decision_reasoning` | string | Decision.reasoning（截断 500 字符） | optional |
| `served_intent_layer` | string | Decision 自报服务的意图层（H.1 后才有，F.1 阶段为空） | optional |
| `conscience_allowed` | bool | ConscienceVerdict.allowed | optional |
| `conscience_reason` | string | ConscienceVerdict.reason | optional |
| `eval_success` | bool | Evaluation.success | optional |
| `eval_cost` | float | Evaluation.cost | optional |
| `eval_duration_ms` | int | Evaluation.duration_ms | optional |
| `aspect_gap` | float | EnergyState.aspect_gap | ✅ |
| `peer_trust_avg` | float | EnergyState.peer_trust_avg | ✅ |
| `balance` | float | EnergyState.balance | ✅ |
| `mode` | enum | LoopMode (active/idle/sleeping/event) | ✅ |
| `is_wait` | bool | Decision.action == "wait" | ✅ |
| `wait_references_telos` | bool | "telos" 出现在 reasoning（M6 计算用） | optional |

**Schema 版本**：v1.0。冻结后只允许追加新列，不允许修改/删除。

---

## Schema — Final Metrics CSV

经 computers/ 聚合后的最终基线报告。一行一个 (agent, task_category) 组合。

| 列 | 类型 | 描述 |
|---|---|---|
| `run_id` | string | |
| `agent_id` | string | |
| `category_id` | string | benchmarks/v1 taxonomy 类别（R01..G06） |
| `targets_disease` | enum | R/V/S/A/G |
| `task_count` | int | 该类别的任务数 |
| `m1_result_deviation_rate` | float | 0~1 |
| `m2_verification_miss_rate` | float | 0~1（仅 adversarial 类别有意义） |
| `m3_aspect_gap_response_rate` | float | 0~1 |
| `m4_lessons_impact_rate` | float | 0~1 |
| `m5_reaction_latency_p50_ms` | float | |
| `m5_reaction_latency_p95_ms` | float | |
| `m5_reaction_latency_p99_ms` | float | |
| `m6_idle_thinking_ratio` | float | 0~1 |
| `notes` | string | 特殊情况说明（数据不足等） |

---

## CollectorAdapter 接口

```python
# observability/metrics/collector.py
from typing import Protocol
from civitasos_runtime.models import TickContext, EnergyState

class CollectorAdapter:
    """
    通过 CognitiveLoop._on_reflect_fns 注入。每 tick 调一次。
    输出一行 raw CSV。
    """

    def __init__(self, *, run_id: str, agent_id: str, writer: "RawWriter"):
        self.run_id = run_id
        self.agent_id = agent_id
        self.writer = writer
        self._task_id: str | None = None
        self._tick_seq: int = 0

    def bind_task(self, task_id: str) -> None:
        """benchmarks runner 在每个 task 开始前调用。"""
        self._task_id = task_id
        self._tick_seq = 0

    def __call__(self, ctx: TickContext, energy: EnergyState) -> None:
        """注入到 _on_reflect_fns 的钩子签名（待 SDK 暴露）。"""
        if self._task_id is None:
            return  # 不在 benchmark 上下文内，不采集
        self._tick_seq += 1
        try:
            row = self._build_row(ctx, energy)
            self.writer.write(row)
        except Exception:
            # 守则 5：采集失败不影响 agent
            pass
```

---

## 单元测试覆盖（最低门槛）

- `test_schema.py`: 21 列定义都存在，类型正确，必需字段标记一致
- `test_collector.py`: 注入 mock TickContext，验证生成的 row 与 schema 一致；未 bind_task 时不写入
- `test_writer.py`: 并发 100 个 tick 写入不丢行；磁盘写失败时 raise 但不传播
- `test_computers/test_m1.py`: 给定 fixture（10 tick CSV + 任务 success_criteria），M1 计算结果正确
- 同理 m2..m6（每个 computer 至少 3 个 case：典型 / 边界 / 空数据）

---

## F.0.a 通过标准（roadmap 引用）

- ✅ 6 项指标采集器对每项均有可工作示例（不是 mock）
- ✅ Raw / Final 两个 schema 评审通过
- ✅ 单元测试覆盖率 ≥ 80%（schema + collector + writer + 6 个 computers）
- ✅ CollectorAdapter 在真实 civitasos-runtime 上可工作（至少 1 个 minimal task 跑通输出 CSV）

---

## 与 civitasos-runtime 的协作 hooks

需要在 civitasos-runtime 暴露的接口（极小改动）：

| Hook | 现状 | 需要的改动 |
|---|---|---|
| `_on_reflect_fns` | ✅ 已存在（loop.py:127） | 暴露为 public `add_reflect_observer(fn)` |
| `briefing.metadata.task_id` | ❌ 无 | benchmarks runner 在 perceive 注入前赋值 |
| `EnergyState` 引用 | 内部 | adapter 通过 `loop._energy.state` 访问（暂可接受） |

> **决定**：F.0.a 只设计；civitasos-runtime 的 minimal hook 暴露作为 F.0.a 实现阶段的小 PR，不算入 G 阶段范围（守则 6 不抢跑也不卡进度——这是 F.0 自身的实现成本）。
