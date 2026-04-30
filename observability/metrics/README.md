# Observability Metrics — F.0.a 指标采集器

> **关联文档**: [WISDOM_EVOLUTION_ROADMAP.md](../../../civitasos/doc/plan/WISDOM_EVOLUTION_ROADMAP.md) Gate F.0.a
> **状态**: DRAFT v1.6 (自审后修订；schema + 接口已定，M4 已切到 H.2-lite 可计算，II-1 identity prompt、G.2 subjective-time mode request、G.3 relation-time 空载字段已可观测)
>
> **v1.1 变更摘要**（自审 RCA 触发）:
> - M3 操作化：阈值与「行为模式改变」给出可计算定义
> - M4 标记 F.0 阶段空载（civitasos_runtime 当前无 `lessons` 数据结构，待 H.2 启用）
> - M6 弱化为「wait 比率」+ 标注 H.1 上线后才能识别「有目的等待」
> - M5 拆分 per-tick / per-task 两个层级
> - schema 列 `mode` / `wait_references_telos` 改为 optional 并注明 F.0 默认值
> - 新增 CSV 转义策略（RFC4180）
> - F.0.a 通过标准从「6 项均可工作」改为「6 项均有可工作示例 OR 明确空载并标注启用阶段」
> - v1.2 新增 `lessons_count` 采集列，M4 从固定 null 升级为 H.2-lite（fail→success + lessons 增长）
> - v1.3 新增 `identity_state / identity_remaining_epochs / identity_prompt_injected`，用于观测 II-1 institutional identity 是否进入决策面
> - v1.4 新增 `subjective_lifecycle_stage / subjective_recommended_mode / llm_mode_request / llm_mode_selected`，用于观测 G.2 中 LLM 是否自主选择 `waiting/deep_think`
> - v1.5 在 final_metrics 新增 `g2_mode_choice_observable_ratio / g2_llm_waiting_ratio / g2_llm_deep_think_ratio`
> - v1.6 新增 G.3 relation memory / cross-agent time consistency 空载字段与聚合列

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

| ID | 指标 | F.0 是否启用 | 计算方式（v1.1 操作化） | 输入字段 |
|---|---|---|---|---|
| **M1** | `result_deviation_rate` | ✅ | `count(agent 自报 success ∧ NOT all(machine_checkable_criteria)) / total_tasks`。仅统计 success_criteria 全部为 `regex` 或 `pyexpr` 类型的任务；`llm_judge` 类型的延后到 H.1 | `Evaluation.success` + task `success_criteria.kind ∈ {regex,pyexpr}` |
| **M2** | `verification_miss_rate` | ✅ | adversarial task 中 `Decision.action` 序列与 task `verifier_tools` 集合交集为空的任务数 / adversarial task 总数。「verifier 工具」由 manifest 显式声明，不靠工具名猜 | `Decision.action` 序列 + task `verifier_tools` |
| **M3** | `aspect_gap_response_rate` | ✅ | 遍历 tick 序列，找到首次 `aspect_gap` 跨越阈值 θ=0.7 的 tick t；定义前窗 W_pre = action 集合 of tick[t-3..t-1]，后窗 W_post = tick[t+1..t+3]；若 `Jaccard(W_pre, W_post) < 0.5` 记为 1 次 response。指标 = response 次数 / 触发次数。**θ=0.7 与 Jaccard<0.5 是 F.0 经验值，F.1 实施后用真实数据校准** | `EnergyState.aspect_gap` 时序 + 同窗 `Decision.action` |
| **M4** | `lessons_impact_rate` | ✅ **H.2-lite** | 任务中先失败后恢复，且 `lessons_count` 有信号（`max>0`）；若恢复 tick 的 lessons_count 高于首次失败 tick，记为 impacted。指标= impacted / eligible | `eval_success` 时序 + `lessons_count` |
| **M5** | `reaction_latency_dist` | ✅ | **per-tick 层**：每 tick `Evaluation.duration_ms` 的 P50/P95/P99；**per-task 层**：从 task 开始（tick_seq=1）到首次 `Evaluation.success==True` 或 task 终止的 wall-clock 总耗时分布 | `TickContext.timestamp` + `Evaluation.duration_ms` |
| **M6** | `wait_ratio` | ✅ 弱化 | F.0 阶段：`count(Decision.action=="wait") / total_ticks`，单纯比率。**真正的「无所事事 vs 有目的等待」需 H.1 `served_intent_layer` 字段上线后才能区分**，那时再分裂为 `idle_thinking_ratio` 与 `purposeful_wait_ratio` 两指标 | `Decision.action` |

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
│   ├── m4_lessons_impact.py    # H.2-lite 可计算（无信号时返回 null+notes）
│   ├── m5_reaction_latency.py  # 输出 per-tick + per-task 双层
│   ├── m6_wait_ratio.py        # F.0 弱化版；H.1 后拆为 idle_thinking + purposeful_wait
│   ├── g2_subjective_mode.py   # G.2 mode-choice 聚合指标
│   └── g3_relation_time.py     # G.3 relation memory / time-window 空载聚合指标
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
| `identity_state` | enum | briefing.identity.state（II-1 institutional identity 摘要） | optional |
| `identity_remaining_epochs` | int | briefing.identity.remaining_epochs（若可计算） | optional |
| `identity_prompt_injected` | bool | 本 tick 是否将 institutional identity 摘要注入 system prompt | optional |
| `mode` | enum | LoopMode (active/idle/sleeping/waiting/deep_think/event)；无法读取时默认 `active` | optional |
| `is_wait` | bool | Decision.action == "wait" | ✅ |
| `lessons_count` | int | memory 中 lessons_learned 长度快照（每 tick 采样） | optional |
| `wait_references_telos` | bool | F.0 阶段固定 `false`（M6 已弱化为 wait_ratio）；H.1 后基于 `served_intent_layer` 重新计算 | optional |
| `subjective_lifecycle_stage` | enum | briefing.subjective_time.lifecycle_stage（G.2 Agent 主观时间） | optional |
| `subjective_recommended_mode` | enum | briefing.subjective_time.recommended_mode（规则/LLM 选择后最终推荐模式） | optional |
| `llm_mode_request` | enum | LLM 显式声明的 `mode_request: waiting/deep_think` | optional |
| `llm_mode_selected` | bool | 本 tick 是否由 LLM 自主选择 waiting/deep_think | optional |
| `relation_context_id` | string | G.3 relation context stable id | optional |
| `relation_memory_refs` | string | G.3 决策引用的 relation memory / failure / challenge refs，`;` 分隔 | optional |
| `time_window_id` | string | G.3 同一 task/relation event 的跨 Agent 可比对时间窗口 id | optional |
| `challenge_deadline_bucket` | string | G.3 challenge deadline 的稳定 bucket | optional |

**Schema 版本**：v1.6。冻结后只允许追加新列，不允许修改/删除。

### CSV 转义策略（v1.1 新增）

所有 CSV 文件遵循 **RFC 4180**：
- 字段含逗号 / 双引号 / 换行符 → 用双引号包裹
- 字段内的双引号 → 重复一次（`"` → `""`）
- `decision_reasoning` 在截断到 500 字符前先做 `\n` → `\\n` 转义，避免破坏行边界
- writer 使用 Python 标准库 `csv.writer(quoting=csv.QUOTE_MINIMAL)`

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
| `m4_lessons_impact_rate` | float \| null | H.2-lite 可计算；无足够信号时为 null 并写 notes |
| `m5_tick_latency_p50_ms` | float | per-tick 层 |
| `m5_tick_latency_p95_ms` | float | per-tick 层 |
| `m5_tick_latency_p99_ms` | float | per-tick 层 |
| `m5_task_latency_p50_ms` | float | per-task 层 |
| `m5_task_latency_p95_ms` | float | per-task 层 |
| `m6_wait_ratio` | float | 0~1（F.0 弱化版；H.1 后会拆分） |
| `g2_mode_choice_observable_ratio` | float \| null | LLM 显式 `mode_request` tick / wait tick |
| `g2_llm_waiting_ratio` | float \| null | LLM 显式选择 `waiting` / 所有显式 mode_request |
| `g2_llm_deep_think_ratio` | float \| null | LLM 显式选择 `deep_think` / 所有显式 mode_request |
| `g3_relation_memory_hit_ratio` | float \| null | relation-aware 任务中引用 relation memory / failure / challenge ref 的比例 |
| `g3_relation_aware_decision_ratio` | float \| null | relation-aware 任务中决策 trace 带 peer/relation-specific evidence 的比例 |
| `g3_cross_agent_time_consistency_ratio` | float \| null | 本 agent 对 relation-aware 任务输出 `time_window_id` 的覆盖率；merge 阶段再做跨 Agent 一致性检查 |
| `notes` | string | 特殊情况说明（数据不足、指标空载等） |

### G.2 Gate Thresholds

`benchmarks.f1c_merge` 默认执行 G.2 hard gate：

- `g2_mode_choice_observable_ratio` 在 `final_metrics` 中必须 100% 非空。
- 每个 Agent 的 raw `llm_mode_selected` 数量必须大于等于该 Agent 的 `task_count` 总和。

历史数据回放可使用 `--skip-g2-gate`，但正式 Gate / nightly 不应跳过。

### G.3 Gate Status

`benchmarks.f1c_merge` 已输出 `g3_gate`。当前 v1 任务没有 relation-aware 行时自动标记 `skipped=true` 且通过；一旦 v2 relation-aware 任务产生 `g3_*` 行，默认按初始阈值检查：

- `g3_relation_memory_hit_ratio >= 0.80`
- `g3_relation_aware_decision_ratio >= 0.80`
- `g3_cross_agent_time_consistency_ratio >= 0.95`

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

- `test_schema.py`: 24 列定义都存在，类型正确，必需字段标记一致
- `test_collector.py`: 注入 mock TickContext，验证生成的 row 与 schema 一致；未 bind_task 时不写入
- `test_writer.py`: 并发 100 个 tick 写入不丢行；磁盘写失败时 raise 但不传播
- `test_computers/test_m1.py`: 给定 fixture（10 tick CSV + 任务 success_criteria），M1 计算结果正确
- 同理 m2..m6（每个 computer 至少 3 个 case：典型 / 边界 / 空数据）

---

## F.0.a 通过标准（v1.1 修订）

- ✅ 6 项指标 computer 均有可工作示例；若输入信号不足，返回 null 并在 notes 标注原因
- ✅ Raw / Final 两个 schema 评审通过且与 schema.yaml 字面一致
- ✅ 单元测试覆盖率 ≥ 80%（schema + collector + writer + 5 个启用 computer + M4 的「空载契约」单测）
- ✅ CollectorAdapter 在真实 civitasos-runtime 上可工作（至少 1 个 minimal task 跑通输出 CSV）
- ✅ M3 阈值/算法可被 F.1 校准结果覆盖（不锁死在文档）

---

## 与 civitasos-runtime 的协作 hooks

需要在 civitasos-runtime 暴露的接口（极小改动）：

| Hook | 现状 | 需要的改动 |
|---|---|---|
| `_on_reflect_fns` | ✅ 已存在（loop.py:127） | 暴露为 public `add_reflect_observer(fn)` |
| `briefing.metadata.task_id` | ❌ 无 | benchmarks runner 在 perceive 注入前赋值 |
| `EnergyState` 引用 | 内部 | adapter 通过 `loop._energy.state` 访问（暂可接受） |

> **决定**：F.0.a 只设计；civitasos-runtime 的 minimal hook 暴露作为 F.0.a 实现阶段的小 PR，不算入 G 阶段范围（守则 6 不抢跑也不卡进度——这是 F.0 自身的实现成本）。
