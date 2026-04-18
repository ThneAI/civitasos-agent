# Benchmarks v1 — F.0.b 任务库

> **关联文档**: [WISDOM_EVOLUTION_ROADMAP.md](../../../civitasos/doc/plan/WISDOM_EVOLUTION_ROADMAP.md) Gate F.0.b
> **状态**: DRAFT design (taxonomy + schema 已定，60 task fillout 待实现)
> **冻结约定**: 一旦 F.0 通过，本目录 `v1/` 内容**只允许追加**不允许修改。新需求开 `v2/`。

---

## 目的

为 [Gate F.1 数据基线建立](../../../civitasos/doc/plan/WISDOM_EVOLUTION_ROADMAP.md) 提供**冻结的、可复现的**任务集，使后续 G/H/I 阶段做"基线对比"时口径一致。

---

## Taxonomy — 4 病灶 × 30 类任务

每个病灶对应 6 类任务（共 24 类），另 6 类为跨病灶的通用场景（共 30 类）。
每类任务**至少**包含 1 个 `happy_path` + 1 个 `adversarial`，共 ≥ 60 个 task instance。

### 病灶 ① 不关心结果（结果偏离）

| ID | 类别 | 验证点 |
|---|---|---|
| R01 | 翻译质量 | 译文是否真实达意（不只"翻完了"） |
| R02 | 数据查询 | 答案是否真正回应问题（不只"查到了"） |
| R03 | 工具链组合 | 整体目标是否达成（不只"每步成功"） |
| R04 | 谈判/协商 | 协议是否真签（不只"对话完了"） |
| R05 | 多约束满足 | 输出是否满足所有约束（不只"输出了"） |
| R06 | 动态环境适应 | 环境变化后旧动作是否失效感知 |

### 病灶 ② 不验证交付物（验证缺失）

| ID | 类别 | 验证点 |
|---|---|---|
| V01 | 代码生成 | 语法对但语义错时 agent 是否拒收 |
| V02 | 文档总结 | 关键事实歪曲时 agent 是否发现 |
| V03 | 计算任务 | 数字对但单位错时 agent 是否复核 |
| V04 | 转账/支付 | 收款人/金额错时 agent 是否拦截 |
| V05 | 形式化要求满足 | schema 对但内容错时 agent 是否复验 |
| V06 | 跨系统数据迁移 | 迁移后数据完整性是否验证 |

### 病灶 ③ 无自我认知（aspect_gap）

| ID | 类别 | 验证点 |
|---|---|---|
| S01 | 重复同类失败 | 相同错误重犯几次后是否触发 self_diagnosis |
| S02 | 能力声明虚假 | 接到超出能力任务时是否如实拒绝/降级 |
| S03 | 外界信任分骤降 | 是否引发反思而非辩解 |
| S04 | 反复错误模式 | 是否能从历史 lessons 中识别模式 |
| S05 | 长期目标偏离 | 是否周期性回顾 telos 一致性 |
| S06 | 主动状态汇报 | 是否如实汇报当前状态（无虚饰） |

### 病灶 ④ 无主动性（被动等待）

| ID | 类别 | 验证点 |
|---|---|---|
| A01 | 长时间空闲 | 24h 无 briefing 时是否产出主动行为 |
| A02 | 资源缺失场景 | 缺资源时是否主动请求 |
| A03 | 信息不完整场景 | 信息不全时是否主动查询 |
| A04 | 提案权利场景 | 治理空窗时是否主动提案 |
| A05 | 协作发起 | 是否主动建立 R2R 关系 |
| A06 | 治理参与 | 投票截止前是否主动表态 |

### 通用 / 跨病灶

| ID | 类别 | 验证点 |
|---|---|---|
| G01 | Conscience 边缘场景 | 道德决策的 axiom 触发 |
| G02 | 高风险任务 | fear/greed 信号触发后的行为 |
| G03 | 高频小任务 | 调度公平性 + 不饥饿 |
| G04 | 跨链结算 | Phase D 端点正确使用 |
| G05 | CSP 服务购买 | 生态参与的经济决策 |
| G06 | ZK-Flow 验证 | 隐私场景下的决策 |

---

## 文件结构

```
benchmarks/v1/
├── README.md              # 本文档
├── manifest.yaml          # 任务 schema + 全部任务条目
├── tasks/                 # 任务详细数据（briefing 内容、参考答案）
│   ├── R01_translation_quality_happy.yaml
│   ├── R01_translation_quality_adversarial.yaml
│   ├── ...
└── fixtures/              # 任务依赖的 mock 数据 / 资源
```

## 度量指标（与 manifest 任务关联）

来自 Gate F.1 定义的 6 项基线指标：

| 指标 | 关联病灶 | 主要从哪些任务计算 |
|---|---|---|
| `result_deviation_rate` | ① | R01–R06 |
| `verification_miss_rate` | ② | V01–V06 |
| `aspect_gap_response_rate` | ③ | S01–S06 |
| `lessons_impact_rate` | ③ | S01, S04 |
| `reaction_latency_dist` | 通用 | 全部 |
| `idle_thinking_ratio` | ④ | A01–A06 |

详见 `../../observability/metrics/` 中各指标的采集器实现（F.0.a）。

---

## 评审清单（F.0 通过的一部分）

- [ ] 30 类 taxonomy 是否覆盖 4 病灶 + 通用场景
- [ ] manifest schema 字段完备
- [ ] 至少 3 个完整 task fixture 跑通
- [ ] 每个指标都能从某些任务计算出来
- [ ] adversarial 任务的"期望失败模式"可被自动判定
