# F.1 — 数据基线建立 设计文档

> **关联文档**: [WISDOM_EVOLUTION_ROADMAP.md](../../civitasos/doc/plan/WISDOM_EVOLUTION_ROADMAP.md) Gate F.1
> **状态**: DRAFT v1.1(自审后修订;待评审)
> **前置**: F.0 通过(commit 4ac62cb,49/49 tests + smoke 端到端 OK)
> **目的**: 把 F.0 的"测试床"接到真 backend + 真 LLM + 真任务集,跑出**首份基线报告**
>
> **v1.1 变更摘要**(自审 18 项 finding 触发,详见 §11):
> - **B1+B2+B3 联合修复**: 放弃 "briefing 注入" + "LLM 自评 sentinel";改为**真实 backend task 生命周期**(orchestrator 创建真 task → agent 走 pool_claim → task_execute(done=true) → orchestrator 监听 backend task state 写 sentinel)。M1 self_reported_success 语义统一到"agent 是否在真实 SDK 路径上调了 task_execute(done=true)"。
> - **M1**: §2.2 验证方式分布按病灶分别约束,而非全局
> - **M2**: §3.5 显式说明 3-agent 差异化机制 + inter-agent 行为相似度兜底检验
> - **M3**: §5.4 评审清单加"无反直觉发现"的具体处置要求
> - **M4**: §4.4 失败后**重跑全部**(简单可复现);可选 resume 移到 minor
> - **M5**: §6 task_loader 必须**同时**支持单文件内联 + $ref 索引(向后兼容)
> - **M6**: §0 新增范围声明,坦白"测试网"= localhost docker compose
> - **M7**: §5.2 加 ollama 模型 sha256 snapshot 强制
> - 8 项 minor 见 §11

---

## 0. 设计原则与范围声明

### 0.1 范围声明(roadmap 偏离的诚实标注)

Roadmap §F.1 字面规定"测试网部署 3 个 civitasos-agent"。本 F.1 把"测试网"**界定为** `deploy/docker-compose.yml` 起的 **localhost 3-node cluster**(node1/node2/node3 + CSP);远程 testnet 部署留给 I.1。理由:

1. F.1 目的是"测量"而非"运维";远程 testnet 引入网络抖动会污染 m5_tick_latency
2. localhost 3-node 已能验证共识/P2P/CSP 等核心路径
3. 若评审认为不接受此偏离,可加跑 "F.1.c.附" — 在远程 testnet 上重跑同样 60 task 与 localhost 数据交叉验证(成本巨大,默认不做)

### 0.2 设计原则(继承 F.0)

1. **不假实现** — F.1 必须用真 collector + 真 agent.py + 真 backend + 真 LLM 跑真 task,**不允许 fake_agent 出现在基线数据中**
2. **不抢跑** — F.1 只**测量**,不优化、不调整阈值、不改 runtime;一切改进留给 G/H/I
3. **可复现** — 同一 run_id + 同一 manifest + 同一 runtime git rev → 任何机器可重跑(允许 LLM 随机性导致数值波动,但口径一致)
4. **冻结口径** — F.1 一旦产出"基线报告 v1",`benchmarks/v1/`、`schema.yaml`、`computers/` 全部进入"只追加不修改"状态,后续 Gate 改进必须能与之对齐
5. **诊断 > 美观** — 报告优先暴露问题(4 病灶发病率、反直觉发现),不做"成绩展示"

---

## 1. F.1 子阶段拆分

按"先扩展任务集 → 再接真 agent → 再扩规模 → 最后报告与评审"的依赖顺序拆 4 个 sub-gate:

| Sub-gate | 目标 | 关键产出 | 阻塞依赖 |
|---|---|---|---|
| **F.1.a** | 任务库 v1 全量化 | `benchmarks/v1/` ≥60 task instances(30 类 × ≥2 variants);adversarial 期望失败模式可被 success_criteria 自动判定 | F.0.b |
| **F.1.b** | 真 Agent 接入 orchestrator | `agent.py` 在 `BENCHMARK_TASK_ID` 模式下挂 CollectorAdapter + 写 sentinel;orchestrator 用 docker compose 管理 backend;**至少 1 个真 task 端到端跑出 raw_ticks**(替换 fake_agent) | F.0.c, deploy/docker-compose.yml |
| **F.1.c** | 3-agent × 60-task 全量基线运行 | 3 个 agent 配置(差异化 capabilities)各自独立跑全 60 task;产出 3 套 `runs/` 数据 + 1 份合并 final_metrics.csv | F.1.a, F.1.b |
| **F.1.d** | 基线报告 + 评审 | `benchmarks/v1/REPORT_v1.md` + 可视化(matplotlib HTML/PNG);至少 1 个反直觉发现;评审通过 | F.1.c |

> 每个 sub-gate 完成 = 提交一个 commit + 通过本节列出的"通过标准"。

---

## 2. F.1.a — 任务库全量化

### 2.1 任务规模约束

- **下限**: 30 类 × 2 variants = 60 task instances(roadmap 规定的 100+ 折中下限,见下 §2.5)
- **上限**: 30 类 × 4 variants = 120(预算友好,LLM 推理总量可控)
- **每类必含**: ≥1 happy_path + ≥1 adversarial(F.0.b 已规定)

### 2.2 验证方式分布(按病灶分组,v1.1 修订)

v1.0 全局约束 "≥40% regex" 会逼出劣质 task(R 系列翻译质量本不适合 regex)。改为**按病灶分组**:

| 病灶簇 | machine-checkable(regex/pyexpr)占比 | llm_judge 占比 | 备注 |
|---|---|---|---|
| **V/A/G**(验证缺失/被动等待/通用) | **≥60%** | ≤40% | 这些病灶天然适合机械验证(收款人/时间戳/调用顺序等) |
| **R/S**(结果偏离/自我认知) | **≥30%** | ≤70% | 翻译质量、谈判、自我反思等天然需要语义判断 |

**报告输出强制要求**(防止 LLM-judge 子集稀释 machine-check 子集): F.1.d REPORT 里 M1/M2 数值必须**分别给出**:

- M1_machine = 仅基于 regex/pyexpr 验证的 deviation rate
- M1_llm_judge = 基于 llm_judge 验证的 deviation rate(F.0 conservative 实现下为 null,等 H.1 后填)

**强约束**: 每个 adversarial task 的 `verifier_tools` 必须**至少 1 项**,否则 M2 永远算不出该任务的 miss(F.0.c m2_verification_miss.py 的 filter)。

### 2.3 fixtures 复用 vs 唯一

- 同一类的不同 variants **可复用**同一 fixture(如 R01 多个翻译任务用同一段源文)
- adversarial 必须有"对抗性 fixture"(如 V04 邮件地址末位被改)和明确的 `expected_failure_mode` 字段(F.0.b manifest schema 已定义)

### 2.4 文件组织

`benchmarks/v1/manifest.yaml` 当前 3 个内联 task。规模到 60 后内联会爆炸,改为:

```
benchmarks/v1/
├── manifest.yaml            # 仅含 schema_version / allowed_metric_codes / taxonomy / **task 索引**
├── tasks/
│   ├── R01/
│   │   ├── happy_01.yaml    # 单 task 完整定义,被 manifest 通过 $ref 引用
│   │   ├── happy_02.yaml
│   │   └── adversarial_01.yaml
│   ├── V04/
│   │   └── ...
│   └── A01/
│       └── ...
└── fixtures/                # 已存在
```

**task_loader 改造**: 增加 `$ref: tasks/R01/happy_01.yaml` 的解析(相对路径,fail-fast 校验文件存在);**所有 F.0.b 的 fail-fast 校验规则保持不变**。

> 风险: $ref 解析增加测试复杂度。**降级方案**: 若 $ref 实施成本高,可保留单文件 manifest,通过 yaml anchor + 拆 include 文件的形式分组。决策点放在 F.1.a 实施开始时。

### 2.5 任务规模与 roadmap "100+" 的差异说明

Roadmap §F.1 写"100+ 真实任务",我们 F.1.a 下限定 60。**理由**:

- 60 = 30 类 × 2 variants,**保覆盖**(每类至少 happy+adversarial 各 1 个)
- 100 是任务**实例**总数,在"3 agent × 60 task = 180 个 raw_ticks 序列"的口径下,统计基数已远超 100
- 若评审认为 60 不够,F.1.a 可加 variants 到 90,无需改其他子阶段

**评审决策点**: F.1.a 完成时由人工 review 是否补到 90/120;**不在本设计阶段拍板**。

### 2.6 F.1.a 通过标准

- ✅ `benchmarks/v1/tasks/` 下 ≥60 个 task yaml(每类 ≥2 variants,4 病灶 24 类 + 通用 6 类齐全)
- ✅ `task_loader.load_manifest()` 能解析新结构,所有 fail-fast 规则覆盖
- ✅ 验证方式分布满足 §2.2(可由一个新的 `tests/test_manifest_coverage.py` 校验)
- ✅ 每个 adversarial 都有 `expected_failure_mode` 与至少 1 个 `verifier_tools`
- ✅ 单元测试 ≥6 个新 case(覆盖 $ref 解析失败、循环引用、规模约束)

---

## 3. F.1.b — 真 Agent 接入 orchestrator

### 3.1 目标

把 F.0 的 fake_agent 用 真 `agent.py` 替换;orchestrator 启动前确保 backend 已在跑。

### 3.2 实施模式 — 真 backend task 生命周期(v1.1 重写)

**v1.0 路线被自审 B1+B2+B3 否决**:
- B1: runtime `_perceive()` 无 hook 点,"briefing 注入"无干净实施路径
- B2: 同一 LLM 既决策又自评 → M1 deviation rate 因"LLM 自我肯定偏置"而失真
- B3: F.0 的 `agent_self_reported_success` 语义在 v1.0 自评方案下漂移

**v1.1 方案**: **不**注入 briefing,**不**让 LLM 自评。orchestrator 在启动 agent 之前,**先在 backend 创建一个真 task**(通过 `POST /v1/tasks` 之类的真实 SDK API),把 `task.briefing` 字段设成 manifest 里的内容。agent 通过正常 `agent.briefing()` perceive 拿到该 task,走真实 SDK 路径(pool_claim → execute → confirm),最后调 `task_execute(done=true)` 或类似 API 把 task 标记完成。orchestrator 轮询 backend task state,**当 task state 落入终态(done/failed/canceled)时**写出 sentinel,SIGTERM agent。

#### 3.2.1 5 个 BENCHMARK_* 环境变量(v1.1 修订)

| Env | 含义 | F.0 → F.1 变化 |
|---|---|---|
| `BENCHMARK_RUN_ID` | 当前 run id | 不变 |
| `BENCHMARK_TASK_ID` | manifest 中的 task id(如 `R01_happy_01`)— **本地标识符,与 backend task id 不同** | 语义保留 |
| `BENCHMARK_RAW_CSV` | CollectorAdapter 写入路径 | 不变 |
| `BENCHMARK_SENTINEL_DIR` | sentinel 写出目录 | 不变,但**写入方为 orchestrator**(非 agent) |
| ~~`BENCHMARK_BRIEFING_FILE`~~ | ~~JSON briefing 路径~~ | **删除** — briefing 不再走文件,而是 backend 真 task |
| **`BENCHMARK_BACKEND_TASK_ID`**(新) | orchestrator 在 backend 创建的真 task id,供 agent 在 capabilities 匹配时优先识别 | 新增 |

#### 3.2.2 agent.py 改造(最小入侵,v1.1 实测可行)

仅在 `agent.py` 顶层加一个 helper,**不改 runtime,不改 SDK**:

```python
# agent.py 新增片段(伪代码)
def _install_benchmark_mode_if_present(runner):
    if not os.getenv("BENCHMARK_TASK_ID"):
        return
    from benchmarks.collector_adapter import CollectorAdapter
    from benchmarks.benchmark_mode import install
    install(runner)  # 注册一个 high-priority rule + collector
```

`benchmarks/benchmark_mode.py` 内做两件事:

1. **挂 CollectorAdapter** 到 `runner.on_reflect`(F.0 已实现)
2. **注册一个 high-priority rule** `priority=999, name="benchmark_prefer_target_task"`,优先 pool_claim 那个 `BENCHMARK_BACKEND_TASK_ID`,避免 agent 跑去做无关 task

#### 3.2.3 完整时序

```
┌─ orchestrator ─┐                  ┌─ backend ─┐         ┌─ agent.py ─┐
│                │                  │           │         │            │
│ 1. POST /v1/tasks (briefing,      │           │         │            │
│    success_criteria) ─────────────►           │         │            │
│ 2. 收到 backend_task_id           │           │         │            │
│ 3. spawn agent (env: BACKEND_TASK_ID, RAW_CSV, SENTINEL_DIR)         │
│                │                  │           │         │ 4. perceive│
│                │                  │           │ ◄───────┤    briefing│
│                │                  │           │ ─task──►│ 5. claim   │
│                │                  │           │         │ 6. execute │
│                │                  │           │ ◄───────┤ 7. confirm │
│                │                  │  state    │         │            │
│ 8. poll GET /v1/tasks/{id} ──────► done/failed│         │            │
│ 9. write sentinel (kind from state)            │         │            │
│ 10. SIGTERM agent                             │         │            │
└────────────────┘                  └───────────┘         └────────────┘
```

### 3.3 sentinel 由 orchestrator 写出 — 语义重定义(v1.1)

v1.0 让 agent 写 sentinel。v1.1 改由 **orchestrator 写**(基于 backend task state):

| backend task state | sentinel kind | exit_code | M1.agent_self_reported_success |
|---|---|---|---|
| `done` | `done` | 0 | **true** — agent 真实调用了 confirm/execute(done=true) |
| `failed`(agent 主动调 fail API) | `failed` | 3 | **false** — agent 自己说失败 |
| `canceled`(agent 调 abandon API) | `give_up` | 4 | **false** |
| 超时未变(orchestrator 因 wall-clock/tick-limit 强杀) | 不写 sentinel | 1 或 124 | **null** — 无 agent 主观判断 |

**关键: M1 deviation 的语义现在变成 "agent 用真实 SDK action 表达完成" vs "用 verifier 客观验证是否达成"**。这是 F.0 设计本意的还原 — 当 agent 调 `task_execute(done=true)` 时,他/她**就**是在自报 success。

#### 3.3.1 SDK API 是否齐全的核对(v1.1 必须前置确认)

实施 F.1.b 第一步:确认 `civitasos_runtime` 的 `Agent` 类(或 SDK)是否暴露:

- ✅ `pool_claim(task_id)` — 已有(`runtime/runner.py:237` 反向 abandon 已用)
- ❓ `task_execute(task_id, result, done: bool)` — **待核对**
- ❓ `task_fail(task_id, reason)` — **待核对**
- ❓ `task_abandon(task_id)` — pool_abandon 应该等价

**若任一缺失** → F.1.b 实施第一动作是**与 SDK 维护者协商最小新增**(F.1.b 范围内,因为 SDK 是 agent 的依赖,不是 runtime/loop;改 SDK 不算违反 "不改 runtime")。**若无法协商** → 退化为方案 X(连续 N tick 都 wait 即视为完成,success=undecided),**M1 数据视为 partial coverage** 在 REPORT 中标注。

#### 3.3.2 orchestrator 新增能力

```python
# orchestrator.py 新增伪代码
class BackendTaskClient:
    def create(self, task_spec: TaskSpec, run_id: str) -> str: ...   # POST /v1/tasks
    def get_state(self, backend_task_id: str) -> dict: ...           # GET /v1/tasks/{id}
    def cleanup(self, backend_task_id: str): ...                     # DELETE 或 mark archived
```

poll 循环增加第 5 项检查:**backend task state 终态** → 写 sentinel → SIGTERM。优先级置于 sentinel 检查之前。

### 3.4 backend 启动方式

复用 `deploy/docker-compose.yml`:

```bash
# F.1.b 实施时,orchestrator CLI 增 --backend-mode 参数:
benchmarks/orchestrator.py \
  --manifest benchmarks/v1/manifest.yaml \
  --agent-command "python /abs/agent.py" \
  --backend-mode docker-compose \
  --backend-compose-file deploy/docker-compose.yml \
  --backend-services node1,node2,node3,csp \
  --runs-root runs/
```

orchestrator 在 `run()` 起始处:

1. `docker compose -f $FILE up -d $SERVICES`
2. 等待 `http://localhost:8099/healthz` 200(timeout 90s)
3. 跑全部 task
4. **不**自动 down,留给 operator(避免数据丢失,适合 F.1.c 多次跑)

> **降级**: `--backend-mode external` (默认):假设 backend 已经跑着,orchestrator 不管启停。F.0 的现有行为。

### 3.5 LLM 选择与 3-agent 差异化机制(v1.1 显式化)

- **F.1 默认 LLM**: `ollama:qwen3:latest`(host 已装,docker-compose runtime 模板已用)
- **温度**: 强制 `temperature=0.2`;**写入 agent_config.snapshot.env**

**3-agent 差异化的因果链**(v1.1 新增,回应自审 M2):

```
capabilities 不同(alpha=trading,analysis  /  beta=scouting,translation  /  gamma=scholar,research)
  ↓
auto_claim_matching 规则匹配的 task 集合不同
  ↓
briefing 中 active_tasks 不同
  ↓
LLM prompt 实际 context 不同
  ↓
决策序列 + reflect 内容不同
  ↓
raw_ticks.csv 数据有差异
```

**伪三样本检测**(F.1.d 报告必含): 计算 inter-agent 在**相同 task** 上的 action 序列 Jaccard 相似度;若 ≥ 0.95,基线视为伪样本,需重新设计 capabilities 矩阵或 task 分配策略,**F.1.d 不通过**。

**为什么不让 3 agent 用不同 LLM**: F.1 是"测量自身病灶",不是"对比模型"。LLM 变量被控制 → 3 agent 数据可合并(同 LLM 不同 context),病灶发病率有统计意义。

### 3.6 F.1.b 通过标准

- ✅ `python agent.py` 在设置 5 个 BENCHMARK_* env vars 后,行为等价于 fake_agent(写 raw_ticks + sentinel)
- ✅ orchestrator 能用 `--backend-mode docker-compose` 拉起 backend,并在 backend healthz OK 后启动 agent
- ✅ 在 backend 真跑的环境下,跑通 R01_happy_01 一个 task,raw_ticks.csv 行数 > 0,sentinel 被写出,exit_code 与 sentinel 一致
- ✅ agent 自评 LLM 调用不计入 eval_duration_ms(test 校验)
- ✅ 新增/改动测试 ≥4 个(benchmark mode hook 安装、briefing 注入、self-report sentinel 写出、self-report 不污染 latency)

---

## 4. F.1.c — 3-agent × 60-task 全量运行

### 4.1 编排策略

```
for agent_profile in [alpha, beta, gamma]:
    run_id = baseline-v1-{profile}-{ts}
    orchestrator.run(
        manifest=v1,
        agent_command=f"python agent.py --profile {profile}",
        runs_root=runs/,
        run_id=run_id,
    )
```

3 个 agent 串行跑(F.0.c 注脚 "ollama 并发会污染 m5_tick_latency");每个跑 60 task。

### 4.2 资源预算估算(评估期产出)

| 项 | 估值 | 来源 |
|---|---|---|
| 平均 tick 数/task | 30 | 介于 max_ticks=20(R01)与 60(V04)之间 |
| 平均 LLM 调用/tick | 1.5 | decide + 自评偶发 |
| ollama qwen3 平均推理 | ~3s/调用 | host 实测(待 F.1.b 校准) |
| 单 task wall-clock | 30 × 1.5 × 3 = ~135s | |
| 单 agent 全跑 60 task | 60 × 135 = **2.25 小时** | |
| 3 agent 串行 | **6.75 小时** | |
| ollama 模型加载/磁盘 IO 余量 | ×1.3 | |
| **F.1.c 总预算** | **~9 小时** | |

→ 单次基线运行可在一夜跑完。**预算友好。**

### 4.3 数据合并

3 个 run_id 各自的 `runs/{rid}/raw_ticks/*.csv` 合并到 `benchmarks/v1/baselines/v1.0/raw_ticks_merged.csv`(加一列 `run_profile`),aggregator 仍按 (agent_id, category_id) 聚合,产出 `final_metrics_merged.csv`。

### 4.4 失败容忍(v1.1 简化)

- 单个 task 失败不阻塞其他 task(F.0.c orchestrator 已实现)
- 单个 agent 跑挂 → operator **完整重跑该 agent 的全 60 task**(丢弃前次 run_id 数据,新建 run_id);理由:F.0.c orchestrator 当前无 resume 状态文件,"算 diff 重跑剩余" 易引入数据完整性 bug,违反"可复现"原则
- 可选 resume 能力:F.1.b 实施时**若工作量 < 1 天**则加(`--skip-if-sentinel-exists` flag),否则推迟到 G 阶段
- 即使 60 task 中部分异常退出,只要数据采集完整,**仍计入基线**;REPORT 明确标注"基线包含 N 个异常退出 task"

### 4.5 F.1.c 通过标准(v1.1 加强)

- ✅ 3 个 run_id 的 raw_ticks CSV 总行数 ≥ 3 × 60 × 5 = 900(假设每 task 至少 5 tick)
- ✅ 3 个 run_id 的 summary.json `tasks_completed + tasks_terminated_abnormally == 60`
- ✅ **每个 agent 的 tasks_completed ≥ 50**(允许 ≤10 异常退出/超时;v1.1 新增,防止行数足够但分布烂)
- ✅ `final_metrics_merged.csv` 6 项指标(M4 仍为 null+notes)对每个 (agent, category) 都有数值或显式 null
- ✅ 基线运行**端到端无人工干预可重跑**(给 reviewer 复现用)
- ✅ **inter-agent 行为相似度** Jaccard < 0.95(v1.1 新增,见 §3.5)

---

## 5. F.1.d — 基线报告 + 评审

### 5.1 报告产出

`benchmarks/v1/baselines/v1.0/REPORT.md` + 同目录下:

- `figures/m1_deviation_by_category.png` — 4 病灶分组柱状图
- `figures/m3_aspect_gap_distribution.png` — aspect_gap 时序散点(校准 θ=0.7 是否合理)
- `figures/m5_latency_cdf.png` — tick latency CDF
- `figures/m6_wait_ratio_by_agent.png` — 3 agent 的 idle thinking 对比
- `final_metrics_merged.csv`(F.1.c 产物拷贝)
- `raw_ticks_merged.csv.gz`(原始,gzip 压缩归档)

### 5.2 报告必含 4 节

1. **Executive Summary** — 4 病灶各自发病率(数字)+ 一句话定性
2. **Methodology** — manifest snapshot、runtime git rev、**ollama 模型 sha256 snapshot**(`ollama list --format json` 强制)、LLM 温度,**确保可复现**;若 reviewer 复现时 sha256 不匹配,告警但不阻塞(允许"近似复现")
3. **Findings** — 按 M1..M6 分节,每节给:
   - 数值(分位数/均值)
   - **M1/M2 必须分 machine_check / llm_judge 子集分别给**(v1.1 §2.2 强制)
   - 病灶映射
   - **adversarial 任务的 expected_failure_mode vs 实际表现**对比表(v1.1 minor m3)
   - **至少 1 个反直觉发现**(或诚实声明无,见 §5.3)
4. **Calibration Notes** — M3 的 θ=0.7 实测是否合理?是否需要 M4 在 H.2 之后接入?M5 的 latency 异常值原因?(给 G/H 阶段做改进依据)

### 5.3 反直觉发现要求

Roadmap 通过标准: "至少 1 个意外发现(数据反直觉处)"。如果 F.1.d 发现"数据完全符合直觉",**不能编造**;应在报告里诚实标注 "no counter-intuitive finding observed; possible reasons: (a) task set too narrow, (b) agent behavior too uniform" 并提议 v1.1 task 扩展或 J 阶段诱导多样性。

### 5.4 评审清单(v1.1 加强)

- [ ] 报告四节齐全,数据图表可在 reviewer 本机重现
- [ ] 4 病灶发病率有数字,且每个数字关联到至少一个 task variant 的具体证据
- [ ] M1/M2 分 machine_check / llm_judge 子集给数,无遗漏
- [ ] **adversarial expected_failure_mode 实际命中表**完整
- [ ] 至少 1 个反直觉发现(或诚实声明"无");**若声明无,reviewer 必须**:(a) 确认任务集 30 类全覆盖 (b) 给出"下一阶段如何诱导多样性"的具体建议(写入 REPORT)
- [ ] inter-agent Jaccard 相似度 < 0.95(防伪样本)
- [ ] M3 θ 校准结论(沿用 / 需要改 / 数据不足无法判断);**若需改,只能记入 G/H 阶段 backlog,不允许在本 commit 改 schema/computers**
- [ ] 后续 G/H 阶段改进**优先级**有数据依据(不是拍脑袋)
- [ ] reviewer ≥1 人签字(可以是另一个 session 的自我评审,但需以 commit 形式存证)

### 5.5 F.1.d 通过标准

- ✅ REPORT.md 4 节齐全
- ✅ 4 病灶发病率均出现且有溯源
- ✅ 评审清单 6 项全过
- ✅ 报告 commit 后,`benchmarks/v1/` 进入冻结状态(README.md 加 `frozen: true` flag)

---

## 6. 文件组织(F.1 完成态,v1.1 修订)

```
civitasos-agent/
├── benchmarks/
│   ├── F1_BASELINE_DESIGN.md         # 本文档
│   ├── RUN_BASELINE_DESIGN.md        # F.0 设计(保留)
│   ├── orchestrator.py               # 新增 --backend-mode docker-compose + BackendTaskClient
│   ├── backend_task_client.py        # ★ 新增,封装 POST/GET /v1/tasks
│   ├── aggregator.py                 # 新增 merged 模式(--profile-column run_profile)
│   ├── task_loader.py                # 新增 $ref 解析,**保留单文件内联兼容**(M5)
│   ├── benchmark_mode.py             # ★ 新增,被 agent.py import
│   ├── _fake_agent.py                # 保留(orchestrator 单元测试需要)
│   ├── tests/
│   │   ├── test_manifest_coverage.py # ★ 新增,F.1.a 校验(分布约束 + 每 cat ≥1 adv)
│   │   ├── test_benchmark_mode.py    # ★ 新增,F.1.b 校验
│   │   ├── test_backend_task_client.py # ★ 新增,mock backend 测交互
│   │   ├── test_task_loader_compat.py# ★ 新增,验证单文件 + $ref 双模式
│   │   └── ...(继承 F.0,**全部不动**)
│   └── v1/
│       ├── README.md                 # F.1.d 后添加 frozen: true
│       ├── manifest.yaml             # 改成索引型($ref);**老 inline 形式仍被 loader 支持**
│       ├── tasks/                    # ★ 新增 30+ category 子目录
│       ├── fixtures/                 # 继承 + 扩展
│       └── baselines/
│           └── v1.0/                 # ★ F.1.d 报告与数据归档
│               ├── REPORT.md
│               ├── figures/
│               ├── final_metrics_merged.csv
│               ├── raw_ticks_merged.csv.gz
│               ├── llm_snapshot.json # ★ ollama list --format json(M7)
│               └── runtime_snapshot.txt
├── agent.py                          # 加 _install_benchmark_mode_if_present 调用
└── observability/                    # F.1 不动(仍冻结于 F.0 v1.1)
```

**向后兼容硬约束(M5)**:
- F.0 写的 `test_task_loader.py` / `test_aggregator.py` / `test_orchestrator.py` **一行不能改**
- 当前 `benchmarks/v1/manifest.yaml`(3 task 内联)必须**继续被 loader 接受**
- $ref 解析失败时,fall back 到 inline 解析,而不是 fail-fast(因为可能是过渡期 manifest)

---

## 7. 风险登记 + 缓解策略(v1.1 修订)

| # | 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|---|
| R1 | 60 task 写不完(人工成本) | 高 | 阻塞 F.1.a | 用任务模板 + 复用 fixtures + 同类 happy 共享 LLM 提示模式;若仍超时,**评审决议接受 36 task 下限**(每类 1 happy + 0.2 adv) |
| **R2'** | **SDK 缺 task_execute(done=true) API** | 高 | 阻塞 F.1.b 完成信号 | F.1.b 第一动作:核对 SDK + 协商最小新增;若拒绝,降级为 "连续 N tick 都 wait" 启发式,M1 标注 partial |
| R3 | docker-compose backend 启动慢/失败 | 中 | F.1.b 阻塞 | orchestrator healthz + cluster_peers≥2 双重 readiness 轮询;失败 fail-fast 输出 backend logs;支持 `--backend-mode external` 降级 |
| R4 | M3 θ=0.7 实测全部触发或全部不触发(算不出 rate) | 中 | 报告无 M3 数字 | F.1.d 报告诚实标注;**不允许临时调 θ 让数据"好看"**(违反原则 4) |
| R5 | LLM 推理时间超估(超过 9h 预算) | 中 | F.1.c 跑不完一夜 | 缩 max_ticks 上限(评审决议);v1.1 已无 self-report 调用,预算更宽松 |
| R6 | 反直觉发现"挤"不出来 | 低 | 卡 F.1.d 评审 | §5.3 + §5.4 评审清单已规定"诚实声明无 + reviewer 必须给多样性建议" |
| R7 | benchmarks/v1/ 冻结后发现 fixture bug | 低 | 触犯"只追加"原则 | bug 用 v1.0.1 patch 子目录承载,**不修改 v1.0/**;严重则开 v2 |
| R8 | docker compose 与 host ollama 网络不通 | 中 | runtime 启动失败 | compose 已用 `host.docker.internal:11434`(macOS/Windows OK);Linux 需 `--add-host=host.docker.internal:host-gateway`,文档明确写出 |
| **R9** | **ollama 单实例并发瓶颈** | 中 | 多 agent 并行会请求队列堆积,m5 抖动 | orchestrator CLI 在 `--backend-mode docker-compose` 下**硬拒绝** `--max-parallel > 1`;实施时 unit test 覆盖此校验 |
| **R10** | **3-agent 行为相似度过高(伪样本)** | 中 | 基线无统计意义 | F.1.c 通过标准 §4.5 加 Jaccard < 0.95 硬指标;不达标 → 调 capabilities 矩阵重跑 |
| **R11** | **真 backend task 创建失败 / state 卡住** | 中 | F.1.b 卡死 | BackendTaskClient 内置 retry + 创建后 health check + cleanup 逻辑;orchestrator wall-clock 兜底 |

---

## 8. 自审清单(v1.1 全部✅,见 §11 finding 处置表)

- [x] §1 子阶段拆分能 unblock 评审吗?— 每 sub-gate 通过标准客观可验证
- [x] §2.2 验证方式分布约束 — 改为按病灶分组(M1)
- [x] §3.3 self-report LLM 自评是否假实现 — **方案被否决**,改用真 backend task 生命周期(B1+B2+B3 联合修复)
- [x] §3.5 LLM 温度 0.2 行为单一 — F.1.b 实施后小规模试跑校准;§3.5 加差异化机制 + Jaccard 兜底(M2)
- [x] §4.2 资源预算乐观 — v1.1 去掉 self-report 调用,预算更宽松(m1)
- [x] §5.3 "无反直觉发现"评审路径 — §5.4 评审清单加具体处置要求(M3)
- [x] §6 文件组织对 F.0 测试影响 — 加"向后兼容硬约束"段(M5)

---

## 9. 不在 F.1 范围(避免抢跑)

- ❌ 改 runtime/loop.py(G.1+)
- ❌ 部署到公网 testnet(I.1)
- ❌ 多机分布式 backend(J.1)
- ❌ Lessons store / M4 真实计算(H.2)
- ❌ LLM-as-judge 评分(H.1)
- ❌ 引入 H.1+ 的意图层(`served_intent_layer` 仍留空)
- ❌ 优化 prompt / 改 conscience(F.1 是测量,不是优化)

---

## 10. 与 F.0 的契约关系

```
F.0.a (collector + computers)  ──┐
                                  │
F.0.b (manifest schema)          ─┼──> F.1 不修改,仅扩展数据 (tasks/, baselines/)
                                  │
F.0.c (orchestrator + aggregator)─┘
                                  │
                                  ↓
F.1.a (60+ tasks)
F.1.b (real agent + docker compose backend)
F.1.c (3 agent × 60 task 全量跑)
F.1.d (报告 + 评审 + 冻结)
```

F.1 完成 → 解锁 G.1(共识时间);所有 G/H/I 阶段必须能与 `benchmarks/v1/baselines/v1.0/final_metrics_merged.csv` 做对比证明改进。

---

## 11. 自审 finding 处置表(v1.1 新增)

本章是 v1.0 → v1.1 的自审报告浓缩。共发现 18 项 finding,处置如下:

### 🔴 BLOCKER(3 项,**全部修**)

| # | finding | v1.1 处置 |
|---|---|---|
| B1 | runtime 无 perceive hook,briefing 注入无干净路径 | **§3.2 重写**:不再注入 briefing,改为 orchestrator 在 backend 创建真 task,agent 走真实 perceive |
| B2 | 同 LLM 既决策又自评 → M1 因"自我肯定偏置"失真 | **§3.2-3.3 重写**:废弃 LLM 自评,改用真 SDK action(`task_execute(done=true)`)作为 M1.self_reported_success 信号源 |
| B3 | F.0 self_reported_success 语义在 v1.0 自评方案下漂移 | **§3.3 表格统一**:sentinel kind 由 backend task state 一对一映射,无歧义 |

### 🟡 MAJOR(7 项,**全部修**)

| # | finding | v1.1 处置 |
|---|---|---|
| M1 | §2.2 全局验证分布约束逼出劣质 task | §2.2 改为按 V/A/G vs R/S 病灶分组约束;REPORT 强制分子集给数 |
| M2 | 3 agent 差异化机制未说明,reviewer 会质疑伪样本 | §3.5 加因果链 + Jaccard < 0.95 硬指标 |
| M3 | "无反直觉发现" 评审路径在清单未体现 | §5.4 评审清单加具体处置要求 |
| M4 | F.0 orchestrator 不支持"重跑剩余 task" | §4.4 改为"重跑全部 60";resume 移到可选 |
| M5 | task_loader $ref 改造会让 F.0 测试失败 | §6 加"向后兼容硬约束":单文件内联 + $ref 双模式;F.0 测试一行不改 |
| M6 | "测试网" 偏离 roadmap 字面要求 | §0.1 加范围声明,坦白 "localhost docker compose" 是合理收缩 |
| M7 | ollama 模型版本无固化机制 | §5.2 强制 `ollama list --format json` snapshot;§6 加 `llm_snapshot.json` |

### 🟢 MINOR(8 项,**实施时顺手修**,不阻塞设计)

| # | finding | 实施时如何修 |
|---|---|---|
| m1 | §4.2 漏算 self-report 推理预算 | v1.1 已去掉 self-report,无需修 |
| m2 | 每 category ≥1 adversarial 无自动校验 | `test_manifest_coverage.py` 加一个 case |
| m3 | adversarial `expected_failure_mode` 死字段 | F.1.d REPORT 加对比表(§5.2 已加) |
| m4 | docker-compose readiness 仅 healthz 不够 | orchestrator healthz + `cluster/peers≥2` 双重 check(§7 R3 已修订) |
| m5 | self-report prompt token 无界 | v1.1 已去掉,无需修 |
| m6 | §7 漏 R9 ollama 单实例瓶颈 | §7 已加 R9 + max_parallel>1 硬拒 |
| m7 | frozen 是软约定 | task_loader 实施时加 `git diff --quiet HEAD -- v1/tasks/` 检查 |
| m8 | F.1.c 通过标准只看行数 | §4.5 已加 "每 agent ≥50 完成" 硬指标 |

### 仍开放的疑问(F.1.b 实施第一步必须解决)

- **R2'**: SDK 是否暴露 `task_execute(done=true)` / `task_fail` / `task_abandon` 三件 API?需要 grep + 与 SDK 维护者协商;若全无,降级路径已在 §3.3.1 写明。
