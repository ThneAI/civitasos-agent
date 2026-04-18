# F.1 — 数据基线建立 设计文档

> **关联文档**: [WISDOM_EVOLUTION_ROADMAP.md](../../civitasos/doc/plan/WISDOM_EVOLUTION_ROADMAP.md) Gate F.1
> **状态**: DRAFT v1.0(待自审与评审)
> **前置**: F.0 通过(commit 4ac62cb,49/49 tests + smoke 端到端 OK)
> **目的**: 把 F.0 的"测试床"接到真 backend + 真 LLM + 真任务集,跑出**首份基线报告**

---

## 0. 设计原则(继承 F.0)

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

### 2.2 验证方式分布(防 M4 二次空洞)

| 验证 kind | 占比目标 | 理由 |
|---|---|---|
| `regex` | ≥40% | F.0 conservative M1 算法只对 regex+pyexpr 100% eligible,基数必须够 |
| `pyexpr` | ≥30% | 数值/集合判定的主力 |
| `llm_judge` | ≤30% | F.0 conservative M1 会跳过这部分;F.1 报告里需单独标注"non-machine-checkable subset" |

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

### 3.2 agent.py 改造(最小入侵)

新增 `BENCHMARK_TASK_ID` 模式:当此环境变量存在时,agent 进入"基线模式":

| 行为 | 普通模式 | 基线模式(BENCHMARK_TASK_ID set) |
|---|---|---|
| **Loop start** | `runner.start()` 无限运行 | 仍 `runner.start()`,由 sentinel 决定结束 |
| **Briefing source** | `agent.briefing()` 拉 backend | 第一个 tick 把 `BENCHMARK_BRIEFING_FILE` 内容**注入到首次 perceive 结果**;后续 tick 仍拉 backend |
| **Reflect hook** | 由用户 `runner.on_reflect()` 注册 | runner 内部自动注册 `CollectorAdapter`,绑定 `BENCHMARK_TASK_ID`,写到 `BENCHMARK_RAW_CSV` |
| **结束信号** | SIGTERM | agent 在判断"任务完成/失败/放弃"时写 sentinel 到 `BENCHMARK_SENTINEL_DIR`,然后**继续运行**;orchestrator 检到 sentinel 后 SIGTERM |

**实施方式**: agent.py 顶部加 `_install_benchmark_mode(runner)` helper(<60 行),不污染普通生产路径。

> **关键决策**: briefing 注入仅作用于**第一个 tick**,之后 agent 正常 perceive。这模拟真实场景:agent 收到一个"任务交付",然后在真实 backend 环境里完成它(可能涉及 pool_claim、tool calls、conscience 检查)。

### 3.3 sentinel 写出策略

agent 何时写 sentinel?这是 F.1.b 最微妙的决策点。三个候选:

| 方案 | 描述 | 优点 | 缺点 |
|---|---|---|---|
| **A. agent 自评** | runtime 增 `agent.report_task_done(task_id, success, reason)` API,生产环境 no-op,基线模式写 sentinel | agent 行为完全自主,符合 M1 "self_reported_success" 语义 | 需改 runtime;现有 runtime 没有"任务完成自报"概念 |
| **B. orchestrator 探测** | orchestrator 监控 backend 的 task state(claimed→done),自己写 sentinel | 不改 runtime | 把"agent 自报"变成"客观结算",**M1 算法失效**(M1 必须 agent 自评 vs 真实结果) |
| **C. 规则嵌入** | 在 `agent.py` benchmark hook 里加一条 conscience-like 规则:每个 reflect 后检查"是否所有 success_criteria 已经在 history 中达成",达成则写 sentinel | 不改 runtime | 检查需要 agent 知道 success_criteria → 但 M1/M2 设计前提就是 agent **不该**直接看 criteria |

**采用方案 A 的简化版**: 不改 runtime,在 agent.py benchmark hook 里加一个 reflect 钩子,**让 agent LLM 自评**:每 N tick 让 LLM 输出一个 JSON `{done: bool, reason: str, confidence: float}`(prompt 仅给 briefing,不给 success_criteria)。orchestrator 拿到 done=true 就让 agent 写 sentinel。

```python
# benchmark_mode.py(伪代码)
@runner.on_reflect
def benchmark_self_report(ctx):
    if ctx.tick_count % SELF_REPORT_EVERY_N == 0:
        verdict = ask_llm_self_evaluate(briefing=ORIGINAL_BRIEFING, history=ctx.recent_decisions)
        if verdict["done"]:
            sentinel_path = SENTINEL_DIR / ("done" if verdict["success"] else "failed")
            sentinel_path.write_text(json.dumps(verdict))
```

> **风险**: 这个自评 LLM 调用会污染 m5_tick_latency 指标。**对策**: 自评在 reflect 阶段独立计时,不计入 eval_duration_ms;collector 已经只读 `evaluation.duration_ms`。

> **不抢跑提醒**: 自评 LLM 是 F.1 评测脚手架,不是 H.1 的 LLM-as-judge(那是别人评 agent)。这里是**agent 评自己**,M1 设计本来就需要这个信号。

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

### 3.5 LLM 选择与口径

- **F.1 默认 LLM**: `ollama:qwen3:latest`(host 已装,docker-compose runtime 模板已用)
- **3 agent 差异化**: capabilities 不同(trader/scout/scholar),但 LLM 相同,**保证基线对比时模型变量被控制**
- **温度**: 强制 `temperature=0.2`(降低 LLM 抖动对基线统计的污染);**写入 agent_config.snapshot.env**

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

### 4.4 失败容忍

- 单个 task 失败不阻塞其他 task(F.0.c orchestrator 已实现)
- 单个 agent 跑挂(进程不存在)→ orchestrator 报错退出,operator 修复后**只重跑该 agent 的剩余 task**
- 所有 task 都跑完 → 即使 60 task 中部分异常退出,只要数据采集完整,**仍计入基线**;F.1 报告需明确"基线包含 N 个异常退出 task"

### 4.5 F.1.c 通过标准

- ✅ 3 个 run_id 的 raw_ticks CSV 总行数 ≥ 3 × 60 × 5 = 900(假设每 task 至少 5 tick)
- ✅ 3 个 run_id 的 summary.json `tasks_completed + tasks_terminated_abnormally == 60`
- ✅ `final_metrics_merged.csv` 6 项指标(M4 仍为 null+notes)对每个 (agent, category) 都有数值或显式 null
- ✅ 基线运行**端到端无人工干预可重跑**(给 reviewer 复现用)

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
2. **Methodology** — manifest snapshot、runtime git rev、LLM 版本、温度,**确保可复现**
3. **Findings** — 按 M1..M6 分节,每节给:
   - 数值(分位数/均值)
   - 病灶映射
   - **至少 1 个反直觉发现**(roadmap 通过标准)
4. **Calibration Notes** — M3 的 θ=0.7 实测是否合理?是否需要 M4 在 H.2 之后接入?M5 的 latency 异常值原因?(给 G/H 阶段做改进依据)

### 5.3 反直觉发现要求

Roadmap 通过标准: "至少 1 个意外发现(数据反直觉处)"。如果 F.1.d 发现"数据完全符合直觉",**不能编造**;应在报告里诚实标注 "no counter-intuitive finding observed; possible reasons: (a) task set too narrow, (b) agent behavior too uniform" 并提议 v1.1 task 扩展或 J 阶段诱导多样性。

### 5.4 评审清单

- [ ] 报告四节齐全,数据图表可在 reviewer 本机重现
- [ ] 4 病灶发病率有数字,且每个数字关联到至少一个 task variant 的具体证据
- [ ] 至少 1 个反直觉发现(或诚实声明"无")
- [ ] M3 θ 校准结论(沿用 / 需要改 / 数据不足无法判断)
- [ ] 后续 G/H 阶段改进**优先级**有数据依据(不是拍脑袋)
- [ ] reviewer ≥1 人签字(可以是另一个 session 的自我评审,但需以 commit 形式存证)

### 5.5 F.1.d 通过标准

- ✅ REPORT.md 4 节齐全
- ✅ 4 病灶发病率均出现且有溯源
- ✅ 评审清单 6 项全过
- ✅ 报告 commit 后,`benchmarks/v1/` 进入冻结状态(README.md 加 `frozen: true` flag)

---

## 6. 文件组织(F.1 完成态)

```
civitasos-agent/
├── benchmarks/
│   ├── F1_BASELINE_DESIGN.md         # 本文档
│   ├── RUN_BASELINE_DESIGN.md        # F.0 设计(保留)
│   ├── orchestrator.py               # 新增 --backend-mode docker-compose 分支
│   ├── aggregator.py                 # 新增 merged 模式(--profile-column run_profile)
│   ├── task_loader.py                # 新增 $ref 解析
│   ├── benchmark_mode.py             # ★ 新增,被 agent.py import
│   ├── _fake_agent.py                # 保留(orchestrator 单元测试需要)
│   ├── tests/
│   │   ├── test_manifest_coverage.py # ★ 新增,F.1.a 校验
│   │   ├── test_benchmark_mode.py    # ★ 新增,F.1.b 校验
│   │   └── ...(继承 F.0)
│   └── v1/
│       ├── README.md                 # 添加 frozen: true
│       ├── manifest.yaml             # 改成索引型(若采用 $ref)
│       ├── tasks/                    # ★ 新增 30+ category 子目录
│       ├── fixtures/                 # 继承 + 扩展
│       └── baselines/
│           └── v1.0/                 # ★ F.1.d 报告与数据归档
│               ├── REPORT.md
│               ├── figures/
│               ├── final_metrics_merged.csv
│               └── raw_ticks_merged.csv.gz
├── agent.py                          # 加 _install_benchmark_mode 调用
└── observability/                    # F.1 不动(仍冻结于 F.0 v1.1)
```

---

## 7. 风险登记 + 缓解策略

| # | 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|---|
| R1 | 60 task 写不完(人工成本) | 高 | 阻塞 F.1.a | 用任务模板 + 复用 fixtures + 同类 happy 共享 LLM 提示模式;若仍超时,**评审决议接受 36 task 下限**(每类 1 happy + 0.2 adv) |
| R2 | agent.py 自评 LLM 不收敛(永远不写 sentinel) | 中 | 所有 task 走到 wall-clock 才结束,污染 m5 | self-report prompt 加"严格 5 tick 内必出 done/failed"硬约束;orchestrator 把 wall-clock 缩到 max_ticks × 30s |
| R3 | docker-compose backend 启动慢/失败 | 中 | F.1.b 阻塞 | orchestrator healthz 轮询 + 失败 fail-fast 输出 backend logs;支持 `--backend-mode external` 降级 |
| R4 | M3 θ=0.7 实测全部触发或全部不触发(算不出 rate) | 中 | 报告无 M3 数字 | F.1.d 报告诚实标注;**不允许临时调 θ 让数据"好看"**(违反原则 4) |
| R5 | LLM 推理时间超估(超过 9h 预算) | 中 | F.1.c 跑不完一夜 | 缩 max_ticks 上限(评审决议);或减少 self-report 频率 |
| R6 | 反直觉发现"挤"不出来 | 低 | 卡 F.1.d 评审 | §5.3 已规定"诚实声明无"路径 |
| R7 | benchmarks/v1/ 冻结后发现 fixture bug | 低 | 触犯"只追加"原则 | bug 用 v1.0.1 patch 子目录承载,**不修改 v1.0/**;严重则开 v2 |
| R8 | docker compose 与 host ollama 网络不通 | 中 | runtime 启动失败 | compose 已用 `host.docker.internal:11434`(macOS/Windows OK);Linux 需 `--add-host=host.docker.internal:host-gateway`,文档明确写出 |

---

## 8. 自审清单(实施前必过)

- [ ] §1 子阶段拆分能 unblock 评审吗?(每个 sub-gate 通过标准是否客观可验证?)
- [ ] §2.2 验证方式分布约束是否过严?会不会逼出"为了凑比例而硬写 regex"的劣质 task?
- [ ] §3.3 方案 A 自评 LLM 是否构成"假实现"?(辨析:agent 评自己 ≠ judge 评 agent;前者是 M1 数据来源,后者是 H.1)
- [ ] §3.5 LLM 温度 0.2 是否过低导致行为单一?(可在 F.1.b 实施后小规模试跑校准)
- [ ] §4.2 资源预算是否乐观?(实际 LLM 推理时间在 F.1.b 跑通后再校准)
- [ ] §5.3 "无反直觉发现就诚实标注"会不会被 reviewer 当成"不通过"?(预先在评审章程里明确这是合法路径)
- [ ] §6 文件组织是否会让现有 F.0 测试失效?(需做向后兼容性核对)

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
