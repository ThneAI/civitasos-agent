# F.0.c — 基线测试床调度脚本设计

> **关联文档**: [WISDOM_EVOLUTION_ROADMAP.md](../../civitasos/doc/plan/WISDOM_EVOLUTION_ROADMAP.md) Gate F.0.c
> **状态**: DRAFT v1.1 (自审后修订；脚本契约 + 文件结构已定，实现待 F.0 实施)
> **依赖**: F.0.a (observability/metrics/) + F.0.b (benchmarks/v1/manifest.yaml)
>
> **v1.1 变更摘要**（自审 RCA 触发）:
> - 删除虚构的 `task.done` 动作，改为 sentinel 文件协议 (`.done` / `.failed` / `.give_up`)
> - 明确 watcher 读 tick_seq 的 IPC：**CSV 每行 flush+fsync，watcher tail 文件**
> - `wall_clock_per_tick_s` 从硬编码 30s 改为可配置，默认 60s
> - summary.json 补 `agent_self_reported_success` 字段（M1 计算需）
> - metrics_targeted 采用 m1..m6 代号，aggregator 校准到 final_metrics CSV 列名

---

## 设计原则

1. **不入侵 civitasos_runtime / agent.py** — 调度器是 agent.py 的外层包装器，通过环境变量与 task_id binding 传参
2. **不假实现** — 失败/超时/异常必须如实记录，禁止 fallback 成功
3. **可重入** — 同一 run_id + task_id 重跑会归档而不是覆盖
4. **隔离性** — 每个 task 一个 agent 进程 + 独立 data_dir，不复用状态
5. **不抢跑** — F.0.c 只跑 baseline，不评分、不下结论；评分留给 F.1 的 evaluator

---

## 顶层契约

```bash
benchmarks/run_baseline.sh \
  --manifest benchmarks/v1/manifest.yaml \
  --tasks "R01_happy_01,V04_adversarial_01,A01_happy_01" \   # 可选，默认全跑
  --agent-config configs/agent_baseline.env \                # AGENT_NAME / LLM 等
  --runs-dir runs/ \
  --max-parallel 1                                            # F.0 阶段串行，避免观察混淆
```

输出：

```
runs/
└── {run_id}/                          # run_id = baseline-YYYYMMDD-HHMMSS-<short_uuid>
    ├── manifest.snapshot.yaml          # 本次运行使用的 manifest 快照（防漂移）
    ├── agent_config.snapshot.env       # 本次 agent 配置快照
    ├── runtime.snapshot.txt            # civitasos-runtime git rev + python ver
    ├── summary.json                    # 任务完成情况汇总
    ├── tasks/
    │   ├── R01_happy_01/
    │   │   ├── raw_ticks.csv           # F.0.a Raw Tick CSV (22 列)
    │   │   ├── agent.log               # agent stdout/stderr
    │   │   ├── final_state.json        # 任务结束时 EnergyState + memory 摘要
    │   │   ├── briefing.json           # 实际注入 agent 的 briefing
    │   │   ├── sentinel.json           # agent 写出的 done/failed/give_up sentinel（可能不存在）
    │   │   └── exit_code.txt           # 0=agent_reported_done / 1=tick超限 / 2=异常退出 / 3=agent_reported_failed / 4=agent_gave_up / 124=wall-clock超时
    │   ├── V04_adversarial_01/
    │   │   └── ...
    │   └── ...
    └── final_metrics.csv               # F.0.a Final Metrics CSV (14 列), 由 computers/ 在所有 task 跑完后聚合
```

---

## 调度状态机（每个 task）

```
┌──────────────┐
│  PREPARE     │  copy fixtures, mkdir tasks/{id}/, render briefing
└──────┬───────┘
       │
┌──────▼───────┐
│  LAUNCH      │  spawn agent.py with env: TASK_ID + TASK_BRIEFING + DATA_DIR=tasks/{id}/data
└──────┬───────┘
       │
┌──────▼───────┐
│  OBSERVE     │  agent 内部 CollectorAdapter.bind_task(task_id) 后开始写 raw_ticks.csv
│              │  watcher 监控 tick_seq 是否达到 max_ticks
└──────┬───────┘
       │
       ├──→ tick_seq >= max_ticks → SIGTERM agent → exit_code=1
       ├──→ agent 写出 sentinel 文件 → SIGTERM agent → 由 sentinel 决定 exit_code (见下方协议)
       ├──→ wall-clock 超时 (max_ticks * wall_clock_per_tick_s) → SIGKILL → exit_code=124
       └──→ agent 进程异常退出                   → exit_code=2
       │
┌──────▼───────┐
│  TEARDOWN    │  flush csv, dump final_state.json, archive log
└──────┬───────┘
       │
┌──────▼───────┐
│  NEXT TASK   │
└──────────────┘

所有 task 跑完后:
┌──────────────┐
│  AGGREGATE   │  observability/metrics/computers/* 读取所有 raw_ticks.csv → final_metrics.csv
└──────────────┘
```

---

## 文件结构

```
benchmarks/
├── v1/                              # F.0.b 任务库
│   ├── README.md
│   └── manifest.yaml
├── run_baseline.sh                  # ★ 顶层入口
├── runner/
│   ├── __init__.py
│   ├── orchestrator.py              # 状态机、并发控制、信号处理
│   ├── task_loader.py               # 从 manifest.yaml 加载 + 校验
│   ├── briefing_renderer.py         # 把 task.briefing + fixtures 拼成 agent 启动入参
│   ├── agent_launcher.py            # subprocess 启动/监控/超时
│   ├── snapshot.py                  # runtime/config/manifest 快照
│   └── aggregator.py                # 调用 observability/metrics/computers/* 聚合
├── configs/
│   ├── agent_baseline.env           # 基线 agent 配置（默认 LLM / 默认 stake / heartbeat）
│   └── agent_baseline.env.example
├── tests/
│   ├── test_task_loader.py
│   ├── test_briefing_renderer.py
│   ├── test_orchestrator_state_machine.py    # 用 fake agent 测状态机
│   └── test_aggregator_smoke.py
└── runs/                            # gitignored，运行产物
```

---

## 关键决策与职责边界

| 关注点 | 决策 |
|---|---|
| **Task → Agent 通信** | 通过 5 个环境变量：`BENCHMARK_RUN_ID`, `BENCHMARK_TASK_ID`, `BENCHMARK_BRIEFING_FILE`(JSON path), `BENCHMARK_RAW_CSV`, `BENCHMARK_SENTINEL_DIR` |
| **agent.py 改动** | F.0.c 实施时新增 ~30 行：检测 `BENCHMARK_TASK_ID` → 安装 `CollectorAdapter` 到 loop → bind_task 后启动；agent 同时暴露 sentinel 写出 API |
| **briefing 注入** | `briefing_renderer.py` 把 task.briefing + task.metadata.task_id 写到 perceive 来源（agent 端 perceive 读 `BENCHMARK_BRIEFING_FILE`） |
| **fixtures 注入** | `task.fixtures` 列表中的文件被 copy 到 tasks/{id}/fixtures/，agent 通过 tools 读取 |
| **CSV 写入 IPC** | `RawWriter` 每写一行后 `flush() + os.fsync()`；watcher 以 200ms 轮询 tail raw_ticks.csv 读最后一行的 tick_seq，不需额外 IPC 通道 |
| **超时策略** | wall-clock 上限 = `max_ticks * wall_clock_per_tick_s`，默认 `wall_clock_per_tick_s=60`（覆盖典型 LLM 推理），可在 agent_baseline.env 覆盖；到点 SIGTERM，再 10s 不退则 SIGKILL |
| **Sentinel 协议**（v1.1 新增） | agent 认为任务结束时在 `BENCHMARK_SENTINEL_DIR` 下写出三选一文件：`done`（成功，exit_code=0）/ `failed`（agent 自认失败，exit_code=3）/ `give_up`（agent 主动放弃，exit_code=4）。文件内容为 JSON `{success: bool, reason: str, final_artifact: any}`。watcher 检到文件后 SIGTERM agent。 |
| **失败定义** | exit_code != 0 → 任务标记为 `terminated_abnormally` 或 `agent_reported_failure`，但 raw_ticks.csv 仍参与统计（M1/M3 等指标看部分序列） |
| **并发** | F.0 阶段强制 `--max-parallel 1`（避免 ollama / civitasos backend 并发干扰指标）；F.1 后再放开 |
| **重入** | 同 run_id 二次运行 → 自动归档为 `runs/{run_id}.archived-{ts}/` 后重新建目录 |
| **快照** | 启动时 `git -C civitasos-runtime rev-parse HEAD` + `pip freeze` + manifest.yaml 拷贝，写入 runs/{run_id}/ |
| **metric 名对齐** | aggregator 启动时校准所有 task 的 `metrics_targeted` 代号必须在 `manifest.allowed_metric_codes` 中，且与 final_metrics CSV 列名严格对应；不一致则启动时 fail-fast |

---

## briefing JSON Schema（agent 端契约）

```json
{
  "schema_version": "1.0",
  "run_id": "baseline-20260418-153022-a3f2",
  "task_id": "R01_happy_01",
  "category_id": "R01",
  "targets_disease": "R",
  "telos": "<task.telos 原文>",
  "briefing": "<task.briefing 原文>",
  "max_ticks": 50,
  "tools_allowed": ["text.translate", "text.read"],
  "fixtures_dir": "/abs/path/to/runs/.../tasks/R01_happy_01/fixtures",
  "success_criteria": [...],            // agent 不应直接读，但 logger 会落盘
  "expected_failure_mode": "..."
}
```

---

## summary.json Schema

```json
{
  "run_id": "baseline-20260418-153022-a3f2",
  "started_at": "2026-04-18T15:30:22Z",
  "finished_at": "2026-04-18T16:42:11Z",
  "manifest_path": "benchmarks/v1/manifest.yaml",
  "manifest_sha256": "...",
  "runtime_git_rev": "deb1329",
  "agent_config_sha256": "...",
  "wall_clock_per_tick_s": 60,
  "tasks_total": 60,
  "tasks_completed": 58,
  "tasks_terminated_abnormally": 2,
  "tasks": [
    {
      "task_id": "R01_happy_01",
      "exit_code": 0,
      "tick_count": 12,
      "wall_clock_ms": 84321,
      "raw_csv_rows": 12,
      "agent_self_reported_success": true,    // v1.1 新增；M1 计算依赖
      "sentinel_kind": "done",                 // done / failed / give_up / null
      "sentinel_reason": "all criteria met"   // 来自 sentinel.json.reason
    }
  ]
}
```

---

## 测试覆盖（最低门槛）

- `test_task_loader.py`: manifest 校验，包含未知字段、缺失必需字段、引用不存在 fixture、`metrics_targeted` 不在 `allowed_metric_codes` 四种异常路径
- `test_briefing_renderer.py`: 给定 task → 输出 briefing JSON 严格符合 schema
- `test_orchestrator_state_machine.py`: 用 fake agent（直接退出 / 死循环 / 超时 / 写 done sentinel / 写 failed sentinel / 写 give_up sentinel）覆盖 6 种 exit_code 分支
- `test_aggregator_smoke.py`: 给一个最小 runs/ 目录跑通聚合，输出 final_metrics.csv 列齐全；验证 metric 代号不一致时 fail-fast

---

## F.0.c 通过标准（roadmap 引用）

- ✅ `run_baseline.sh` 能在干净环境一键跑通 manifest 中的 3 个示例任务（不要求 60 个，全量在 F.1）
- ✅ 输出符合上述目录结构 + summary.json/raw_ticks.csv schema
- ✅ 异常 task 不阻塞其他 task；exit_code 真实反映原因（无掩盖）
- ✅ 单元测试覆盖率 ≥ 75%（test 列表 4 项全过）
- ✅ snapshot 三件套（manifest / agent_config / runtime）齐全且可复现

---

## 与 F.0.a / F.0.b 的依赖关系

```
F.0.b (manifest.yaml)  ──┐
                          ├──> task_loader / briefing_renderer
                          │
F.0.a (CollectorAdapter)─┼──> agent.py 注入 + raw_ticks.csv
                          │
F.0.a (computers/)       ─┴──> aggregator → final_metrics.csv
```

F.0.c 不引入新的指标定义，只负责"让 agent 在受控环境跑 task + 让 collector 写出数据 + 触发聚合"。

---

## 不在 F.0.c 范围（避免抢跑）

- ❌ LLM-as-judge 评分（H.1）
- ❌ 自动告警 / 阈值（F.1 的 evaluator 之后）
- ❌ 多 agent 并行（J 阶段）
- ❌ testnet 部署 civitasos backend（这是 I.1 prerequisite，F.0.c 假设 backend 已在 localhost:8099 跑着）
