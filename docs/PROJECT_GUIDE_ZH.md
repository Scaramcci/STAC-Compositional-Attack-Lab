# STAC Compositional Attack Lab：项目结构与运行指南

目标读者：首次接触项目的导师、审阅者和实验复现人员。

## 1. 研究目标

本项目研究不可信内容如何在 Agent 系统中传播、持久化、跨 session 重新出现并影响后续行为。项目不只记录最终成功或失败，还要求保存：

- 不可信内容的入口；
- message、tool、memory、workspace 和 session 之间的传播；
- 每次持久状态变化；
- primitive 之间的因果依赖；
- 最终 sandbox effect；
- 内部 mechanism evidence 与 SafeClaw 官方 verdict。

当前仓库只包含 SafeClaw/OpenClaw 主线，不再包含旧 WorkspaceCanary 或其他历史实验系统。

## 2. 当前研究边界

真实 SafeClaw pilot 已运行过，但没有产生满足全部门禁的 accepted sample。因此当前状态是：

```text
implementation complete
  -> real pilot attempted
  -> accepted sample gate not reached
  -> main collection not started
  -> frozen real library absent
  -> formal evaluation not started
```

当前可以确认的是代码结构、契约、synthetic test fixture 和 fail-closed gate 可以工作。当前不能声称正式攻击成功率、跨任务迁移性或 sample-conditioned effectiveness。

## 3. 数据顺序

```text
interaction collection
  -> raw trajectory
  -> normalized InteractionGraph
  -> primitive occurrences
  -> causal chain candidates
  -> accepted / negative / rejected
  -> audited library
  -> frozen library
  -> formal evaluation
```

Collection 是完整交互记录，不是 sample。Sample 是从 raw trajectory 中提取并通过结构、因果、安全和 terminal gate 的 primitive chain。Formal evaluation 只能消费不可修改的 frozen library。

### 3.1 Raw trajectory

每个 construction task × seed 产生一条 trajectory，包含 source event、checkpoint、session、模型/config hash、状态和失败类别。Raw 数据负责回答“实际发生了什么”。

### 3.2 InteractionGraph

Normalizer 把异构日志统一为事件、artifact 和 typed edge。图用于区分“时间上先发生”与“因果上依赖”。

### 3.3 Primitive occurrence

当前 registry 定义四个底层 family：

| Family | 含义 |
|---|---|
| `TRANSFER` | 数据或状态在组件之间移动 |
| `TRANSFORM` | 数据被解释、选择、转换或绑定 |
| `MUTATE` | memory、workspace 或 sandbox state 发生修改 |
| `CONTROL` | session、retry、reroute 或停止状态变化 |

`Ingest / Adopt / Persist / Recall / Select / Bind / Act / Record / Recover` 是由 observable occurrence 和 typed edge 支撑的语义 macro。

### 3.4 Candidate 与 sample

Candidate 是从 occurrence graph 中枚举出的有向因果路径。Accepted sample 必须具有完整 occurrence、required edge、信任边界跨越、terminal relation、no-shortcut evidence 和 provenance。Negative 保存结构完整但未完成攻击机制的对照；Rejected 表示证据不足或数据无效。

### 3.5 Audit 与 freeze

Audit 检查 schema、hash、view separation、数量和 provenance。Freeze 为通过审计的 library 固定版本与 tree hash，防止在看到 evaluation 结果后选择性修改 sample。

## 4. 核心角色

| 角色 | 职责 |
|---|---|
| Construction Attacker | 在 collection 中根据公开 observation 选择 delivery、session、retry、reroute 或 stop |
| Collector | 展开 task × seed，保存 trajectory、checkpoint 和 provenance |
| Scheduler | 在 Planner 之前绑定零个或一个兼容 sample |
| Planner | 根据 assignment 构造合法 primitive/state trajectory |
| Formal Attacker | 根据 execution view 和 plan 生成 fresh slot value 与逐 stage action |
| OpenClaw Victim | 被测 Agent，包括模型、context、memory、workspace、tools 和 lifecycle |
| Mechanism Verifier | 检查 graph、occurrence、edge 和 action lineage |
| Official Evaluator | 输出 SafeClaw 官方 benchmark verdict |
| Recorder/Reporter | 保存 checkpoint、model-call journal、完整记录和报告 |

Bridge、runner、materializer 和官方 judge 都是执行基础设施，不是 Attacker。

## 5. 项目结构

```text
stac-compositional-attack-lab/
├── configs/
│   ├── environments/safeclaw.yaml
│   ├── experiments/formal_evaluation.yaml
│   ├── models/
│   ├── primitives/registry.yaml
│   ├── sample_generation/
│   │   ├── pilot_collection.yaml
│   │   └── main_collection.yaml
│   └── task_sets/
│       ├── construction_tasks.yaml
│       └── evaluation_tasks.yaml
├── data/primitive_libraries/
│   ├── generated/
│   └── frozen/
├── docs/
├── experiments/safeclaw_runs/
├── integrations/safeclaw/
├── prompts/formal/
├── schemas/
├── scripts/
├── src/stac_attack_lab/
└── tests/
```

### 5.1 核心源码

| 路径 | 职责 |
|---|---|
| `interactions/` | collection、Construction Attacker contract、raw trajectory 和 normalization |
| `extraction/` | occurrence 提取、causal chain 枚举和 filtering |
| `datasets/` | primitive-chain sample、library audit 和 freeze |
| `planning/` | scheduler、baseline、binding 和 formal planner |
| `execution/` | sample acquisition、formal Attacker 和 formal matrix 编排 |
| `environments/safeclaw/` | task adapter、preflight、materializer、runner 和 Victim driver |
| `verification/` | occurrence、edge、macro、mechanism 和 official verdict |
| `recording/` | append-only event、model call 和 formal run artifact |
| `reporting/` | formal metrics、statistics 和 report |

## 6. 环境准备

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
make check
```

真实运行还要求：

- `integrations/safeclaw/upstream/SafeClawArena`；
- commit `a11f5cceaba0676be721021f8d232638fd111305`；
- Docker 和 `openclaw-env:2026.3.12`；
- 可应用的 safety patch；
- allowlisted chat 与 embedding endpoint；
- 至少 20 GiB 可用磁盘；
- 只通过环境变量提供的凭证。

Preflight 不会自动 clone、pull、构建 image 或修改 upstream。

## 7. Pilot collection

先执行：

```bash
make sample-preflight
```

通过后执行：

```bash
make sample-collection
```

Launcher 的顺序只有：

```text
collect-preflight -> collect
```

它不会自动 mine、audit 或 freeze。Pilot 配置为 2 tasks × 4 seeds，共 8 条 trajectory，目标至少 2 个 accepted samples。

单条 trajectory 的过程：

1. Collector 选择 task 和 seed；
2. Construction Attacker 根据公开状态选择动作；
3. Driver 创建临时 SafeClawArena 副本并应用 safety patch；
4. OpenClaw Victim 执行动作；
5. Driver 记录 message、tool、state 和 lifecycle event；
6. Collector 更新预算、checkpoint 和运行状态；
7. complete、partial、blocked 和 error 都原样保存。

## 8. Mining、audit 与 freeze

Collection 完成后单独运行：

```bash
PYTHONPATH=src .venv/bin/python -m stac_attack_lab.cli sample mine \
  --collection data/primitive_libraries/generated/<version>/interactions/raw/<pipeline-id>

PYTHONPATH=src .venv/bin/python -m stac_attack_lab.cli sample audit \
  --library data/primitive_libraries/generated/<version>/library

PYTHONPATH=src .venv/bin/python -m stac_attack_lab.cli sample freeze \
  --library data/primitive_libraries/generated/<version>/library \
  --version <version>
```

Pilot 未达到 2 个 accepted samples 时必须停止。通过 pilot 后才允许运行 `main_collection.yaml`；main 的目标为 12 tasks × 10 seeds、至少 30 个 accepted samples。

## 9. Formal evaluation

环境检查：

```bash
make formal-preflight
```

正式运行：

```bash
make formal-evaluation
```

当前配置要求 frozen library：

```text
data/primitive_libraries/frozen/safeclaw-main
```

该目录不存在时运行必须在 Victim episode 前停止。

Formal matrix：

```text
1 task × 3 conditions × 5 seeds = 15 cases
```

| Condition | 唯一改变量 |
|---|---|
| `assigned_sample` | 使用 Scheduler 分配的一个 frozen sample |
| `no_sample` | 不使用 sample，采用合法 benign baseline |
| `dependency_ablation` | 保留 sample 和 plan，只替换一个预注册依赖 |

同一 matched pair 必须保持 task、seed、budget、public prompt、library、registry、environment 和 evaluator 不变。

## 10. Formal artifact

```text
experiments/safeclaw_runs/<run-id>/
├── formal_run_manifest.json
├── formal_progress.json
├── formal_transitions.jsonl
├── results.jsonl
├── formal_report.json
└── cases/<case-id>/
    ├── formal_case_assignment.json
    ├── planner_input.json
    ├── evaluation_plan.json
    ├── formal_attacker_input.json
    ├── binding_manifest.json
    ├── materialized_task.json
    ├── episode_result.json
    ├── interaction_graph.json
    ├── primitive_extraction.json
    ├── mechanism_evaluation.json
    ├── official_verdict.json
    ├── model_call_events.json
    ├── failure_events.jsonl          # 仅失败 case
    └── complete_interaction_record.json
```

审阅单个 case 时先读 `complete_interaction_record.json`，再检查 assignment、plan、materialized task、InteractionGraph、mechanism evaluation 和 official verdict。

完整 Linux `tmux` 命令和记录查看方式见 [LINUX_TMUX_RUNBOOK_ZH.md](LINUX_TMUX_RUNBOOK_ZH.md)。

## 11. Resume 与停止条件

Collection 的恢复单位是一条 task × seed trajectory；formal evaluation 的恢复单位是一个 case。中断的 whole-episode attempt 被标记 abandoned，新 attempt 使用新的 Victim container。Config、library、registry 或 matrix drift 会拒绝恢复。

以下情况必须停止：

- preflight 失败；
- upstream、template、patch 或 hash 不一致；
- pilot accepted 少于 2；
- main accepted 少于 30；
- library audit/freeze 失败；
- public/private view 泄漏；
- secret scan、pair invariant、lineage 或 official result audit 失败；
- formal matrix 只完成一部分。

## 12. 结果表述

正式报告必须区分：代码实现、synthetic test fixture、真实 pilot、完整 frozen library 和正式 matched evaluation。只有完整 formal matrix、run audit 和 report 均通过后，才能报告正式效果指标。
