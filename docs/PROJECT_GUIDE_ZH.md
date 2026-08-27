# STAC Compositional Attack Lab：项目结构与运行指南

更新日期：2026-08-27  
目标读者：首次接触本项目的导师、审阅者和实验复现人员

## 1. 项目概览

STAC Compositional Attack Lab 是一个研究 Agent 组合攻击传播过程的实验框架。与只统计最终 attack success rate 的方法不同，本项目把攻击建模为一条可观察、可验证的组件交互链，并记录：

- 不可信内容从何处进入；
- 内容在 Agent、tool、workspace、memory 和 session 之间如何传播；
- 哪一次状态变化造成持久化；
- 何时发生跨 turn 或跨 session 召回；
- 哪条依赖使最终 sandbox effect 成为可能；
- 官方 benchmark verdict 与内部 mechanism evidence 是否一致。

项目只面向授权的 SafeClaw/OpenClaw 隔离 benchmark、synthetic service 和无价值 canary。凭证仅用于连接实验模型服务，不得进入 prompt、配置、运行产物或研究数据。

## 2. 当前研究边界

仓库包含三类不同成熟度的内容，必须分开理解。

| 路径 | 用途 | 当前状态 | 是否属于 formal-v2 研究结果 |
|---|---|---|---|
| Legacy STAC offline/online | 历史本地 WorkspaceCanary 攻击链 | 30 个冻结样本，30 个 evaluation episode | 否；仅证明历史链路可运行 |
| Formal-v2 synthetic regression | 测试 primitive miner、library 和 formal executor | 1 accepted synthetic、1 negative | 否；只用于确定性回归 |
| Real SafeClaw formal-v2 | 真实 collection、冻结 primitive library、matched evaluation | Gate A blocked，main/formal 未启动 | 尚无结果 |

2026-08 服务器进度记录显示：

- 原始 pilot：4 trajectories，`accepted=0/2`；
- recovery pilot：8 trajectories，`accepted=0/2`；
- main collection：未启动；
- `formal-v3-safeclaw-20260824`：未生成；
- 15-case formal evaluation：未启动。

这些服务器生成 artifact 没有同步到当前本地 checkout。本地可以检查代码和进度记录，但不能重新计算服务器 collection tree hash 或重审其 raw trajectory。

## 3. 最核心的数据顺序

项目中最容易混淆的是 `collection` 和 `sample`。

```text
interaction collection
  -> raw trajectory
  -> normalized InteractionGraph
  -> primitive occurrences
  -> causal chain candidates
  -> accepted / negative / rejected
  -> audited sample library
  -> immutable frozen sample
  -> formal evaluation
```

因此：

- Collection 是收集完整交互轨迹；
- Candidate 是从轨迹中枚举出的因果链候选；
- Sample 是通过结构、因果、安全和 terminal gate 的 candidate；
- Frozen library 是通过整体审计且不可覆盖的 sample 集合；
- Formal evaluation 只能读取 frozen library。

CLI 中的 `sample collect` 表示“sample acquisition 流水线的 collection 阶段”，不是已经产生 sample。

## 4. 关键术语

### 4.1 Raw interaction trajectory

一次 construction task × seed 的完整尝试，包含 source event、checkpoint、session id、模型和配置 hash、collection status 与 failure category。

### 4.2 InteractionGraph

来源无关的统一交互图。节点和边描述 message、tool、state read/write、lifecycle、artifact lineage 和 causal dependency。

### 4.3 Primitive occurrence

从可观察 event 中抽取的一次底层状态转换。formal-v2 有四个互斥 family：

| Family | 说明 |
|---|---|
| `TRANSFER` | 数据或状态在组件之间移动 |
| `TRANSFORM` | 输入被解释、选择、绑定或转换 |
| `MUTATE` | workspace、memory 或 sandbox state 被修改 |
| `CONTROL` | session、retry、reroute 或停止状态变化 |

### 4.4 Semantic macro

`Ingest / Adopt / Persist / Recall / Select / Bind / Act / Record / Recover` 是由多个 core occurrence 和 typed edge 支撑的高层解释，不是额外的底层 primitive enum。

### 4.5 Primitive chain sample

一条通过 deterministic filter gate 的因果链。Sample 同时具有三种物理隔离视图：

| 视图 | 使用者 | 内容 |
|---|---|---|
| Planner public view | Scheduler、Planner | sanitized 结构、能力、预算和公开状态类型 |
| Execution binding view | Formal Attacker、materializer | 合法 slot、surface、retry/reroute 和绑定约束 |
| Private evidence view | Auditor、verifier | occurrence、event、artifact、checkpoint 和 construction provenance |

### 4.6 Formal case 与 pair

Case 是一个 `task × condition × seed`。Pair 是同一 task 和 seed 下的匹配条件组；pair 内必须保持 public prompt、budget、library、registry、environment 和 official evaluator 不变。

## 5. 整理后的项目结构

```text
stac-compositional-attack-lab/
├── README.md
├── SECURITY.md
├── Makefile
├── pyproject.toml
├── configs/
│   ├── README.md
│   ├── environments/
│   ├── experiments/
│   ├── models/
│   ├── primitives/
│   ├── sample_generation/
│   └── task_sets/
├── data/
│   ├── README.md
│   ├── seeds/
│   ├── generated/
│   ├── frozen/
│   ├── interactions/
│   ├── primitive_candidates/
│   ├── primitive_libraries/
│   └── provenance/
├── docs/
│   ├── README.md
│   ├── PROJECT_GUIDE_ZH.md
│   ├── EXPERIMENT_PROTOCOL.md
│   ├── PROMPTS.md
│   ├── DECISIONS.md
│   └── archive/
├── experiments/
│   ├── README.md
│   ├── runs/
│   └── safeclaw_runs/
├── integrations/
│   ├── agentdojo/
│   └── safeclaw/
├── prompts/
│   ├── formal/
│   ├── judges/
│   ├── offline/
│   └── runtime/
├── schemas/
├── scripts/
│   ├── README.md
│   ├── run_safeclaw_sample_collection.sh
│   ├── run_formal_evaluation.sh
│   └── legacy/
├── src/stac_attack_lab/
└── tests/
```

整理原则：

1. 根目录只保留项目入口和构建文件；
2. 当前文档位于 `docs/` 顶层；
3. 阶段性计划、旧状态和旧命令原样归档；
4. 当前 v2 launcher 位于 `scripts/`，旧 wrapper 位于 `scripts/legacy/`；
5. v1 配置保留稳定路径以维护 provenance 和测试，但通过 `configs/README.md` 明确分类；
6. 冻结数据、历史 evidence 和 schema 不因目录整理而改写。

## 6. 配置层

### 6.1 当前 formal-v2 配置

| 配置 | 路径 | 职责 |
|---|---|---|
| Pilot collection | `configs/sample_generation/safeclaw_adversarial_v2_pilot.yaml` | 2 tasks × 2 seeds，target 2 |
| Recovery pilot | `configs/sample_generation/safeclaw_adversarial_v2_recovery_pilot.yaml` | 已执行的 2 tasks × 4 seeds 恢复版本 |
| Main collection | `configs/sample_generation/safeclaw_adversarial_v2.yaml` | 12 tasks × 10 seeds，target 30 |
| Construction task set | `configs/task_sets/safeclaw_construction_v2.yaml` | 训练 split、template hash、公开能力和 surface |
| Formal experiment | `configs/experiments/safeclaw_formal_v2.yaml` | 15-case matrix、budget、model 和 frozen library |
| Formal task set | `configs/task_sets/safeclaw_compositional_v2.yaml` | PSE 2.1 task、pair、slot 和 baseline |
| Environment | `configs/environments/safeclaw_openclaw_v2.yaml` | upstream、Docker、model 与 embedding contract |
| Primitive registry | `configs/primitives/formal_v1.yaml` | 当前 core primitive 和 macro registry |
| Formal Attacker | `configs/models/formal_attacker.yaml` | GPT-compatible Attacker 配置 |
| Optional Planner | `configs/models/formal_planner.yaml` | 仅 LLM Planner condition 使用 |

Pilot、rerun 和 recovery 都是版本化 execution record。已经存在输出时，不应修改 config 后续跑同一路径；新尝试必须使用新 config 和新 `library_version`。

### 6.2 Legacy 配置

`mvp_*`、`stac_sample_build_*`、Huihui evaluation、SafeClaw v1 environment/task/formal config 用于历史复现或 regression。它们不是当前 formal-v2 默认入口。

## 7. 核心源码分层

### 7.1 Contract 与配置

- `contracts.py`：legacy task、graph、event、artifact 和 result 契约；
- `config.py`：实验与模型配置；
- `schema_registry.py`：可生成的 JSON Schema 注册；
- `env_loader.py`：读取本地 `.env`，不打印凭证值。

### 7.2 Interaction collection

- `interactions/collector.py`：展开 task × seed、resume、raw trajectory 落盘；
- `interactions/construction.py`：Construction Attacker observation/action contract；
- `interactions/safeclaw_collection.py`：Attacker 与完整 SafeClaw Victim 的自适应闭环；
- `interactions/normalizer.py`：来源事件标准化。

### 7.3 Primitive 与 sample acquisition

- `primitives/`：core family、subtype 和 macro registry；
- `extraction/occurrences.py`：event -> occurrence；
- `extraction/chains.py`：occurrence graph -> causal path candidate；
- `extraction/filtering.py`：结构、split、terminal、shortcut 和因果 gate；
- `datasets/primitive_chain.py`：candidate/sample/view/manifest contract；
- `execution/sample_generation.py`：collect、mine、audit、freeze 总编排。

### 7.4 Formal planning 与 execution

- `planning/formal_scheduler.py`：预分配零个或一个 sample；
- `planning/formal_baselines.py`：fixed、no-sample、dependency ablation 和 trajectory；
- `planning/formal_llm.py`：可选 LLM Planner；
- `execution/formal_attacker.py`：独立 Formal Attacker；
- `execution/formal_action_loop.py`：逐 stage Attacker/Victim loop；
- `execution/formal_interactive_episode.py`：whole-episode attempt 和 resume；
- `execution/safeclaw_formal.py`：formal matrix 总编排。

### 7.5 Environment、verification 和 recording

- `environments/safeclaw/preflight.py`：SafeClaw 环境门禁；
- `environments/safeclaw/materializer.py`：allowlisted task materialization；
- `environments/safeclaw/interactive_driver.py`：OpenClaw Victim bridge；
- `verification/safeclaw_official.py`：官方 verdict；
- `verification/formal_aggregate.py`：内部 mechanism verdict；
- `recording/formal_run_recorder.py`：artifact、checkpoint、secret scan 和 audit；
- `recording/model_calls.py`：可观察 model-call journal；
- `reporting/formal_report.py`：正式报告。

## 8. 角色与权限边界

### 8.1 Construction Attacker

发生在 sample collection 阶段。它只看到 construction task、公开组件清单、公开 transcript/status 和剩余预算。输出动作类型包括：

- `deliver_message`
- `start_new_session`
- `retry`
- `reroute`
- `stop`

它不看 private oracle，也不决定 candidate 是否 accepted。

### 8.2 Collector 与 Construction Victim

Collector 负责 matrix、resume、failure isolation 和写盘。Construction Victim 是完整 SafeClaw/OpenClaw Agent 环境。Driver 将 agent response、tool call、memory/workspace write、later-session read 和 lifecycle 转为结构化 source event。

### 8.3 Scheduler 与 Planner

Scheduler 在任何 Planner/model call 之前完成 sample compatibility 检查，并绑定零个或恰好一个 sample。Planner 只能基于这个 assignment 构造 trajectory，不能查看 private evidence，也不能更换 sample。

当前 `assigned_sample` 和 `dependency_ablation` 使用 deterministic `FixedSamplePlanner`，`no_sample` 使用 `NoSamplePlanner`。虽然仓库存在 LLM Planner 配置，但当前三种 condition 不会调用它。

### 8.4 Formal Attacker

Formal Attacker 接收：

- public task；
- benchmark public prompt；
- 一个 sample 的 execution view；
- validated plan；
- prior public observations 和剩余预算。

它先生成 setup realization 和 fresh slot values，再按 trajectory 逐 stage 产生 Victim-visible action。它不能读取官方 success/safe condition、credential、private oracle 或完整 private library。

### 8.5 Materializer、Victim 与 Evaluator

Materializer 只修改 task set 预注册的 JSON pointer。OpenClaw Victim 是被测系统。Mechanism Verifier 根据 observed graph 判断 sample 机制是否出现；Official Evaluator 给出 benchmark verdict。二者互相补充，但都不能修改环境或伪造执行事实。

`judge.py`、runner、bridge 和 materializer 都不是 Attacker。

## 9. 从零开始的环境准备

### 9.1 Python 质量环境

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
make check
make schemas
```

`make check` 包含 Ruff、mypy 和 pytest。当前代码要求 Python 3.11+。

### 9.2 SafeClaw external checkout

真实路径必须存在：

```text
integrations/safeclaw/upstream/SafeClawArena
```

并满足：

- commit 为 `a11f5cceaba0676be721021f8d232638fd111305`；
- `scripts/judge.py`、`scripts/reset_env.sh` 和 `Dockerfile` 存在；
- safety patch 可在 ephemeral copy 上应用；
- upstream 本身保持 clean，不直接修改。

仓库不会自动 clone 或更新 upstream。

### 9.3 Docker 与模型

要求：

- Docker daemon；
- image `openclaw-env:2026.3.12`；
- `SAFECLAW_MODEL`；
- Victim/Attacker 的 OpenAI-compatible endpoint/key；
- `SAFECLAW_EMBEDDING_MODEL`；
- 独立 embedding endpoint/key；
- host 和 Docker 均通过真实 `/v1/embeddings` probe；
- 至少 20 GiB free disk。

变量名可参考 `.env.example`。密钥值不得写入 Git、Markdown、tmux 命令或运行报告。

## 10. Collection preflight

对一个明确授权、尚未使用的版本化 config 运行：

```bash
make sample-preflight \
  CONFIG=configs/sample_generation/<authorized-version>.yaml
```

等价 CLI：

```bash
PYTHONPATH=src .venv/bin/python -m stac_attack_lab.cli \
  sample collect-preflight \
  --config configs/sample_generation/<authorized-version>.yaml
```

Preflight 检查：

1. adapter 是 `safeclaw_adaptive_construction`；
2. execution gate 已显式开启；
3. formal test split 不可作为 construction source；
4. construction task 与 formal task 不重叠；
5. safety constraint 齐全；
6. task/template/registry/prompt/model/bridge/patch 路径存在；
7. task hash、upstream commit 和 patch applicability 正确；
8. Attacker 不是 fake model；
9. Victim 和 embedding 环境变量完整；
10. Docker、image、disk 和 resumable output 状态有效。

Preflight 不启动 Attacker、Victim 或 Docker episode。它只检查 embedding selector/endpoint/key 是否配置，不替代真实 embedding probe。

## 11. Interaction collection

```bash
make sample-collection \
  CONFIG=configs/sample_generation/<authorized-version>.yaml
```

长任务建议使用 tmux：

```bash
tmux new-session -d -s stac-collection \
  "cd '<project-root>' && exec bash scripts/run_safeclaw_sample_collection.sh --config configs/sample_generation/<authorized-version>.yaml"
```

Launcher 的实际顺序只有：

```text
collect-preflight -> collect
```

不会自动执行 mine、audit 或 freeze。

### 11.1 单 trajectory 内部过程

1. Collector 选定 task 和 seed；
2. Construction Attacker 创建不含 private oracle 的 manifest；
3. Victim driver 创建临时 SafeClawArena copy；
4. safety patch 应用到临时 copy；
5. mode-0600 model config 写入临时目录；
6. Construction Attacker 根据 public observation 给出下一动作；
7. Victim 执行动作，返回 response、tool call 和 state；
8. Driver 生成 source event 和 checkpoint；
9. Collector 更新 session/turn/action/tool/token/event/wall-time budget；
10. `complete / partial / blocked / error` 均原样保存；
11. collection manifest 和 tree hash 固化输入。

### 11.2 Raw 输出

```text
data/primitive_libraries/generated/<library-version>/
└── interactions/raw/<pipeline-id>/
    ├── collection_manifest.json
    ├── collection_stage_manifest.json
    ├── collection_failures.jsonl
    └── trajectories/<trajectory-id>/
        ├── raw_trajectory.json
        ├── source_events.jsonl
        └── checkpoints.jsonl
```

已有 `collection_stage_manifest.json` 时，resume 会验证所有 hash 后直接返回。Config drift、额外/缺失文件、source ref 篡改或 trajectory mismatch 都会 fail closed。

## 12. Deterministic mining

Collection 完成后单独运行：

```bash
PYTHONPATH=src .venv/bin/python -m stac_attack_lab.cli sample mine \
  --collection data/primitive_libraries/generated/<library-version>/interactions/raw/<pipeline-id>
```

Mining 不调用模型，不初始化 Construction Attacker，也不启动 Victim。内部顺序：

```text
validate immutable collection
  -> normalize each trajectory
  -> extract core occurrences
  -> enumerate bounded causal paths
  -> attach semantic macros
  -> filter candidates
  -> build physically separated library views
  -> write mining manifest and output hashes
```

Accepted sample 必须有 observable occurrence、required typed edge、trust-boundary crossing、完整 construction outcome、terminal relation 和 no-shortcut evidence。Partial、blocked、error、缺 terminal 或缺关键依赖的候选进入 negative/rejected。

## 13. Library audit 与 freeze

```bash
PYTHONPATH=src .venv/bin/python -m stac_attack_lab.cli sample audit \
  --library data/primitive_libraries/generated/<library-version>/library
```

Audit 检查 schema、hash、manifest、view separation、accepted/negative/filter consistency 和 target count。

只有 passing audit 才能 freeze：

```bash
PYTHONPATH=src .venv/bin/python -m stac_attack_lab.cli sample freeze \
  --library data/primitive_libraries/generated/<library-version>/library \
  --version <new-frozen-version>
```

Freeze 要求 audit report 与当前 library 完全一致。缺失、失败或 stale audit 都会拒绝。Frozen version 不能覆盖。

当前 main config 的门槛是：

```text
12 tasks × 10 seeds = 120 trajectories
accepted samples >= 30
```

由于 Gate A pilot 尚未通过，当前不允许启动 main collection 或生成正式 library。

## 14. Formal preflight

```bash
make formal-preflight
```

等价 launcher：

```bash
bash scripts/run_formal_evaluation.sh --preflight-only
```

Launcher 依次运行：

1. `safeclaw pse-smoke`：加载 pinned 官方 evaluator，验证 PSE scoring contract；
2. `safeclaw preflight`：检查 upstream、commit、required file、patch、model env、Docker、image 和 disk。

进入 formal orchestrator 后还会检查：

- `execution_enabled=true`；
- task set 为 `ready`；
- config 与 environment target contract 一致；
- frozen library 存在且 `manifest.frozen=true`；
- library registry hash 与当前 registry 一致；
- task template hash 和 upstream commit 一致。

## 15. Formal evaluation matrix

当前 config：

```text
1 task × 3 conditions × 5 seeds = 15 cases
```

| Condition | 改变量 | 保持不变的内容 |
|---|---|---|
| `assigned_sample` | 使用一个 scheduler-assigned sample | task、seed、budget、environment、official evaluator |
| `no_sample` | 不选择 sample，使用合法 benign slot value | 同上 |
| `dependency_ablation` | 只替换一个 preregistered sample-derived slot | 同一 sample、plan、pair 和其余 slot |

正式运行：

```bash
make formal-evaluation
```

或显式指定：

```bash
bash scripts/run_formal_evaluation.sh \
  --run-id safeclaw-formal-v2-main \
  --config configs/experiments/safeclaw_formal_v2.yaml \
  --preflight configs/environments/safeclaw_openclaw_v2.yaml
```

当前 frozen library 不存在，因此命令应在 Victim episode 之前 fail closed。

## 16. 单个 formal case 如何运行

1. 读取 task template，校验 hash；
2. 生成 public task 和完整 benchmark public prompt；
3. Scheduler 做 compatibility filtering 并绑定零个或一个 sample；
4. 检查 pair invariants；
5. Planner 生成 validated primitive/state trajectory；
6. Sample condition 下，Formal Attacker 生成 setup realization；
7. dependency ablation 只替换一个允许的 slot；
8. Materializer 生成 binding manifest 和 materialized task；
9. Formal Attacker 逐 stage 生成 action；
10. OpenClaw Victim 返回 public observation；
11. Action loop 验证 action/observation/event/state lineage 和预算；
12. 完成 whole episode 后读取 sanitized SafeClaw result；
13. Official Evaluator 解析 benchmark verdict；
14. Normalizer 重建 InteractionGraph；
15. Primitive extractor 重建 occurrence；
16. Mechanism Verifier 对照 selected sample 检查 node/edge/macro；
17. Recorder 写入 complete interaction record 和 formal result；
18. Run audit 和 report 从持久化 artifact 重建。

## 17. Formal 输出结构

```text
experiments/safeclaw_runs/<run-id>/
├── formal_run_manifest.json
├── formal_progress.json
├── formal_transitions.jsonl
├── results.jsonl
├── formal_report.json
├── tmux-run.log
├── cases/<case-id>/
│   ├── formal_case_assignment.json
│   ├── planner_input.json
│   ├── evaluation_plan.json
│   ├── formal_attacker_input.json
│   ├── formal_attack_setup.json
│   ├── binding_manifest.json
│   ├── materialized_task.json
│   ├── episode_result.json
│   ├── interaction_graph.json
│   ├── primitive_extraction.json
│   ├── mechanism_evaluation.json
│   ├── official_verdict.json
│   ├── model_call_events.json
│   ├── formal_result.json
│   └── complete_interaction_record.json
└── runner/<case-id>/
    ├── attempt ledger
    ├── attempt-*.log
    ├── model/action journal
    └── sanitized result
```

`complete_interaction_record.json` 是审阅单个 case 的最佳入口，它连接 assignment、plan、sample、Attacker、materialized task、Victim sessions、graph、primitive evidence、official verdict 和 accounting。

## 18. Resume 与失败处理

### Collection

- durable unit：一个 task × seed trajectory；
- 已完成 trajectory 校验后跳过；
- failure 以 class/category 记录；
- immutable stage manifest 禁止在完成后追加或改写 raw tree。

### Formal evaluation

- durable unit：一个 case；
- whole-episode attempt 独立；
- crash attempt 标记 abandoned；
- 新 attempt 使用新 Victim container 和不重叠 action id；
- `--resume` 跳过已经 `recorded` 的 case；
- config/library/registry/case matrix drift 会拒绝恢复。

### 停止条件

以下任一条件出现都必须停止：

- preflight 不通过；
- upstream、template、patch 或 hash 不一致；
- embedding endpoint 未真实验证；
- pilot accepted 少于 2；
- main accepted 少于 30；
- library audit/freeze 失败；
- public/private view 泄漏；
- secret scan 失败；
- pair invariant、lineage、official result 或 mechanism audit 失败；
- formal matrix 只完成一部分。

## 19. 如何审阅结果

### 审阅 sample library

建议顺序：

1. `library_manifest.json`；
2. `library_audit.json`；
3. `accepted_samples.jsonl`；
4. `planner_public_index.jsonl`；
5. `execution_views.jsonl`；
6. `private_evidence.jsonl`；
7. `filter_decisions.jsonl` 和 negatives。

### 审阅 formal case

建议顺序：

1. `complete_interaction_record.json`；
2. `formal_case_assignment.json`；
3. `evaluation_plan.json`；
4. `materialized_task.json`；
5. `formal_action_loop.json`；
6. `interaction_graph.json`；
7. `mechanism_evaluation.json`；
8. `official_verdict.json`；
9. `formal_result.json`。

### 审阅整体实验

读取 `formal_run_manifest.json`、`formal_progress.json`、`results.jsonl`、run audit 和 `formal_report.json`。不要只看 terminal log 或单个成功案例。

## 20. 当前可以和不可以声称什么

可以声称：

- 组合攻击被建模为 observable typed interaction graph；
- collection、mining、audit、freeze 和 formal execution 已实现为独立 gate；
- Scheduler、Planner、Attacker、Victim、Verifier 和 Official Evaluator 有明确权限边界；
- synthetic regression 和 legacy 30-case 路径已有可复现 artifact；
- real pilot 已执行但未产生 accepted sample。

不可以声称：

- formal-v2 攻击成功率；
- sample-conditioned attack effectiveness；
- 跨任务或跨模型迁移性；
- 30 个真实 SafeClaw primitive samples 已冻结；
- 15-case formal matrix 已完成；
- 已覆盖完整 Agent 攻击面或系统化防御比较。

## 21. 扩展项目时的规则

新增 primitive 时，需要同步增加：

- primitive spec；
- event/graph 映射；
- typed edge 规则；
- deterministic verifier；
- schema；
- unit 和 e2e tests。

新增 environment 时，应实现统一的 reset/snapshot/restore/step 或完整 episode contract，并保证 private oracle 不进入模型 prompt。

新增 condition 时，应 preregister 唯一改变量、pair invariant、sample visibility、model role 和统计方法。存在 model config 不代表该模型在当前 condition 中被实际调用。

新增 collection/recovery 时，应使用新 config、新 seed、新 version 和新 output root，保留旧失败证据。

## 22. 文档与历史材料

当前有效文档：

- `README.md`
- `docs/PROJECT_GUIDE_ZH.md`
- `docs/EXPERIMENT_PROTOCOL.md`
- `docs/PROMPTS.md`
- `docs/DECISIONS.md`
- `SECURITY.md`

历史计划、handoff、命令和状态位于 `docs/archive/`。归档文件用于解释项目演进，不应覆盖当前代码、配置和 gate。

