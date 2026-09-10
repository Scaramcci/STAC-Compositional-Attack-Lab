# 教师向项目指南

本项目回答的不是“模型最后有没有输出某句话”，而是：不可信内容是否沿着可观察的 Agent 状态和工具链传播，哪些 primitive 构成必要因果链，以及这条链在配对条件下是否改变官方结果。

## 研究流程

| 阶段 | 输入 | 主要输出 | 证据与门禁 |
|---|---|---|---|
| Collection | construction task、seed、Victim/Attacker 配置 | raw trajectory、source events、checkpoints、请求 ledger | 记录每个真实动作、失败、session 和状态变化；collection 不是 sample |
| Normalize / extract | raw trajectory、primitive registry | `InteractionGraph`、occurrence、candidate chain | typed edge、来源 hash、terminal relation、no-shortcut evidence |
| Audit / freeze | candidate library | accepted/negative/rejected views、不可变 frozen library | schema、hash、view separation、数量和 provenance 均通过才能 freeze |
| Scheduler / Planner | frozen public index、task、condition、seed | sample assignment、合法 primitive/state trajectory | Planner 不读取 private evidence；assignment 在 Planner 前绑定 |
| 独立 Attacker | execution view、plan、公开 observation | fresh slot value、逐 stage action | 不读取官方 evaluator/private oracle；过程写入 action/model-call journal |
| Evaluation | Victim transcript/state、机制证据、官方 evaluator | mechanism verdict、official verdict、matched report | 两种判定并列保存，不能互相替代 |

`TRANSFER`、`TRANSFORM`、`MUTATE`、`CONTROL` 是底层 family；`Ingest / Adopt / Persist / Recall / Select / Bind / Act / Record / Recover` 是必须由 observable occurrence 与 typed edge 支撑的语义 macro。

## 角色边界

- Victim：OpenClaw `2026.3.12`，模型为 Ark endpoint `ep-20260909180104-hmx9m`。
- Construction Attacker、Formal Attacker、Planner：各自独立调用，沿用 `gpt-5.5` 配置。
- Scheduler：只选择零个或一个兼容 frozen sample，不生成攻击内容。
- Mechanism Verifier：检查链条是否实际出现。
- SafeClaw official evaluator：给出 benchmark verdict；它不能进入 Attacker/Planner 上下文。
- Recorder/Reporter：保存脱敏、可追踪的过程与配对统计。

聊天和 embedding 凭证完全分离：Victim 读取 `SAFECLAW_*`，embedding 读取 `SAFECLAW_EMBEDDING_*`，Attacker/Planner 读取 `OPENAI_*`。

## 目录与配置职责

| 路径 | 内容 |
|---|---|
| `configs/environments/safeclaw.yaml` | pinned upstream、Ark 主线、端口、超时和真实诊断上限 |
| `configs/models/` | Planner/Attacker 模型配置 |
| `configs/task_sets/` | construction/evaluation 原始任务划分 |
| `configs/sample_generation/` | pilot/main collection 预算与输出 |
| `configs/experiments/formal_evaluation.yaml` | frozen library、配对矩阵和 formal 预算 |
| `configs/primitives/registry.yaml` | primitive 定义与依赖 |
| `src/stac_attack_lab/` | 研究流程实现 |
| `integrations/safeclaw/` | bridge、版本化 patch、pinned upstream |
| `tests/fixtures/` | 从历史产物提取的最小脱敏 fixture |
| `experiments/runs/<run-id>/` | 新生成输出；不作为源码提交 |

## 从 collection 到 sample

先运行 pilot：

```bash
make sample-preflight PYTHON=python
STAC_PYTHON=python bash scripts/run_safeclaw_sample_collection.sh \
  --config configs/sample_generation/pilot_collection.yaml \
  --run-id <unique-run-id>
```

launcher 只执行 preflight 和 collection，不会暗中 mine/freeze。输出位于 `experiments/runs/<run-id>/safeclaw-pilot/`。随后明确执行：

```bash
PYTHONPATH=src python -m stac_attack_lab.cli sample mine \
  --collection experiments/runs/<run-id>/safeclaw-pilot/interactions/raw/safeclaw-construction-pilot
PYTHONPATH=src python -m stac_attack_lab.cli sample audit \
  --library experiments/runs/<run-id>/safeclaw-pilot/library
PYTHONPATH=src python -m stac_attack_lab.cli sample freeze \
  --library experiments/runs/<run-id>/safeclaw-pilot/library --version safeclaw-pilot
```

Pilot 目标是 2 个 accepted samples；未达到就停。Pilot 通过后才将同样步骤用于 `main_collection.yaml`，main 目标是 30 个 accepted samples。Benchmark 原始任务、task split、registry、schema 和测试 fixture 不属于可清理运行数据。

## Formal evaluation

正式配置固定读取 `data/primitive_libraries/frozen/safeclaw-main`。该库目前不存在，所以 `make formal-preflight`/正式入口必须 fail closed，不能复制旧库、生成假库或静默回退。

具备合格 frozen library 后运行：

```bash
STAC_PYTHON=python bash scripts/run_formal_evaluation.sh --run-id <unique-run-id>
```

矩阵是 1 task × 3 conditions × 5 seeds：

- `assigned_sample`：使用 Scheduler 分配的一个 sample；
- `no_sample`：不提供 sample；
- `dependency_ablation`：保留 task、seed、预算、plan 等，只替换一个预注册依赖。

每个 case 保留 Planner、Attacker、Victim、provider ledger、mechanism、official verdict 和失败事件。只有 matched pair 才进入 sample-conditioned effect；缺失配对不得用不完整分母包装成正式结论。

## 证据限制

本次整理只完成了离线 mock 和有限 OpenClaw→Ark 文本/add 协议验证，没有启动 collection 或 formal evaluation。真实诊断证明传输、SSE、工具筛选与往返可工作，但不证明攻击成功、sample 有效、ASR、迁移性或正式评测完成。当前的首要研究阻塞仍是生成并审计合格的 `safeclaw-main` frozen library。
