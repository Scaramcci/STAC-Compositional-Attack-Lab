# STAC Compositional Attack Lab

面向 Agent 系统组合攻击传播、持久化与因果验证的可复现实验框架。

本项目不只判断“攻击是否成功”，还记录攻击如何进入 Agent、经过哪些组件、何时写入持久状态、如何跨 turn/session 被重新激活，以及最终 effect 是否由完整的事件和状态证据支持。项目仅用于授权的 SafeClaw/OpenClaw 隔离 benchmark、synthetic service 和无价值 canary，不面向真实账号、生产系统或公网目标。

## 当前状态

| 部分 | 状态 | 可以得出的结论 |
|---|---|---|
| Legacy STAC offline/online | 已完成 30 个冻结样本和 30 个 evaluation episode | 历史单一组合攻击链与记录基础设施可运行 |
| Formal-v2 synthetic library | 1 个 accepted synthetic sample，1 个 negative | Miner、library、Planner、Attacker、materializer 和 verifier 可做确定性回归 |
| Real SafeClaw pilot | 原 pilot 与 recovery pilot 均为 `accepted=0/2` | Gate A 未通过，不能进入主 collection |
| Main collection | 未启动 | 不存在 30 个真实 accepted primitive samples |
| Formal-v2 evaluation | 未启动 | 不存在 15-case ASR、迁移性或 sample-conditioned 研究结果 |

当前正式实验必须保持 fail closed：不能用 synthetic library 替代真实 library，不能降低 accepted threshold，也不能把 partial matrix 表述为正式结果。

## 研究问题

项目把一次组合攻击表示为带类型的交互图，主要回答：

1. 不可信内容从哪个入口进入 Agent？
2. 内容经过了哪些组件和信任边界？
3. 哪次操作造成持久化、召回、控制流变化或 sandbox effect？
4. 哪条 causal edge 是完整攻击链必需的？
5. 攻击被阻断时，失败发生在哪个 primitive 或依赖上？
6. 官方 benchmark success 与内部 mechanism evidence 是否一致？

formal-v2 使用四个互斥的底层 primitive family：`TRANSFER`、`TRANSFORM`、`MUTATE`、`CONTROL`。`Ingest / Adopt / Persist / Recall / Select / Bind / Act / Record / Recover` 是建立在 observable occurrence 和 typed causal edge 上的语义 macro。

## 系统流程

```text
安全与环境检查
  -> interaction collection
  -> raw trajectory + checkpoints
  -> normalized InteractionGraph
  -> primitive occurrence extraction
  -> causal chain mining and filtering
  -> sample library audit
  -> immutable frozen sample library
  -> Scheduler assigns zero or one sample
  -> Planner builds a validated trajectory
  -> independent Attacker realizes the attack
  -> OpenClaw Victim executes in SafeClaw
  -> mechanism verifier + official evaluator
  -> complete record + formal report
```

这里的 `collection` 发生在 `sample` 之前。Collection 保存完整交互轨迹；sample 是从轨迹中确定性挖掘、审计并冻结的因果 primitive chain。

## 核心角色

| 角色 | 职责 |
|---|---|
| Construction Attacker | 在 collection 阶段根据公开 observation 生成 delivery、session、retry 或 reroute 动作 |
| Collector | 展开 task × seed matrix，保存 raw trajectory、event、checkpoint 和 provenance |
| Scheduler | 根据 public task、能力和预算，在 Planner 之前绑定零个或一个 sample |
| Planner | 基于单个已分配 sample 构造合法 primitive/state trajectory |
| Formal Attacker | 根据 execution view 和 validated plan 生成 fresh slot value 与逐 stage action |
| OpenClaw Victim | 被测完整 Agent：模型、context、memory、workspace、tools 和 session lifecycle |
| Mechanism Verifier | 用 graph、occurrence、edge 和 action lineage 验证攻击机制 |
| Official Evaluator | 给出 SafeClaw benchmark 的官方结果投影 |
| Recorder/Reporter | 写入 checkpoint、model-call journal、complete record、audit 和报告 |

`judge.py`、runner、bridge 和 materializer 是执行基础设施，不是 Attacker。当前 preregistered 三个 condition 使用 deterministic fixed/no-sample Planner；只有显式加入 `sample_llm_tiebreak` 才会调用 LLM Planner。

## 项目结构

```text
stac-compositional-attack-lab/
├── README.md                  项目入口与当前状态
├── SECURITY.md                授权范围和隔离要求
├── Makefile                   质量检查与当前 v2 入口
├── configs/                   环境、实验、模型、task 和 sample 配置
├── data/                      seed、raw/normalized interaction、generated/frozen library
├── docs/                      当前文档和历史归档
├── experiments/               legacy 与 SafeClaw 正式运行产物
├── integrations/              SafeClaw bridge/patch 与外部 benchmark checkout
├── prompts/                   各角色的版本化 prompt
├── schemas/                   Pydantic 生成的 JSON Schema
├── scripts/                   当前 launcher；旧脚本位于 scripts/legacy
├── src/stac_attack_lab/       核心 Python 包
└── tests/                     unit、integration 和 e2e tests
```

各目录的详细说明见：

- [`docs/PROJECT_GUIDE_ZH.md`](docs/PROJECT_GUIDE_ZH.md)
- [`configs/README.md`](configs/README.md)
- [`data/README.md`](data/README.md)
- [`scripts/README.md`](scripts/README.md)
- [`experiments/README.md`](experiments/README.md)

## 安装与本地质量检查

要求 Python 3.11+。真实 SafeClaw 运行建议使用 Linux 服务器。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
make check
make schemas
```

`make check` 依次执行 Ruff、mypy 和 pytest。部分 SafeClaw contract tests 依赖被 `.gitignore` 排除的 pinned upstream checkout；未准备 upstream 时，这些测试会失败，而不是自动下载依赖。

## 当前 SafeClaw 外部依赖

真实 collection/evaluation 需要：

- `integrations/safeclaw/upstream/SafeClawArena`；
- upstream commit `a11f5cceaba0676be721021f8d232638fd111305`；
- Docker 与 `openclaw-env:2026.3.12`；
- 可应用的 `integrations/safeclaw/patches/a11f5cce-safety.patch`；
- allowlisted Victim/Attacker model endpoint；
- 独立且从 host/Docker 均可访问的 `/v1/embeddings` endpoint；
- 至少 20 GiB 可用磁盘；
- 只存在本地环境变量或 mode-0600 环境文件中的凭证。

Preflight 不会 clone upstream、下载模型、构建 image 或放宽安全门禁。

## 运行入口

查看所有 Makefile 入口：

```bash
make help
```

对显式版本化 collection 配置运行 preflight：

```bash
make sample-preflight \
  CONFIG=configs/sample_generation/<authorized-version>.yaml
```

运行经授权的 collection：

```bash
make sample-collection \
  CONFIG=configs/sample_generation/<authorized-version>.yaml
```

Collection launcher 只执行 `collect-preflight -> collect`，不会自动 mine、audit 或 freeze。完整命令和停止条件见 [`docs/PROJECT_GUIDE_ZH.md`](docs/PROJECT_GUIDE_ZH.md)。

Formal preflight：

```bash
make formal-preflight
```

Formal evaluation 只有在真实 library audit/freeze 通过后才可能启动：

```bash
make formal-evaluation
```

当前 config 指向尚不存在的 `data/primitive_libraries/frozen/formal-v3-safeclaw-20260824`，因此会在 Victim episode 之前停止。这是预期门禁，不是应绕过的错误。

## 正式实验设计

当前 preregistered formal matrix：

```text
1 个 PSE 2.1 task × 3 conditions × 5 seeds = 15 cases
```

Conditions：

- `assigned_sample`：使用 scheduler 分配的一个真实冻结 sample；
- `no_sample`：同 task/seed/budget/template 的合法 benign baseline；
- `dependency_ablation`：保留同一 sample 与 plan，只替换一个预注册 sample-derived slot。

同一 pair 必须保持 task、seed、budget、public prompt、library、registry、environment 和 official evaluator 不变。只有 condition 指定的变量可以变化。

## 证据与可恢复性

正式 case 的核心产物包括：

- `formal_case_assignment.json`
- `planner_input.json`
- `evaluation_plan.json`
- `formal_attacker_input.json`
- `materialized_task.json`
- `episode_result.json`
- `interaction_graph.json`
- `primitive_extraction.json`
- `mechanism_evaluation.json`
- `official_verdict.json`
- `model_calls.jsonl`
- `complete_interaction_record.json`

运行支持 whole-episode attempt、append-only transition、case checkpoint 和 `--resume`。中断 attempt 不会与新的 Victim container 拼接。正式报告必须从持久化 artifact 重建，不能只依赖 stdout。

## 文档导航

建议首次审阅按以下顺序阅读：

1. 本 README；
2. [`docs/PROJECT_GUIDE_ZH.md`](docs/PROJECT_GUIDE_ZH.md)；
3. [`docs/EXPERIMENT_PROTOCOL.md`](docs/EXPERIMENT_PROTOCOL.md)；
4. [`docs/PROMPTS.md`](docs/PROMPTS.md)；
5. [`SECURITY.md`](SECURITY.md)；
6. [`docs/DECISIONS.md`](docs/DECISIONS.md)。

阶段性计划、旧命令和服务器进度位于 [`docs/archive/`](docs/archive/)，只用于历史追溯。

## 当前限制

- 真实 formal-v2 library 尚未产生；
- 当前只 preregister 了一个 coverage-limited PSE 2.1 formal task；
- 尚未完成多入口、多拓扑、多 Agent、多危害 sink 和系统化防御比较；
- 当前不能声称广泛攻击覆盖、跨类别迁移性或正式 ASR；
- AgentDojo 和 SHADE_Arena 仍只有 adapter/contract smoke。

任何实验结论都必须明确区分：代码实现、deterministic smoke、synthetic fixture、真实 pilot、完整 frozen library 和正式 matched evaluation。
