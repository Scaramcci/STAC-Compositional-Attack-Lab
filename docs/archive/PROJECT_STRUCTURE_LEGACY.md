# Project Structure

> Archive snapshot：该说明已由 `docs/PROJECT_GUIDE_ZH.md` 替代，路径和运行状态可能与当前仓库不同。

本文档说明模块职责、依赖方向、离线到在线的数据流、角色隔离和运行产物。研究状态与尚未实现的范围见 [`docs/RESEARCH_STATUS.md`](docs/RESEARCH_STATUS.md)。

## 顶层结构

```text
stac-compositional-attack-lab/
├── configs/                 实验、模型和环境配置
├── data/
│   ├── seeds/               合成任务与原语种子
│   ├── generated/           尚未冻结的离线构建产物
│   └── frozen/              审计后不可变的数据集和构建对话
├── docs/                    研究协议、prompt、决策与当前状态
├── experiments/runs/        evaluation 对话、事件、判定和进度
├── prompts/                 各角色的版本化 prompt 资产
├── schemas/                 Pydantic 生成的 JSON Schema
├── scripts/                 运行入口和 Huihui/vLLM 启动脚本
├── src/stac_attack_lab/      核心实现
└── tests/                   单元、端到端和集成 contract tests
```

## 核心模块职责

| 模块 | 职责 |
|---|---|
| `contracts.py` | 定义任务、攻击图、模型输出、事件、artifact、verdict 和运行结果契约 |
| `registry.py`, `primitives/` | 注册并实现当前四个攻击原语 |
| `graph/` | 编译和验证攻击节点、边、前置条件、预算及终止目标 |
| `environments/workspace_canary.py` | 提供无公网、无 shell、合成 canary 的四组件环境 |
| `models/` | Fake、Gemini、OpenAI-compatible 和本地 Huihui 客户端 |
| `planning/` | fixed、random、rule-based 和 LLM adaptive planner |
| `execution/offline.py` | 生成候选样本、执行 Victim、确定性验证并保留通过样本 |
| `execution/online_stac.py` | 按攻击图执行 Planner、Attacker、Victim 和 verifier 状态机 |
| `recording/` | 写入事件、对话、artifact、快照、checkpoint 和 audit |
| `verification/` | 根据事件、lineage 和状态计算 hard verdict，附加语义标签 |
| `datasets/` | 审计并冻结离线样本，在线阶段校验绑定关系和 hash |
| `reporting/` | 从持久化记录重建聚合报告 |
| `environments/*_adapter.py` | 对 AgentDojo、SHADE_Arena 做只读发现与 contract smoke |

依赖方向为：

```text
contracts/config
  -> graph/primitives/environment/model
  -> planning/execution/verification/recording
  -> datasets/reporting
  -> CLI
```

底层模块不依赖 CLI 或报告模块，确定性 verifier 不调用或修改环境。

## 当前攻击链与组件传播

当前 registry 包含四个原语：

1. `tool_response_injection`：不可信 retrieval tool 内容进入 Victim。
2. `memory_write`：Victim 将相关 artifact 写入 workspace memory。
3. `memory_retrieval`：memory retriever 在后续阶段把持久化内容返回 Victim。
4. `canary_tool_trigger`：Victim 生成 action tool 参数，本地环境检查其 lineage。

当前默认图是固定线性图：

```mermaid
flowchart LR
    RT["Retrieval tool"] -->|untrusted artifact| V1["Victim"]
    V1 -->|memory write| MS["Memory store"]
    MS --> MR["Memory retriever"]
    MR -->|retrieved artifact| V2["Victim"]
    V2 -->|tool arguments| AS["Local action sink"]
    AS --> HV["Deterministic verifier"]
```

这是一类组合攻击基线，不代表已经实现多入口、多拓扑或多危害攻击集合。

## 离线到在线的数据流

```text
data/seeds/tasks.jsonl
  -> Planner/attack graph candidate
  -> PromptWriter/Attacker stage messages
  -> Gemini Victim executes in WorkspaceCanaryEnv
  -> events + artifacts + snapshots
  -> deterministic hard verification
  -> accepted samples + failures + conversations
  -> dataset audit and immutable freeze
  -> Huihui evaluation loads exact frozen sample
  -> online Planner/Attacker/Victim execution
  -> conversations + events + verdicts + progress
```

离线阶段的正式配置是 `configs/experiments/stac_sample_build_gpt_gemini.yaml`。候选执行完整攻击链并通过 hard verification 后才进入冻结数据集。evaluation 使用 `configs/experiments/evaluation_gpt_huihui_4090.yaml`，保持 GPT 角色不变，只把 Victim 替换为本地 Huihui。

SafeClaw formal matrix adds a matched no_sample path. BaselineBinding carries no sample/chain identity; it can materialize only template slots that explicitly allow baseline.task_set. Each task-set row declares both value maps and the exact sample_derived_slots delta. Sample-bound and baseline cases share the pair id, task, seed, budget, template, official oracle hash, environment configuration, and runner.

## 角色隔离

- Planner 只看到公开攻击图、合法 frontier、预算和粗粒度阶段状态，不看到 private oracle。
- Attacker 只接收 Planner 选中的一个节点及该阶段冻结模板，不能自行改图或合并多个阶段。
- PromptWriter 负责离线阶段最终 Victim-visible message，与 Attacker 使用独立 prompt 和 schema。
- Victim 使用固定 `prompts/runtime/victim_system.md`，不同 condition 下 hash 必须一致。
- Verifier/Judge 只能产生语义辅助标签，不能覆盖确定性 hard verdict。
- Recorder 记录可观察消息、结构化输出和证据引用，不请求隐藏 chain-of-thought。

## 对话和执行证据

### 离线样本构建

```text
data/frozen/stac-verified-30-v0.1/
├── conversations.jsonl       全部角色的模型请求和响应
├── samples.jsonl             30 个冻结样本及 prompt/graph hash
├── failures.jsonl            未接受候选及原因
├── transcript_audit.json     对话完整性审计
└── verification/<candidate-id>/
    ├── events.jsonl          环境工具事件
    ├── verdicts.jsonl        确定性阶段判定
    ├── artifacts/            入口、memory、retrieval artifact
    └── snapshots/            工具执行前后状态
```

### 正式 evaluation

```text
experiments/runs/evaluation_gpt_huihui_4090-02cb0b56baac/
├── conversations.jsonl       Planner 到 Attacker、Attacker 到 Victim、工具和 verifier 对话
├── run_manifest.json         模型、数据集、prompt hash 和配置来源
├── progress.json             当前汇总进度
├── attack_progress.jsonl     每个攻击的 append-only 状态变化
├── transcript_audit.json     对话完整性与隔离审计
├── results.jsonl             每个 episode 的机器可读汇总
└── <attack-id>/
    ├── events.jsonl
    ├── verdicts.jsonl
    └── report.json
```

对话不是结果摘要。研究攻击如何传播时，应优先读取 `conversations.jsonl`，再通过 `related_event_ids`、`artifact_refs`、`snapshot_refs` 和 `hard_verdict_refs` 连接到执行证据。

## 可恢复执行

`recording/progress.py` 为每个攻击建立幂等 key，原子更新 `progress.json`，并将状态追加到 `attack_progress.jsonl`。配额或临时错误不会删除已完成攻击，恢复命令跳过已经完成的 key。

`recording/conversations.py` 为模型和工具交互分配稳定 call/event id，过滤环境秘密，并运行 transcript audit。当前已知的 attempt 级事件标识和运行指标问题记录在 `docs/RESEARCH_STATUS.md`，扩展实验前必须修正。

For SafeClaw no_sample, planner and materialization artifacts record legal_baseline, a baseline binding id, canonical changed pointers, template hash, and protected evaluation hash. Interaction normalization and official evaluation still run, while attack-mechanism aggregation remains empty because no sample chain was selected.

## 扩展方法

新增攻击原语时，需要同时增加 `PrimitiveSpec`、环境行为、图验证规则、确定性 predicate、schema 和测试。新增传播类型还应定义 artifact transformation、taint/lineage 继承和信任边界变化。

新增环境时，实现 `environments/base.py` 的 `Environment` 协议：`reset`、`snapshot`、`restore`、`step`、`public_spec` 和 `private_oracle`。private oracle 不得进入任何模型 prompt。

新增 verifier 时，在 `verification/` 中实现纯函数或纯类，只读取已记录事件和快照，返回带 evidence refs 的 `VerifierVerdict`，不得修改环境。

新增防御时，应将其实现为明确的传播节点策略，并记录输入 lineage、决策、拦截位置、输出 artifact 和 benign utility，避免把 verifier 的事后判定误当成运行时防御。
