# Research Status

本文档面向项目审阅，说明当前实验已经实现到哪里、尚未实现什么，以及扩展为系统化攻击传播与防御研究前必须修正的问题。这里不讨论攻击成功率或模型优劣。

## 2026-08-20 formal-v2 状态

- 底层 primitive 已统一为 `TRANSFER / TRANSFORM / MUTATE / CONTROL` 四个可观察状态差分 family。
- 老师的九项 capability-transition primitive 已实现为 semantic macro registry；`Adopt` 的 E3/E4 语义证据不能覆盖缺失的 E1/E2 hard fact。
- formal sample acquisition 需要显式 Construction Attacker manifest；`ordinary_trace` 在 G5 fail closed，只能进入 negative/control pool。
- synthetic construction 已尝试 2 条轨迹：1 条 accepted、1 条 defense-blocked negative。冻结版本为 `formal-v2-attack-synthetic`。
- public planner、execution binding 和 private evidence 三视图已物理分离并通过泄漏审计。
- formal planner 先选择 public macro chain，再用独立 prompt 提议 primitive/state trajectory；代码会重验 backbone、机制支持、persistence、trigger、公开 judge predicate、allowed actions 和因果 controls。
- independent formal Attacker 已实现并 fail closed：它只接收 public task、execution view 和 validated plan，生成 fresh slot values 与逐 stage actions；materializer 和 evaluator 仍不充当 Attacker。
- SafeClaw adaptive construction adapter、完整 Victim subprocess driver、非执行 preflight 和 crash-safe resume 已实现；真实模型 Sample Collection、正式 attack run、ASR 与迁移性结论均未运行。

## 当前研究思路

项目把攻击表示为由攻击原语组成的有向图。每个原语对应一次组件交互，每次交互记录消息、工具事件、artifact、lineage、环境前后快照和 verifier evidence。这样可以从完整轨迹回答攻击从哪里进入、经过哪些组件、在哪里持久化、何时影响行为，以及危害在哪个本地 sink 形成。

当前已实现的图只有一类：

```text
retrieval tool injection
  -> Victim
  -> workspace memory write
  -> memory retrieval in a later stage
  -> Victim tool arguments
  -> synthetic local canary sink
```

它是多阶段组合攻击，但仍是单一攻击家族。任务文本和候选 seed 有变化，入口、传播介质、图拓扑和危害 sink 没有发生根本变化。

## 已经实现

- 六个独立角色：Planner、Attacker、Victim、PromptWriter、Verifier、Judge。
- 每个角色独立 prompt、输入输出 schema、模型配置、权限和 abstain 行为。
- 固定 Victim system prompt，并在不同实验 condition 中校验 hash 一致。
- 四个攻击原语及其线性攻击图。
- 本地 `WorkspaceCanaryEnv`，只允许合成数据和无价值 canary。
- 事件、artifact lineage、环境快照和阶段 verdict 的结构化记录。
- 根据事件和 lineage 执行的确定性 verifier；LLM 标签不能覆盖它。
- FakeModelClient 的确定性离线、在线和报告测试闭环。
- GPT-5.5 + Gemini 的离线样本构建流程，包含候选拒绝、审计和不可变冻结。
- GPT-5.5 + 本地 Huihui-Qwen3 的 evaluation 流程。
- 每个攻击单独 checkpoint、append-only 进度、quota pause 和 resume。
- 模型请求/响应、工具交互和 verifier feedback 的完整可观察 transcript。
- 基础 clean、单点消融、memory guard 和报告代码路径。
- SafeClaw no_sample 合法同模板对照：仅预注册的 sample-derived slot 可改变，且不会被计为完整攻击链成功。
- AgentDojo 与 SHADE_Arena 的只读 adapter/contract smoke。

## 已经完成的运行

- 离线阶段已产生并冻结 30 个可执行样本，目录为 `data/frozen/stac-verified-30-v0.1/`。
- evaluation 阶段的 30 个计划 episode 已全部完成，目录为 `experiments/runs/evaluation_gpt_huihui_4090-02cb0b56baac/`。
- evaluation 中只有一个 primary attack condition 和一个 seed。
- clean、ablation 和 defense 尚未进行同等规模的正式模型运行。
- 50-from-200 continuation 收集配置已实现但尚未运行；它必须冻结为新版本，不能覆盖现有 30 行数据集。

## 对话数据索引

离线构建完整对话：

```text
data/frozen/stac-verified-30-v0.1/conversations.jsonl
```

正式 evaluation 完整对话：

```text
experiments/runs/evaluation_gpt_huihui_4090-02cb0b56baac/conversations.jsonl
```

按单个攻击提取对话：

```bash
jq -c 'select(.attack_id == "<attack-id>")' conversations.jsonl \
  | jq -s 'sort_by(.sequence_no)'
```

按角色查看结构化响应：

```bash
jq -c 'select(.event_type == "model_response") |
  {sequence_no, attack_id, sender_role, recipient_role, model_id,
   parsed_structured_response}' conversations.jsonl
```

这些 transcript 包含 Planner decision、Attacker message、Victim 可观察请求/响应、tool request/result、Verifier 评论和 Judge 标签。仓库不记录隐藏 chain-of-thought。

## 尚未实现

### Formal-v2 下一执行阶段

- 运行 `configs/sample_generation/safeclaw_adversarial_v1.yaml` 的 preflight 与真实 construction collection。
- 用真实 construction trace 扩展新版本 frozen library，保留 positive、partial、blocked、rejected 和 error。
- 随后执行 matched formal attack/control；在此之前不报告 ASR。

### 系统化攻击覆盖

- 入口类型尚未扩展到用户内容、文件、预置记忆、Agent 间消息、Planner context 和任务交接。
- 传播操作尚未覆盖摘要、改写、压缩、委派、序列化和跨会话召回。
- 尚无分片重组、多来源汇聚、可信/不可信混合和延迟条件触发。
- 尚无分支、汇聚、循环、跨 Agent 和跨会话攻击图。
- 当前危害只有本地 canary sink，尚未定义多种安全影响及严重度。

### 传播与转折点分析

- 尚未给每条边统一记录 taint before/after、transformation 和 authority change。
- 尚未自动识别首次持久化、首次信任提升、首次重组、首次行为采纳和首次危害授权。
- 尚未通过 node/edge ablation 估计组件和传播边的因果贡献。
- 当前报告没有 edge-level conditional propagation、路径迁移和 time-to-interception。

### 防御研究

- 目前只有基于来源的 `MemoryIntegrityGuard` 基线。
- 尚未实现入口 provenance、instruction/data isolation、retrieval quarantine、Agent handoff validation、action authorization 和 runtime monitor。
- 尚未完成单点防御、分层防御和 adaptive attacker 的匹配实验。
- 尚未记录防御误报、benign utility、延迟/token 开销、绕过率和攻击路径迁移。

## 扩展实验前必须修正

1. 在线节点不能因为任意工具结果为 `ok` 就通过，必须匹配预期 primitive、工具、参数约束和后置状态。
2. 每次 retry/reroute 必须生成唯一 attempt event id，不能覆盖同一节点之前的尝试。
3. `utility_success`、tokens、duration、retries、reroutes 和 tool-call 数量必须从真实记录计算，不能使用默认常量。
4. 失败 verdict 也必须引用事件、artifact 和 snapshot evidence，便于定位传播中断点。
5. Judge 标签应区分 `attack_effect` 与 `safety_verdict`，避免 `pass/fail` 语义混用。
6. 正式研究必须使用 matched clean、多个 seed 和按任务/攻击图分层的实验设计。

## 下一阶段建议

1. 先修复 attempt 级记录和节点判定，再复跑当前链，建立可信基线。
2. 定义 `EntryPoint`、`PropagationEdge`、`Transformation`、`TrustBoundaryCrossing`、`TurningPoint`、`HarmSink` 和 `DefenseIntervention` 契约。
3. 扩展攻击原语和图家族，并用覆盖矩阵控制组合数量。
4. 增加 node/edge ablation 和自动传播路径报告。
5. 将防御实现为传播边上的可插拔策略，运行无防御、单点、组合和自适应条件。
6. 最后接入 AgentDojo 与 SHADE_Arena，验证合成环境中发现的传播规律是否具有外部有效性。

因此，目前仓库已经完成“单一组合攻击链的可复现执行与完整记录基础设施”，尚未完成“多入口、多传播机制、多重组方式、多危害和多防御的系统研究”。
