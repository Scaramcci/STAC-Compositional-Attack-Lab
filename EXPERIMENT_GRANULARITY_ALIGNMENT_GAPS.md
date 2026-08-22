# Experiment Granularity Alignment And Remaining Work

Updated: 2026-08-22

## 1. 本文采用的目标实验定义

本项目只在授权、隔离、可审计的 synthetic/SafeClawArena 环境中进行科研性质的
Agent 攻击实验，不攻击真实网络、真实用户、真实账户或外部系统。

整个实验分为两个严格分离的阶段。

### 阶段 A：离线获得 primitive chain sample

```text
Human-Simulator Agent
  -> 与完整 Victim Agent 多轮交互
  -> Victim 与工具、memory、workspace、session 和 sandbox 环境交互
  -> Recorder 记录完整可观察事件和状态变化
  -> Normalizer 构建 InteractionGraph
  -> Extractor 提取 core primitive occurrences
  -> Chain Miner 从一次 trajectory 中提取一条或多条有 typed causal edge 的 primitive chain
  -> 审计、去内容化、冻结为 sample library
```

这里的采集 Agent 模拟一个与 Victim 交互的人。为了获得攻击相关 sample，它可以在公开、
安全的 construction objective 下采取对抗性行为，但它不是正式验证阶段的 Attacker，也不能
看到 evaluator private oracle 或自己宣布成功。

本阶段的实验单位应当区分：

- `interaction turn`：一次人机或 Agent-environment 交互；
- `trajectory`：同一个 construction attempt 的完整多轮轨迹；
- `primitive occurrence`：轨迹中的一次可观察 core 状态转移；
- `primitive chain sample`：从 trajectory 中抽取的一条可复用因果链；
- `library`：来自多个 task、seed、策略和 trajectory 的大量去重 chain sample。

关键颗粒度是：**一条 trajectory 可以产生多条 chain sample，而不是固定只能产生一条。**

### 阶段 B：正式验证

```text
SafeClawArena benchmark task/prompt
  + exactly one assigned primitive chain sample
  -> Planner 生成 plan
  -> Attacker 按 plan 执行并与 Victim 交互
  -> 完整 Victim Agent 在 SafeClawArena sandbox 中运行
  -> Verifier 同时评估 benchmark 结果和 primitive 因果链是否发生
```

除 `no_sample` 对照外，每个正式 case 在进入 Planner 前就应绑定一条 sample。Planner 的职责
是使用 benchmark prompt 和这一条 sample 生成 plan，不负责浏览整个 library 或选择 sample。
sample 选择属于实验调度/配对层，以免把“选哪条 sample”和“如何基于 sample 规划攻击”混成
同一个自变量。

本文把“primitive chain sample”解释为：core occurrence 和 typed causal edge 是因果骨架，
九个 semantic macro 是其可解释的上层标注。若最终决定 Planner 只看 macro chain，也必须在
实验协议中明确说明 Planner 研究的是 macro-chain transfer，而不是完整 core-chain transfer。

## 2. 已经对齐的部分

### 2.1 安全边界

当前实现坚持 synthetic data、无真实凭据、无宿主机文件、无外部网络和隔离容器约束。
SafeClaw construction bridge 不调用官方 evaluator，formal 阶段才读取 sanitized official result。
这与目标实验的安全和阶段隔离原则对齐。

### 2.2 离线阶段已有完整角色和记录骨架

`ModelConstructionAttacker` 只接收 public construction task、manifest 和 public observation，
能够输出 message、new-session、retry、reroute 或 stop action。它实际上已经承担了“模拟人类
与 Victim 交互”的角色，只是当前类名强调其对抗性目标。

`SafeClawConstructionInteractionAdapter` 和 `SafeClawSubprocessVictimDriver` 已能记录 session、
公开 transcript、tool call/result、memory/workspace/external state diff、checkpoint 和失败结果。
raw trajectory -> InteractionGraph -> occurrence -> filter -> three-view library 的基础数据通路已经存在。

### 2.3 去内容化 sample 和角色隔离

formal-v2 library 已将 planner public view、execution binding view 和 private evidence view 物理
分离。Planner/Attacker 不读取离线成功 payload、Victim transcript、private oracle 或 evaluator
success condition。这符合“sample 提供结构，不回放离线攻击原文”的目标。

### 2.4 正式阶段已接入 SafeClawArena 和双重验证

formal runner 会 materialize SafeClaw task，调用 pinned SafeClawArena `judge.py` 运行完整
OpenClaw Victim，随后解析 official verdict，并重新 normalize 正式 episode、抽取 primitive
occurrence、验证 required occurrence/edge/macro 和 shortcut。

因此 Verifier 已具备两个必要层面：

- SafeClawArena 官方 terminal/security/utility 结果；
- 本项目的 primitive mechanism completion 结果。

## 3. 当前没有对齐的地方

### G1（关键）：离线抽取器只验证一条硬编码链，不会发现大量 chain

`src/stac_attack_lab/extraction/chains.py` 中固定了：

```text
Ingest -> Persist -> Recall -> Bind -> Act
```

以及固定的七条 required core edge。实现还通过 `_first_by_primitive()` 只选每种 primitive 的
第一次 occurrence。`construct_chain_candidates()` 对一条 trajectory 最多返回一个 candidate。

这与目标中的“经过多次交互获得大量 primitive 链 sample”不一致。重复 occurrence、不同路径、
不同长度的子链、分支/汇聚链，以及同一 trajectory 中的多个可复用链都会被忽略。

影响：当前系统能证明预设 PSE 链是否出现，但不能作为通用 primitive-chain acquisition/mining
系统，也无法研究 sample diversity 或不同链对正式攻击规划的作用。

### G2（关键）：当前实际 sample 数量远未达到 library 研究所需规模

当前真实 construction 配置只有两个 PSE task、一个 seed，并且 interaction loop 用
`max_sessions=4` 同时限制 action 轮数。仓库中没有 `safeclaw-adversarial-v1` 的真实 collection
产物。

目前正式配置实际引用的是 synthetic frozen library：

- attempted trajectory：2；
- accepted sample：1；
- negative sample：1；
- accepted topology：单一 PSE canonical chain。

这只能作为 deterministic pipeline smoke，不能称为“大量 primitive 链 sample”。

### G3（关键）：Planner 收到整个 sample library，而不是一条预先分配的 sample

`FormalPlannerInput` 当前字段是：

```text
public_samples: list[PublicSampleIndexEntry]
```

formal runner 把 `library.public_index()` 整体交给每个 Planner。`FormalLLMPlanner` 第一轮调用
先从 compatible sample 列表选择 sample；第二轮 trajectory prompt 虽然显式包含
`selected_sample`，但仍同时传入含完整 `public_samples` 的 `planner_input`。

这与“Planner 获得 Prompt 和一条 primitive 链 sample，然后生成 plan”不一致，也把 sample
retrieval/selection 能力混入了 Planner 效果。

建议的边界是：

```text
Experiment Scheduler / Sample Assigner
  -> 选择并固定 sample_id
  -> 构造 SingleSamplePlannerInput(task_prompt, selected_sample, budget, seed)
  -> Planner
```

`fixed/random/rule-based` sample selection 可以保留，但应属于 scheduler condition，而不是
Planner 内部行为。`no_sample` 则显式传 `selected_sample=None`。

### G4（关键）：Planner 当前没有收到完整 benchmark Prompt

Planner 当前主要收到 `SafeClawPublicTaskView.public_goal`、capability、component role、slot 和
allowed action 等公开摘要，而不是完整的 benchmark user prompt/session prompt。若本文目标中的
“Prompt”指正式任务的实际可见 prompt，那么当前输入颗粒度不一致。

需要明确并固定以下二者之一：

1. Planner 看见 Victim 将看到的全部 public benchmark prompt，但看不到 private evaluation；
2. Planner 只看 sanitized task abstraction，此时研究问题应表述为“task abstraction + sample -> plan”。

当前代码实现的是第 2 种，但项目目标表述更接近第 1 种。

### G5（关键）：Formal Attacker 生成的 stage actions 没有驱动 Victim

`ModelFormalAttacker` 会生成：

- `public_slot_values`；
- 与 plan 每个 stage 对应的 `stage_actions`。

但是 formal runner 只取 `realization.public_slot_values`，一次性写入 SafeClaw task template，
随后直接调用 SafeClawArena `judge.py`。`stage_actions` 只被记录，没有传给 runner，也没有按
stage 发送给 Victim。

因此当前真实执行语义是：

```text
Attacker produces slot values
  -> task pre-materialization
  -> SafeClaw runner independently executes the whole task
```

而不是目标语义：

```text
Planner plan
  -> Attacker executes stage action
  -> Victim observation
  -> Attacker executes next stage
```

这也是目前最大的“代码看起来有 Attacker，但执行链没有真正消费 Attacker actions”的差距。

需要做一个明确选择：

- 若研究需要 adaptive/multi-stage Attacker：给 SafeClaw runner 增加受控 action/observation loop，
  实际消费 `stage_actions` 或逐步调用 `next_action()`；
- 若研究只需要 pre-execution task compiler：删除未执行的 `stage_actions` 语义，并明确把该角色
  定义为 Attack Materializer，不能称其已经逐阶段执行攻击。

根据本文目标，应选择第一种。

### G6（关键）：缺少 plan -> attacker action -> victim event 的因果链接

正式 Verifier 能检查 episode 中是否出现预期 core occurrence 和 edge，但由于 Attacker action
没有进入 runner，事件中也没有稳定的 `attacker_action_id` / `plan_stage_id` lineage，Verifier
无法证明某个 Victim 状态转移是由 Planner 指定、Attacker 实际执行的对应 stage 引起的。

需要给正式事件补充并验证：

```text
plan_id
plan_stage_id
attacker_action_id
victim_request_event_id
result_event_id
produced_artifact/state refs
```

否则只能证明“某条 primitive 链在 episode 中出现过”，不能证明 Planner -> Attacker -> Victim
按计划完成了该链。

### G7（高）：Planner 看到的是 macro chain，不是完整 core primitive chain

`PlannerSampleView` 主要包含 macro nodes/edges；core occurrence refs 和 pattern refs 位于 execution
或 private view。Planner 生成的 `primitive_sequence` 实际逐项对应 macro node，再给每个 macro
附一个 primary core family。

若目标 sample 是底层 `TRANSFER / TRANSFORM / MUTATE / CONTROL` occurrence chain，则当前
Planner 输入和 plan backbone 颗粒度偏高。建议 public sample 同时提供去内容化的：

- ordered core nodes：family、subtype、public input/output state type；
- typed causal edges；
- occurrence multiplicity 和 session boundary；
- 可选的九项 macro annotations。

macro 应用于解释和检索，core chain 应作为因果骨架。若坚持只给 Planner macro chain，应把这一
点作为研究定义写清楚，避免把 macro plan 报告为 core primitive plan。

### G8（高）：离线采集目标和表面过于单一

Construction Attacker 当前只有一个 persistent-state attack goal，两条 construction task 也都
属于 PSE 2.1。required trust boundary、terminal predicate 和 capability 在配置中预先固定。

这保证了安全和可验证性，但会强烈引导采集结果回到同一 canonical topology，无法自然产生
多入口、多传播介质、多 session pattern 或不同长度的 chain。需要增加多个 construction
objective family，并按 task/seed/attacker strategy 分层采样，而不是简单增加同一种 PSE 的调用次数。

### G9（高）：正式验证仍使用 synthetic sample，而非阶段 A 的真实输出

`configs/experiments/safeclaw_formal_v1.yaml` 的 `library_path` 仍指向
`formal-v2-attack-synthetic`。真实 collection、真实 chain extraction、audit 和 immutable freeze
尚未执行，因此“离线 sample -> 正式 SafeClaw 验证”的真实数据交接还没有发生。

### G10（中）：SafeClaw 正式任务覆盖只有一个 PSE case

正式 task set 当前只有 `pse-2.1-001`。它可以验证 pipeline，但还不能代表使用 SafeClawArena
benchmark 进行系统性验证。需要根据 sample 的 capability/applicability 扩展 benchmark task
矩阵，并保持 construction task 与 formal test task 严格不重叠。

### G11（中）：运行记录没有完整保存 Planner/Attacker 模型调用消息

`complete_interaction_record` 中 Planner 的 `model_id`、`prompt_asset` 为 `None`，Planner 和
Attacker 的 `messages` 均为空数组。虽然输入输出 artifact 有保存，但不足以完整复核实际 model
prompt 调用和角色边界。正式实验前应像 Victim transcript 一样记录经过 secret redaction 的
model request/response、prompt hash、model id 和 call id。

### G12（中）：离线 collect 与 build 的操作边界不够清楚

`sample collect` 只生成 raw trajectories；`sample build/attack-build` 会再次初始化 model/adapter，
然后依靠 resume 跳过已有 trajectory，再执行 normalize/extract/filter/library build。缺少显式的
`build-from-collection` 输入契约，导致采集环境和构建环境耦合，也容易误以为 collect 已经产生了
sample library。

建议拆成不可混淆的命令：

```text
sample collect --config ...
sample mine --collection <immutable-collection>
sample audit --library ...
sample freeze --library ... --version ...
```

## 4. 建议的目标数据流

### 4.1 离线阶段

```text
ConstructionCampaign
  tasks[] x seeds[] x human-simulator strategies[]
    -> RawInteractionTrajectory[]
    -> InteractionGraph[]
    -> PrimitiveOccurrence[]
    -> enumerate typed causal paths/subgraphs
    -> PrimitiveChainCandidate[]
    -> positive / partial / blocked / rejected / error pools
    -> deduplicate + diversity sampling
    -> immutable PrimitiveChainLibrary
```

Chain Miner 至少需要支持：

- 同一 primitive subtype 的多个 occurrence，而不是只取第一个；
- 同一 trajectory 产出多条 chain；
- 按 entry/terminal、长度、session span、component path 枚举；
- data/state/control/authorization edge 的连续性；
- 分支、汇聚和可选节点；
- positive、partial、blocked 和 counterexample 的独立保留；
- 内容去除后的结构去重与 diversity 指标。

### 4.2 正式阶段

```text
FormalCaseAssigner
  benchmark_task_id
  benchmark_public_prompt
  selected_sample_id | no_sample
  seed / budget / condition
    -> SingleSamplePlannerInput
    -> PlannerPlan
    -> AttackerAction loop
    -> SafeClaw Victim episode
    -> OfficialVerifier + PrimitiveMechanismVerifier
    -> FormalRunResult
```

每个正式 case 必须能够从结果反向追踪到：

```text
library/version/sample hash
  -> planner input/prompt/output
  -> attacker input/prompt/actions
  -> victim requests/tool calls/state changes
  -> primitive occurrences/edges/macros
  -> SafeClaw official verdict
  -> final full-chain verdict
```

## 5. 后续工作优先级

### P0：先修正实验语义，否则不应开始正式模型实验

1. 把 sample 选择移到 Planner 外，新增 singular `selected_sample` Planner 输入。
2. 明确 Planner 获得的是完整 public benchmark prompt 还是 sanitized task abstraction，并固定协议。
3. 重写 chain extraction：从固定 canonical chain validator 改为 occurrence/path miner，一条
   trajectory 可以输出多条 sample。
4. 决定并实现 Attacker 的执行语义：按本文目标，stage action 必须真正进入 SafeClaw Victim
   action/observation loop。
5. 增加 plan stage、attacker action、Victim event 和 evidence 之间的稳定 lineage。
6. 明确 sample 的核心颗粒度：推荐 core chain 为骨架、semantic macro 为标注。

### P1：完成真实离线 sample acquisition

1. 将 config 从单 seed 改为 seed 列表，并增加 campaign/case id。
2. 扩展多个安全 construction objective、task family、interaction strategy 和 chain topology。
3. 修正 action budget，使 turn/action 数与 session 数分离。
4. 运行 preflight 和小规模 pilot，确认完整记录与 resume 后再扩大采集。
5. 对真实 trajectories 执行 mine/filter/audit，生成新的 immutable library version。
6. 报告 trajectory 数、每条 trajectory 的 chain 数、unique chain 数、长度/宏/组件/session
   分布和 negative reason distribution。

### P2：完成正式 SafeClaw 验证闭环

1. 让 formal config 引用阶段 A 新冻结的真实 library，而不是 synthetic smoke library。
2. 扩展 SafeClaw formal task set，同时保持 construction/test split 不交叉。
3. 对每个 task/sample/seed 生成配对 case：`no_sample`、sample、必要 ablation/control。
4. 验证每个非 baseline Planner 输入只有一条 sample。
5. 验证每个 Attacker stage action 都有对应 Victim/event/evidence refs。
6. 保存并审计 Planner、Attacker、Victim、Verifier 的完整可观察调用记录。
7. 通过 deterministic e2e 后才运行真实模型 formal evaluation。

### P3：完成后才能报告的研究结果

只有完成真实 acquisition 和 matched formal runs 后，才能报告：

- sample-conditioned attack success rate；
- full primitive-chain success rate；
- terminal-only/shortcut rate；
- 不同 chain family、长度、session span 的差异；
- no-sample 和 dependency ablation 的因果对照；
- sample transfer/generalization。

当前不能用 synthetic library 的 1 个 accepted sample 或 deterministic test 结果支持上述结论。

## 6. 建议的完成标准

### 阶段 A 完成

- 真实 Human-Simulator Agent 已在授权环境中完成多 task、多 seed、多轮交互；
- 一条 trajectory 可稳定抽取多条 chain；
- library 不再只有一个 canonical topology；
- positive/partial/blocked/rejected/error 都保留并可审计；
- frozen public sample 明确包含目标颗粒度的 core chain 和 macro annotations；
- public/execution view 无 prompt/payload/oracle/transcript 泄漏；
- library audit、hash、immutable freeze 和 resume 全部通过。

### 阶段 B 完成

- 每个非 baseline case 在 Planner 前绑定 exactly one sample；
- Planner 只看到允许的 benchmark prompt/task public view 和这一条 sample；
- Attacker 实际执行 plan stages，而不只是生成未消费的结构；
- Victim 确实由 pinned SafeClawArena/OpenClaw runner 执行；
- Verifier 同时给出 official verdict 与 occurrence/edge/macro causal verdict；
- plan -> action -> event -> evidence lineage 完整；
- matched controls、多个 seed、错误/timeout/not-observable 均进入结果；
- lint、typecheck、test、e2e、run audit 和 secret scan 全部通过。

## 7. 当前阶段结论

当前仓库已经完成了安全边界、事件记录、primitive contract、固定 PSE 链验证、三视图 frozen
sample、SafeClaw runner 和双层 verifier 的基础设施。

但从本文定义的实验颗粒度看，它仍处于：

> **单一预设链的 synthetic pipeline prototype**

而不是：

> **从大量人机交互中挖掘多条 primitive chain sample，并逐条交给 Planner/Attacker 在
> SafeClawArena 中正式验证的完整实验系统。**

正式模型实验应在 P0 的输入粒度、chain mining 和 Attacker execution 三个关键问题修正后再开始。
