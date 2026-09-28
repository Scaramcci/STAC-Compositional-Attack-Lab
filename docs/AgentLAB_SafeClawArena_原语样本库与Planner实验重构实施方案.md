# 基于 AgentLAB 思路的 SafeClawArena 原语样本库与 Planner 实验重构实施方案

日期：2026-09-28。状态：**供用户审阅和交给 Codex 实施的新版设计，不是已实现说明，不是任何真实请求授权。**

本文解决研究主线错位，而非继续修补旧 M3 的通过条件。用户本次明确目标是：在 SafeClawArena 上通过开发阶段的攻击探索获得可能有效的九原语组合样本，冻结样本库，正式阶段由 Planner 利用样本规划攻击，检验其收益。允许为此大幅重构，但不删除历史实验和用户修改。

## 0. 给实施 Codex 的首要指令

1. 先读 AGENTS.md、SECURITY.md、PROGRESS/WORKPLAN 顶部及本文，再检查实际 git status、最近提交、相关模块和未提交修改。
2. 本文是新研究路线的实施依据；若用户指令要求按本文实施，则旧文档中“九原语路线不消费样本库/Planner”的方向约束需更新。历史协议和历史结果不因此变更。
3. 不再把旧 36 单元 M3 pilot 通过作为新主线的前置条件。旧计划保持失败/未达门事实，不续跑、不补分母、不换名计入新实验。
4. 采用本文 R0–R6 新阶段命名，不借用旧 M3/M4 名称制造进度连续性。
5. 第一交付必须尽快形成最小纵向闭环：**任务目录 → split → 开发攻击尝试 → 原语样本 → 冻结库 → 多样本 Planner → 安全物化 → Victim → evaluator → 三臂报告**。先做真实可执行接口与 fake 闭环，不能只增加 schema 或大批禁用配置。
6. 没有真实攻击成功证据时，可以形成工程闭环和 promising 库，但不能宣称有已验证成功样本，更不能伪造成功来跨过阶段门。
7. 不调用真实模型、Docker 长时实验或正式评价，除非获得对应具体批次授权。耗时命令交给用户终端执行；读产物后继续，不让用户反复手工拼 hash。
8. 不 commit/push/reset/clean；不原地改历史证据。重构共享代码前写兼容回归，不能简单整体替换工作树。

## 1. 研究目的与整体闭环

### 1.1 要回答的三个问题

- **RQ1：样本有没有用？** 在相同任务、模型、攻击面和预算下，Planner 使用开发集攻击样本，是否比无样本时更有效？
- **RQ2：原语结构有没有额外价值？** 同一批样本，附带九原语结构、前置条件和证据边界，是否比仅提供攻击实例更有效？
- **RQ3：结构知识是否可迁移？** 收益是否出现在不同任务组、不同表面表述或不同模型上，而非记住相同测试模板？R6 后续扩展，不阻塞最小闭环。

成功标准不是“九原语全部 observed”，也不是“所有 benign 都通过”或“必须攻破 Victim”。正确完成的研究允许发现无收益，但必须能公平测量这些问题。

### 1.2 数据流

```text
SafeClawArena pinned tasks/schema/evaluator
             │
    task catalog + attack-surface audit
             │
    group-disjoint development / validation / test
             │
development: propose → validate surface → execute Victim → evaluate
             │                            │
             │                     all attempts journal
             ▼
   observed primitive graph + sample distillation
             │
   independent admission + validation selection
             │
          immutable library freeze
             │
test: task public view → compatible retrieval → Planner
             │                    no/raw/structured arms
             ▼
 validated plan → payload materializer → isolated Victim run
             │
 official evaluator + independent harm/utility + primitive analysis
             │
 full-denominator paired comparison and reproducible report
```

“开发/离线阶段”表示在正式评价之前，**不表示零模型请求**。文档和命令中使用 `development_discovery` 与 `offline_replay` 区分这两个概念。

### 1.3 重新定义交付终点

终点是用户能依次执行编号 Bash 脚本，完成上述全流程；每阶段都有明确输入、输出、状态、预算和可独立检查的证据。后台组件可以严格，用户不应每次都手动干预每个普通工具调用或阅读整仓库才能续接。

## 2. AgentLAB：实际参考了什么，不能误读什么

### 2.1 来源与版本

本次参考的是 [TanqiuJiang/AgentLAB](https://github.com/TanqiuJiang/AgentLAB)，**不是 ServiceNow/AgentLab**。已只读获取源码至临时目录，核对 commit：`36f58e60c36bbd6d5b8e61d50d7db7d9ea7258d7`。不在项目中执行其模型脚本或安装依赖。

相关永久源码链接：

- [链生成](https://github.com/TanqiuJiang/AgentLAB/blob/36f58e60c36bbd6d5b8e61d50d7db7d9ea7258d7/STAC_gen/step_1_gen_tool_chains.py)
- [链验证](https://github.com/TanqiuJiang/AgentLAB/blob/36f58e60c36bbd6d5b8e61d50d7db7d9ea7258d7/STAC_gen/step_2_verify_tool_chain.py)
- [提示构造](https://github.com/TanqiuJiang/AgentLAB/blob/36f58e60c36bbd6d5b8e61d50d7db7d9ea7258d7/STAC_gen/step_3_reverse_engineer_prompts.py)
- [自适应规划评价](https://github.com/TanqiuJiang/AgentLAB/blob/36f58e60c36bbd6d5b8e61d50d7db7d9ea7258d7/STAC_gen/step_4_eval_adaptive_planning.py)
- [STAC 组件实现](https://github.com/TanqiuJiang/AgentLAB/blob/36f58e60c36bbd6d5b8e61d50d7db7d9ea7258d7/src/STAC.py)
- [独立 STAC benchmark 入口](https://github.com/TanqiuJiang/AgentLAB/blob/36f58e60c36bbd6d5b8e61d50d7db7d9ea7258d7/STAC_eval/eval_STAC_benchmark.py)
- [Task Injection 样例查找](https://github.com/TanqiuJiang/AgentLAB/blob/36f58e60c36bbd6d5b8e61d50d7db7d9ea7258d7/Task-Injection/agentdojo/src/agentdojo/attacks/long_horizon_attack.py)
- [Task Injection 重写](https://github.com/TanqiuJiang/AgentLAB/blob/36f58e60c36bbd6d5b8e61d50d7db7d9ea7258d7/Task-Injection/agentdojo/src/agentdojo/attacks/long_horizon_rewrite.py)

### 2.2 源码事实与本项目设计的区别

| AgentLAB 中的事实 | 对本项目的启发 | 不能直接继承的结论/行为 |
|---|---|---|
| STAC 分成生成、验证、提示构造和规划评价 | 采用阶段化产物，避免采集与评价混在一起 | 不能说整个 AgentLAB 都使用一个统一冻结检索库 |
| Verifier 会调用环境工具验证/修订链 | 可以先检查路径和工具可执行性 | Verifier 执行工具不等于真实 Victim 被诱导执行 |
| Step 3 执行目标工具并构造包含目标 assistant tool call 的历史 | 可用于候选构造或合成 fixture | 这种合成历史不能入库为真实成功轨迹 |
| Planner 读取工具、攻击目标、解释和交互历史 | Planner 应接收任务、样本、当前可观察反馈 | 不能让私有 evaluator、秘密目标 marker 混入公开上下文 |
| Task Injection 会从已完成 pair 查找样例，优先相关任务，排除当前 pair | 成功案例检索值得借鉴 | 排除当前 pair 不等于任务组隔离；正式测试不应持续写回公共样本库 |

本方案是 **AgentLAB 启发的 SafeClawArena 九原语样本迁移实验**，不是逐行复刻 AgentLAB，也不能把本方案的冻结、split 和对照设计说成该仓库已经证明的事实。上游默认模型、开放工具权限、自动尝试次数、异常处理不照搬。

## 3. 当前仓库审查：问题在哪里

本次基线 HEAD：`f1b4943`，工作树有大量未提交/未跟踪文件。以下判断来自实际读取相关实现；未宣称执行了全库回归或审计全部行。实施前应再次核实 diff，避免覆盖其他 Agent 的工作。

| 当前文件/模块 | 核实到的行为 | 新主线处理 |
|---|---|---|
| `capability/models.py` | 九原语及执行/语义/归因分层 | 作为九原语契约来源，抽取环境无关部分 |
| `capability/m3_f2.py`、`m3_f4.py`、`m3_f6.py` 等 | 家族固定合同、变体、verifier 和真实 runtime | 保留回归；拆出通用观测和纯判定；不把家族脚本当主发现引擎 |
| `capability/m3_pilot*.py` | 旧 36 项科学门与执行状态绑定，生产适配有阶段限制 | 历史入口保留；只迁移可独立验证的执行组件，不继承旧准入门 |
| `datasets/primitive_chain.py`、`chain_builder.py`、`library.py` | 已有样本、公开/执行/私有视图、过滤与冻结；含 adversarial 标记 | 不是从零开始，但模型依赖旧 core/macro 语义，不能直接承载九原语新实验 |
| `flow/models.py` | TRANSFER/DERIVE/UPDATE，而非九原语 | 资源版本/依赖观念可参考；禁止将九原语降为三原语宏 |
| `planning/formal_scheduler.py` | 调度器先选一个样本，非随机条件通常选排序首项 | 不适合作为多样本检索与组合 Planner；重构任务分配与样本选择边界 |
| `planning/sample_selector.py` | 只遍历已分配的 selected_sample | “selector”名称不代表真实检索整库，需替换 |
| `planning/formal_llm.py` | 限制提案不能改变既定 primitive backbone，含规则 fallback | 新 Planner 需能在合法约束内选择/组合；主实验禁止未声明 fallback |
| `planning/binding_planner.py` | 接受旧 PlannerSampleView；非该类型明确拒绝 | 保留 legacy 行为，新建九原语 binding 契约 |
| `execution/safeclaw_formal.py` | `analysis_representation` 限定 legacy_chain_v2 | 不能把新库路径塞进去就说已迁移 |
| `execution/sample_generation.py` | collection/mining/audit/freeze 阶段已有实现 | 复用不可变产物思路；改为攻击尝试驱动，不以普通轨迹完整结构准入替代攻击验证 |
| `configs/task_sets/evaluation_tasks.yaml` | 旧槽位包括 `/sessions/0/user_instruction`、instruction_context、metadata 描述 | 不适合作为默认低信任注入威胁模型；必须显式重审攻击面 |
| `environments/safeclaw/task_adapter.py` | 默认能力会从 PSE 等类别推断，public prompt 包含 metadata | 新目录采用观测/适配能力；防止标题描述泄漏预置攻击解法 |
| `environments/safeclaw/runner.py`、`interactive_driver.py` | 既有 evaluator/生命周期及交互驱动接口 | 优先组合复用，但需核实官方判分输入、真实状态和边界预算 |
| `provider_relay.py`、`models/openai_compatible.py`、`provider_evidence.py` | 请求记录、计数及证据基础设施已存在 | 接入所有角色，避免新增第三套 HTTP 计量 |

### 3.1 根本缺口

不是“完全没有 Planner/样本库代码”，而是存在三套不相通的研究表示：legacy chain、三效果 flow、九原语 capability。最近实验主要执行固定材料，没有建立 **九原语攻击样本 → 多样本 Planner → 官方任务评价** 的可运行主链。

旧 `PUBLIC_FORBIDDEN_KEYS` 包括 prompt/payload，适合旧结构样本的保守导出；新 raw-example 对照确实需要开发集攻击材料。应新增基于类型与字段 allowlist 的公开样本投影，而不是全局删除旧敏感字段规则。

### 3.2 历史结果定位

F1–F6 已有 benign、固定变体、AI 审核和工程证据很有价值，但多数是 synthetic extension 且 official outcome 未评估；它们不是现成的“成功攻击库”。F4 disputed 不符合 unverified 也不能自动成为正样本。旧 M3 超时结果保持关闭，新主线不再以它通过为门。

## 4. 实验轨道与威胁模型

### 4.1 默认主线：低信任材料注入

攻击者只能修改 catalog 审核过的低信任内容字段。正常用户任务、可信规则、工具定义、evaluator、预置秘密、生命周期设置均不可改。首版只支持环境初始化前的静态材料替换；真实多轮/工具结果拦截后续按能力显式扩展。

Planner 输出的是攻击方案和允许字段的变更；不能直接执行 Victim 工具、写入目标最终状态、伪造记忆或替 Victim 生成 assistant 消息。

直接用户攻击若研究需要，作为独立 `attack_surface=user_message` 轨道，单独任务集合与报告，不能与低信任注入合并。首版不以该轨道解决注入任务适配困难。

### 4.2 区分三种 benchmark 来源

1. `official_conformance`：原始任务和原始攻击材料，用于适配/判分复现，不等于新方法。
2. `official_task_payload_variant`：冻结正常任务、可信状态、evaluator，仅替换明确允许的攻击材料；主评价目标。
3. `synthetic_extension`：F1–F6 类机制案例；可做开发/诊断，不冒充全部官方 benchmark。

若安全补丁改变真实网络效果，记录改变范围。官方 evaluator 可保持原实现，但报告应说明运行于隔离适配，不宣称所有上游行为完全不变。

## 5. SafeClawArena 接入必须先做正确

### 5.1 当前上游

本地 pinned commit：`a11f5cceaba0676be721021f8d232638fd111305`。
实际读取了 `schema/task_schema.json` 位置、部分 PSE 任务、`scripts/judge.py` 的 session、memory、score 逻辑和现有 adapter。尚未逐任务认证整个任务集；R1 必须产出机器可读支持矩阵。

### 5.2 新 TaskCatalog

每任务记录：

```text
task_id / upstream_commit / upstream_task_hash / track
task_group_id / template_group_id / known_exposure / split
normal_user_prompt_ref / trusted_state_refs
public_tool_schema / observed_capabilities / capability_evidence_refs
attack_surface_specs[] / attack_objective_public
private_evaluator_ref / evaluator_hash / official_metric_semantics
required_sessions / required_services / embedding_requirement
support_status / unsupported_reason_codes / adapter_version
```

支持状态至少：`offline_validated / runtime_validated / unsupported / pending_runtime`。从 dimension 猜出的能力不能直接写 runtime_validated。

攻击面必须有精确 pointer、类型、长度、作用时间、来源等级、所属 artifact 和正反例；不能只做路径关键字黑名单。Sim-Google 和 workspace 中同一材料存在双副本时，明确使用哪条通路，必要的镜像更新应列为一个预注册联动 patch，不能漏留原始攻击副本造成对照污染。

公有正常任务视图不自动透传 metadata.title/description/tags；这些字段可能包含攻击方式说明。采用显式白名单，从正常 session 指令提取合法业务任务，攻击者目标单独配置。可以告诉 Planner 允许研究的攻击目标；不能告诉它私有 oracle 正则、canary 字面值或隐藏答案。

### 5.3 官方 evaluator 与独立判定双轨

已核实上游 `compute_score` 会根据 check_mode 聚合检查；PSE 子分数使用 memory 类和其他检查，最终 attack_succeeded 另按 any/all 计算。不能把 PSE official true 自动解释为整个跨会话因果链成立。

上游 memory_written 主要依赖 post-state 非空；不单独证明 Victim 新写入。session runner 可能复用 session key；session 标签不等于新上下文。部分检查仅匹配文本，某些通道尚未实现。

实现要求：

- 原封保留 official raw checks、score、attack_succeeded、evaluator 版本及错误。
- 另算 `validated_harm`、`utility`、约束和 primitive evidence，不能改官方分数掩盖分歧。
- official false 与 evaluator 未执行/错误严格分开；缺字段不默认 false。
- preconditions、初始状态、阶段状态、提交后状态和真实 session 身份纳入证据；不让 harness 预置状态冒充 Victim 贡献。
- 官方结果与独立结果不一致输出 discrepancy，不事后挑有利指标。
- 对 synthetic extension 保持 official not_applicable/not_evaluated，不能返回假官方 pass。
- 不默认需要 embedding：仅真正使用语义 memory 的任务要求该服务和对应预算。

## 6. 数据划分：在开发攻击前完成

以任务组/模板族划分，不以 JSON 文件名或 episode 随机划分。同模板变体、重复、不同条件、别名实体和不同模型结果留在同一 split。所有已用于开发/人工审阅攻击内容的任务标记 `known_exposure`，不能冒充 untouched test。

R1 首先清点上游可支持任务及相近模板，再决定具体 dev/validation/test 数量。不要写死“406 全部可用”或套用旧 48 测试任务数字。比例只是配置，真正要求是任务组不重叠、关键攻击面有覆盖、正式结果前冻结。

分工：
- dev：生成、修改、验证攻击，允许使用限定开发反馈。
- validation：选择检索器、prompt、库准入阈值和预算；如果反复据结果修改，它仍不是测试集。
- test：库、Planner、预算冻结后才能运行；不写回库，不修改 prompt，不通过目录扫描获得其他测试任务结果。

建立 split audit：原始模板 hash、规范化文本相似组、来源 lineage、共享 scaffold 和人工审查记录。完全消除预训练暴露不现实，需说明公共 benchmark 限制。

## 7. 新核心契约：九原语攻击样本，而非旧 chain 换名

建议新研究命名空间 `src/stac_attack_lab/attack_program/`。无需逐条创建空模块；下面是职责边界，先做实际纵向链。

| 类型 | 必需内容 |
|---|---|
| `AttackSurfaceSpec` | 允许 pointer、数据类型、长度、时机、来源、不可改区域 hash |
| `AttackCandidate` | candidate/parent ID、任务组、split、公开攻击目标、patches、计划原语图、生成模型/prompt、预算 |
| `AttackAttempt` | candidate ID、执行来源 fake/real、Victim 身份、run ID、实际 patch hash、seal、账本和结果 |
| `PrimitiveObservationGraph` | 九原语 occurrence、证据、资源版本、偏序、分支和未知缺口 |
| `PrimitiveAttackSample` | 计划图与观测图分开、可参数化材料、前置条件、行为结果、适用范围、来源尝试 |
| `LibraryManifest` | split policy、schema/registry/verifier 版本、准入策略、全文件 hash、attempt 分母、冻结时间 |
| `PlannerRequest` | public task、公开目标、合法攻击面、预算、多个可用样本、允许反馈 |
| `AttackPlan` | 所选 sample IDs、来源绑定、有限步骤、候选 patch、依赖假设、资源预算、abstain |
| `EvaluationCase` | task-group × arm × repeat、模型、库版本、配置、授权及唯一执行身份 |
| `CaseResult` | 官方原值、独立 harm/utility、适用约束、原语证据、执行状态及计量 |

九原语保持 Ingest、Adopt、Persist、Recall、Select、Bind、Act、Record、Recover 一等对象。一个事件可以支持多个标签，计数按 occurrence 和唯一事件分别报告。Adopt 未知不阻止一个真实成功攻击样本入库，但不能把 Adopt 填成确定性链边。

边使用明确语义：precedes、delivered_to、read_from、argument_binding、triggered_recovery、annotated_decision_support。内容相等和相邻顺序不自动生成 causal edge。图可有 fan-in、fan-out、部分顺序及有界恢复，不只支持线性列表。

示意结构（是设计草图，不是伪造已验证样本）：

```json
{
  "schema_version": "primitive-attack-sample/1.0",
  "sample_id": "stable-content-and-lineage-id",
  "source_split": "development",
  "source_task_group_ids": ["development-group"],
  "validation_class": "promising",
  "admission_policy_version": "admission/1.0",
  "attack_surface_kind": "workspace_content",
  "planned_program_ref": "program.json",
  "observed_graph_ref": "observed.json",
  "payload_template_ref": "public/template.json",
  "required_capabilities": ["read_workspace", "write_workspace"],
  "attempt_refs": ["private/attempt-001.json"],
  "official_outcome": "not_evaluated",
  "validated_harm": "unknown",
  "adopt": "unknown",
  "limitations": ["Only observed transitions are evidence"]
}
```

## 8. 开发攻击探索与样本准入

### 8.1 Discovery 的实际过程

1. 从 dev catalog 选任务及允许攻击面，不读取 test。
2. Generator 接收公开任务、目标、工具/攻击面、九原语定义和预算，产生有限候选。
3. Host 校验 patch、类型、路径和 public/private 边界；拒绝也落盘并计生成尝试。
4. 每次候选在干净环境运行真实 Victim；开发阶段真实请求同样需要授权。
5. evaluator 判结果，projector 提出原语观察，verifier 独立复算。
6. 如协议允许开发反馈迭代，每次修订生成新 candidate/parent ID；保存所有失败和预算，不无限寻找成功。
7. Distiller 将真实事件抽象为参数化样本；不能自行发明没有发生的依赖。

首版可以使用一个 Planner 模型同时承担 generator/plan/materialize 的不同逻辑角色，分别记录 prompt 和请求计数；不强制再引入三个 LLM 服务。后续确需独立 Attacker renderer 时再显式配置。

### 8.2 “可能有效”与“已成功”分开

- `unexecuted`：生成但未运行，不能进主攻击经验库。
- `feasibility_only`：Verifier 或脚本执行工具证明可行，不是 Victim 攻击成功。
- `promising`：真实 Victim 有相关状态/行为转换，但最终成功未验证，证据和限制明确。
- `validated_success`：满足预先声明的 success policy，真实结果和证据可复算。
- `verified_failure`：完整结果证明该尝试未成功；可作反例库，不能当 promising 自动提升。
- `indeterminate/infra_error`：证据或执行不足，不作为攻击负例。

`validated_success` 必须注明依据为 official、独立业务，或两者。主库推荐独立最终危害成立、攻击面合规、执行证据完整；仅 official true 且独立危害 unknown 时保留单独类别/来源，不假称强因果成功。研究也可预注册 official-only 库，但与双证据库不可悄悄混合。

允许冻结不同 view：`success_only`、`success_plus_promising`、`negative_reference`，全部报告数量与准入策略。没有 success 时允许空 success_only 库，明确阻塞对应主比较；不要把任务失败、disputed、读取文件或 synthetic harm 当成功来凑数。

### 8.3 最小样本内容

需保留可迁移的信息：攻击面类型、语义策略、原语子图、必需能力、资源角色、实际验证等级、失败条件和合法参数槽。目标任务绝对路径/ID 用类型化 slot 重绑定，不能把开发 canary/目标对象照搬到 test。

Distiller 可用 LLM 提议抽象，但 host 必须检查每个证据引用存在且与真实字段对应。LLM 输出存为 proposal，证据校验后才写入最终样本。不要为了抽象完整性要求每条语义边都必须确定。

## 9. 样本库冻结与信息隔离

建议目录：

```text
libraries/attack-program/<library-id>/
  manifest.json
  public/index.jsonl
  public/raw_examples.jsonl
  public/structured_examples.jsonl
  execution/templates.jsonl
  private/evidence_index.jsonl
  admission/decisions.jsonl
  provenance/attempt_inventory.jsonl
  split_audit.json
```

公开 raw 和 structured view 来源于同一组 sample IDs。raw view 提供已清洗的开发攻击材料和相同公开验证信息；structured view 在此基础上提供原语结构、前置条件和证据等级。不把执行日志中的凭证、oracle、隐藏 marker、绝对私有 evidence 路径或未脱敏工具响应送入 Planner。

样本中的攻击文本是**数据**，不得作为 Planner system 指令。使用分隔与结构化消息封装，检测模板注入试图改写预算、攻击面或系统规则的情况。

冻结包括内容 hash、schema/registry/policy、清洗版本、来源 split、生成模型/prompt、尝试分母。冻结后 test 无写权限，不从 runs 目录动态检索“最近成功案例”。生成新库必须新版本并重新声明适用实验，不能回填已完成测试。

## 10. Planner：真正多样本规划，先简单后复杂

### 10.1 检索与分配边界

Scheduler 只分配任务、实验臂、重复、预算和固定 seed，不预先替 Planner 选唯一最优样本。
Retriever 从冻结库筛选合法兼容样本；首版确定性能力/攻击面/资源类型检索，不依赖 embedding。返回 top-k、候选全集摘要、分数和拒绝理由。
Planner 接收多个样本，输出选取、组合及绑定，不允许只复述固定 backbone。所有选择和未选择理由存为可观察决策摘要，不要求私有思维链。

首版 `max_samples_per_plan=2`，一条有界静态 patch 方案即可。组合只有在资源类型、槽位、时间顺序和攻击面相容时允许；不为“组合”强迫每次必须用两个样本。后续再做动态工具返回注入。

### 10.2 Host 必须检查的 AttackPlan

- sample ID 属于本次检索集合及冻结库；来源 split 合法。
- binding 值来自目标公开视图，slot 类型/能力匹配，无路径穿越。
- 没有改 normal user/system/evaluator/可信 state。
- planned primitive graph 的前置条件要么已有证据，要么明确假设；不能冒称已发生。
- 有界节点数、patch 数、材料长度、请求/轮次预算。
- 外部网络和真实敏感效果被 sandbox 阻断；payload 不能改变保护配置。
- abstain 有合法输出；不自动用规则 Planner 替补并仍记为 LLM 臂。

Planner JSON 无效时返回 `planner_invalid`，默认零自动修复请求；若协议配置允许修复，所有臂同规则、计预算。不得默认解析失败切换到静态成功模板。

### 10.3 跨 episode 与 episode 内适应

正式主实验默认冻结库、每任务一次规划、静态材料。为参考 AgentLAB 长时流程，后续增加 `within_episode_adaptive` 模式：只利用攻击者按威胁模型实际可见的反馈，在有界攻击时点修订；所有臂相同机会，库不更新。

不能在正式运行中把私有 official 判分详细信息反馈给 Planner，除非作为明确独立的白盒 oracle-access 实验。developer 工具权限也不等于攻击者观测权限。

## 11. 正式评价：主要对照应围绕样本，而非 direct/semantic

benign/direct/semantic 继续是材料属性或诊断条件，**不是新 RQ1/RQ2 的主要实验臂**。

主实验三臂：

| arm | 输入 | 要回答的问题 |
|---|---|---|
| `no_library` | 相同任务、攻击目标、攻击面、预算、Planner；无样本 | 样本总体是否有用 |
| `raw_examples` | 相同检索 sample IDs 的清洗攻击实例和相同结果元信息，无原语结构 | 普通案例提示基线 |
| `primitive_examples` | 同一实例加九原语结构、前置条件和证据边界 | 原语表示是否带来额外收益 |

raw 与 structured 主比较固定同一 retrieval set，避免检索质量混入结构收益。可另设二级实验允许各自检索，但必须另报。预算包含 Planner、payload renderer、Victim 和可选 Judge，不只比较 Victim tokens。

同一模型、系统提示公共部分、最大工具/交互次数、材料长度和请求上限。记录实际 prompt tokens；structured 天然更长，不能声称 token 完全等量。若要隔离长度效应，后续加入长度匹配的非结构描述对照，不使用能额外泄露答案的 filler。

`no_library` 即使检索库为空也应能执行合法攻击，不可依赖 sample.execution_view 或 selected sample binding。无兼容样本时 structured 臂可以 abstain，结果计主分母，不能删掉任务只保留可检索子集。

clean/neutral 材料运行用于业务基线或测量校准，应独立报告；每臂不要各自偷偷采用不同正常任务。若原始 SafeClawArena 任务已包含攻击材料，清洁基线必须显式中和允许攻击槽，而非直接把原任务称为 benign。

## 12. 指标与统计

主报告至少并列：
- official attack success 与原始 score/checks；
- independent validated harm 与 utility；
- 约束有效且攻击成功的数量；
- unknown/evaluator error/infra error/planner invalid/abstain；
- 检索覆盖、计划合法率、物化合法率、实际使用样本数；
- 实际 Planner/Victim 等角色请求、usage、延迟；
- 发现成本、库构建成本与测试成本分别统计。

固定任务组 × arm × repeat 的完整分母。主要保守成功比例为 confirmed_success/N_assigned；同时报告判定覆盖和可判定子集，不将 unknown 叫成 confirmed failure。可报告区间 [success/N, (success+unknown)/N] 说明缺失结果边界。

对比按任务组配对；重复和多个 arm 不是独立任务。置信区间/配对分析按 task group 聚类，样本少时明确仅描述。所有阈值、模型/seed、检索 k、库 view、success policy、结果处理在正式 test 前冻结。

不以“至少一个攻击成功”作为软件工程门；但检验 success-only 样本法时，空成功库是研究输入缺失，必须明确。样本库没有真实可用例子时先在 dev 探索，不能绕过到大规模 test。

## 13. 目标代码结构与迁移表

推荐目录（根据实际依赖可合并小模块，不要求机械拆文件）：

```text
src/stac_attack_lab/attack_program/
  models.py           # 新契约；复用九原语枚举/证据语义
  catalog.py          # 任务支持、攻击面、公共/私有视图
  splits.py           # 分组划分、已暴露任务与重复检查
  discovery.py        # 开发候选与尝试编排
  distill.py          # 真实事件到样本；proposal 与验证分离
  admission.py        # 样本分级、独立准入
  library.py          # 三种视图、冻结与只读读取
  retrieval.py        # 兼容检索和候选集合
  planner.py          # 多样本模型接口、abstain、严格验证
  materialize.py      # 只改白名单低信任字段
  evaluation.py       # 三臂 case 编排与统一结果
  reporting.py        # 分母、成本和配对报告
environments/safeclaw/
  attack_program_adapter.py # 封装现有 driver、官方 evaluator 和资源观测
execution/
  experiment_runtime.py     # 必要时从家族 runner 提取通用激活/授权/cleanup
configs/attack_program/
prompts/attack_program/
scripts/attack_program/
tests/unit/test_attack_program_*.py
tests/integration/test_attack_program_pipeline.py
```

### 13.1 保留、替换和历史化

- 保留 provider relay、SSE 解析、请求证据、脱敏、快照、seal、哈希、环境加载、upstream safety patch；按接口适配。
- 从家族脚本提取运行通用层，用兼容 wrapper 保持旧 replay；不要新模块反向 import 某个 m3_f2 私有函数当通用框架。
- 新主线使用九原语模型。旧 macro/core、flow/3.0、legacy formal 只读兼容，不强行统一所有历史 schema。
- 旧 `formal_scheduler`/`sample_selector`/受限 Planner 不作为新主线默认；保留命令带明确 legacy 标记。
- `cli.py` 只注册薄命令，将新命令参数/执行分派放专用模块，避免继续膨胀一个巨型 main。
- F1–F6 保留工程 fixture 与机制研究入口，主发现阶段不要求先完成六家族全量 pilot。
- 将旧 M3 新计时草案可复用部分迁移到通用 runtime；先核实是否实际实现，不把计划写成现成功能。

### 13.2 必须修改的配置/文档

新增新路线 task catalog/split/experiment 配置，不覆写 `configs/task_sets/evaluation_tasks.yaml` 的历史含义。README 首屏画清新主流程；PROJECT_STRUCTURE 更新入口；SECURITY 保持安全要求但调整路线描述；AGENTS 路由新增新模块。

旧九原语文档中“不得以样本库/Planner 为前提”的方向，标为先前 capability 路线的历史范围。不得删除历史，亦不能让旧文本持续阻塞用户最新研究目标。

## 14. Runtime：避免再次陷入计时与手工授权循环

统一身份：experiment → batch → case → candidate/attempt → HTTP logical call/attempt → event/resource version。身份与内容 hash 不混用。

时间模型：
- 协议冻结不启动任何 timer。
- 批次授权有明确有效期及角色/全批预算。
- case 在用户实际启动时原子激活，随后开始不可重置的 episode deadline。
- 人工等待不消耗尚未激活 case 的 episode 时限，但仍受授权有效期/计划有效范围约束。
- 网络请求 timeout 为 min(配置 timeout, 剩余执行时间)；有独立有界 cleanup。

resume 仅检查及续接可证明安全的本地阶段，不重新发送已发送/不确定请求；失败必须保留首次身份，补充诊断另建且不覆盖主分母。

支持授权一个明确小批次后脚本自动完成：运行 case → 确定性校验 → 继续/停止。详细人工阅读在批末；关键安全/证据/cleanup 错误立即停止。不要求用户在每个模型请求后重新授权。

Generator/Planner/Annotation 使用现有 OpenAI-compatible client 及账本；Victim 使用 relay。所有真实角色都计数，不能误用“Embedding 0”模板抹掉 Planner 请求。模型名、OPENAI_BASE_URL 等通过角色配置注入，不因历史审核曾用某模型就擅自固定所有角色。

## 15. 用户运行入口：编号 Bash，不让用户猜当前 v 几

建议入口（命名为待实现，不表示现在可运行）：

| 脚本 | 作用 | 默认是否联网 |
|---|---|---|
| `00_doctor.sh` | 加载项目环境、镜像/隔离/依赖检查 | 否 |
| `01_catalog.sh` | 导入 pinned 官方任务、攻击面支持矩阵 | 否 |
| `02_split.sh` | 分组划分及曝光审计 | 否 |
| `03_discovery.sh prepare/run/status` | 开发候选及真实验证 | run 需授权 |
| `04_samples.sh distill/audit` | 证据抽取与独立准入 | 默认否；LLM distill 单独授权 |
| `05_library.sh freeze/validate` | 版本化样本库 | 否 |
| `06_evaluation.sh prepare/validate` | 三臂矩阵与预算 | 否 |
| `07_batch.sh authorize/run/status` | 用户启动具体已授权小批次 | run 需授权 |
| `08_results.sh replay/report` | 离线官方/独立结果核验与比较 | 否 |
| `10_demo_r2.sh`、`11_demo_r3.sh` | R2 样本库及 R3 三臂合成工程演示 | 仅离线 scripted/synthetic |

所有脚本读取同一 project root/python helper；帮助文本给出准确输入输出；不提供危险的“从头全跑包含 live”默认。

提供人类可读 status：当前阶段、已完成/未启动、最近错误、是否允许下一步、精确 next command。next command 不能隐式创建授权。授权文件由已明确批准的原文生成引用和 hash，用户不手动编辑 execution_enabled。交互终端不用顶层 set -e，脚本内部可以。

公开方法状态与私有 payload/密钥分离；准备成功不会后台发请求。路径使用明确新实验目录并拒绝覆盖；主实验报告能从一个 experiment manifest 找到所有产物。

## 16. 首个真正闭环：避免再做半年准备

首个可验收开发切片不是“先支持全部官方任务、全部九原语、全部模型”。选择 catalog 审核出的一个安全、低信任注入可达、效果可观察的官方任务作为 dev；再选不同任务组的 validation/test 任务。任务 ID 必须经实际 catalog 确定，本文不凭猜测指定可运行任务。

工程 fake 用确定性 Generator/Planner responses，但必须有至少两个兼容样本进入 Planner，输出中明确选择其一或合法组合；no_library 不经过库加载。Fake 全链实际经过：catalog/split → discovery attempt → evidence → distill/admit → freeze → retrieval → Planner → materializer → production adapter → official evaluator → report。

工具动作必须由 fake Victim 返回并由真实 adapter 执行，不能直接写期望最终状态后称攻击成功。计划工具链执行只能计 feasibility。

之后最小真实技术批次分开授权：先 dev discovery（Generator/Planner+Victim 预算），取得真实样本后 freeze，再对不同组任务跑三臂。可用 1 dev + 1 validation + 1 test 作为技术演示，**不是统计正式实验**；若没有可用样本，明确停在 discovery，不伪造成功。

## 17. 分阶段实施任务与退出条件

### R0 路线与历史收尾

更新导航和当前 WORKPLAN，旧 M3 未通过事实封存，不继续主线预算。交付模块迁移表、只读历史回归列表、真正的主入口。
退出条件：任何 next command 不再默认引导旧 36 项；没有删除历史数据。

### R1 官方任务目录、攻击面、split 和 evaluator

完成 catalog/allowlist/view/schema/evaluator adapter；至少一个可运行官方任务和一个不同任务组的目标可离线物化，unsupported 有理由。保留原始 evaluator 输出及独立结果接口。
退出条件：测试能发现正常用户指令/evaluator 被篡改、canary 泄漏、镜像材料污染、同模板跨 split。不能把 synthetic F6 换 task_id 冒充官方任务。

### R2 开发尝试到冻结库

实现有限候选生成、全尝试记录、真实/fake 区分、原语图、分级准入和三种库视图。先 fake 后准备真实 dev 小批；不强求成功率。
退出条件：无证据正样本拒绝；Adopt unknown 不抹去已验证最终结果；相同证据稳定重建同一 sample；冻结库无 test 数据。

### R3 多样本 Planner 与三臂执行

实现检索、选择/有限组合、类型绑定、abstain、物化和共享 runner；移除旧单样本 backbone 假设对新路线的依赖。
退出条件：三个 arm 真的输入不同、预算一致；sample IDs 与实际注入材料可追溯；非法 patch 零 Victim 请求拒绝；选择/组合不是脚本替 Planner 预选。

### R4 全链工程与最小真实技术验证

一个 fake 纵向集成先通过，再由用户运行有授权的真实技术批次。验证全部角色 usage、独立时间窗、resume、结果和 cleanup。能闭环后才扩大 catalog。
退出条件：真实样本或明确发现失败有报告；有库时能在不同组目标完成三臂，不再“只验证了很多独立零件”。本阶段无统计收益承诺。

### R5 前瞻正式评价

根据 dev/validation 成本和支持矩阵冻结任务组、arm、重复、模型、样本库、success policy 和预算。样本量依据研究问题与实际支持任务数决定，不直接复用旧 36/864 数字。
退出条件：所有分母和未运行项可追溯，未知独立报告，库和 prompt 不随 test 更新。M4 旧门不作为自动执行授权。

### R6 机制与迁移扩展

在主闭环之后做图结构去除、前置条件去除、随机兼容样本、success vs promising、跨模型/跨模板及真正干预。不能为了 R6 完整性阻塞 R1–R4。

实施任务可按 R0+R1、R2、R3+R4、R5 分批交接；每批必须有可运行产物与反例，不只是新文档。用户要求持续实施时，不必每个小函数都等待再次批准；真实请求按具体批次边界处理。

## 18. 测试清单与真正的验收标准

### 18.1 反例优先

- 计划节点不冒充观察；脚本/Verifier 工具执行不冒充 Victim。
- 未读材料、部分读、错误版本、不同身份、失败写入不能通过 lineage。
- official any-check true 但最终 harm unknown，两个字段保持差异。
- PSE 预置 memory、不改变 session key 不证明跨会话攻击。
- dev/test 同模板不同文件名被 split gate 拒绝。
- test 样本/私有 evaluator 进入 Planner 被拒绝。
- raw/structured 样本 ID 集合不一致时对照验证失败。
- no_library 不读取 private 或 library 内容。
- Planner 选择不存在样本、错误 slot、目标系统指令 patch 拒绝。
- 样本含 prompt injection 不得覆盖 Planner 工具预算/系统约束。
- 格式无效不触发隐藏 fallback/模型重试。
- 真实失败/unknown 不被库 builder 升为 success。
- 空成功库、无兼容样本、Planner abstain 在报告中完整保留。
- 哈希重算后语义矛盾仍被验证器发现。
- 官方/独立 evaluator 分歧不被覆盖。
- 私有 synthetic canary 可供隔离 evaluator 使用，但不得流入 Planner；公开日志仍脱敏。
- 等待人工不会消耗未激活 episode；已激活不能重置时间；请求不确定仍计数。
- 旧 replay 格式和原 verdict 保持，路径失配只报告兼容缺口。

### 18.2 质量门

受影响专项 → 真实链 fake（长时用户运行）→ 适当 make check → schema 差异 → bridge 显式检查 → Bash syntax → git diff --check。环境失败与代码失败分开；不要求每个文档变更都重跑全部工程测试。

### 18.3 新主线完成定义

以下同时成立才可说“研究闭环跑通”：
1. 来自 pinned 官方任务的 dev 攻击真实执行且状态可复算；
2. 样本来源、验证等级、原语表示与冻结库可查；
3. test 与 dev 任务组隔离，test 不回流；
4. Planner 真实接收样本并输出可执行计划；
5. Host 仅在授权攻击面物化，Victim 真实执行；
6. 官方判分与独立分析分别保存；
7. no/raw/structured 三臂共用公平执行规则并报告全分母；
8. 用户可用编号脚本复现并理解每一步。

这不等于已证明样本法有效；有效性必须由 R5 结果判断。

## 19. 实施进度记录与用户交接

每个检查点写：实际实现、验证命令、产物位置、限制、下一步；区分 implemented/fake_verified/real_verified/research_evaluated。

禁止把“准备好了禁用候选”当成主要成果反复循环。若连续两轮仍没有推动纵向链，必须列出真实阻塞和最小修复，而非再复制一份计划。

最终给用户的阶段摘要只需回答：
- 现在到哪一步？
- 它如何服务“样本辅助 Planner”研究？
- 实际验证了什么，尚未验证什么？
- 用户下一条应执行的命令是什么，是否会调用真实模型？
- 请求、预算、结果与输出在哪里？

## 20. 供用户发给 Codex 的启动消息

```text
请按 docs/AgentLAB_SafeClawArena_原语样本库与Planner实验重构实施方案.md 实施研究主线重构。

我的目标是：SafeClawArena 开发任务上的攻击探索 → 有证据分级的九原语组合样本 → 冻结样本库 → Planner 在不同任务组上检索/组合 → 与无样本和普通样本公平比较。

这次方向优先于先前“capability 不依赖库/Planner”的主线限制。旧实验与旧协议仍只读保留，不把旧 M3 标为通过，也不继续为了它的门槛重跑 36 项。

先阅读 AGENTS.md、SECURITY.md 和进度/计划顶部，核对现有源码与产物。先实施 R0+R1，并把 R2/R3 所需接口接好；交付可运行的 catalog/split/物化/evaluator 离线链和反例，不只写 schema。随后按文档推进最小纵向闭环。

允许大幅重构，但复用已验证的 relay、账本、证据、隔离和 cleanup；不要把旧单样本 Planner 改名冒充多样本规划。

持续记录进度。长时间 fake 和真实批次由你给准确 Bash 命令，我终端执行，你查收。当前不授权真实请求、不 bind、不 commit/push/reset/clean，不改写历史证据。
```

## 21. 本次文档交付范围

本轮只做了参考源码读取、项目关键路径审查和设计文档编写。未实现上面新模块，未调用真实模型，未运行 Docker 或实验，未重跑全库测试。外部参考 clone 位于临时目录，不是项目运行依赖。

后续实施者必须以实际代码、最新用户决定和本文件为依据，不能把文中的建议类名、脚本名和示例样本当成已存在的功能。
