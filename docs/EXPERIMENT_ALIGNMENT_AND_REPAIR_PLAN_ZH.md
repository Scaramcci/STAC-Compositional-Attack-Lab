# STAC 实验思路对齐、代码审查与服务器修改计划

日期：2026-09-06  
用途：交给服务器上的 Codex 执行修改；本文不是“修改已经完成”的报告。  
审查基线：Git HEAD `396b0eec8a621ffffe5a215dd5ee70eaeab6e4ae`，加上当前工作区此前完成的方舟 embedding 适配及测试修改。  
SafeClawArena 固定版本：`a11f5cceaba0676be721021f8d232638fd111305`。  
本轮范围：阅读源码、执行不联网的最小复现、撰写本文；不修改实现代码，不运行攻击实验，不修改旧样本标签。

## 0. 给执行 Codex 的首要指令：先规划、持续落盘、支持中断续接

**开始修改实现之前，必须先创建 `docs/IMPLEMENTATION_WORKPLAN.md` 和 `docs/IMPLEMENTATION_PROGRESS.md`。**

本文是研究目标和问题清单。服务器 Codex 应先核对实际 checkout、已有修改和运行产物，再写自己的可执行工作规划；不能直接跳进代码修改。工作规划须引用本文，列出文件级任务、依赖、验收方法、迁移方式和尚待证实的假设。文件已经存在时先读取并续写，不能覆盖历史。

执行规则：

1. 先记录 Git commit、`git status --short`、Python 环境、upstream commit、镜像 ID、可用运行产物目录；不记录密钥或 `.env` 内容。
2. 阅读服务器的 AGENTS.md；把本轮用户已明确授权的科研 benchmark 范围与仓库约束一起纳入规划。不要重新误解为攻击真实网络对象，也不要因旧文档的成功样本阈值而拒绝修正该阈值的语义。
3. 使用本文的任务编号 W00–W10；每个任务状态只能是 `pending / in_progress / blocked / verified`。写完代码不是 verified；通过对应验收并记录证据才算。
4. 每完成一个子任务、发现新问题、改变设计或执行重要测试后更新进度。每次模型上下文接近耗尽、转交或停止前，必须写清下一条可执行动作；不能只在聊天中记录。
5. 长测试或真实实验启动前，先记录命令、run ID、日志目录、进程或 tmux 会话、预算与终止条件。命令用占位变量引用凭证，不把密钥写入文档、命令行参数、Git 或日志。
6. 将工作拆成可验证的小批次；保留用户已有修改，禁止用 reset/clean 覆盖。若需要提交，按当前用户对 Git 操作的授权执行，至少记录本批文件列表与 diff 摘要。
7. 中断后先读本文、工作规划、进度记录和 Git diff；检查上次进程是否仍运行、哪些检查有新鲜结果。禁止重新启动同一计费实验或把旧产物误当作新版本成功。
8. 旧数据永不原地重写。解析/采集协议改变要增加版本号，写新派生产物并保留源 run 的 hash。缺失的历史观测不能通过 LLM 补写为事实。
9. 不得把“样本数达到 2/30”“攻击成功”当作修复完成的替代证据；不允许为了验收制造 accepted、改官方 verdict、删掉真实失败。

建议进度文件至少包含：

```markdown
# Implementation progress
Updated: <UTC 时间>
Baseline commit: <hash>
Current branch / worktree: <值>
Scope / current design version: <值>

## 当前状态
- 当前任务：Wxx / 子任务
- 已完成并验证：<任务、文件、测试、日志或提交引用>
- 正在修改：<文件、已改到哪里、尚未验证的内容>
- 未完成：<按依赖排列>
- 阻塞：<证据、影响范围、可继续的独立工作>
- 设计决定：<原因、替代方案、是否改变实验语义>

## 下一次从这里继续
1. <可直接执行的一条动作>
2. <其后检查>

## 最近验证
| 命令/实验 | exit code / 结果 | 代码版本 | 产物路径 | 能证明什么 / 不能证明什么 |
|---|---|---|---|---|

## 正在运行的任务
<run ID、进程、tmux、日志、是否调用计费 API、如何查询/恢复>

## 变更日志（追加，不覆盖）
- <时间> Wxx：<改动、证据、下一步>
```

## 1. 应当实现的实验，而不是沿用当前代码的隐含定义

### 1.1 用户确认的目标

这是在受控、可靠环境中的科研攻击实验。离线采样阶段和正式 evaluation 都使用 **SafeClawArena benchmark 及其环境**，不是对生产系统或真实对象的攻击，也不是只用自行编写的 JSON fixture 代替真实 benchmark。

两阶段如下：

```text
离线采样：SafeClaw task / 场景
  → 人、Construction Agent、Victim Agent 与环境的实际交互
  → 保存原始观测
  → 抽取信息流、状态流、控制流 primitive 实例及依赖
  → 得到可复用的 primitive 路径 / 依赖子图 samples

正式验证：SafeClaw 公开任务 Prompt + 一条指定 sample
  → Planner 生成面向当前任务的攻击计划
  → Attacker 通过该任务允许的注入面执行、观察和调整
  → Victim 在 benchmark 环境完成原有任务
  → SafeClaw 官方 verifier 评估结果，另做 primitive 机制验证
```

“离线”是相对正式 evaluation 的采样/建库阶段，不表示不能调用远程模型 API。样本采集和样本后的本地重解析，也不是一回事。

### 1.2 Collection 与 Mining 为什么可以分开

- **Collection** 记录发生了什么：人的输入、Agent 的输入/输出、工具请求/返回、附件/文件/记忆的内容版本、状态变化和会话边界。
- **Mining / extraction** 把记录转换为结构：primitive 实例、源/目的组件、artifact 版本、依赖边以及可重用路径。
- 一个对话回合可能包含零个、一个或多个 primitive；一次 episode 可以产出多条路径。一段聊天文本本身不能证明 memory 被写入，也不能证明下一轮真的读取了 memory。
- 保留两个内部阶段有助于修改解析器后重用昂贵交互数据、审计证据、避免重复调用 API。**用户入口应允许“采集完成后自动抽取”，不必手工连续执行多个命令。**逐条抽取和全部采完再抽取应得到同一版本下的一致结果。

因此问题不是“存在 Mining”本身，而是当前 Mining 和 acceptance 把 sample 限定成了某类已经达成终点的攻击链。

### 1.3 什么才是 sample，什么才是 accepted

本计划采用的目标语义：

> sample 是从实际观测抽象出来、具有可追溯证据的 primitive 路径或保留必要依赖的子图。sample 可用性、交互完成度和攻击是否成功，是三个独立维度。

例如：附件被读取 → 内容写入 memory，即使后续 Victim 拒绝某项操作，也可以留下前面这条有证据的路径。用户输入 → 工具请求 → 工具拒绝，同样是有价值的阻断路径。不能把“正常流程或未成功攻击”自动等同于“无效数据”。

建议拆分标签，实际字段名由 W01 定稿：

| 维度 | 建议取值 / 含义 |
|---|---|
| `trace_status` | complete、partial、error；表示采集进程情况 |
| `structure_status` | valid、partial、invalid；表示节点和引用结构 |
| `evidence_status` | observed、inferred、insufficient；推断不可升级成直接事实 |
| `sample_status` | usable、quarantined；满足定义且可追溯才 usable |
| `behavior_outcome` | allowed、blocked、error、unknown；具体行动结果 |
| `official_attack_outcome` | success、failure、not_evaluated、error；由官方评测产生 |
| `attack_relevance` | 研究上的相关性标签，不能取代事实证据 |
| `evaluation_eligibility` | 对某任务/接口/预算是否适用，和“是否可入样本库”分离 |

`accepted` 如保留兼容名称，应明确等价于“通过样本结构与证据规则”，而非“攻击成功”。原始记录即使不足以建链也必须留存。正式选择可以使用有证据的路径，但必须预先固定是否使用部分路径/阻断路径的选择策略，并在结果中分层报告。

### 1.4 Primitive 的“最小不可分”要落实到可观察粒度

不能声称现有 TRANSFER / TRANSFORM / MUTATE / CONTROL 四个 family 就是四个不可分原语；它们是分类。应定义在当前观察接口下不能再拆的**一次动作或状态转换**，并保留 actor、source、destination、输入/输出 artifact 版本、时间、工具调用 ID、作用域、结果与证据。

一个模型“回复”不自动等于 `extract`；一个工具请求被成功发出，不自动等于工具目标成功；看到 memory 文件存在，不自动等于它被检索进上下文。把一项工具调用拆成请求发出、工具处理、结果返回、具体读写效果，并按证据关联。

宏如 Ingest / Persist / Recall 是可选解释层，不能反过来要求所有样本长成 Ingest→Persist→Recall→Bind→Act。分叉与汇合需要图；给 Planner 的“一条链”可以是选定路径，但必须携带它依赖的必要前驱/支撑子图，不能丢掉 ALL/ANY 等条件。

## 2. 证据范围与本次最小复现

### 2.1 有哪些证据，没有哪些证据

已审查：collection/bridge、normalizer、occurrence extractor、chain miner/filter、sample builder/library、planner/binding、formal attacker/action loop、formal bridge、mechanism verifier、task configs、pinned upstream judge 与 PSE task，以及此前新增的模型适配。

本机 `data/` 和 `experiments/` 只有说明与 `.gitkeep`，**没有服务器失败 pilot 的 raw trajectory、source events、filter decisions 或运行日志**。不能据此断言上次服务器运行的唯一根因。服务器 W00 必须取回原始证据，并核对当时的 commit；如果当时代码不同，要明确区分。

此前 119 个测试通过，包含大量 synthetic fixtures；这不等于真实 collection 能产出有效 sample，更不等于研究设计正确。

### 2.2 本次已执行的无网络最小复现

使用当前 `SafeClawSubprocessVictimDriver.apply()`，只将 `_send_bridge()` 替换成预设返回，**没有手写理想 primitive 图**。预设过程：

1. s1：提交文本，返回一次 memory 写工具调用；memory 从空变为 synthetic note；usage 可见。
2. 发出 start_new_session。
3. s2：提交文本，返回一次模拟工具调用；memory 保留，sim_google_calls 从空变为一条记录。
4. 将该 driver 真正生成的 source_events 交给真实 normalizer、extractor、miner、filter。manifest 设为 completed、adversarial_trace，能力和 split 满足规则。

观察结果：

```json
{
  "evidence_kind": "synthetic_bridge_projection_not_historical_run",
  "events": 10,
  "edges": 6,
  "occurrences": 10,
  "unresolved": {},
  "accepted": 0,
  "negative": 2,
  "candidate_paths": [
    ["external_ingress", "extract", "request"],
    ["external_ingress", "extract", "request", "external_effect"]
  ]
}
```

失败原因：两条路径均有 `candidate_occurrence_not_hard_pass:<tool request>`；第一条另有 `terminal_predicate_missing`、`terminal_relation_not_observed:partial`。图中确实出现 memory_write→memory_retrieve 的 state 边，但该支路未连进入口到终点的路径。

这证明：**即使 normalization audit 没有 unresolved，当前真实采集投影与 acceptance 之间也存在结构性矛盾。**不能仅靠增加 collection 次数、换更强模型或增加 token 预算来解决。

复现是适配层回归证据，不是实际 Victim 行为或历史攻击成功证据。执行方应把以上步骤做成永久回归测试，预期新的语义能保留确有证据的片段；绝不能把模拟中的“memory 有内容”保留为“实际 recall 已证实”的判据。

## 3. 审查发现：按优先级处理

下列定位以基线文件/函数为准；实现者应使用符号搜索，行号会随此前修改变化。P0 表示影响研究有效性或核心数据链路，P1 表示可靠性/覆盖度。

### F01 / P0：有效路径被“已完成攻击终点”门槛排除

定位：`extraction/filtering.py:filter_chain_candidate`（G1、G5），`datasets/chain_builder.py:build_primitive_chain_sample`，`execution/sample_generation.py:mine_sample_collection`。

当前要求每个 occurrence 是 passed+hard_fact，manifest 必须 completed，必须 adversarial_trace、tainted ingress、terminal_relation=observed，且无 shortcut。sample builder 只接收所有 gate 通过的候选；ordinary_trace 甚至会在 mining 的 manifest 检查处被拒绝。代码中的“终点 observed”是自定义终点，不等于官方 attack_succeeded。

修改方向：按 1.3 拆分数据质量、观察结果与攻击结果；保留正常/阻断/部分执行中的有证据路径。端到端攻击机制验证仍可严格，但它不是所有 sample 入库的前提。

### F02 / P0：真实采集器将所有工具调用固定为 attempted

定位：`interactions/safeclaw_collection.py:SafeClawSubprocessVictimDriver.apply`，原约 636–652 行；`extraction/filtering.py` occurrence gate。

所有 tool_call 被标为 attempted，extractor 原样传递；过滤器要求全部 passed。能到达 external_effect 的常规候选路径会经过这个 request，从而被拒绝；没有工具调用时，external state diff 又没有 request 依赖可以连回入口。本次复现确认这一点。

修复不能简单地把全部 attempted 改成 passed。应分别定义“请求已观察/已派发”“工具成功/拒绝/异常”“目标效果已证实”；匹配真实 tool_call_id/result，并使链条可表达失败结果。

### F03 / P0：memory 的输入/输出关系断裂，同时伪造了 recall 的确定性

定位：同一 `apply()` 的 memory retrieval（约 580–607 行）、response（608–635）、state_specs（654–690）。

- memory_write 只有前后 hash 和 state_ref，没有输入 artifact、工具因果来源或输出内容版本；入口/回复与写入没有可追溯连接。
- 新会话后只要 post_state.memory_content 非空就合成 passed 的 retrieve。文件存在并不证明 Agent 实际读取。
- recall artifact 没有 parent lineage；后续 response/tool 的输入又只绑定当前消息或最终回复，导致 recall→使用路径断开。
- 所有最终回复都被命名为 extract_victim_response，并把当前消息设为 parent；这不是内容抽取的真实证据。

修复：从实际工具事件、记忆检索返回及上下文注入记录构造关系；有文件快照就只能声明文件存在/变化。不可见的内部使用标 unknown。不要用预期 plan、时间相邻或一次 hash 差异补造数据依赖。

### F04 / P0：采集入口与 benchmark 的真实注入面不一致

定位：`interactions/construction.py:ConstructionAttackerAction`、`integrations/safeclaw/construction_bridge.py:main`、`configs/task_sets/construction_tasks.yaml`。

动作类型主要是 deliver_message/new_session/retry/reroute/stop；bridge 把 delivery 统一转成 `user_instruction`，没有根据 delivery_surface 实际写入邮件/附件/MCP tool 返回。retry/reroute 主要记录控制事件。把一个正常用户请求直接标为 untrusted ingress，会混淆上层用户授权与下层恶意内容入口。

修复：为 task 声明真正可编辑的 lower-trust artifact/工具返回位置，明确角色；人和 Agent 的输入用同一动作日志。保持 benchmark 的合法用户任务，除非该 task 明确允许攻击者控制该用户消息。人可提建议、选择场景或提交授权内容，但不能在日志外修改受测状态。

### F05 / P0：collection 没有保存足够的原始事实，异常会丢掉已发生的交互

定位：`interactions/collector.py:_write_collected,collect_interactions`；driver 的 `finish/abort`；construction bridge 的 `finish`。

- 大部分数据在整个 collect 返回后才落盘；中途异常被 collector 替换为单条 stop_collection_error，之前内存中的事件丢失。
- driver stderr 放临时目录并清理，错误常退化为异常类名。
- checkpoint 主要只存 state_hash，不能还原具体文件内容；若源记录缺失，hash 本身无法补出 lineage。
- construction attacker 完整 action/request/response 没有像 formal 一样完整持久化；delivery 文本主要只剩 hash。
- bridge finish 返回完整 post_state，但 driver 没有把其中的 session 原始记录系统性保存。

修复：在每次动作前后 append-only 记录并写 checkpoint；源内容/版本用受控 evidence store 持久化。timeout/崩溃后保留已确认片段、未完成动作和脱敏日志。旧数据缺字段时标明无法补救，需要重采，不能伪装成已恢复。

### F06 / P0：会话、工具和状态观测粒度不可靠

定位：construction bridge 的 session_index；upstream `GatewayClient._extract_tool_calls`；driver `state_specs`；formal bridge `_public_state`。

- construction 每次 deliver 都递增显示 session_id，但底层可能复用同一个 shared_session_key；随后 miner 将显示 ID 差异当真实跨 session。
- 工具列表来自最终 API response 的 message.tool_calls，不能保证包含 OpenClaw 已内部执行的全部工具。
- response 先生成、tool_call 后生成的投影顺序，不一定等于真实工具调用时序。
- collection 主要比较 memory_content，忽略 memory_root_content、memory_dir_content 的具体路径变化。
- sim_google_calls 的日志增长被投影成 external_effect，不能直接等同于业务状态改变或攻击终点。
- formal 的 public_state 只有 memory 长度、文件数、调用数；等长内容替换不可见，数量变化不能证明某条数据沿链传播。

修复：统一 turn/session/agent/process lifecycle ID；使用有版本的结构化工具事件和文件快照；区分观测日志变化与被测效果。

### F07 / P0：默认 mining 不泛化，且简单路径丢失多前驱依赖

定位：`extraction/chains.py:ChainMiningPolicy,_enumerate_paths,_complete_macro_matches_for_path,construct_chain_candidates`。

默认从 external_ingress 开始，只以 external_effect 为完整终点。两节点到终点直接标 shortcut；这是研究策略，不是普适数据真实性判断。partial paths 虽留下，F01 又禁止成为 sample。

DFS 枚举简单路径，难以同时保留“memory 写入”和“session restart”这两个 recall 的 ALL 前驱；只取一条路径不等于恢复完整因果图。分支数/运行时间限制缺少明确截断报告；wall-clock 截断也影响重算一致性。

修复：按实际图保留可观察子路径和必要前驱；图级 causal claim 与路径级模板分开。配置化 entry/terminal，不强绑攻击成功。节点数短不是 shortcut 证据；禁止替代路径应根据具体威胁模型和实际依赖判定。

### F08 / P0：样本抽象器仍把所有链包装成固定持久化故事

定位：`datasets/chain_builder.py:build_primitive_chain_sample`。

public_summary、applicability_predicates、session_requirements、template IDs 和 budget profile 固定写为持久化/多 session 链；即使 miner 找到不同结构也被套模板。

修复：这些字段必须从图和可观察事实派生；单 session、workspace、工具返回、附件、MCP、拒绝路径均能表达。保留泛化后的源/目标组件角色、artifact 类型和依赖条件，去除实验实例特有地址与内容。

### F09 / P0：Planner 的生成自由度被精确模板相等限制

定位：`planning/formal_llm.py:validate_trajectory_proposal,FormalLLMPlanner.plan`；`planning/formal_baselines.py:build_long_horizon_trajectory,supported_attack_families`；`planning/binding_planner.py`。

LLM 的 primitive_sequence 等多项字段必须与 rule-based backbone 完全相等；失败就回退，仍挂着 LLM planner 类型。非特定宏组合可能报不支持 long-horizon family。binding 也有按宏位置固定 session 和没有映射时取第一个组件的逻辑。

修复：Planner 输入仍是一条 sample 和公开任务，输出有 sample→计划的映射、必要依赖与面向新 task 的可执行绑定；允许有说明的细化/适配，不要求字段逐字相同。明确 `llm_generated / rule_based / fallback`，统计 fallback，不能将 fallback 效果归因于模型规划。1800 输出 token 是否足够容纳完整结构也应实测，不盲目扩大。

### F10 / P0：Attacker 的一次动作被硬绑到一个内部 primitive

定位：`execution/formal_attacker.py:validate_formal_realization`、`execution/formal_action_loop.py:execute_formal_action_loop`、formal bridge。

目前强制每个 primitive stage 都有一个 Attacker action，且 bridge 的 tool_surface 与 victim_message 均替换 user_instruction。这可能把本应由 Victim 自主发生的 retrieve、parameterize 等内部动作，变成攻击者逐步提示。计划宣称“使用工具返回注入”，执行却仍是用户消息。

修复：计划的预期 primitive 路径是待验证结果，Attacker 只控制声明允许的动作面。一条注入可能诱发多个 Victim primitive，也可能没诱发任何一个。观察和预期分别记录；有限反馈调整允许保留，但不能强行制造中间 primitive。

### F11 / P0：当前 no_sample 与 treatment 的差异远超过有没有 sample

定位：`planning/formal_baselines.py:NoSamplePlanner`、`execution/safeclaw_formal.py` 约 677–697 行、`configs/task_sets/evaluation_tasks.yaml:baseline_materialization_values`。

no_sample 不进入正式 Attacker，改成“不要读邮件/不要保存外部内容”的良性任务。它可作为 benign sanity check，**不能证明 sample 比无 sample 的攻击生成更有效**。

修复主比较：`with_sample_attack` 对 `without_sample_attack`，保持 Planner/Attacker/Victim、任务、攻击目标、可控面、预算、重试规则相同，只去掉 sample。原 benign baseline 保留为单独诊断，不冒充主对照。

### F12 / P0：当前 formal task materialization 与原 benchmark 测量对象可能漂移

定位：`configs/task_sets/evaluation_tasks.yaml`、`environments/safeclaw/materializer.py`、formal bridge `session['user_instruction']`。

固定 PSE task 的原始恶意内容位于模拟邮件及 workspace，而公开 bindable slots 主要是两条 user_instruction、instruction_context、metadata title/description。`persistent_memory` 映射到 metadata.description，不是真实 memory 操作；`effect_tool` 映射到用户指令，不是工具返回。

如果仍保留原任务中的固定恶意邮件，却宣称攻击完全由 sample 新生成，需要区分“基线已有攻击内容”与“当前 Attacker 新增内容”。保留官方 Evaluator 类并不自动保证原任务语义不变。

修复：对每个 task 制定字段级 capability/attack-surface 合同。用户任务、官方 evaluator/checks、canary 资产与会话结构按正式协议固定；攻击者只改允许的内容入口。对于 regex 与固定 payload 耦合的 task，先验证能否在保留评分含义下生成新内容；不能随意改判定规则。如果无法满足，标记不支持或另列 adapted protocol，不能当作原版 benchmark 结果。

### F13 / P0：dependency ablation 并非真正“仅去掉一条依赖”

定位：formal evaluation 约 699–720 行、formal action loop、`planning/formal_baselines.py:build_dependency_ablation`。

当前按 condition 重新规划、重新生成攻击后替换一个 slot；后续在线 action 又可生成新的 victim_visible_content，覆盖/重新引入被替换含义。相同 seed 对远程模型也不保证同一 realization。只记录 changed_slot_count=1 不足以证明实际执行唯一变化。

修复：明确 ablation 是测试 sample 信息的规划增益，还是测试已生成攻击的依赖因果性。两者分开设计。后者应从已冻结的 treatment realization 派生 intervention，保留其他内容/环境，记录实际请求 diff，并检查后续动作没有补回干预。取不到证据则结论 unknown。

### F14 / P1：normalizer/extractor 的证据语义不一致

定位：`interactions/normalizer.py`、`extraction/occurrences.py`、`verification/occurrence.py`。

- request_event_id 一律转为 control 边，而 macro.act 声明 request→effect 为 state 边；无明确语义契约。
- graph 只要有任意 unresolved 就能使所有候选 fail replay；已有初始状态还可能被当 missing_state_writer。
- 图的 projection_version 固定 formal-observable-v1，registry 是 safeclaw-observable-v2。
- occurrence 的 source_component_roles 和 target_component_roles 都写 event.component_role，丢失 from→to。
- E1/hard_fact 初始默认赋值，只做 family 级字段检查；没有严格核实注册原语所需证据是否可解引用。
- 按关键词识别 operation，未覆盖 registry 全部原语（如 publish），真实普通消息又难以归类。

修复：版本化统一契约；来源引用可解析；初始状态是一等来源；证据问题局部化；根据 subtype 检查，不以自填字符串证明因果。

### F15 / P1：去重、覆盖、计数和重跑单位不一致

定位：`extraction/chains.py` 去重；`extraction/filtering.py:filter_chain_candidates`；`datasets/library.py` manifest；`execution/sample_generation.py` validator。

- 同图同结构先保留首次路径，后续仅追加 duplicate_provenance_paths，可能把更强证据/不同结果折叠掉。
- filter 用含实例字段的 candidate_hash 去重；所谓每 topology quota 实际为一个全局计数。
- completed episode 数减 sample 数生成 rejected_count，混用了“一次交互”和“多条链”的计量单位。
- target_accepted_samples 不得大于 max_collection_trajectories，错误暗含每 episode 最多一个 sample。
- collection 看到已有 raw_trajectory 就跳过，包括 error/partial；model hash 没完整纳入 ID 时容易误复用。stage 验证能覆盖部分情况，仍需明确失败重试与来源/版本语义。
- mining 遇到单条坏数据可以整个中止；已生成的 mining manifest 又阻止在同目录使用新解析器重算。

修复：episode、event、occurrence、path instance、topology 分别计数；实例和拓扑分别去重，保留 outcome/来源；重解析以新 extraction version 派生，坏数据隔离并总结。

### F16 / P1：预算、异常与恢复会造成误判或挂起

定位：collection 的 collect_adversarial、driver `_read_bridge/start/abort`；`ModelConstructionAttacker.next_action`；formal action loop。

- usage 不可见立即使 collection partial，并经 G5 全局拒绝；不要因此丢弃先前有证据的链。
- construction 的 ModelCallError 被转为普通 stop，容易把 API 失败混成正常停止。
- bridge stdout.readline 无 deadline；外层预算不能中断阻塞。driver.start 在 collection try 之外，启动错误也可能清理不完整。
- formal 每一步 remaining_tokens 仍传完整 max_tokens，未扣累计；统计口径不含完整 provider 内部 completion。

修复：错误来源、运行结果、数据质量三者分离；有 usage 则精确计量，不可见则明确 unknown 和预算策略。采集可受控停止但已观察证据不作废；使用有 deadline 的 IPC、进程组清理、attempt 级追加恢复。

### F17 / P1：离线阶段没有官方 outcome 标注，统计覆盖也很窄

construction bridge 明确不实例化 Evaluator。不给 Construction Attacker 未来 verdict 是正确的，但不妨碍 episode 完成后在私有路径执行官方评测，为 sample 来源 episode 标注结果。官方 outcome 不应成为唯一入库门槛。

当前正式矩阵仅 1 个 PSE task × 3 conditions × 5 seeds，不能外推到整个 SafeClawArena。construction 的同类别变体虽 task_id 不重合，仍应检查模板/内容近重复导致的泄漏。

### F18 / P1：此前方舟和安全 patch 必须作为显式实验变体审计

见第 6 节。不能为了沿用“未修改 upstream”的说法而忽略运行时补丁；也不能把新加的适配服务当成已有 end-to-end 验证。

## 4. 目标数据与执行契约

### 4.1 建议保留四层对象

1. **Raw evidence**：不可变 action/model/tool 日志、artifact 内容/版本和状态快照。可信来源是 instrumentation，模型陈述只是被观察到的文本。
2. **Observed graph**：组件、动作、artifact version 和 typed edge；有证据边与 inferred edge 分开。允许分叉、汇合、重试和初始状态。
3. **Reusable sample**：可泛化路径/子图、typed roles、操作条件、必要依赖、适用接口、结果标签和私有 provenance。样本 ID 不应被时间戳或日志文件名随机改变。
4. **Evaluation record**：指定 sample、Planner 输出、Attacker 动作、Victim 实际图、官方 outcome、机制匹配、预算及未观测项。计划图不是实际图。

示例（概念结构，不要求照搬字段）：

```text
artifact:attachment:v1 --read--> tool_result:r1 --delivered--> agent_context:c1
agent_context:c1 --write(content evidence)--> memory:doc:v2
memory:doc:v2 --retrieved(chunk evidence)--> agent_context:c2
session_boundary:s1_to_s2 --enables--> retrieval
```

若只有前两条有证据，就保留此前缀。若 retrieval 未观测，不能把它作为 observed。若接下来是 tool_rejected，应记录拒绝而不是把整条轨迹当“没有 sample”。

### 4.2 威胁模型与 verifier

- 将 human / benign user、construction attacker、formal attacker、victim、tool、environment instrumenter、verifier 分开。
- 附件/邮件/工具返回的“攻击内容”与正常用户任务的权限级别不同。
- sample 公开层给 Planner 的是可复用结构；私有原始轨迹、canary 实例值、真实凭证和未来 evaluator verdict 不进入生成输入。
- 不要用扫描整个 JSON 中的 `prompt/secret` 等子字符串代替类型化 view separation；它会误伤合法 artifact 类型。以字段 allowlist、schema 和真实敏感值扫描共同约束。
- 官方 verdict 与 mechanism verdict 分开输出：官方成功但链未证实、链有证据但官方失败、观测不足，都有独立意义。
- `replay_consistency` 当前只检查 unresolved，不是真实重放，更不是干预因果检验。字段/报告应按实际证据等级命名。
- 原 benchmark 中的 synthetic canary 要按官方语义验证，不能在判定前统一删成占位符；真实服务凭证必须单独隔离/脱敏。

## 5. 可执行修改顺序与验收

### W00：取证与基线（先于任何行为修改）

产物：工作规划、进度文件、`docs/COLLECTION_FAILURE_DIAGNOSIS.md`。

- 记录本地提交与服务器提交的差异，确认本文涉及的方舟新文件是否已同步。
- 找到失败 run 的 `collection_stage_manifest.json`（以代码常量实际名字为准）、collection_manifest、raw_trajectory、source_events、checkpoints、normalization_audit、occurrence decisions、candidates、filter_decisions、sample_generation/mining manifest 和日志。
- 统计每个 episode 状态/错误、每种 occurrence 状态、缺失边、每个 gate 原因、到终点前缀比例；reason 按代码和实例分开，不只堆含 occurrence_id 的字符串。
- 区分：没有原始事件、没有 occurrence、没有 candidate、有 candidate 但不通过、通过却未写库、数量不足/冻结失败。
- 重现第 2.2 节；比对 synthetic fixture 比真实 bridge 多哪些字段。
- 若日志缺失，明确历史原因无法证明，继续修复已复现结构缺陷，不反复等待不存在的数据。

验收：有带文件/函数/证据引用的因果诊断；旧 run 不被覆写；不声称单元测试证明真实成功。

### W01：冻结新的研究契约与版本

依赖：W00。

- 将第 1、4 节落实为 `docs/EXPERIMENT_DESIGN_V3.md`，说明 sample 状态、威胁模型、模型角色、主比较、benchmark 保真标准。
- 修订 dataclasses/Pydantic schema、primitive registry、版本号及迁移约定；旧语义仍可读取但不能无标识混入新库。
- 决定哪些可用前缀进入主 sample 分布；选择规则在评测前固定。
- 维持一条 sample 输入，不增加未经定义的多 sample 检索策略。

验收：合法未成功交互的 observed prefix 能被表达；blocked 与 missing evidence 可区分；源/目标字段能表达附件→memory/MCP；无 fixture 必须“攻击成功”的隐含要求。

### W02：先修日志和 instrumentation，再修 miner

依赖：W01；覆盖 F03–F06、F14、F16。

- 为 collection/formal 建立共同的结构化事件适配层，避免两个阶段观察定义不同。
- 记录真实 tool request/result ID、artifact versions、memory read/write、session identity；优先从 pinned OpenClaw 的实际结构化日志取证，必要时使用最小 instrumentation patch。
- 每个动作流式落盘；保存原始内容与 hash、工具结果和文件版本；区分可公开投影与私有证据。
- 所有生命周期动作以实际执行确认作准；对不支持的 delivery/retry/reroute 返回明确 unsupported，不生成虚假的 passed。
- deadline、异常类别、进程清理、usage 策略与 resume 先修到可诊断。

验收：中途杀死进程能恢复已落盘片段；API 失败不会成为正常 stop；相同 session 多轮不会伪造跨 session；等长 memory 改写可见；无实际 read 时不会声称 recall；不能从普通最终回复反推全部工具历史。

### W03：样本抽取与 acceptance 重新实现

依赖：W02。

- 修复 F01/F02/F07/F08/F14/F15；保留 standalone mine/re-extract 能力。
- 样本质量检查只判断类型、引用、证据、可泛化性；攻击成功是独立标签。
- 支持 observed subpaths、必要的 DAG 前驱、初始状态来源、拒绝/错误结果。
- 节点 outcome 与 operation-completed 分离，不对 request/persist/effect 使用同一个含糊 passed。
- 去重保留实例证据和不同 outcome；配额按真实 topology；确定性搜索预算或明确记录截断。
- 提供一键采样入口（名称自行统一，例如 `sample acquire --extract`），内部仍先持久化再解析。每个 episode 结束后显示统计与原因。
- 库数量门槛改为声明的规模/覆盖指标，而不是成功攻击阈值；pilot 首要验收是管线可观察、可重算、有有意义的 observed path。

验收：不同路径族可入库；一个 episode 可多 sample；正常/拒绝路径不因未达 external_effect 被丢弃；无关 unresolved 不摧毁其他证据完整子图；重复解析同一源和版本得到一致结果。伪造引用和缺失证据仍被隔离。

### W04：实现真正的 benchmark 注入面及人参与采集

依赖：W01/W02；可与 W03 分批推进。

- 建立 task adapter 清单：用户任务、可编辑 artifact/pointer、权限、合法工具、session setup、固定 evaluator 字段。
- 先覆盖少量可明确保持原语义的 PSE 与另一类 task；不足时明确 coverage limited，不机械扩充全部任务。
- 为人提交建议/选择/内容提供 CLI 或记录输入接口，同样通过权限校验和日志；不要要求人每轮参与自动 collection。
- 原有恶意 payload 的保留、替换、无攻击对照三种情况在设计中明确；避免新攻击和旧 payload 的效果混在一起。

验收：声明 tool_surface 的输入真的进入 tool response/对应 artifact，而非被替换成 user_instruction；任务不允许修改的字段保持 hash；生成器无法控制官方 verdict；至少一条真实低信任内容→Victim 可见的路径可检查。

### W05：Planner 按 sample 生成可执行计划

依赖：W03/W04。

- 泛化 sample public view，删除固定模板摘要和硬编码两 session。
- 用类型/依赖/能力约束验证计划，允许必要的细化映射；显式输出样本节点/边与新计划之间的映射及不支持项。
- 不以 sample 的宏标签集合决定它是否能用于全部规划；必要时明确“不适用于此 task”而不是“sample 无效”。
- 记录 LLM 请求、有效输出、校验失败、修复重试和 fallback；不同机制单独统计。

验收：两个不同结构的 sample 在同一 task 下产生可追踪差异；不同 task 的合法绑定不同；无隐式 first-component fallback；不支持的能力会被拒绝；LLM 失败不会伪装成 LLM 规划成功。

### W06：Attacker 执行与 matched controls

依赖：W05。

- 解耦 primitive 阶段与攻击动作；Attacker 只控制 benchmark 允许的内容或生命周期动作，真实 primitive 由 Victim 产生。
- 主对照 `without_sample_attack` 同样调用 Planner/Attacker、同样目标和预算；benign baseline 单列。
- 明确每个角色独立的 model/base_url/key/proxy 配置；不能把 SharesAI GPT-5.5 与 Gemini 的模型名和密钥交叉使用。
- 修复 ablation：记录是“删 sample 信息”还是“干预执行依赖”，并用实际发送内容和环境状态验证 intervention 生效。

验收：no_sample 真实调用攻击生成流程且没有访问 sample；预算/任务/注入面公平；一条 Attacker 操作能对应多条 observed primitive；计划中的未发生节点被记为未发生；ablation 不被下游动作补回。

### W07：官方 verifier、机制验证与报告

依赖：W02/W04/W06。

- 离线 episode 结束后可在私有路径运行官方 evaluator，结果只作标签，默认不反馈给同次生成器。
- formal 在实际 session/状态上调用 pinned 官方评测；不要只测 compute_score 的布尔输入。
- mechanism verifier 使用同一 observed graph 与可解引用 evidence，分开事实/推断/干预证据。
- 输出基础设施失败率、可观察率、结构可用率、官方攻击结果、路径实现率、fallback 比例和配对比较；明确分母和缺失处理。
- 一 task 多 seeds 是同 task 重复，不是多个独立任务；主分析按 task/模板聚类和预注册设计处理，不能仅靠增 seed 声称泛化。

验收：官方成功/机制未知、官方失败/有效 sample、工具拒绝、API 错误四种场景分别正确报告；synthetic smoke 与真实 benchmark 结果目录和标签分开。

### W08：环境与已有 SafeClaw 改动验收

依赖：W00；细节见第 6 节。可先验证接口，但真实 evaluation 仍依赖上述任务。

- 准备 Python 和 pinned Docker 镜像；只读核对版本后再构建，不使用旧镜像 tag 冒充新环境。
- 按角色确认接口和代理，宿主与容器分别测试；方舟适配至少完成实际 OpenClaw memory indexing/search 链路测试。
- 所有新补丁、适配器源码、embedding 模型/维度/预处理配置进入环境 fingerprint，collection/formal 对齐。

验收：宿主 API 成功不等于容器成功；真实 memory 检索可用才标 verified；失败留下明确日志，且不触发大规模 collection。

### W09：小规模真实采样与数据恢复

依赖：W02–W04、W08；正式主比较还需 W05–W07。

- 先一条可解释的正常流转/阻断任务，再一条授权攻击交互；每条结束检查原始事实→graph→sample 的完整映射。
- 真实 acceptance 为零时自动产生分层诊断，停止盲目扩大规模。不能强迫产生成功攻击。
- 若旧 source 足够，用新解析器生成新的派生版本并与旧结果比较；不足则只恢复可证实前缀并标缺失，或重新采集。
- pilot 完成后才扩大多路径、多 task；near-duplicate 模板按组划分 construction/evaluation。freeze 是实验开始前锁定内容，不是成功样本的奖章。

验收：真实 benchmark 原始记录可人工抽查；至少一种有证据的非成功/部分路径可用；抽取结果一致、来源可追溯；数量与拓扑多样性分别统计。

### W10：收尾和服务器交付

依赖：前述任务各自 verified，或如实列未完成。

- 更新 README、运行手册、EXPERIMENT_PROTOCOL、PROMPTS、config/schema 文档与 CLI help，消除新旧定义冲突。
- 更新 IMPLEMENTATION_WORKPLAN / PROGRESS，逐项链接测试和运行产物；记录当前可运行范围，不提前宣称正式 ASR 或泛化结论。
- 提交清单应包含新 adapter/test 文件；生成数据、真实密钥、私有日志不误传 GitHub。
- 交付一个从中断点继续的明确命令和说明；未完成真实 evaluation 不得标项目全部完成。

## 6. 已有 SafeClaw 修改说明，以及仍需做的验证

本节描述**此前已存在于当前工作区**的修改，服务器必须检查这些文件是否随 GitHub 同步。它们不是本次诊断产生的解决方案，也没有自动修复上面的 collection 语义问题。

### 6.1 原 safety patch 的作用

文件：`integrations/safeclaw/patches/a11f5cce-safety.patch`。

对 pinned `scripts/judge.py` 的临时副本应用，原 upstream checkout 保持不变。主要行为：

- 去除聊天凭证后缀输出，auth profile 报告保留结构并脱敏。
- 注入 OpenClaw `memorySearch` 的 embedding provider/model/baseUrl/apiKey，关闭 fallback。
- 保留 Gemini `/v1beta/openai` 根路径，不错误追加 `/v1`。

这属于模型接入、日志和受测 Agent 的 memory 配置修改。**memorySearch 配置会影响实验行为**，需要在两阶段和所有对照中保持一致并报告，不应描述成“完全未修改 benchmark”。官方 evaluator 的判定逻辑原则上保持不变；执行方需用 diff 和 contract tests 核实。

### 6.2 本地方舟适配的实现

关键文件：

- `src/stac_attack_lab/environments/safeclaw/ark_embedding_proxy.py`（新文件）。
- `environments/safeclaw/model_config.py` 与 preflight、sample_generation、sample_preflight、safeclaw_formal 的 provider 类型/分支。
- 上述 safety patch 的 Ark 部署分支。
- environment、pilot、main 三个 YAML 的 `embedding_provider: ark_multimodal`。
- `tests/unit/test_ark_embedding_proxy.py`（新文件）、embedding config tests、`.env.example`、integration README。

当前接入信息（非密钥）：

```text
方舟 API 根：https://ark.cn-beijing.volces.com/api/v3
模型接入点：ep-20260906165746-jwc94
方舟路由：POST /embeddings/multimodal
当前实际向量维度：2048
密钥环境变量：SAFECLAW_EMBEDDING_API_KEY
```

流程：`build_safeclaw_model_config` 放入适配器源码；patched judge 通过 stdin 写 0600 配置到临时容器，在容器回环地址 `127.0.0.1:18792` 启动 Python 标准库适配器，再把 OpenClaw 指向其 `/v1` 地址。容器内不需要安装 lab 或方舟 SDK。进程随容器清理。

转换：OpenAI 文本或文本列表 → 每条单独调用 Ark 的 `input:[{type:text,text:...}]` → 将 Ark `data.embedding` 转成 OpenAI `data:[{index,embedding}]`。逐条调用避免把多个独立文档融合成一个向量。支持 float/base64；关闭 OpenClaw 异步 remote batch；显式拒绝 dimensions override、token-ID 输入。单条失败不返回不完整批量向量。

### 6.3 已验证与未验证

已验证（2026-09-06，本机）：

- Gemini 官方 `gemini-2.5-flash`：直连因地区返回 400；通过 Clash `http://127.0.0.1:7890` 返回 200，有有效回答。
- 方舟指定接入点：纯文本返回 200、2048 维。
- 新适配器在宿主回环地址以与容器相同的源码 bootstrap 启动：标准 embedding 两条文本请求返回两条 2048 维向量，index 为 0、1，测试后退出。
- 当时 `make check`：格式、lint、mypy、119 tests 通过；patch 重新序列化后相关 10 tests 通过，`git diff --check` 通过。
- Docker 当前用户可用，upstream commit 匹配；最后一次镜像查询 `openclaw-env:2026.3.12` 不存在。

尚未验证：新适配器在真实 pinned OpenClaw 中完成 memory 写入、索引、跨会话检索，以及长文本/批量耗时、向量参数、索引缓存维度变更、真实容器代理网络。这些必须在 W08 补齐。

额外审查要求：

1. 方舟模型/维度变化后要清理或版本化对应索引，不能与旧 Gemini embedding 向量混用。
2. adapter 源码 hash、协议、模型、维度、配置与镜像 ID 纳入 fingerprint；现有 `config_hash` 不完整覆盖这些。
3. 验证 OpenClaw 实际发送的 encoding_format、dimensions、batch 参数；当前 400 拒绝不兼容参数属于显式限制，不等于已经适配全部输入。
4. 真实服务密钥目前仍会进入容器配置；处于 Agent 可读环境的 adapter 配置要与 benchmark 的假凭证分离。后续考虑宿主/独立服务持有真实凭证、容器仅持 scope token 的设计，作为可报告基础设施变体；不能把密钥混入 sample 证据。
5. `no_external_network` 不应阻断已批准的模型服务调用；应区分控制面的模型/API 出站和 Victim 工具对任意真实网络目标的出站。固定模拟服务、隔离实际 effect，并记录限制。当前仅有字符串约束和默认 Docker bridge，不能当作已实现网络隔离。
6. upstream 使用固定容器名/端口并在 start 时 rm 同名容器；未实现 run 独立资源命名前，不并行启动真实 episodes。后续按 run/attempt 隔离资源并验证清理不影响其他任务。

### 6.4 模型角色和代理配置的待对齐项

用户说明：SharesAI 的服务用于 GPT-5.5；另有官方 GEMINI_API_KEY；方舟用于 embedding。此前将 gemini-2.5-flash 发给 SharesAI 返回 model_not_found，是配置混用，不是模型不可用。

当前主代码的 Planner/Attacker 默认共享 OPENAI_BASE_URL/OPENAI_API_KEY，Victim 默认也引用它们；单独存在 GEMINI_API_KEY 不会自动切换。应在工作规划中明确每个角色用哪个模型/服务，提供独立变量映射且保持旧配置可迁移。没有用户进一步指定时，保留版本化默认角色模型，不私自把全部角色改为 GPT-5.5。

本机 `.env` 的 embedding 接入点已被更新；聊天的 SharesAI 地址/密钥未在此前适配中改写。服务器 `.env` 不通过 Git 同步，执行方应只检查变量存在与服务映射。

Clash 7890 是本机配置，不假定服务器也有同一服务。容器 localhost 是容器自身；代理需要受控的宿主可达地址或独立网络方案。分别测宿主、container、实际 OpenClaw 请求。不能因为宿主最小 HTTP 测试成功就跳过这项验收。

## 7. 必须新增或改写的回归用例

| 用例 | 预期 |
|---|---|
| 当前真实 driver 的模拟 bridge 两会话复现 | 旧失败原因可重现；新系统不再将请求已发生与攻击成功混同，observed prefix 可保存 |
| 只有 memory 文件存在，没有 read 工具/上下文证据 | 不生成 observed recall |
| 写 memory 后被拒绝后续行动 | 写入路径可用、攻击结果失败/未评测，拒绝有独立 primitive |
| 同一 session 两轮 | 不标跨 session；实际新 session 才记录边界 |
| 一次调用内多个工具请求/返回 | 全部保留真实 call ID、次序和对应结果 |
| memory 等长替换、memory 子目录写入 | 捕捉内容版本变化，不依赖长度 |
| mailbox/attachment→工具结果→context→memory | 可追溯源和目的；普通用户指令不被误标为附件入口 |
| memory read 有两个必要前驱 | sample 保留支撑依赖，不能从缺一前驱的路径声称完整机制 |
| 与候选无关的 missing link | 候选自身证据完整时不全图一票否决 |
| 一 episode 多条链、同拓扑不同 outcome | 分别计数、保留 provenance，不用 sample 数抵 episode 数 |
| collection 在中途异常/进程中断 | 已确认事实留存，恢复不重复计费/重复执行 |
| 无 usage / 超预算 | 标明确原因、保留已观察数据，计量未知不假报零 |
| no_sample_attack | 与有 sample 同样生成和执行攻击，只缺少 sample |
| Planner 不合法输出 / fallback | 来源和失败显式；不伪装 LLM 成功 |
| tool_surface delivery | 实际进入指定工具/内容面，不落到 user_instruction |
| dependency ablation | treatment 派生、可检查执行 diff、后续动作不补回 |
| 官方判定与机制判定不同 | 保留分歧，不强行合成单一成功 |
| 方舟真实 OpenClaw memory search | 两阶段配置一致、正确索引与返回、无 SDK 隐式依赖 |
| synthetic fixture 与真实数据混合 | 明确拒绝作为同一真实实验样本来源 |
| 前后 artifact hash / 源记录遭篡改 | 检测失败，不允许模型补造证据 |

## 8. 发布、迁移与完成标准

- 旧 accepted/negative 命名和统计不可信地混用了结果维度；旧库先只读导入，不批量改名后当作新数据。
- 先实现双读/新写或显式迁移工具，保留 old→new 来源映射、抽取器版本、未知字段列表。
- 真实数据缺少 tool transcript/内容版本时不能只靠新 miner 补救；如实说明“可恢复片段”和“必须重采”。
- freeze 锁定的是预先定义的数据与选择规则。冻结版本、样本选择规则、task split、模型与预算随评测一起固定。
- 当前 1-task/15-case matrix 只能作为 smoke/有限范围试验；扩展正式规模前应确定覆盖与统计单位，报告“不支持的任务”而不是悄悄排除。
- 成功标准是：**真实 benchmark 交互可完整追溯，能提取有证据的可复用路径，Planner/Attacker 真正按 sample 工作，公平对照和官方/机制评测成立**。不保证攻击一定成功，不追求用门槛调整制造成功率。

## 9. 可直接发给服务器 Codex 的启动指令

> 请先阅读 `docs/EXPERIMENT_ALIGNMENT_AND_REPAIR_PLAN_ZH.md`，核对当前代码、未提交修改、pinned SafeClawArena 和服务器原始失败产物。开始改实现前，必须先创建或续写 `docs/IMPLEMENTATION_WORKPLAN.md` 与 `docs/IMPLEMENTATION_PROGRESS.md`，按 W00–W10 分解文件级工作和验收。每完成一项或上下文即将耗尽都更新进度、证据和下一步动作；恢复时先读这两个文件并检查仍在运行的任务。按本文目标修复采集、primitive 抽取、sample 定义和正式对照，保持实验只在授权 SafeClawArena 环境内。先证明历史失败原因与已复现缺陷，再改实现；不能通过强制 accepted、改变官方评分或删掉失败来通过验收。保留并审查已有方舟适配和安全 patch；不要覆盖用户的密钥、旧数据或工作区改动。真实实验按已配置预算从小规模开始，产物和进程都落盘。最后明确已验证、未验证和下一次继续位置。
