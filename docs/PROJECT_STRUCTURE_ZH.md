# STAC Compositional Attack Lab：项目结构与逐部分讲解大纲

> 阅读基准：2026-09-17 当前工作区的源码、配置和文档。本文是学习路线与源码导航，不是运行验收报告；没有启动 Docker、调用模型或重新运行实验。后续可以直接按章节编号提问。

## 1. 项目总体目标：它究竟在研究什么？

本项目是一个面向授权、隔离 SafeClaw/OpenClaw 环境的组合攻击研究框架。它关注的不只是最后是否触发某个不安全结果，还包括：不可信内容如何进入代理上下文、是否改变持久状态、是否在之后的会话中被读取、是否影响工具调用，以及这些步骤之间是否存在可验证的依赖。

项目的主要工作可以分成两条流水线：

1. **样本构建流水线**：Construction Attacker 与 Victim 交互 → 保存原始轨迹 → 规范化交互图 → 抽取原语实例 → 构建与过滤候选链 → 审计 → 冻结样本库。
2. **正式评测流水线**：读取冻结库和评测任务 → 分配配对条件 → Planner 制定轨迹计划 → 独立 Attacker 实现具体动作 → Victim 执行 → 机制验证与官方判定 → 审核运行 → 统计报告。

因此，它同时包含实验调度、模型调用、环境适配、数据集构建、证据验证和报告生成。它不是单一的攻击提示词脚本。

### 1.1 后续讲解应先回答的问题

- 为什么要从真实轨迹提取 chain，而不是直接让模型编写一条攻击链？
- 为什么需要把 Planner 和 Attacker 分开？
- 为什么“最终结果成功”不等于“计划中的机制成立”？
- 为什么采集任务和正式评测任务需要分离？

## 2. 角色与核心术语

| 术语 | 在本项目中的含义 | 主要代码位置 |
|---|---|---|
| Victim | 被研究的 OpenClaw 代理；调用目标模型，读取环境并执行工具 | `environments/safeclaw/`、两个 bridge |
| Construction Attacker | 采集阶段的动作生成者，根据公开观察与剩余预算决定下一步 | `interactions/construction.py` |
| Planner | 根据任务、样本公开结构与预算制定评测计划 | `planning/` |
| Formal Attacker | 正式评测阶段的独立动作生成者，将计划中的 stage 实现为具体交互 | `execution/formal_attacker.py` |
| Core primitive | 对可观察行为的底层分类：传递、变换、状态修改、控制 | `primitives/core.py` |
| Occurrence | 某个 primitive 在某条轨迹中的具体发生实例，带事件和证据引用 | `interactions/models.py` |
| Macro | 由 core primitive 模式构成的较高层行为概念 | `primitives/macros.py` |
| Artifact | 被传递、派生、写入或读取的内容对象，记录 hash 与血缘 | `interactions/models.py` |
| Typed edge | 带类型的依赖边，用来描述数据、状态或控制关系 | `interactions/models.py`、`verification/edges.py` |
| Primitive chain sample | 经构建与过滤后的结构化样本，包含公开、执行、私有证据视图 | `datasets/primitive_chain.py` |
| Binding | 把样本中的抽象角色或槽位映射到具体任务允许的对象 | `planning/binding_planner.py` |
| Episode / Session | 一次实验交互与其中的会话；会话标签和实际会话身份需要区分 | `environments/safeclaw/` |
| Provenance | 数据来源与构建身份：配置、模型、源码、注册表、任务等 hash | 各种 manifest、recorder |
| Frozen library | 通过审计后冻结、不能覆盖的正式输入样本库 | `datasets/library.py` |
| Official verdict | SafeClaw 官方评估器给出的终点与任务结果 | `verification/safeclaw_official.py` |

### 2.1 四类底层原语

- **TRANSFER**：内容或请求从一个位置到另一个位置，例如外部输入进入上下文、工具请求、工具响应、持久内容取回。
- **TRANSFORM**：内容转为新的可观察表示，例如提取、总结、参数化、合并、清洗。
- **MUTATE**：状态发生改变，例如 memory 写入、workspace 写入、配置更新、沙箱外部状态变化。
- **CONTROL**：合法执行路径或生命周期发生变化，例如分支、拒绝、重试、等待、重启、停止。

### 2.2 高层宏

注册表包含 `Ingest`、`Adopt`、`Persist`、`Recall`、`Select`、`Bind`、`Act`、`Record`、`Recover`。这些名字帮助表达完整路径，但每个宏是否成立仍要检查它要求的底层节点、依赖与证据。例如 Recall 要求生命周期边界与之后的 retrieve，不能仅凭出现 `memory_search` 字样推断成立。

### 2.3 证据等级

`primitives/core.py` 定义 E1 为直接观测、E2 为确定性派生、E3 为干预证据、E4 为语义证据。注册表使用 E1/E2 支撑 hard pass，E3 支撑因果主张；语义判断不能覆盖缺失的硬事实。

## 3. 根目录结构

```text
STAC-Compositional-Attack-Lab/
├── src/stac_attack_lab/       Python 主实现
├── configs/                  模型、环境、任务、原语、采集和评测配置
├── prompts/formal/           模型角色的提示词资产
├── integrations/safeclaw/    上游桥接脚本、安全 patch、外部 checkout
├── schemas/                  JSON 数据契约
├── scripts/                  标准运行入口与诊断入口
├── tests/                    单元、集成、端到端测试和 fixture
├── data/primitive_libraries/ 生成中与冻结后的样本库
├── experiments/runs/         按 run ID 隔离的运行产物
├── docs/                     协议、进度、操作说明与学习文档
├── pyproject.toml            Python 包、依赖、CLI 与质量工具配置
├── Makefile                  常用操作和质量检查入口
├── README.md                 项目总览与推荐入口
├── SECURITY.md               项目安全和授权边界
├── .env.example              环境变量配置样例
└── .gitignore                排除凭证、缓存和生成产物
```

主包采用 `src` 布局，要求 Python 3.11+，运行时依赖 Pydantic、PyYAML、jsonschema。开发依赖包括 pytest、ruff、mypy。安装后命令 `stac-attack-lab` 指向 `stac_attack_lab.cli:main`；也可以通过 Python module 入口调用。

`.env` 是本地凭证配置，不是研究数据。解释配置时应看变量名和使用位置，不复制实际密钥。缓存目录与 `.DS_Store` 不属于实验主流程。

## 4. 主源码：基础设施与入口

以下路径均相对于 `src/stac_attack_lab/`。

| 文件 | 作用 | 建议讲解重点 |
|---|---|---|
| `__init__.py` | Python 包入口文件 | 包如何被导入 |
| `cli.py` | 解析 CLI，串联 sample、revalidation、safeclaw、schema 操作 | 命令怎样到达业务函数，错误怎样影响退出 |
| `contracts.py` | 定义统一的 `StrictModel` 基类 | 严格模型如何约束输入输出 |
| `config.py` | 角色模型配置与配置读取辅助函数 | provider、model、endpoint 环境变量如何绑定 |
| `env_loader.py` | 环境变量加载辅助逻辑 | 本地配置如何进入运行时 |
| `hashing.py` | 稳定对象 hash 和文件 hash | 为什么配置、样本、产物都要记录 hash |
| `schema_registry.py` | 维护、检查数据模型与 schema 的对应关系 | Python 模型与 JSON 契约如何保持一致 |

`cli.py` 是理解项目入口的最佳起点，但不是所有业务逻辑的所在地。阅读时应沿它导入和调用的模块继续追踪。

## 5. 采集层：`interactions/`

| 文件 | 作用 |
|---|---|
| `models.py` | 定义原始轨迹、事件、artifact、依赖边、原语实例等核心数据对象 |
| `base.py` | 定义采集适配接口与预算相关契约，隔离框架和具体环境 |
| `construction.py` | 定义 Construction Attacker 输入、观察、动作、循环及模型动作解析 |
| `collector.py` | 按 task/seed 组织采集，保存轨迹与阶段产物，处理失败和重复产物 |
| `safeclaw_collection.py` | 将 SafeClaw driver 接入采集接口，准备公开上下文并执行构建交互 |
| `fixture_adapter.py` | 使用本地 fixture 提供确定性输入，供离线测试和开发 |
| `normalizer.py` | 将源事件、状态与内容引用转为统一 InteractionGraph，记录无法解析的关系 |
| `__init__.py` | 子包入口 |

### 5.1 采集循环应怎样理解？

Construction Attacker 收到公开任务目标、可观察状态、合法动作类型与预算，输出结构化动作；adapter/driver 执行动作，返回 Victim 可观察结果；框架记录事件与预算变化，再决定是否继续。停止、错误和预算耗尽都应留下产物。

### 5.2 为什么规范化是一层独立模块？

上游 tool call/result、session、workspace 状态等信息并不天然具有统一格式。normalizer 将它们组织成图，供后续抽取与验证复用。它同时承担证据关系保真：区分请求与响应、实际 session 身份、读写状态、artifact 血缘和 unresolved links。

### 5.3 原始轨迹与交互图的区别

原始轨迹记录“采集到哪些源文件、事件和 checkpoint”；交互图表达“哪些事件处理哪些 artifact，事件之间有哪些可观察关系”。前者是来源记录，后者是统一分析表示。

## 6. 抽取层：`extraction/`

| 文件 | 输入 → 输出 | 作用 |
|---|---|---|
| `occurrences.py` | InteractionGraph → occurrence 与抽取决策 | 把可观察事件匹配为具体底层原语实例，并附上证据 |
| `chains.py` | 图、occurrence、registry → chain candidates | 利用结构与依赖构建候选链，组织宏与 core 节点 |
| `filtering.py` | candidates、图、原语、策略 → accepted/negative 与逐门决策 | 执行 G0–G8 过滤并保留拒绝理由 |
| `__init__.py` | 子包入口 | 模块组织 |

### 6.1 G0–G8 的职责

| Gate | 名称 | 主要检查 |
|---|---|---|
| G0 | schema/type | 注册表身份、图身份及结构类型 |
| G1 | occurrence evidence | 实例是否可观察、是否有硬事实与 E1/E2 支撑 |
| G2 | causal edge | 必需的带类型依赖边是否存在、匹配且可观察 |
| G3 | environment binding | 环境是否提供宏要求的能力 |
| G4 | replay consistency | 是否有 unresolved links 等引用一致性问题 |
| G5 | attack relevance | shortcut 与按策略启用的攻击相关性检查 |
| G6 | split/privacy | 来源 split 合法、没有使用被排除的正式任务 |
| G7 | portability/dedup | 绑定槽位合法、候选没有重复 |
| G8 | coverage/diversity | 候选接受是否超过配额 |

**当前实现细节必须单独理解**：`execution/sample_generation.py` 中 mining 使用 `require_attack_relevance=False`。G5 仍拒绝 forbidden shortcut，但不会强制所有 relevance findings 成为拒绝条件。因此 accepted 可以是具有有效证据的短交互链，并不自动证明攻击目标成立。

此外，G8 当前批处理使用单个累计 `topology_count`；仅凭门名不能认为已经实现了完整的按拓扑多样性统计。后续讲解应区分门禁意图和具体算法。

## 7. 原语与样本层：`primitives/`、`datasets/`

| 文件 | 作用 |
|---|---|
| `primitives/core.py` | 原语家族、结果状态、证据等级、底层原语规格 |
| `primitives/macros.py` | 高层宏模式及底层节点/边要求 |
| `primitives/formal_registry.py` | 加载注册表、解析 primitive/macro 标识与别名，提供统一版本身份 |
| `datasets/primitive_chain.py` | candidate、sample、filter decision、manifest 与各种视图的数据模型 |
| `datasets/chain_builder.py` | 将候选链转为样本，生成视图、状态和稳定 hash |
| `datasets/library.py` | 构建、加载、审计、冻结样本库，检查内容与 manifest 一致性 |

### 7.1 三种样本视图为什么重要？

- `PlannerSampleView`：面向规划的公开结构，包括所需能力、角色、节点边、绑定槽位等。
- `ExecutionBindingView`：面向执行和验证的结构与绑定信息。
- `PrivateEvidenceView`：证据来源与审计信息，不应混入模型公开输入。

这些视图把“模型做计划所需的信息”和“验证者检查真实性所需的信息”分开。正式任务也有公开视图与内部描述的区分。

### 7.2 accepted、audit、admission、freeze 的区别

1. **accepted**：某个候选通过当前样本过滤策略。
2. **library audit**：库的结构、hash、引用和阶段要求可核验，样本数量达到该配置目标。
3. **construction admission**：独立检查轨迹完整性、实际身份与跨会话持久化读写使用等工程证据。
4. **freeze**：以已通过且未过期的审计结果为前提，将生成库变为正式输入。

前一个结论不能替代后一个。尤其不能从“一条 accepted 短链”推断“跨会话攻击样本已合格”。

## 8. 规划层：`planning/`

| 文件 | 作用 |
|---|---|
| `formal_base.py` | 正式预算、case assignment、Planner 输入、stage、长程轨迹和评测计划的契约 |
| `formal_scheduler.py` | 兼容性检查、样本排序、条件分配与配对不变量检查 |
| `sample_selector.py` | 样本选择辅助逻辑，根据能力与预算寻找兼容样本 |
| `binding_planner.py` | 将样本槽位绑定到公开任务，或构建无样本 baseline binding |
| `formal_baselines.py` | NoSample、Fixed、RandomCompatible、RuleBased 等规划器及计划构建辅助函数 |
| `formal_llm.py` | LLM Planner 的结构化提案、绑定和轨迹生成，以及提案验证 |

### 8.1 Scheduler 与 Planner 的区别

Scheduler 先确定某个 case 的任务、条件、seed、预算和分配样本，固化 assignment。Planner 根据分配后的输入制定计划。当前代码提供 `SingleSamplePlannerInput`：不能把正式流程想象为 Planner 任意浏览私有库并替换已分配条件。

### 8.2 Binding 与 payload 的区别

Binding 指明样本中的抽象角色怎样对应具体环境对象；payload 是 Attacker 实现阶段动作的具体内容。合法 binding 不代表 payload 必然有效，也不代表 Victim 一定执行。

### 8.3 为什么同时提供规则与 LLM 规划器？

规则、固定、随机和无样本实现可以提供不同基线；LLM 提案仍需经过结构与权限验证。代码支持的规划器范围大于当前配置启用的条件矩阵。

## 9. 执行层：`execution/`

| 文件 | 作用 |
|---|---|
| `sample_generation.py` | 采集、mining、stage manifest、审计与冻结的业务编排；核对既有阶段 hash |
| `sample_preflight.py` | 采集配置和环境的运行前检查 |
| `construction_admission.py` | 对采集产物进行独立工程准入检查，输出证据缺口与原因 |
| `revalidation.py` | 准备版本化、默认禁用真实执行的复验目录；组织离线复验 |
| `deadline.py` | 在 POSIX 主线程中提供可中断的墙钟期限，约束阻塞 I/O |
| `safeclaw_formal.py` | 正式评测总编排：读取配置和任务、建立 case matrix、规划、执行、验证与记录 |
| `formal_attacker.py` | 独立 Attacker 的输入、动作和 realization；模型输出的约束与解析 |
| `formal_action_loop.py` | 逐 stage 执行动作、管理公开反馈和动作记录 |
| `formal_interactive_episode.py` | 将正式计划的交互执行接到环境 episode/driver |

### 9.1 预算有哪些层次？

Session、turn、action、tool、event、token、wall time 和实际 provider request 是不同计数，不能互相替代。逻辑模型决策与实际上游 HTTP attempts 也需要分开；失败请求可能已消耗请求预算。

collection 的 `max_tokens` 是 action 后累计 Victim usage 的检查，不是每个请求发送前的硬 token 限制，也不是所有角色的统一 token 费用上限。应结合具体配置、ledger 和 accounting 解读。

### 9.2 prepare / offline 的目的

`revalidation prepare` 生成独立 run 身份、配置及来源记录；`offline` 根据本地产物做 mining/audit/admission。它们用于复验工程证据，不能自动替代一次新的真实运行。

## 10. SafeClaw 环境层：`environments/safeclaw/`

| 文件 | 作用 |
|---|---|
| `contracts.py` | 任务描述、公开任务视图、公开提示、绑定和 episode 结果契约 |
| `task_adapter.py` | 从上游任务构造本框架使用的任务描述和公开表示 |
| `materializer.py` | 按 task set 允许的 JSON pointer 生成运行任务，限制修改范围 |
| `preflight.py` | 检查 upstream、patch、Docker、配置和必要环境条件 |
| `runner.py` | 环境运行组织与生命周期相关逻辑 |
| `interactive_driver.py` | 与 bridge 子进程通信、执行动作、观察状态、核算预算并清理 |
| `trajectory.py` | 上游轨迹投影与转换辅助逻辑 |
| `observations.py` | 构造受限、公开的环境观察 |
| `redaction.py` | 脱敏凭证与敏感字段，保留适合核验的证据身份 |
| `model_config.py` | Victim 与 embedding 的运行时模型配置 |
| `provider_relay.py` | 独立 relay 的认证、请求预算、工具过滤、转发与脱敏 ledger |
| `ark_embedding_proxy.py` | 将 OpenAI embedding 请求适配为 Ark 多模态文本 embedding 请求 |
| `__init__.py` | 子包入口 |

### 10.1 三套模型服务配置

- Planner / Attacker：角色配置读取 `OPENAI_*` 对应变量；当前配置模型名是 `gpt-5.6-sol`。
- Victim：读取 `SAFECLAW_MODEL`、`SAFECLAW_BASE_URL`、`SAFECLAW_API_KEY`。
- Embedding：独立读取 `SAFECLAW_EMBEDDING_*`。

这些是代码/配置中的角色设置，不表示本次已检查服务可用性。Embedding 服务与聊天模型承担不同任务，不能以聊天 API 正常推断 memory 检索链路正常。

### 10.2 Provider relay 为什么独立？

Victim 通过 relay 调用目标模型，relay 在真实 HTTP 边界计数、限制请求并过滤工具。集成设计让 Victim 获得 relay 地址和临时入口凭证，目标 provider key 保留在 relay 容器。每个 run 使用独立网络与生命周期管理；设计是否在某次运行中完整实现仍需检查该 run 的证据。

### 10.3 Ark embedding proxy 在适配什么？

OpenClaw 使用 OpenAI 风格的 embedding 接口；Ark 多模态接口的请求和返回形状不同。proxy 按文本逐条发送，再转回 OpenAI `data[]`，保留顺序，避免把多个文档融合成一个向量。代理位于临时 Victim 容器内部，并记录独立调用预算。

## 11. 上游接入：`integrations/safeclaw/`

| 路径 | 作用 |
|---|---|
| `construction_bridge.py` | 采集阶段桥接 Construction 动作、上游 TaskRunner 和可观察事件 |
| `formal_bridge.py` | 正式阶段接收并执行逐 stage 动作，返回公开状态与结果 |
| `patches/a11f5cce-safety.patch` | 对固定版本 upstream 临时副本应用受控配置与敏感输出处理 |
| `upstream/SafeClawArena/` | 外部上游 checkout；被忽略，不属于本项目自主实现的主包 |
| `README.md` | pinned commit、接口适配、模型与容器接入说明 |

主包负责研究契约、调度和分析；bridge 负责把这些动作连接到上游实际运行接口。固定上游 commit 是复现条件，preflight 不会自动下载或更新它。patch 应用于临时副本，不能假定开发 checkout 本身已被修改。

## 12. 验证层：`verification/`

| 文件 | 作用 |
|---|---|
| `formal_models.py` | occurrence、edge、macro、官方结果、预算统计与正式结果的数据契约 |
| `occurrence.py` | 检查具体原语实例的可观察性与证据是否足够 |
| `edges.py` | 检查 typed path、artifact ancestry 和因果依赖边 |
| `macros.py` | 按宏模式检查所需 core occurrence 与依赖 |
| `formal_aggregate.py` | 汇总机制验证、动作 lineage、消融信息和最终结果分类 |
| `safeclaw_official.py` | 解析官方判定，并提供官方 PSE 评估器 smoke 检查 |

### 12.1 两条判定路径

**机制判定**检查计划要求的节点、边、宏、动作来源和无 shortcut 条件；**官方判定**检查 benchmark 的终点和合法任务表现。正式结果同时保留这两类信息。

可能出现：终点成功但机制不完整、机制完整但终点失败、环境/API 错误、未到达或不可观察。`not_observable` 表示证据不足；不能直接改写为“没发生”。

### 12.2 跨会话机制需要哪些证据？

至少要区分：实际 session 身份变化、同一持久作用域、写入前后变化、后续读取内容、读取结果进入上下文、之后的使用关系。标签不同、hash 存在、按时间相邻或一次空 `memory_search` 都不足以单独证明完整路径。

## 13. 记录与报告：`recording/`、`reporting/`

| 文件 | 作用 |
|---|---|
| `recording/events.py` | 事件记录相关辅助逻辑 |
| `recording/model_calls.py` | 模型调用的可观察记录、prompt 身份、请求/响应投影和脱敏 |
| `recording/formal_run_recorder.py` | 正式 run 的持久化、manifest、case 产物与完整性审计 |
| `reporting/formal_report.py` | 从已持久化运行产物生成报告 |
| `reporting/formal_metrics.py` | 汇总成功率、机制节点/边/宏指标、错误、观测覆盖与配对差异 |
| `reporting/statistics.py` | Wilson 区间与 McNemar 精确检验 |

记录层的目标是让报告可以从文件重建，而不是只依赖运行结束时的终端输出。报告必须说明分母：例如官方结果可观察的 case 与全部 case 未必是同一集合；usage/cost 未返回时应保留未知状态。

## 14. 模型与提示词：`models/`、`prompts/`

| 路径 | 作用 |
|---|---|
| `models/base.py` | 模型客户端抽象与调用契约 |
| `models/openai_compatible.py` | OpenAI-compatible HTTP 调用、结构化结果解析、attempt ledger 与有界重试 |
| `models/factory.py` | 根据角色配置构造客户端 |
| `prompts/loader.py` | 加载 prompt，读取身份/版本并计算 hash |
| 根目录 `prompts/formal/construction_attacker.md` | 采集 Attacker 的目标、观察和动作输出规范 |
| `prompts/formal/chain_selector.md` | 样本选择相关提案提示 |
| `prompts/formal/trajectory_planner.md` | 长程轨迹规划提示 |
| `prompts/formal/independent_attacker.md` | 正式独立 Attacker 的阶段动作提示 |
| `prompts/formal/no_sample_attacker.md` | 无样本条件的 Attacker 提示 |

Prompt 是版本化实验输入，但权限与数据契约还必须由代码验证。不能只因为提示词要求“遵守预算”就认为预算已经被硬性执行。

## 15. 配置目录：`configs/`

| 路径 | 作用 |
|---|---|
| `environments/safeclaw.yaml` | upstream、镜像、bridge、Victim、embedding 与 preflight 参数 |
| `models/formal_planner.yaml` | Planner 角色模型配置 |
| `models/formal_attacker.yaml` | 采集与正式 Attacker 相关模型配置 |
| `primitives/registry.yaml` | core primitive、macro、角色、证据策略、版本 |
| `task_sets/construction_tasks.yaml` | 采集任务及来源 split、模板身份 |
| `task_sets/evaluation_tasks.yaml` | 正式任务、配对信息、可绑定与可消融槽位 |
| `sample_generation/pilot_collection.yaml` | 小规模 pilot：2 tasks × 4 seeds，目标至少 2 accepted |
| `sample_generation/main_collection.yaml` | main：12 tasks × 10 seeds，目标至少 30 accepted |
| `sample_generation/cross_session_revalidation.disabled.json` | 默认禁用真实执行的跨会话复验模板 |
| `experiments/formal_evaluation.yaml` | 正式条件、seeds、预算、冻结库与角色 prompt 路径 |

部分 `.yaml` 文件使用 JSON 对象写法；JSON 是 YAML 的子集，应按内容及对应模型理解，而不是凭扩展名判断配置语义。

当前正式协议是 1 个 PSE 2.1 task × 3 conditions × 5 seeds，即计划 15 cases。三个条件为 `assigned_sample`、`no_sample`、`dependency_ablation`。矩阵存在于配置中，不表示这些 case 已经运行。

- assigned_sample：使用分配样本作为规划输入。
- no_sample：提供无样本基线。
- dependency_ablation：在预注册允许范围内修改样本相关依赖槽位，用配对结果研究依赖作用。

同一配对组应保持 task、seed、公开提示、预算、目标环境等不变量；消融不能任意更改任务。

## 16. 数据契约目录：`schemas/`

这里的 schema 对应不同阶段的 JSON 数据形状：

- 原语定义：`core_primitive_spec`、`attack_macro_spec`。
- 采集与交互：`raw_interaction_trajectory`、`interaction_event`、`interaction_graph`、`construction_observation`、`construction_attacker_action`。
- 抽取与样本：`primitive_occurrence`、`primitive_chain_candidate`、`primitive_chain_sample`、`accepted_sample_record`。
- 阶段与样本库：collection/mining manifest、library manifest、audit report、preflight report。
- 规划与执行：planner input、case assignment、evaluation plan、attacker input、attack realization。
- 环境与结果：task descriptor、public task view、public prompt、binding、episode result、formal run result。

`schema_registry.py` 和 `schemas build` 负责关联与生成。它们属于契约资产，不是每次实验的结果文件。

## 17. 脚本、诊断与质量检查

| 入口 | 作用 |
|---|---|
| `scripts/run_safeclaw_sample_collection.sh` | canonical pilot/main collection 入口，支持 preflight-only |
| `scripts/run_formal_evaluation.sh` | formal preflight/evaluation 入口，要求合格冻结库 |
| `scripts/run_cross_session_revalidation.sh` | prepare/offline 复验入口 |
| `scripts/diagnostics/run_openclaw_diagnostics.py` | offline、受控 live、memory-live 协议与生命周期诊断 |
| `src/stac_attack_lab/diagnostics/openclaw_mock.py` | 本地 mock provider、重试回放与受限工具检查 |
| `make check` | ruff 格式/静态检查、mypy 类型检查、pytest |
| `make schemas` | 重新生成 schema |

诊断证明的是特定协议或生命周期检查，不自动证明攻击成功，也不能计入正式评测指标。本次只阅读相关实现，没有执行这些运行入口。

## 18. 测试目录：`tests/`

- `unit/`：配置、模型客户端、relay/embedding proxy、预算/deadline、规范化、原语抽取、过滤、样本库、准入、Planner、调度、记录与统计等局部行为。
- `integration/test_safeclaw_adapter_contract.py`：环境 adapter 契约。
- `e2e/test_safeclaw_formal_pipeline.py`：正式流水线的端到端组合行为。
- `fixtures/`：最小、脱敏、确定性数据，包括样本生成与 SafeClaw 任务示例。

测试文件是理解“作者希望模块保证什么”的重要辅助阅读材料。例如 `test_construction_admission.py` 对应准入标准，`test_formal_scheduler_public_prompt.py` 对应公开提示与配对分配，`test_formal_verification.py` 对应机制验证。fixture 和 mock 通过不能替代真实环境证据。

## 19. 数据与运行产物：`data/`、`experiments/`

### 19.1 两类目录的职责

`data/primitive_libraries/generated/` 保存生成中、可审计的样本工作树；`frozen/` 保存正式不可覆盖输入。`experiments/runs/<run-id>/` 保存按唯一身份隔离的运行证据。新运行入口推荐输出到 runs；历史 generated 内容与新运行产物可能共存。

### 19.2 典型样本构建产物

```text
<build-root>/
├── interactions/raw/<collection-id>/
│   ├── collection_manifest.json
│   ├── collection_stage_manifest.json
│   └── trajectories/<trajectory-id>/raw_trajectory.json
├── interactions/normalized/<trajectory-id>/
│   ├── interaction_graph.json
│   └── normalization_audit.json
├── extraction/
│   ├── <graph-id>-occurrences.jsonl
│   └── <graph-id>-decisions.json
├── library/
│   └── library_manifest.json + 样本/记录文件
├── sample_generation_manifest.json
├── mining_stage_manifest.json
└── library_audit_report.json
```

这是帮助理解数据流的示意；具体源事件、checkpoint、journal 和 ledger 还要按该 run 的 manifest 查找，不能假定每次运行全部完整。

### 19.3 建议如何阅读一条轨迹？

先看 manifest 与 collection status，再追 source events 和 checkpoint；之后看 normalized graph、抽取 decisions、候选 gate 决策、library audit/admission，最后才看 summary。报告数字应能追溯到这些底层文件。

## 20. 现有文档与当前事实边界

| 文档 | 阅读用途 |
|---|---|
| `README.md` | 总览、依赖、推荐入口 |
| `docs/EXPERIMENT_PROTOCOL.md` | gate 顺序、配对设计、指标、停止条件 |
| `docs/PROMPTS.md` | 提示词资产、Planner/Attacker 输入权限 |
| `docs/LINUX_TMUX_RUNBOOK_ZH.md` | Linux 环境、日志、诊断、停止和恢复 |
| `docs/IMPLEMENTATION_PROGRESS.md` | 历史实施与验证事实；阅读时核对日期和 run |
| `docs/IMPLEMENTATION_WORKPLAN.md` | 尚未完成的研究工作和验收项 |
| `docs/CLEANUP_MANIFEST.md` | 清理路径、理由与恢复说明 |
| `SECURITY.md` | 授权、凭证、隔离边界 |

当前工作区检查到：

1. 主流程的源码、配置、schema 和测试文件已存在。
2. 存在历史 generated 和 runs 产物；本文没有对每个历史 run 做完整内容审计。
3. 正式配置要求 `data/primitive_libraries/frozen/safeclaw-main`；当前该目录不存在。因此不能仅凭 formal 配置中的 `execution_enabled=true` 认为已具备正式评测条件。
4. 进度文档描述了真实复验、离线修复、partial trajectory 与准入失败等不同阶段，不能把其中某一轮结果当作整个项目当前验收结论。
5. `README.md` 和 `docs/README.md` 引用的 `PROJECT_GUIDE_ZH.md` 当前缺失；检查前工作区已将它标为删除。本文另建文件，没有恢复或改写该删除。
6. 本次没有核验真实 provider 可用性、Docker 状态、全量测试或正式效果。

## 21. 推荐的逐章讲解顺序

### 第一轮：建立研究模型

- 1–2：研究目标、角色、原语、宏、证据等级。
- 3–4：目录、Python 包和 CLI 入口。

### 第二轮：理解样本怎样产生

- 5：Construction Attacker 与 Victim 的交互循环。
- 6：事件怎样变为 occurrence 和 chain，G0–G8 怎样接受或拒绝。
- 7：样本三视图、accepted/audit/admission/freeze。
- 19：用一条实际产物核对全过程。

### 第三轮：理解正式评测怎样工作

- 8：Scheduler、Planner、binding 与长程轨迹。
- 9：独立 Attacker、action loop 与预算。
- 15：三条件配对设计与 dependency ablation。

### 第四轮：理解环境与证据

- 10–11：driver、bridge、upstream、relay、embedding。
- 12：节点、边、宏、官方判定与 shortcut。
- 13：怎样从持久化记录生成统计结论。

### 第五轮：源码细读与工程现状

- 14、16–18：模型调用、prompt、schema、脚本和测试。
- 20：哪些是已实现能力，哪些有实际证据，哪些仍未通过验收。

后续可以这样问：“先讲第 5 章，沿调用链解释一次 collection”“讲清 occurrence 和 macro 的关系”“选一条轨迹，从 raw 到 accepted 逐文件解释”。讲解时可以依次给出概念、实际类/函数、输入输出、调用关系、失败分支和对应测试。
