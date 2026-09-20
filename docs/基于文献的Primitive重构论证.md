# 基于文献的 Primitive 重构：传递、派生与状态更新

> 状态说明（2026-09-20）：本文保留为设计论证，不是实验结果，也不证明三原语具有普适
> 最小性。当前实现位置和版本边界以
> [PRIMITIVE_V3_IMPLEMENTATION.md](PRIMITIVE_V3_IMPLEMENTATION.md) 为准。

日期：2026-09-19  
性质：研究设计报告；提出可供验证的抽象，不宣称已经完成实验或证明现实世界的绝对完备性。  
材料：`primitive-related-papers/` 中的八篇 PDF，以及本目录原有 `README.md`。论文定位以本地 PDF 版本为准，页码从 PDF 第一页起计。

## 1. 我的结论

我建议采用以下三个**参数化操作族**作为底层 primitive：

| 原语 | 中文 | 唯一核心问题 | 典型实例 |
|---|---|---|---|
| `TRANSFER` | 传递 | 一个已有信息对象，被交付到了哪个执行域？ | 消息收发、工具请求与回包、读取某个 memory 版本 |
| `DERIVE` | 派生 | 一次处理，根据哪些输入产生了什么输出？ | 摘要、推断、计划、工具选择、参数绑定、生成代码 |
| `UPDATE` | 状态更新 | 哪个具有独立身份的资源，其实际生效状态改变了？ | memory 写入、文件删除、权限授予、调度改变、环境副作用 |

三者需要与**类型化对象、数据/控制依赖、版本关系、授权范围、证据等级**一起使用。只有三个动作名称，无法表达完整的信息传播。

这里的推荐与原有四类方案不同：保留 `TRANSFER`；把 `TRANSFORM` 改称 `DERIVE`，避免暗示每次处理都改变语义；把 `MUTATE` 和旧 `CONTROL` 中的实际状态变化统一为 `UPDATE`。旧 `CONTROL` 中描述“上游如何影响选择”的部分，改为依赖关系；生成选择结果的部分归入 `DERIVE`。

选择三类，不是因为论文中存在一个公认的“三原语定理”。这是我综合文献后提出的设计：**信息的交付、信息的产生、资源的生效变化，分别具有不同的证据和组合接口；控制、安全和语义角色作为必须保留的结构信息，而不再混进同一级动作分类。**

对于“整个离散空间且没有冗余”，能够严谨争取的表述是：

> 在预先固定的观察范围、对象粒度和执行语义下，用三个不可互相替代的操作族，组合表示有限的人—Agent—环境交互记录。具体日志的覆盖程度与分解一致性还需要验证。

不能把它表述成“已证明所有可能的信息传播都唯一分解成这三个原语”。本报告后面明确说明条件、反例和验证方法。

## 2. 先修正原有论证中的问题

### 2.1 九项词表混合了不同分类标准

`Ingest / Adopt / Persist / Recall / Select / Bind / Act / Record / Recover` 对讲述攻击链很有用，但并非同一粒度的操作：

- `Ingest / Recall` 按信息来源区分。
- `Select / Bind` 按派生结果的用途区分。
- `Persist / Record` 按写入对象区分。
- `Act` 常覆盖前面若干副作用。
- `Recover` 是失败处理的一段流程。
- `Adopt` 涉及内容被如何使用，通常不能直接从模型内部读取。

这些名称可以保留为上层宏和标签，但不能直接作为互斥的底层 enum。

### 2.2 四坐标证明不能承担现实完备性的结论

原有 `README.md` 把状态写成 `V × D × W × C`，再分别定义只改变一个坐标的操作。这能得到一个**定义内的独立性结论**，但还有三个缺口：

1. **坐标的独立性尚未成立。** 权限变化可以是 ACL、配置或授权表的写入；调度变化可以是任务状态更新。若 `W` 已包括这些，`C` 就重叠；若明确排除，则四分类成立依赖人为分区。
2. **图记录不等于被研究系统的状态。** 新增一条 provenance 边是观察者的记账，不能据此断言现实执行中存在一个只改变 `D` 的物理步骤。
3. **多效果事件不一定能按任意顺序串行拆开。** 原子事务同时写入数据与权限，若拆成两个独立可调度步骤，会引入真实系统不存在的中间状态。

因此，不能用“先定义四个互不重叠的坐标”代替“论证现实事件为何适合四种原语”。本报告改用对象接口与事件效果建立模型，并保留事务分组。

## 3. 从哪些论文借鉴了什么

以下不是逐篇综述，而是“哪一部分改变了本报告的设计”。原文主张与本报告的推导分别写明。

### 3.1 FIDES：最主要的操作语义依据

**阅读位置：** §3、§3.1，PDF 第 4–5 页；§4.1–4.2，第 6–8 页；§4.4，第 9–10 页；§5.1–5.2，第 10–11 页。[P1]

**原文提供什么：** FIDES 将模型调用表示为消息历史到输出的计算，将工具表示为同时读取/更新 datastore 并返回结果的函数；planner 自身还有状态。§4.2 区分调用工具的标签和每个参数的标签。§5 通过隐藏变量和受约束读取控制 planner 能接触的信息。

**我如何使用：** 将“产生输出”“交付输出”“使状态变化生效”区分开；调用名、参数字段和执行条件分别保留来源。一个工具返回了文本，不代表它只做了文本变换；一个模型看到了变量句柄，也不代表它看到了变量内容。

**不照搬什么：** FIDES 的 `Query / MakeCall / Finish` 是其 planning loop 的动作接口，不是跨人、Agent、环境的最小原语。它的安全保证依赖模型与策略假设；本报告的轨迹表示不会自动继承该保证。

### 3.2 CaMeL：控制影响必须保留，但不必成为第四种动作

**阅读位置：** §5.3–5.4，PDF 第 9–11 页，Figure 7；§7，第 19–21 页，Figures 14–16。[P2]

**原文提供什么：** CaMeL 在值上保留来源和允许的读取者，并在解释器中跟踪依赖。STRICT 模式把条件/循环的依赖传播给相关执行。§7 说明，即使请求内容不包含秘密，请求是否发生、发生次数等行为也可能携带信息。

**我如何使用：** 图必须保留 `data_dep` 与 `control_dep`。不能把“没有复制上游字符串”判定为“没有传播”；也不能用调用先后顺序冒充控制依赖。

**不照搬什么：** 我们不要求 Agent 预先生成可信 Python 计划，也不将 CaMeL 的解释器依赖提取能力假定为任意 LLM 都具备。本文合并旧 `CONTROL` 是操作分类选择，绝不是删除控制流信息。

### 3.3 AgentArmor：保留字段级来源，不直接复制其推理模式表

**阅读位置：** §5.1，PDF 第 4–7 页，Figure 2 与 Table 1；§5.2，第 7 页。[P3]

**原文提供什么：** AgentArmor 从 trace 构造 CFG、DFG 和 PDG；把工具名与参数拆开；Table 1 区分用户直接要求、参数化执行、条件执行等模式。部分依赖由 LLM analyzer 推断，工具内部读写则需要 property registry 补充。

**我如何使用：** 一次 `DERIVE` 可以产出结构化调用对象，但必须允许追踪 `tool_name`、`recipient`、`body` 等字段的不同来源。工具副作用需要契约或状态证据，而不能仅看工具名字。

**不照搬什么：** Table 1 的八种推理模式不作为八个底层原语；“匹配某种模式”也不是已证明的因果关系。图中由分析器推断的边必须与实际日志边区分。

### 3.4 NeuroTaint：来源要跨存储延续，语义证据需要分级

**阅读位置：** §3.3，PDF 第 5 页；§4.1–4.3，第 6–9 页，Figures 2–3。[P4]

**原文提供什么：** 区分显式内容传播、隐式控制影响、异步来源复用；DCPG 在 memory 写入与读取间维持 lineage；检测结合字符串、语义相似度和 sink-time counterfactual analysis。

**我如何使用：** memory 必须有版本和写入来源；语义相似度只产生候选依赖；是否影响决策需要另行验证。

**特别需要谨慎：** §4.3 展示的 judge prompt 是询问 LLM 在替换来源后“是否还会调用”；其 confidence 为模型自报，原文也说明它不是校准概率。紧接的例子又描述了重新查询 Agent。因此，仅凭该节不能把所有结果都等同于完整环境下的受控重放。本报告把“LLM 反事实判断”和“实际干预重跑”分开。

**不照搬什么：** 三种传播情形不是三个动作原语。跨会话是时间结构，可以同时包含复制、语义派生和控制影响，不是另一种独立运算。

### 3.5 Agent-BOM：对象、关系、安全属性分层

**阅读位置：** §III.A–B，PDF 第 5–9 页；Tables IV–VI；§IV.A，第 7–8 页。[P5]

**原文提供什么：** 区分静态能力对象和运行时语义节点；通过消息、调用、写入、影响等关系连接，并附加来源、权限、确认状态和环境变化等属性。风险判定建立在路径和上下文条件之上。

**我如何使用：** tool、skill、memory 是对象类型；来源、授权和用途是属性或关系；攻击是路径上的判定。不能把它们都变成操作名称。

**不照搬什么：** 其 `flows_to / influences / selects / invokes / writes_to` 等边服务于审计查询，并未被证明是无冗余生成集。`GoalNode / ReasoningNode` 也不使隐藏认知状态自动变成可观察事实。

### 3.6 其余三篇：作为反例来源，而非原语命名依据

| 论文及位置 | 用来检验什么 | 对本报告的约束 |
|---|---|---|
| MCPTox，§2.2–3.1、Figure 2，PDF 第 2–4 页 [P6] | 恶意工具不用被调用，其描述就可能影响另一个工具的选择或参数 | metadata 是信息对象；“执行了恶意工具”不是传播必要条件 |
| Skill-Inject，§2.2–2.5、§3，PDF 第 3–4 页 [P7] | 合法 skill 本就包含指令；风险取决于具体任务与授权 | 不能把所有 `data → instruction` 或所有“听从第三方指令”自动判为攻击 |
| ACIArena，§3.1–3.2，PDF 第 3–4 页 [P8] | 输入、profile 和消息投毒通过多 Agent 拓扑传播 | 传递要与 actor 类型无关；多 Agent 不另增一类运算 |

这些论文提出了有用的建模约束，但没有一篇证明本文三类集合的最小性。推荐集合是本报告的综合推导。

## 4. “整个离散空间”的可操作定义

### 4.1 我们表示哪一种空间

研究对象是**可记录的离散交互及其依赖图**，包括信息交付、计算输出、资源版本和执行状态变化。

不试图枚举自然语言的所有含义，也不恢复未外显的人类意图或 LLM 隐藏推理。文本相同是否意义相同，也不由原语类型直接决定。

固定抽象配置 `Ω`，至少包括：

```text
Ω = (执行域边界, 信息对象粒度, 可观察资源,
     通道事件粒度, 时间精度, 可用日志/工具契约)
```

离散化的是事件、对象身份和版本；文本、向量或传感器值可以作为载荷。若要研究连续时间、能耗或模拟信号侧信道，必须先扩展 `Ω` 并重新检查覆盖性。

### 4.2 三种基础对象

**执行域 `C`：** 能在本抽象中单独接收或处理内容的地方，例如人类用户接口、Agent 会话、隔离 LLM、工具进程、外部服务。同一 Agent 的隔离 planner 与 executor 可以是不同执行域；不能为了多造一次 `TRANSFER` 而临时改变边界。

**不可变信息对象 `X`：** 消息、文本片段、工具描述、请求字段、结果、决策 token、资源版本快照。相同字节不意味着相同 provenance；两个独立来源不能仅按 hash 合并为同一个对象。

**可变资源 `R`：** 有稳定身份、且有独立于当前一次输出的生效状态的对象，例如 memory entry、文件、数据库记录、权限表、任务队列、会话生命周期与物理环境变量。

每个资源版本用不可变快照表示：`r@v0 → r@v1`。版本快照是 `X` 中的对象，资源的“当前生效版本”是运行状态中的引用。这样可以表达后续 read 实际读到了哪次 write。

### 4.3 哪些状态变化不重复记账

所有操作物理上都会改变机器状态，但本抽象不记录每一次内存写：

- 接收消息导致的临时接收槽变化由 `TRANSFER` 表达，不另外补一个 `UPDATE`。
- 一次计算产生临时输出由 `DERIVE` 表达，不因为分配内存就追加 `UPDATE`。
- 若接收消息同时写入了被 `Ω` 单独跟踪的持久日志，则“交付”与“日志持久化”是两个不同效果，后者记 `UPDATE`。
- provenance 图自身的新增节点/边属于观察器记账，不递归生成被研究系统的 `UPDATE`。

这套粒度约定要在标注前固定。所谓“无冗余”首先要求同一事实只记一次，而不是同一现实调用只能有一个效果。

## 5. 三个原语的精确定义

### 5.1 `TRANSFER`：交付一个已有对象

```text
TRANSFER(source, destination, artifact_or_version, channel, delivery_id)
```

**语义：** 使已有信息对象在目标执行域的一次输入位置上可用，保留对象身份及来源。不做语义判断，不自行改变对象内容。

成功交付不等于接收者注意、理解、相信或服从。向人展示信息只能证明接口交付；向模型传入上下文只能证明它是候选输入。

适用：用户消息、Agent 间通信、工具请求/返回、加载 skill、读取 memory 或文件的指定版本。源可以是另一个执行域，也可以是资源版本。

**边界规则：**

- 同一对象重复交付给同一接收者是两个 occurrence；重复次数本身可能影响行为。
- `TRANSFER` 默认是交付/复制，不隐含从源删除。真正的移动要另记源资源更新。
- 协议序列化若在 `Ω` 中被视为透明编码，可以保持对象身份；摘要、脱敏、翻译不能偷藏在通道里，必须显式 `DERIVE`。
- “读取句柄”与“读取句柄指向的内容”是不同对象的交付。此点直接来自 FIDES/CaMeL 的隔离设计启发。

### 5.2 `DERIVE`：处理输入并产生输出

```text
DERIVE(executor, input_refs, operation_ref, output_refs, invocation_id)
```

**语义：** 在执行者的局部处理边界，产生一个或多个输出对象。处理可以是确定性计算、LLM 采样、规则匹配、感知编码或人类外显输出。

适用：翻译、摘要、过滤、拼接、检索排序、归纳、决策、参数绑定、生成代码。检索中“哪些记录被选中”可为派生；选中记录原文的交付为 `TRANSFER`。

选择 `DERIVE` 而不是 `TRANSFORM`，因为它不预设语义发生变化：相同输入可被复制到新生成文本，也可能被扭曲、保留或忽略。是否改变语义由额外证据判断。

**输入关系必须区分：**

```text
available_input   实际传入处理过程，可证明暴露
data_dep          输出值/内容的依赖
control_dep       输出选择、事件发生与否、次数或顺序的依赖
```

一次 LLM invocation 的完整输入通常可以记录；哪一段真的影响了哪个参数，则未必可知。不能把 `available_input` 全部升级成已经验证的因果边。

**边界规则：**

- 决策 token、调用对象可以作为输出；新决策本身不是已经执行的动作。
- 未记录中间思考时，将一次调用视为黑盒派生，不虚构 `belief → goal → plan` 的内部路径。
- 多输入、多输出用一个带端口的事件或超边表示，避免把共同原因误拆成独立充分原因。
- 外部新输入、随机性、模型版本与环境初值允许作为显式边界根。来源未知就标 `unknown`，不要声称所有信息都来自之前可见的文本。
- 纯转发已有对象不额外加“恒等派生”。但确实发生了一次模型调用且输出恰好相同，仍可记录真实计算事件。

### 5.3 `UPDATE`：使资源新状态生效

```text
UPDATE(executor, resource_refs, before_versions, after_versions,
       input_refs, effect_kind, transaction_id)
```

**语义：** 修改一个或多个被 `Ω` 跟踪的资源，使其新状态生效。它既包括持久业务状态，也包括可观察的运行控制状态。

可用子型：

```text
effect_kind ∈ {memory, world, control, authority, configuration, ...}
```

这些是资源/效果标签，不再各自宣称为一种不可替代的底层运算。

适用：写入/删除 memory、修改文件、提交数据库事务、发送服务创建邮件记录、批准授权、撤销权限、取消任务、提交下一执行分支、更新模型参数。

**边界规则：**

- 计算出 `new_value` 不等于资源已经更新；请求被发送也不等于副作用成功。
- 创建和删除使用存在性标记或 tombstone 表示，保留历史版本。
- 覆盖不意味着抹掉历史 provenance；回滚本身是一次新更新。
- 副作用前后值都不可见时，只能记“尝试/未知结果”，或按明确工具契约推断并标证据级别，不能编造已生效的状态差分。
- 物理操作只覆盖离散观察到的环境变量或契约效果，不声称恢复连续世界的完整状态。

### 5.4 失败、拒绝和超时怎么表示

`status ∈ {attempted, succeeded, rejected, failed, timeout, unknown}` 是 occurrence 的结果属性，不是第四个原语。

拒绝可能有一段可观察过程：派生拒绝决定，更新任务为 blocked，再向用户交付解释；不存在的内部步骤不补画。超时不能自动等价于“工具没有产生副作用”；部分成功应按真实写入记录。

## 6. 为什么控制、安全与“采纳”不另列原语

### 6.1 原有 `CONTROL` 实际包含三件事

| 现象 | 新表示 |
|---|---|
| 根据检索结果选择一个工具或分支 | `DERIVE(... → decision)` |
| 条件影响某次调用是否发生 | `control_dep(condition, occurrence)` |
| runner 将待执行分支、权限或生命周期实际切换 | `UPDATE(resource=control_state)` |

它们分别是计算、依赖、状态更新。再加一个宽泛 `CONTROL`，会让同一个“选择工具”在 `DERIVE` 和 `CONTROL` 间反复摇摆。

`control_dep` 必须是一等关系：即使 sink 参数没有上游内容，仍能表示上游决定了调用发生。不能用一条普通 `happens_before` 代替它。[P2][P3]

如果后续研究需要“控制面变更”作为单独实验维度，可以把 `UPDATE.control / UPDATE.authority` 作为稳定子型或消融目标；不必因此增加底层操作族。

### 6.2 “数据变成指令”主要是使用角色与授权的问题

同一段文字作为引用、工具描述、计划依据或执行指令时，可以字节完全相同。为此在消费关系上记录：

```text
use_role ∈ {content, evidence, instruction, constraint,
            goal, decision, argument, executable, unknown}
```

角色属于“这个对象在此次事件中怎么被使用”，不必是对象全局唯一的属性。

例如网页命令影响了工具调用：先有网页的 `TRANSFER`，再有调用对象的 `DERIVE`；若证据足够，可标注网页到决策的 `control_dep` 以及 `use_role=instruction`。这表示它在行为上被用作指令，不能等同于已直接观测到模型内部“相信了它”。

Skill-Inject 提醒我们：第三方内容有时本来就被授权提供指令。因此，`Adopt` 不能天然带上“攻击成功”的含义。[P7]

### 6.3 保留来源、策略标签与授权依据

建议附加：

```text
provenance: 原始来源、载体、版本、直接父对象
security_label: confidentiality / integrity
authorization: issuer / subject / action_scope / resource_scope / expiry
policy_context: task_id / policy_version / approval_evidence
```

这些字段不必全部由系统提供；缺失时明确 unknown。

在保守 IFC 配置中，派生输出可继承候选输入及控制条件标签的 join；这是一种**可能依赖的安全上界**，不是精确语义因果图。[P1][P2]

“网页说自己已经获得批准”只是一项内容。真正授予权限是授权资源的 `UPDATE`，应有独立签发与范围证据。文本被包装成 JSON、摘要或新消息，都不自动消除原始低可信来源。

合法的 endorsement/declassification 也不删除来源：若系统实际改变策略标签或授权状态，记录受授权的 `UPDATE`；若只是分析员事后改判，则属于审计结论变化，不伪造一次运行时事件。

## 7. 组合结构：不能只保留一串字母

完整表示建议为：

```text
G = (执行域/资源/版本/信息对象, 操作 occurrence,
     类型化依赖, happens-before, 事务分组, 证据与安全属性)

occurrence.kind ∈ {TRANSFER, DERIVE, UPDATE}
```

组合需要满足：输入可达、对象类型匹配、read 指向存在的版本、写入前后版本连贯、会话与执行域一致。**操作表示不强制每一步都合法授权**，否则无法表示已经发生的越权攻击；是否合法由策略判定层处理。

多 Agent 汇合是多个输入进入同一次派生；fan-out 是一个对象的多次交付；循环按 occurrence 和版本展开。并发保留偏序，不按时间戳强行认定数据或因果联系。跨会话依赖沿资源版本延续，不要求两个会话共享上下文。

一次 API 调用可以同时产生 `DERIVE`、`UPDATE` 和 `TRANSFER` 的效果。没有内部日志时，它们可作为一个原始事件的多个**效果面**，共享 `source_event_ref`；若属于原子事务，还要共享 `transaction_id`。这不表示已经观察到了三个可独立调度的真实步骤。

对于原子“发送并修改状态”，图允许联合转移；不能展开出“已更新但尚未发送”这种不可达中间状态。这里追求的是效果表示的完备，而不是保证所有事件都能串行执行成单原语指令。

## 8. 用具体场景检查是否丢失信息

以下是抽象示例，不是本项目已经跑出的轨迹。`T/D/U` 分别表示三类原语；未展示的步骤不代表实际不存在。

### 8.1 正常的人—Agent—工具问答

```text
T(user → agent, question)
D(agent, question → query_request)
T(agent → search_tool, query_request)
T(index@v → search_tool, candidate_records)
D(search_tool, query + candidate_records → ranked_result)
T(search_tool → agent, ranked_result)
D(agent, question + ranked_result → answer)
T(agent → user, answer)
```

如果只观察到搜索服务接口，则内部查询是黑盒派生，不虚构具体索引版本。纯查询不凭工具调用本身添加 world update；被单独跟踪的查询日志另计。

### 8.2 MCP 描述影响了另一个工具

```text
T(MCP server → agent, tool_description)
T(user → agent, legitimate_task)
D(agent, task + description → call{tool_name, args})
T(agent → selected_tool, call)
[U(selected_tool, target@v0 → target@v1)]
T(selected_tool → agent, result)
```

MCPTox 的关键现象不需要“运行恶意工具”步骤；来源只是 metadata。描述可能影响工具名，也可能只影响某个参数字段；这两种机制在依赖端口上区分。[P6]

### 8.3 跨会话 memory 传播

```text
Session A:
T(web → agent_A, source_text)
D(agent_A, source_text → summary)
U(memory_service, entry@v0 → entry@v1(summary))

Session B:
T(entry@v1 → agent_B, summary)
D(agent_B, current_task + summary → decision_or_answer)
```

省略的写请求通道可按观测粒度补齐。`entry@v1` 必须指回写入的 summary，summary 指回 source_text。这里的跨会话关系由 `UPDATE + 版本读取 + provenance` 组成，不需要独立 `Recall` 运算。[P4]

### 8.4 没有内容复制的控制传播

用户要求“如果检测到异常，发送固定内容的通知”。工具返回布尔值，通知正文始终是常量。

```text
T(detector → agent, anomaly_flag)
D(agent, task + anomaly_flag → decision)
decision --control_dep--> T(agent → notification_tool, fixed_request)
[U(notification_tool, notification_state)]
```

通知正文不含 flag，但事件是否发生仍受其影响。若 runner 暴露了分支提交状态，还可记 `U(control_state)`；若没有这项观察，不应臆造一次更新。缺失执行分支本身不能被画成已发生的调用，而应通过干预轨迹对比分析。[P2]

### 8.5 多 Agent 委派与汇合

```text
D(A, task → subtask)
T(A → B, subtask)
[U(authority_store, grant_scoped_permission_to_B)]
D(B, subtask + local_inputs → result_B)
T(B → A, result_B)
D(A, result_B + result_C → joint_answer)
```

发送任务不等于转移权限；如果并未授予新权限，方括号步骤不存在。汇合必须记录多个输入共同参与，不能把整个系统强行缩成单链。[P5][P8]

### 8.6 Skill、拒绝、删除与环境自主变化

| 现象 | 表示 | 必须避免的误判 |
|---|---|---|
| metadata 触发 skill 加载 | `T(metadata) → D(selection) → T(body)` | 看到 metadata 不等于执行 skill |
| skill 建议引发实际脚本执行 | `D(command) → T(executor) → [U(resource)]` | 指令存在不等于它有授权 |
| 审批拒绝 | `D(deny) → [U(task=blocked)] → T(explanation)` | 不把未执行的业务副作用标为成功 |
| 删除 memory | `U(entry@v → tombstone)` | 删除当前可读值不抹掉审计历史 |
| 环境传感器产生新读数 | `D(sensor, observed_world → reading) → T(reading)` | 无法观察底层世界时保留外生来源 |
| 环境自行改变数据库/设备 | `U(environment, state@v0 → state@v1)` | actor 不限定为 Agent |

## 9. 覆盖性和无冗余：能证明到哪一步

### 9.1 先给定观察语言，再讨论覆盖

设 `L_Ω` 是满足以下接口的有限执行记录集合：

1. 跨执行域输入输出可表示为已有对象的交付。
2. 局部处理可表示为一次输入—输出关系；未知、随机和外生输入允许显式边界根。
3. 独立资源的生效变化有版本差分或效果记录。
4. 复合事件保留其效果分组、原子性和可观察偏序。
5. 未观测部分可以表示为未知，但不冒充已重建内容。

那么，可定义规范化映射 `N : L_Ω → G_Ω`，把交付映射成 `T`、处理映射成 `D`、资源变化映射成 `U`，并保留连接约束。

**条件性表示覆盖命题：** 对上述语言中的有限记录，三种操作族足以表示所有已记录的效果，以及它们已记录的关联与分组。

**证明思路：** 对记录结构归纳。基础交付/处理/更新分别有对应原语；顺序组合保留前后连接；并发组合保留偏序；复合事务保留原始联合效果而不串行化；有限循环按 occurrence 展开。因此没有一条符合该接口的记录需要第四种基础效果。

这证明的是一个明确观察语言的可表示性。**现实中的所有相关行为是否都能忠实映射到该语言，是仍需审查的适配假设。** 若遇到无法保留的观察，例如某种未建模的时间信号，就扩展 `Ω` 或承认漏项，不能说“它必然属于 UPDATE”后直接宣布解决。

### 9.2 无冗余是固定语义接口下的不可替代性

要求替代表示保持执行域、信息对象身份、资源版本和已观察行为，不得添加不存在的对象或效果。

| 删除哪类 | 反例 | 为什么其余两类不能替代 |
|---|---|---|
| `TRANSFER` | 已有消息从 A 原样交付给 B，不产生新内容或独立资源写入 | `DERIVE` 只产生局部输出；`UPDATE` 只更新独立资源，都没有交付接口 |
| `DERIVE` | A 在本地从两个输入计算摘要，未交付、未保存 | `TRANSFER` 不能产生新的摘要；`UPDATE` 不能代替本地处理过程 |
| `UPDATE` | 清除已存在 memory entry，或撤销已经生效的权限 | 传递“删除请求”或生成“撤销建议”都不能使资源变化生效 |

在这份接口契约下，三类各自有另两类不能替代的观察，因此没有可删除的类别。

但这不是与编码方式无关的“全宇宙最小数目=3”。若把所有对象、通道和机器状态压成一块存储，一条万能 `STEP` 或 `UPDATE` 也可模拟所有操作；代价是所有分类信息都藏在参数或解释器里。反过来，把控制和权限单列为类型也完全可行，但不再是本报告选用的最粗操作划分。

### 9.3 为什么不选两类或四类

- **只有传递+派生：** 可表达纯消息系统，但写入承诺、权限生效和环境副作用必须被偷偷藏进“派生”，无法稳定区分建议和实际执行。
- **四类，另设 CONTROL：** 可以人为规定资源分区后使用，但会把依赖、决策与控制资源更新混为一类，且其不可约性依赖额外排除规则。对当前信息传播研究，保留控制依赖与 `UPDATE.control` 更清楚。
- **更多阶段名：** `Select / Bind / Summarize / Recall` 等均可由操作参数、端口或宏恢复；增加枚举数没有增加基础表达能力。

因此，推荐三类的理由是**操作接口明确且较粗，同时安全相关区别没有被删除**，不是单纯追求更小数字。

### 9.4 不保证唯一分解，也不保证自动重放

一次模型调用可能同时选工具、绑定参数、生成解释。没有中间证据时只能作为一个多输出 `DERIVE`；有真实分阶段日志时才拆开。二者可以在更粗投影下等价，不意味着细粒度路径唯一。

还应区分三件事：

```text
格式重建：恢复日志中的对象、字段、顺序、版本。
抽象状态重放：按已记录效果得到相同的被跟踪状态。
真实执行重跑：重新调用模型和环境得到相同结果。
```

前两者在条件满足时可检查；第三者受随机性、外部状态和黑盒行为影响，不能由 primitive 完备性直接推出。

## 10. 原有九项怎么保留

| 原词 | 推荐展开 | 保留的解释信息 |
|---|---|---|
| `Ingest` | `TRANSFER(source → context)` | 来源、输入通道 |
| `Recall` | 资源版本读取的 `TRANSFER`；有检索选择则另加 `DERIVE` | memory 身份、写入版本、检索理由 |
| `Adopt` | 在 `DERIVE` 的输入使用上标注 instruction/goal 等角色；实际 policy 更改才加 `UPDATE` | 行为证据、作用范围、授权依据 |
| `Select` | `DERIVE(... → selected_capability)` | 选择端口与控制来源 |
| `Bind` | `DERIVE(... → bound_arguments)` | 每个参数的来源 |
| `Persist` | `[DERIVE] + [TRANSFER] + UPDATE(memory)` | 生效版本、保存内容 |
| `Record` | `UPDATE(log)`，按需加内容生成与请求交付 | 仅用于被研究系统的实际日志 |
| `Act` | 请求交付、实际处理、可选资源更新和返回组成的宏 | 读/写类型、执行身份、效果 |
| `Recover` | 失败反馈、重新派生计划、可选调度更新与重试交付 | 原因、次数、已发生的部分副作用 |

方括号表示按真实过程选用，而非每次都补齐固定模板。九项留在报告与攻击机制层，三类负责底层记录。

## 11. 最小记录格式与证据要求

不建议现在直接改全部实验代码。先用下面的概念格式手工标注一批轨迹，看是否存在无法决定的边界。

```yaml
event_id: e42
kind: DERIVE
executor: agent_A/session_2
source_event_ref: model_call_17
inputs: [user_task, memory_entry_v3]
outputs: [call_18]
operation_ref: model_and_prompt_version
status: succeeded
dependencies:
  - from: user_task
    to: call_18.tool_name
    relation: control_dep
    evidence: inferred
  - from: memory_entry_v3
    to: call_18.args.recipient
    relation: data_dep
    evidence: inferred
```

这里可以确定模型调用发生且输出了调用对象；两条字段级依赖尚是 inferred。若有精确绑定日志或干预证据，再提升具体边的等级。不要给整个图一次性盖一个“因果可信”的章。

建议至少区分：

| 证据层 | 能说什么 | 不能直接说什么 |
|---|---|---|
| 实际日志/版本差分 | 对象交付了、调用产生了、某状态改变了 | 某段内容必然导致了行为 |
| 工具契约/解释器依赖 | 在契约成立时发生某类读写或依赖 | 黑盒实现一定符合契约 |
| 语义相似/LLM 判读 | 存在候选派生、候选指令使用 | 精确来源或因果效应已证实 |
| 实际受控干预 | 在给定干预和重复实验下，行为分布改变 | 唯一原因、所有环境下都成立 |

对多个来源共同作用，要做联合替换或因子实验；逐个删除但都无影响，不能排除冗余原因。实际重跑需固定可控条件并考虑模型随机性。超时、缺失记录和跨会话缺少旧版本，应降低覆盖/证据结论，而非由 LLM 补出“完整路径”。

## 12. 哪些检查通过后才值得写进论文

以下是建议验证，不是已完成结果。

### 12.1 先建立与三类名称无关的事实清单

在看新 schema 之前，从原始轨迹独立列出：谁收到什么、哪些输出产生、哪些资源改变、哪些字段依赖已知、哪些事实未知。然后检查表示是否保留这些事实，避免用自己的定义给自己打满分。

从正常问答、只读工具、写操作、memory、MCP metadata、skill、多 Agent、审批、失败重试、并发事务各取案例。优先包含反例，而非只挑容易符合模型的攻击链。

### 12.2 比较的必须是完整表示方案

对照可以是九项、旧四项与新三项，但给它们相当的字段预算和标注说明；不能只给新方案 provenance、版本和控制边，然后把收益归功于三个名字。

检查：

- **事实保留率：** 是否保留独立事实清单中的交付、输出、读写版本与可见副作用。
- **无法表达率：** 哪类事实需要新增运算或违反现有定义。
- **标注一致性：** 不同标注者是否同意事件边界、原语与依赖类型；这些指标分别报告。
- **重复计数：** 同一接收、派生或写入是否被多算；合法复合效果不算冗余。
- **控制/授权信息保留：** 能否区分改正文、改收件人、改是否调用，以及有无真实授权。
- **结构往返：** 规范化后是否恢复已记录的版本、字段、偏序和事务分组。

### 12.3 明确何时推翻当前推荐

如果控制资源更新与业务资源更新在实际标注、干预接口和安全判定上必须使用无法统一的契约，就考虑把 `UPDATE` 分成独立操作。若某种环境交互无法用交付、处理和生效变化表达且必须被实验区分，则扩展模型。若差异只是 memory/tool/skill 等载体名称，则优先扩展对象或属性，不增加原语。

目前最值得形成的论文贡献，是一套**可检查的跨组件归约与证据契约**，以及它能否改善攻击链标注和机制实验；“提出三个新名字”本身不足以构成强创新。

## 13. 最终建议

采用 `TRANSFER / DERIVE / UPDATE` 作为下一轮研究的底层候选。操作族负责交付、产生与生效；控制依赖负责解释“为什么发生”；版本关系负责跨时间连接；授权与使用角色负责区分合法调用和越权影响。

FIDES 是执行语义的主要支撑，CaMeL 和 AgentArmor 约束依赖结构，NeuroTaint 约束跨会话来源与证据，Agent-BOM 约束对象/关系/属性分层。其余三篇用于检验表示是否覆盖实际传播场景，不参与凑原语数量。

这比原九项或直接按四坐标自证更适合作为当前起点：它减少了分类标准的混用，保留了语义与控制传播，并明确哪些结论是模型内命题、哪些还需要实验。**推荐的是可论证、可反驳的三类操作模型，而不是已被文献证明的通用最小基。**

## 参考文献与本地定位

以下链接固定所读版本；网页核对用于确认文献身份，具体技术解释取自本地 PDF 正文。AgentArmor 当前网页标题与本地 v3 标题不同，本文按本地版本引用。

- **[P1] FIDES.** *Securing AI Agents with Information-Flow Control*, arXiv:2505.23643v2，2025-09-03。[原文](https://arxiv.org/abs/2505.23643v2)；[本地 PDF](primitive-related-papers/2025-FIDES-Securing-AI-Agents-with-Information-Flow-Control.pdf)。主要定位：§3–5，PDF pp.4–11。
- **[P2] CaMeL.** *Defeating Prompt Injections by Design*, arXiv:2503.18813v2，2025-06-24。[原文](https://arxiv.org/abs/2503.18813v2)；[本地 PDF](primitive-related-papers/2025-CaMeL-Defeating-Prompt-Injections-by-Design.pdf)。主要定位：§5.3–5.4、§7，PDF pp.9–11、19–21。
- **[P3] AgentArmor.** 本地标题 *Securing Large Language Model Agents via Structured Graph Abstraction*, arXiv:2508.01249v3，2025-11-18。[所读版本](https://arxiv.org/abs/2508.01249v3)；[本地 PDF](primitive-related-papers/2025-AgentArmor-Securing-LLM-Agents-via-Structured-Graph-Abstraction.pdf)。主要定位：§5.1–5.2、Figure 2、Table 1，PDF pp.4–7。
- **[P4] NeuroTaint.** *Ghost in the Agent: Redefining Information Flow Tracking for LLM Agents*, arXiv:2604.23374v1，2026-04-25。[原文](https://arxiv.org/abs/2604.23374v1)；[本地 PDF](primitive-related-papers/2026-NeuroTaint-Ghost-in-the-Agent.pdf)。主要定位：§3.3、§4.1–4.3，PDF pp.5–9。
- **[P5] Agent-BOM.** *Towards Security-Auditable LLM Agents: A Unified Graph Representation*, arXiv:2605.06812v1，2026-05-07。[原文](https://arxiv.org/abs/2605.06812v1)；[本地 PDF](primitive-related-papers/2026-Agent-BOM-Security-Auditable-LLM-Agents.pdf)。主要定位：§III、§IV.A、Tables IV–VI，PDF pp.5–9。
- **[P6] MCPTox.** *MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers*, arXiv:2508.14925v1，2025-08-19。[原文](https://arxiv.org/abs/2508.14925v1)；[本地 PDF](primitive-related-papers/2025-MCPTox.pdf)。主要定位：§2.2–3.1、Figure 2，PDF pp.2–4。
- **[P7] Skill-Inject.** *Skill-Inject: Measuring Agent Vulnerability to Skill File Attacks*, arXiv:2602.20156v3，2026-02-25。[原文](https://arxiv.org/abs/2602.20156v3)；[本地 PDF](primitive-related-papers/2026-Skill-Inject.pdf)。主要定位：§2.2–2.5、§3，PDF pp.3–4。
- **[P8] ACIArena.** *ACIArena: Toward Unified Evaluation for Agent Cascading Injection*, ACL 2026。[出版页面](https://aclanthology.org/2026.acl-long.457/)；[本地 PDF](primitive-related-papers/2026-ACIArena.pdf)。主要定位：§3.1–3.2，PDF pp.3–4，印刷页码 10051–10052。

本地既有方案：[Capability-transition Primitive 的离散空间分析](README.md)。本报告是对其研究假设的复核与修订建议，不表示仓库实现已经迁移到三类原语。
