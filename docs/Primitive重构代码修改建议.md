# Primitive 重构：代码修改建议与迁移方案

> 状态说明（2026-09-20）：本文是设计建议及历史迁移依据。当前源码已经实现显式 v3
> reanalysis、AnalysisManifest、有界子图、分层准入和报告；准确接口与剩余边界见
> [PRIMITIVE_V3_IMPLEMENTATION.md](PRIMITIVE_V3_IMPLEMENTATION.md)。下文未来式描述不代表
> 当前实现缺失，也不构成实验事实或真实执行授权。

日期：2026-09-20  
审查对象：`stac-compositional-attack-lab`，HEAD `df7f8da8032ba7f1dac420639038de4a35bf2b3a`。  
理论依据：[基于文献的 Primitive 重构论证](基于文献的Primitive重构论证.md)。
性质：设计建议。本次只新增本报告，没有修改实验代码、启动真实模型请求或进行正式评测。

> 2026-09-20 补充：本文记录的是旧审查时点。第 5 节所述 request-boundary producer
> 缺口已被后续 provider relay、policy、bundle seal 和独立 verifier 实现取代；当前能力与
> 限制以 `IMPLEMENTATION_PROGRESS.md` 顶部及 `PRIMITIVE_V3_IMPLEMENTATION.md` 为准。
> 真实 provider 协议兼容性仍未通过真实请求验证。

## 1. 结论：重构研究表示层，保留运行基础设施

建议采用 `TRANSFER / DERIVE / UPDATE` 三原语，但修改范围要覆盖对象模型、证据、图结构和验证接口。只修改枚举，会把旧有假设带进新名称。

当前系统值得保留的部分包括：原始证据哈希、不可变运行目录、缺失关系记录、请求预算账本、跨会话身份校验、public/private 数据隔离，以及采集、挖掘、审计、冻结的阶段划分。近期代码还区分了运行完成、结构准入、运行时审查、执行授权和官方结果。这些约束应继续生效。

需要大改的是以下研究主干：

1. 用“领域对象和效果”替代“一个事件对应一个原语”的抽取接口。
2. 用带字段端口、资源版本和证据的依赖子图替代以线性路径为主的样本表示。
3. 将交付、可用输入、实际依赖、语义推断和干预结果分别验证。
4. 让同一份原始轨迹支持不同原语方案的离线重分析，不让采集格式绑定某一版理论。

实施方式选择**并行引入 v3 数据契约，按阶段替换主干**。旧版本只负责读取和复现实验，不与 v3 混用 verdict。暂不建设通用 Agent 框架、图数据库或复杂插件系统。

代码生成本身不是主要成本。需要花时间核验的，是实际运行边界、证据生产者、数据迁移和实验结论。建议以验收条件安排重构，不以修改文件数衡量进展。

## 2. 本次审查的证据范围

审查覆盖了原语注册表、交互模型与归一化、原语和链抽取、过滤、准入、验证、样本库、绑定 planner，以及 SafeClaw 的 driver、bridge、relay 和正式评估相关实现。审查开始和离线测试后的嵌套仓库均无未提交变更。

本地使用 `.venv/bin/python`，Python 3.14.7，执行以下六组离线测试：

```text
tests/unit/test_interaction_normalization.py
tests/unit/test_primitive_extraction.py
tests/unit/test_chain_construction_filtering.py
tests/unit/test_construction_admission.py
tests/unit/test_formal_verification.py
tests/unit/test_primitive_chain_library.py

结果：42 passed in 1.61s
```

这不是全量质量门，也不证明真实 SafeClaw 已跑通。`docs/IMPLEMENTATION_PROGRESS.md` 中的 251 tests 是此前验证记录，本报告不把它当成本轮结果。以下“当前实现”指该 checkout；涉及真实服务的能力，没有在本轮做在线验证。

## 3. 当前实现与新理论的具体差距

### 3.1 原语抽取以事件类型为中心，无法自然表示多效果事件

定位：[extraction/occurrences.py:38](../src/stac_attack_lab/extraction/occurrences.py:38)。

`_match_event()` 返回一个原语或 `None`。`tool_call` 通常对应 `TRANSFER.request`，`tool_result` 对应传递，状态写入对应 `MUTATE`，部分消息通过 operation 子串对应 `TRANSFORM`。抽取出的 source/target component roles 都来自当前事件的同一个 component role，不能充分描述真实传递端点。

实际一次工具操作可能包含参数派生、请求交付、资源更新和返回交付。一个事件中有多个效果，多个事件也可能共同证明一个效果。例如请求和回包共同定位一次交付，写入请求和提交记录共同证明一次更新。

**建议：** 将抽取接口改为 `events + evidence -> effects + unresolved_claims`，允许多对多映射。每个效果绑定自己的输入、输出、执行域、资源及证据。事件继续保留为原始运行事实，不强制变成原语。

### 3.2 当前关系类型没有充分区分“关联”“看见”和“依赖”

定位：[interactions/normalizer.py:161](../src/stac_attack_lab/interactions/normalizer.py:161)、[models.py:27](../src/stac_attack_lab/interactions/models.py:27)。

归一化器根据 input artifact 的 producer 建立 data 边；根据 `request_event_id` 建立 control 边。前一种关系的可信程度取决于上游“input”的具体含义；后一种关系首先证明请求与响应配对，并不等同于程序分支控制依赖。

**建议：** 至少区分：

| 关系 | 可以支持的判断 | 不能顺带支持的判断 |
|---|---|---|
| `correlates_with` | 请求与响应属于同一调用 | 上游内容控制了下游决策 |
| `delivered_to` | 信息交付到指定执行域/接收端 | 模型采用了它 |
| `available_input` | 字段出现在某次实际调用输入中 | 输出中的具体字段依赖它 |
| `data_dep` | 可定位的值来源或已验证的数据依赖 | 对最终攻击结果存在因果贡献 |
| `control_dep` | 条件影响执行、选择或次数 | 条件文本被复制 |
| `read_from` | 本次读取对应某个资源版本 | 后续模型使用了读取内容 |
| `happens_before` | 运行顺序受到约束 | 存在内容传播 |

授权约束还应保留资源、主体、权限范围和生效版本。可把它实现为类型化策略约束，不必把所有关系塞入同一个普通边枚举。上表是结构信息，不是新增七种动作原语。

### 3.3 `causal_pass` 的实际判据主要是结构依赖

定位：[verification/edges.py:62](../src/stac_attack_lab/verification/edges.py:62)。

`verify_causal_edge()` 在上下游 occurrence passed 后，对匹配且 `observable=True` 的 typed edge 返回 `causal_pass`；artifact ancestry fallback 也可以返回同一结果。这里没有要求实际干预实验。

这些证据可以支持某些执行依赖，不能直接支持“删除该信息会改变攻击结果”。现有 `EvidencePolicy` 又把 E3 列为 causal evidence，容易让代码和报告使用不同含义。

**建议：** 分开输出 `dependency_verdict` 和 `intervention_result`。确定性运行追踪可以验证结构依赖，不要求每条边都做干预；涉及攻击贡献的因果论断则需要单独的实验设计。旧 `causal_pass` 不能批量迁移为新版本的因果成功。

### 3.4 原语证据判定分散，部分判据只验证字段形状

定位：[extraction/occurrences.py:82](../src/stac_attack_lab/extraction/occurrences.py:82)、[verification/occurrence.py:40](../src/stac_attack_lab/verification/occurrence.py:40)。

抽取器为匹配事件先附 E1，再根据条件附 E2。例如，传递有输入或输出 artifact，写入有不同的 pre/post ref 字符串，控制事件有 lifecycle ID 或 public payload。验证器另有一套规则；对 transform 的 lineage 检查比抽取器更具体。

当前代码确实会降级部分缺证据 occurrence，后续还有准入门禁，因此不能说“所有事件都被无条件当作成功”。问题在于不同阶段对同一证明义务采用了不同规则。

**建议：** 抽取器只提出候选 claim；唯一的 verifier 解析实际证据、复算结论。E1/E2/E3/E4 改为证据方法标签，而非从低到高的通用分数。一个工具调用的直接日志，不能证明另一个 claim，例如外部资源已经改变。

### 3.5 通用状态关联仍依赖排序中的最近写者

定位：[interactions/normalizer.py:213](../src/stac_attack_lab/interactions/normalizer.py:213)。

归一化器通过 `latest_state_writer[state_ref]` 连接读写，末尾根据 write refs 更新索引。它没有在这一层要求精确的 read-from version，也没有在更新该索引时按写入成功状态过滤。对于并发、失败写入、部分读取和版本回滚，这不足以证明读取来源。

近期 bridge/准入已有更严格的文件版本、身份及失败写入处理，应该抽出可复用规则，避免严格 adapter 与宽松通用层并存。

**建议：** 独立建模 `resource_id + version_id`，写入效果引用提交前后版本，读取引用实际返回的版本或字段范围。不能确定时记录 unknown。外部初始状态允许作为声明的根节点，不应为了填满 producer 而伪造一次写入。

### 3.6 链挖掘和过滤仍以单路径为基本单位

定位：[extraction/chains.py:172](../src/stac_attack_lab/extraction/chains.py:172)、[filtering.py:55](../src/stac_attack_lab/extraction/filtering.py:55)。

当前使用有界路径枚举，过滤要求 `len(core_edges) == len(core_nodes) - 1`。模型虽有 ALL/ANY/K_OF_N，但仅有这些字段还不能保留完整的多输入汇合结构。

此外，`_occurrence_arcs()` 将两个事件各自关联的 occurrence 做配对连接。引入多效果抽取后，沿用该逻辑会把属于不同字段或效果的节点连起来。

**建议：** 以依赖子图为样本主体，路径只作为展示视图；边必须绑定效果端口。汇合条件需要 `join_group_id`、成员集合和阈值。宏匹配返回一次具体节点绑定，不能只靠同类原语数量和零散边存在性判断匹配。

### 3.7 “回放一致性”名称超过了该过滤项的实际能力

定位：[extraction/filtering.py:169](../src/stac_attack_lab/extraction/filtering.py:169)。

这里的 replay consistency gate 主要检查 unresolved links，并没有执行回放。仓库另有区分 collection reanalysis 与 bridge replay 的实现，应继续保留这种区分。

**建议：** 本门命名为 graph/reference consistency；另设分析可重复性、driver 记录回放一致性和环境干预重跑结果。三者分别给出方法与输入，不能共用一个 replay_pass。

### 3.8 采集与原语注册表绑定，限制理论迭代

定位：[execution/sample_generation.py:619](../src/stac_attack_lab/execution/sample_generation.py:619)。

当前 mining 要求 registry hash 与 collection stage 中记录的一致。这能避免隐式漂移，但也限制了在相同 raw 上比较四原语和三原语。

**建议：** 保留旧校验，新增显式 reanalysis 路径。采集 manifest 记录当时的配置和任何影响采集行为的理论版本；新 analysis manifest 独立记录投影规则、registry、verifier 和代码 hash。新分析写入新目录，不覆盖旧结论。

若采集时攻击者按旧宏选择路径，同一 raw 重分析仍带有采样偏差。不能把这种对比表述为无偏的原语覆盖比较。

## 4. 目标模型：让原语操作和证据各有接口

建议的数据流如下：

```text
SafeClaw / bridge / relay 原始记录与身份
                    │
            标准化观测 + 证据索引
                    │
      固定 ObservationProfile Ω 的离线投影
                    │
      对象 + TRANSFER / DERIVE / UPDATE 效果
                    │
            依赖 claim → 独立验证
                    │
       依赖子图 / 宏匹配 / 分层样本准入
                    │
          planner 绑定与执行 → 多维评估
```

### 4.1 必须先定义的对象

| 对象 | 最小必要内容 | 解决的问题 |
|---|---|---|
| `ObservationProfile` | 边界、对象粒度、事件范围、隐藏状态、版本 | 同一 trace 因粒度不同产生不同分解 |
| `DomainRef` | 实例身份、角色、session、workspace/租户范围 | 两个 Agent 角色相同但不是同一执行域 |
| `Artifact` | 不可变值、内容摘要、编码/摘要范围、来源定位 | 相同字符串不能证明同一来源 |
| `PortRef` | 所属调用/效果、字段路径、值或子结构范围 | tool name 与 recipient/body 来源不同 |
| `ResourceVersion` | 独立资源身份、版本、可观察状态、前驱关系 | 跨会话状态与并发读写 |
| `Effect` | 三原语之一、类型化参数、source event refs | 一个事件存在多个效果 |
| `EffectGroup` | 共同操作、事务 ID、已知原子性和顺序约束 | 防止把原子多效果编成虚构串行路径 |
| `DependencyClaim` | 端口/版本端点、关系、证据、验证结果 | 避免一个 observable 布尔覆盖多种结论 |
| `EvidenceRef` | 定位、哈希范围、生产者/规则版本、隐私范围 | 第三方可复核结论而非相信标签 |

这些是数据契约，不要求每个对象建立一个包。优先使用现有 Pydantic、JSON/JSONL 和内容哈希机制。Artifact 的来源实例 ID 与 content hash 分开；跨域交付保留来源身份，编码、解析或摘要改变内容时再建立派生输出。

### 4.2 三类效果的建议接口

```text
TRANSFER(artifact, source_domain, target_domain, delivery_endpoint)
DERIVE(invocation, domain, input_ports, output_ports)
UPDATE(resource, before_version, after_version, commit_evidence)
```

每个效果额外携带执行状态、证明义务、证据引用和 effect group。字段缺失不能靠默认 passed 补齐。

- `TRANSFER`：证明交付位置与内容范围。交给 tool client 与进入 provider 请求是两个不同端点，不应自动合并。
- `DERIVE`：证明某次处理产生了输出；输入可用性与具体输入贡献分开记录。LLM 的实际 request/response 能支持调用级派生，却不能精确证明某段文本导致某个参数。
- `UPDATE`：证明具有独立身份的资源出现生效变化。请求写入、返回“成功”和持久状态改变是不同 claim。若只能看到工具声称成功，保留该事实并将实际更新标为未核验。

派生可以产生相同内容，不要求语义改变。相同内容重复写入若没有产生本研究关心的生效变化，可记录 write attempt/no-op；若系统创建了新版本或改变了 ACL，则按 Ω 中的资源语义表示。删除用 tombstone/不存在状态表示，不能用缺字段冒充删除成功。

旧 CONTROL 的处理：生成决策对应 DERIVE；条件对执行的影响对应 control_dep；调度表、权限或生命周期的生效变化对应 UPDATE。仅有“restart requested”的记录不能生成已完成的 session UPDATE。

### 4.3 固定粒度与非冗余规则

第一次实现建议把模型内部作为黑箱，把可定位的模型调用、工具调用、资源版本及外部消息作为观察对象。不要一开始分析隐藏推理过程。

同一观察配置下规定：

1. 同一效果有稳定 ID，多条日志只补充证据，不重复计数。
2. 日志中的“工具调用”本身不额外成为第四个原语；它是多个效果的共同操作记录。
3. 仅因观察者保存了一条日志，不额外产生被研究系统的 UPDATE。
4. 同一个底层效果可以匹配多个语义宏，但统计底层数量时只计一次。
5. 未观测的工具内部步骤作为 opaque gap，不由名称或 LLM 猜成确定效果。

这能约束实现中的冗余，仍不构成现实世界绝对最小性的证明。

## 5. 前置工程：补齐请求边界证据，不放松消费判据

定位：[provider_relay.py:307](../src/stac_attack_lab/environments/safeclaw/provider_relay.py:307)、[construction_admission.py:20](../src/stac_attack_lab/execution/construction_admission.py:20)。

relay 当前记录最终请求哈希、工具列表、状态、usage 和预算，但没有输出逐 artifact 到实际 request 字段的映射。进度文档也明确指出，production context reachability producer 和 strong-consumption producer 尚未接通。

因此，本轮不能把当前瓶颈概括为“API 完全连不上”，也不能把 relay 存在解释成“信息传播链已经有证据”。需要补的是下列接口：

### 5.1 Request-boundary projection

在最终请求序列化后、发送前记录：

- invocation ID、attempt ID、实际 session/domain 身份和最终请求摘要；重试与逻辑调用分别编号。
- message/tool-result 的实际字段位置、call/result ID、来源 artifact、投影内容摘要和摘要范围。
- projection 方法：exact copy、已验证的格式转换、内容句柄、摘要或未知来源。
- 发送尝试、provider 响应与输出引用的关联；SSE 完成/中断状态。

不能仅凭内容 hash 相同关联来源，必须同时满足调用身份和定位关系。provider 前的截断、压缩或摘要需要单独投影；原 transcript 中存在不代表最终请求包含。metadata/handle 可见也不能记作内容全文可见。

该证据证明客户端实际提交的请求内容；传输失败或服务端不可见的内部处理，不能通过客户端日志补证。未知时保留 unknown。

### 5.2 字段派生 verifier

保留现有 exact projection 类强证据规则，并扩展为小型、可测试的规则注册表，例如 exact field copy、JSON projection、已知模板渲染。每条规则给出源字段、目标字段、参数和重算方式。

语义改写和隐式控制通常不满足 exact copy。它们进入 semantic hypothesis 或 intervention track，不能为了获得 accepted 样本而降低确定性规则。LLM 提议的 provenance 要单独标注，不能成为独立证据生产者。

哈希不等于脱敏。证据存储继续采用私有权限与 public 投影分离；明确摘要针对原始字节、规范化结构还是脱敏表示。脱敏后的相等不能证明原始内容相等，低熵秘密也不应公开其可枚举摘要。不要新增 Authorization header、密钥或无必要的完整提示词日志。

## 6. 图挖掘、宏和 planner 的修改

### 6.1 样本主体改为子图

建议采用“从声明的 sink 向后切片，再按依赖闭包构造有界候选”的实现。保留当前节点数、候选数和时间预算，达到限制时记录 truncated，不能声称已覆盖全部组合。

以多个来源生成一个邮件调用为例：收件人来自用户，正文来自工具结果，是否发送还受审批条件约束。抽出一条工具结果到发送的路径会丢失其他必要条件。子图必须保留必需父节点，或以显式 external precondition 表示边界之外的父节点。

ALL/ANY/K_OF_N 的语义绑定到同一目标的输入组，声明“实际观察到的依赖”还是“模板要求的候选条件”。只有一个 trace 时不能凭空证明所有替代分支都可执行。

重复发生的操作按 occurrence 展开，版本关系保证有向结构；重试可在模板层形成循环，在有限实际轨迹中展开。并发按偏序处理，不使用 sequence_no 推断真实因果或唯一执行顺序。

### 6.2 九项宏继续服务论文叙述

Ingest、Adopt、Persist、Recall、Select、Bind、Act、Record、Recover 保留为 pattern/annotation：

- pattern 匹配类型化子图，返回具体节点、字段和约束绑定。
- Adopt 明确区分 exposed、derivation-supported、intervention-supported，不能由“读到了”判定。
- Recover 可以包含多个效果及分支，不必对应单个控制节点。
- 不强制每个样本出现全部宏，也不强制固定顺序。

终点按研究问题声明：外部资源更新、向人或另一 Agent 的信息交付、权限改变等。当前默认 external ingress → external effect 可保留为一个安全研究 profile，不应承担所有信息传播场景。

### 6.3 planner 绑定领域实例和约束

定位：[planning/binding_planner.py:13](../src/stac_attack_lab/planning/binding_planner.py:13)。

当前按 component role 唯一匹配，遇到多个候选会拒绝；session 根据线性位置及 boundary 标记递增。这种拒绝比随意选择安全，但不足以表达多 Agent 与交错会话。

改成显式 DomainRef、resource scope、能力和 session 约束绑定。候选多时给出可核验的选择依据，无法消歧则 abstain。用节点/端口图映射替代“主 component”代表整个操作。

sample ID、模板 ID 和绑定 ID 分开。图 fingerprint 包含原语版本、端点、join、scope 与必要结构；不要继续只用宏名称序列承担 chain identity。planner 仍只访问 public sample view，不能接触隐藏 evaluator 或私有证据内容。

## 7. 验证与准入：一个样本需要多个结论

建议保留独立维度，而不是扩充一个混合 outcome enum：

```text
execution_status     = completed / failed / rejected / pending / unknown
claim_verdict        = verified / refuted / unknown / not_applicable
evidence_method      = direct / deterministic / semantic / interventional
official_outcome     = evaluator-owned result / not_evaluated
```

实际字段值在实施时统一定义；这里强调各维度独立。`not_observable` 应解释为证明能力不足，而不是执行失败。未知写入不能当成成功，也不能在没有反证时当成确定失败。

建立四个准入 profile：

| Profile | 用途 | 必要门禁 |
|---|---|---|
| 描述性轨迹 | 检验表示覆盖和未知情况 | 原始引用/身份有效，缺口明确 |
| 可复核依赖样本 | 验证和挖掘可组合机制 | 声明范围内的必需效果、依赖可验证 |
| 跨会话传播样本 | 研究持久化与后续使用 | 实际 session/scope、版本 read-from、后续使用证据 |
| 干预比较样本 | 估计特定处理的行为影响 | 干预定义、配对条件、实际运行和结果证据 |

低层 profile 通过不能替代高层通过。也不要求描述性样本先证明强消费才能保存，否则无法研究失败、未知和不可表示情况。存储上分开 infra_failure、incomplete、unsupported、verified_negative，避免把所有未 accepted 条目当作攻击负例。

把 `construction_admission.py` 中图完整性、定位有效性、版本和身份检查提取成纯验证函数；该文件保留跨会话 profile 的编排。抽取、挖掘、准入和正式评估调用同一规则集，避免四套“通过”定义。

## 8. 现有消融应保留，但需要限定因果解释

定位：[planning/formal_baselines.py:223](../src/stac_attack_lab/planning/formal_baselines.py:223)、[execution/safeclaw_formal.py:736](../src/stac_attack_lab/execution/safeclaw_formal.py:736)。

仓库已有 dependency ablation：选择 required edge，绑定 materialization slot，替换成 baseline 内容，并检查 slot 注册和实际差异。不能把它描述成“没有消融”。

但 slot 替换可能同时改变多个字段、多个依赖或任务难度。选择一条 target edge 不自动意味着只干预这一条边。

建议记录干预的实际支持范围：被改变的字段/资源版本、预期断开的关系、可能受影响的其他关系、保持不变的因素和实际执行偏差。只有单边隔离有证据时才称 edge ablation，否则称 source/slot ablation。

使用相同任务、权限、预算和起始状态；能控制时固定模型版本与随机参数，仍须承认模型服务的不确定性。分别报告官方成功率、依赖复现率、未知比例、运行失败率，以及具有有效配对的样本数。LLM 反事实判断不能替代实际重跑。

## 9. 文件级修改安排

下表中的路径相对 `stac-compositional-attack-lab/`；“重写”指 v3 实现，不在旧格式上静默改变语义。

| 现有位置 | 建议 | 核心修改 |
|---|---|---|
| `primitives/core.py`、registry | 重写 v3 契约 | 三原语、类型参数、证明义务；旧枚举仅供 legacy 读取 |
| `interactions/models.py` | 重点重构 | 观测与研究解释分离，加入 domain/port/resource/version |
| `interactions/normalizer.py` | 重构为事实归一化 | 取消缺状态默认 passed，不自动把配对当控制依赖 |
| `extraction/occurrences.py` | 重写 | 多对多效果投影，不内嵌最终证据裁决 |
| `extraction/chains.py` | 重写候选主体 | 子图、端口、join 和闭包；路径保留展示用途 |
| `extraction/filtering.py` | 重构 | 分层 profile、明确未知原因、纠正 replay 命名 |
| `verification/occurrence.py`、`edges.py` | 合并共享规则后重构 | 按 claim 验证，拆结构依赖与干预结论 |
| `execution/construction_admission.py` | 拆出通用纯规则 | 保留跨会话编排和强证据要求 |
| `environments/safeclaw/*`、`integrations/safeclaw/construction_bridge.py` | 保留适配主干，补观测 | request projection、真实身份、版本和 commit 证据 |
| `execution/sample_generation.py` | 拆阶段依赖 | raw 与 analysis manifest 解耦，显式新版本 reanalysis |
| `datasets/primitive_chain.py`、`datasets/library.py` | 迁移为图样本 | public/private 隔离和 freeze 保留，重算准入 |
| `planning/binding_planner.py`、formal baselines | 迁移 | 显式领域/字段/作用域绑定，记录干预范围 |
| `execution/safeclaw_formal.py` 等编排 | 后置拆分 | 按计划、运行、验证、聚合责任拆；预算和收尾行为不变 |
| `reporting/formal_metrics.py`、schema registry | 适配契约 | 分母/未知率、结构与因果指标分离，schema 单一来源 |

建议只增加一个研究模型核心包，例如 `flow/`，容纳对象、效果、关系和 invariants。`interactions/` 管观测，`extraction/` 管投影/挖掘，`verification/` 管证明。契约不得反向依赖执行编排或 SafeClaw adapter。先明确这些依赖，再决定文件拆分，不按行数机械拆文件。

MCP、memory、skill 通过 adapter/property contract 映射，不各自建立一套原语。后续扩展至少要求新 adapter 声明：能观察哪些事件、不能证明哪些关系、资源身份如何确定、哪些字段是可信 instrumentation 提供的。

## 10. 分阶段实施与验收

| 阶段 | 交付 | 验收标准 |
|---|---|---|
| A：边界与反例 | Ω、三原语接口、手工标注小样本 | 对消息、工具、memory、权限和事务形成一致分解；保留未知 |
| B：v3 契约和 verifier | 类型模型、schema、纯验证规则 | 非法端点/版本/证据 fail-closed；执行与证明状态独立 |
| C：离线效果图 | 从现有 raw 生成新 analysis | 多效果、fan-in、并发、跨会话可表示；旧 raw 与旧分析不变 |
| D：运行观测 | relay/bridge 的可信证据生产者 | 本地 fake provider/bridge 通过字段投影、重试、截断和身份错配测试 |
| E：挖掘与样本库 | 子图挖掘、宏、profile、v3 library | 相同输入确定性重现；接受与拒绝原因可复核；不继承旧 accepted |
| F：planner 与评估 | 图绑定、干预记录、多维指标 | 多实例绑定不串 session；slot 干预范围可审计；未知不算失败或成功 |
| G：运行验证 | 独立授权的小规模真实验证及报告 | 证据生产链、预算、收尾、官方 evaluator 分别通过后才讨论扩大实验 |

A、B、C 可以先离线推进。D 是真实强证据样本的前置条件；不能用“多跑几次”替代缺失的生产者。G 不在本次请求执行范围内，也不因报告存在而获得自动授权。

**首个编码迭代建议只做 A+B：** 固定边界、编写人工 golden fixtures、建立模型与验证规则。第二个迭代完成 C，用旧 raw 暴露真实缺口；同时补 D 的可独立验证部分。不要第一轮就全面改 planner 和正式实验。

## 11. 测试重点：从正向样例转向表示反例

现有 42 项测试保留为 legacy 回归。v3 增加以下测试，不靠更新 fixture 的预期数量掩盖语义变化：

| 用例 | 应验证的结论 |
|---|---|
| 相同文本来自两个不同工具结果 | 来源实例不因 hash 相等合并 |
| 工具结果存在于 transcript，但未进入最终 request | result observed；context reachability 未验证 |
| 请求只含句柄，没有内容 | handle delivered；内容不可用 |
| user recipient 与 tool body 合成邮件 | 两条字段来源；不能把整个调用全归给工具 |
| 条件影响是否调用，但内容没有复制 | 可表示 control_dep，不强求字符串继承 |
| 两个必要输入汇合 | 保留 join group，不退化为单路径 |
| 一次事务同时改文件和 ACL | 同组多效果；没有额外串行因果边 |
| 请求写入失败、结果未知或写入 no-op | 不生成未经证明的状态变化 |
| 同路径不同 workspace、同内容不同版本 | 不跨 scope 连接；read-from 精确或 unknown |
| 部分读取、显示截断、摘要后输入 | 证据范围受限，不能升级为全文传播 |
| 同一 session 标签但实际身份变化，或反例 | 实际身份决定边界，标签仅辅助 |
| 并发写入、迟到响应、重复日志 | 保持偏序、去重效果；不依赖日志全序猜来源 |
| 只有相邻事件、LLM judge 认为有关 | 不得到确定 data/control 或因果成功 |
| slot 替换同时影响两条边 | 报 source/slot 干预，不声称单边隔离 |
| 缺失原始证据、摘要篡改或错误 schema 版本 | 拒绝验证或明确 unknown，不补造证据 |

另外增加性质测试：ID 重命名不改变规范图；不改变偏序的日志重排不改变依赖；添加无关事件不提高既有 claim 的证据等级；删除支持证据后不能维持 verified；同一 raw 和分析版本重跑结果一致。

## 12. 数据迁移与论文实验

### 12.1 旧数据只读，新版本重新分析

迁移不能把 `TRANSFORM -> DERIVE`、`MUTATE -> UPDATE`、`CONTROL -> UPDATE` 做成无条件替换。尤其旧 CONTROL 必须返回 source events，判断其证明的是决策生成、控制关系还是实际状态变化；不够判断的保留 legacy/unresolved。

每次 analysis 固定 raw manifest hash、采集策略 hash、Ω、投影规则、registry、verifier、代码版本和参数。legacy analysis ID 与 v3 analysis ID 分开；缓存按这些内容寻址。旧 frozen library 不覆盖，新库重新审计、冻结并获得独立 ID。回滚通过切换分析版本和库版本完成，不改写历史结果。

### 12.2 先验证表示，再验证攻击

建议先增加一个表示层实验：在固定 Ω、独立人工标注的轨迹上，比较旧四原语与新三原语的操作覆盖、字段依赖准确性、误连边、无法判断比例和标注者一致性。分开统计可观察事件和隐藏步骤，不能用当前 extractor 自己产生的标签作 ground truth。

随后再回答攻击研究问题：图结构是否提高组合/迁移能力，跨会话来源是否得到保留，某个依赖干预是否改变行为。保持任务、预算、攻击材料与可见信息范围可比；若使用同一套改进 instrumentation，应给对照方法相同证据访问权限，避免把观测增强误归因于三原语。

至少报告两类分母：所有发起的实验尝试，以及满足预先定义的可分析条件的尝试。分别列出基础设施失败、缺证据和任务失败。样本库构建集与正式测试集隔离，冻结后不按测试成功率回选图模式。

三原语数更少本身不是实验优势。值得验证的是：在明确边界下能否减少分类冲突，保存原方案丢失的传播关系，并让组合、迁移和失败原因更容易复核。

## 13. 实施前需要共同确认的研究边界

代码可以按本报告准备 v3，但以下三点应先与导师达成书面共识：

1. 第一阶段研究对象是可观察的人—Agent—工具—环境交互，还是还要解释模型内部语义计算？本报告选择前者。
2. 论文主张是传播表示与可组合机制，还是攻击成功率提升？两者需要不同数据与验收标准，建议先证明表示和证据有效。
3. “因果”指可复核的执行依赖，还是干预下的行为贡献？本报告在代码和指标中将两者分开。

我的推荐是先固定上述边界，完成 v3 的离线表示与请求边界证据，再迁移攻击组合和正式评估。这样即使后续调整三原语的具体粒度，也能重用原始轨迹、运行基础设施和独立验证规则。
