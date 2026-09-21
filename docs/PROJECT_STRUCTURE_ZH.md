# STAC Compositional Attack Lab：项目结构与逐部分讲解大纲

> 更新基准：2026-09-21。本文依据当前源码、配置、测试与顶部权威进度编写，是源码导航和学习大纲，不是实验验收报告。九原语 M0/M1 只完成离线/fake 工程闭环，没有调用真实模型或启动容器。

## 0. 先建立正确的项目全景

这个项目研究 **Agent 系统中可观察的信息传播、状态变化和组合安全机制**。它既要回答“最后有没有出现安全结果”，也要回答：

- 什么对象从哪个域进入了哪个域；
- 新对象是否由哪些输入派生；
- 哪个资源版本是否真正提交、又被哪个读取使用；
- 观察到的先后、相关、可用输入、数据依赖和 read-from 是否被正确区分；
- 某种机制结论由什么证据支持，哪些部分仍然 unknown；
- 正常传播先验能否帮助之后的安全评测，而不从攻击结果倒推样本。

当前仓库包含新的九原语主线与两条历史复现路径：

| 路径 | 当前职责 | 当前边界 |
|---|---|---|
| **Nine-primitive capability** | 当前主线；九原语独立合同、F1 三条件编译、SafeClaw fake adapter、状态 oracle、constraints 和离线报告 | M0/M1 仅有 synthetic/fake 证据；真实 provider、人工 D10、M2+ 尚未执行 |
| **Primitive v3 / observable flow** | 新研究表示；使用 `TRANSFER / DERIVE / UPDATE`、effect graph、显式 dependency claim、分层准入和正常交互采集 | 尚无 v3 library freeze、Planner/formal 执行和真实 intervention；不能压缩为 legacy chain |
| **Legacy chain v2** | 旧的四类 core primitive、宏链、样本库、Planner、正式配对评测和历史复验 | 继续可读、可复现；不应把旧 verdict 自动继承给 v3 |

推荐学习顺序是：先理解公共观测和 v3 证据语义，再理解正常交互采集，然后阅读 legacy/formal 路径。这样不会把旧实现当成当前理论定义。

---

## 1. 项目现在要解决的四个层次

### 1.1 观测层

把人、Agent、模型、工具和环境中实际记录到的事件转换为中性的观察事实。模型内部推理、未记录的工具内部步骤和未记录的外部状态都属于 opaque gap，不能由程序补造。

### 1.2 表示与验证层

将观察投影成 effect graph，并独立验证关系 claim。Projector 负责提出 effect/claim，verifier 根据证明义务重新裁决；候选对象不能自己写入 `passed` 后把该标签当证据。

### 1.3 样本与规划层

项目正在建设从正常、合法交互中获得传播结构先验的路径。v3 的最终 FlowPattern library 尚未实现；现有可冻结和可供 Planner 使用的库仍是 legacy chain v2。

### 1.4 执行与评测层

现有 formal 路径可以调度配对条件、让 Planner 和独立 Attacker 执行、结合机制验证与 SafeClaw 官方判定生成报告。但正式配置仍要求 legacy frozen library，v3 尚未接入。

必须始终分开以下状态：运行是否完成、输入是否完整、claim verdict、结构准入、runtime review、执行授权和 official outcome。

---

## 2. v3 的核心概念

### 2.1 三类 primitive

| Primitive | 精确定义 | 典型例子 |
|---|---|---|
| `TRANSFER` | 把一个已有对象交付给新的域、端口或上下文，不创造新的语义对象 | 用户消息进入 Agent、工具响应返回上下文 |
| `DERIVE` | 根据一个或多个输入产生新的对象 | 摘要、参数绑定、多源合成、生成工具参数 |
| `UPDATE` | 使资源的新版本生效 | memory 写入提交、workspace 文件更新、外部沙箱状态改变 |

失败、拒绝、超时和控制信息不再自动成为第四种动作 primitive；它们由 execution status、依赖、策略和事件控制信息表达。三类划分是在固定 observation profile 下的研究接口，不宣称是所有 Agent 系统的普适最小基。

### 2.2 v3 的主要对象

| 对象 | 作用 |
|---|---|
| `ObservationProfile` | 固定什么可见、什么隐藏、对象粒度与资源语义 |
| `DomainRef` | 标识人、Agent、模型、工具、环境等域实例 |
| `ArtifactOccurrence` | 一次具体出现的对象；即使内容 hash 相同，来源不同也不能合并 |
| `FieldPort` | effect 的精确输入/输出端口 |
| `ResourceVersion` | 资源的具体版本和作用域，支持严格 read-from |
| `Effect` | 一次 TRANSFER、DERIVE 或 UPDATE 效果；一个事件可以产生多个 effect |
| `EffectGroup` | 保留事务、多效果和偏序，不虚构内部线性顺序 |
| `DependencyClaim` | 对两个端口或效果之间关系的待验证声明 |
| `EvidenceRef` | 私有或公开证据的定位、hash、方法与密封输入身份 |
| `EffectGraph` | effects、ports、资源版本、claims、groups 与 unresolved gaps 的统一图 |
| `DependencySlice` | 从显式 sink 反向抽取、保留 fan-in/fan-out 和外部前置条件的子图 |
| `LayeredAdmission` | 按不同证明强度给出互不替代的准入结果 |
| `FlowMacroBinding` | 宏与具体节点、端口、claim、约束的绑定 |
| `AnalysisManifest` | 固化输入、profile、registry、处理源码、参数和产物 hash |

### 2.3 七种关系不是同义词

`correlates_with`、`delivered_to`、`available_input`、`data_dep`、`control_dep`、`read_from`、`happens_before` 各有不同证明义务。

- 时间相邻最多支持顺序相关事实，不能升级为数据依赖。
- 内容相同不能证明同一来源。
- available input 不能自动证明生成结果使用了它。
- read-from 需要资源、workspace、版本、范围和 commit 证据，不能用“最近一次写入”推断。
- exact projection 只证明已声明规则中的窄值对应，不证明唯一来源、普遍语义因果或攻击贡献。

### 2.4 独立状态维度

- `ExecutionStatus`：observed、committed、attempted、failed、unknown、not_applicable。
- `ClaimVerdict`：verified、refuted、unknown、unsupported。
- `InterventionResult`：是否实际执行干预以及结果。
- `OfficialOutcome`：官方评估是否执行及结果。

一个 effect 被观察到，不代表它与另一个 effect 的依赖已经 verified；一个机制链 verified，也不代表官方安全结果成功。

---

## 3. 根目录结构

```text
STAC-Compositional-Attack-Lab/
├── src/stac_attack_lab/
│   ├── flow/                    v3 合同、profile、registry 和纯分析
│   ├── capability/              九原语合同、compiler、oracle、分析、runner 和报告
│   ├── interactions/            采集、规范化、benign 与 v3 投影适配
│   ├── extraction/              legacy chain 与 v3 slice/macro 抽取
│   ├── verification/            legacy 与 v3 的独立验证和准入
│   ├── execution/               benign、reanalysis、readiness、采集与 formal 编排
│   ├── environments/safeclaw/   SafeClaw driver、relay、证据策略与运行边界
│   ├── datasets/                legacy chain library
│   ├── planning/                legacy formal Planner 与 binding
│   ├── recording/               模型调用、事件和 formal 运行记录
│   ├── reporting/               v3 公共报告与 legacy formal 统计
│   ├── models/                  模型客户端
│   └── cli.py                   所有命令的薄入口
├── configs/
│   ├── flow/                    v3 observation profile 与 registry
│   ├── capability/              F1 合同与默认禁用真实兼容性模板
│   ├── benign_collection/       正常交互采集配置，模板默认禁用
│   ├── benign_scenarios/        正常交互场景
│   ├── benign_runtime_tasks/    脱敏正常运行任务
│   ├── primitives/              legacy v2 registry
│   ├── sample_generation/       legacy 攻击采集与复验配置
│   └── experiments/             legacy formal 配置
├── prompts/benign/              合作型正常交互 policy
├── prompts/formal/              legacy Planner/Attacker prompts
├── schemas/                     从 Pydantic 合同生成的 JSON schemas
├── integrations/safeclaw/       bridge、safety patch 与外部 pinned upstream
├── tests/                       unit、integration、e2e 与合成 fixture
├── data/primitive_libraries/    generated / frozen legacy library
├── experiments/runs/            按唯一 run/analysis ID 隔离的产物
├── docs/                        研究论证、实现、协议、进度和运行手册
├── scripts/                     legacy/revalidation/formal shell 入口
├── AGENTS.md                    仓库协作、科研证据与授权规则
├── pyproject.toml               包、依赖和质量工具配置
└── Makefile                     check、schema 和 legacy 常用入口
```

主包使用 `src` 布局，要求 Python 3.11+。Pydantic 严格模型是数据合同的源；schema 由模型生成，不应手工维护第二套语义。

---

## 4. 公共基础设施

相对于 `src/stac_attack_lab/`：

| 文件 | 作用 |
|---|---|
| `contracts.py` | `StrictModel` 基类，拒绝未声明字段并统一序列化契约 |
| `hashing.py` | 稳定对象 hash 与文件 hash；用于一致性，不证明来源真实性 |
| `config.py` | 模型角色配置与简单 YAML/JSON 读取 |
| `env_loader.py` | 将 dotenv 当数据解析，避免把配置作为 shell 执行 |
| `schema_registry.py` | Pydantic 模型和生成 schema 的登记与一致性检查 |
| `cli.py` | 解析命令，调用 execution 层；不应承载复杂研究规则 |

CLI 当前主要分为六组：

- `capability`：九原语 inventory、compile、validate、fake demo、replay 和 report；
- `doctor`：离线检查 workflow readiness；
- `benign`：正常交互 validate、prepare、fixture/live collection；
- `flow`：v3 profile、reanalyze、validate、slice、inspect；
- `sample` / `revalidation`：legacy 采集、mining、审计、冻结与复验；
- `safeclaw`：legacy formal inventory、preflight、run、audit、report。

### 4.1 九原语 capability 主线

`capability/models.py` 将九原语、task/surface/composition、public/runtime view、runtime event、checkpoint、constraint、harm 与 episode result 分开建模。`compiler.py` 只允许 F1 三条件修改登记的低信任材料并密封 runtime task；`environments/safeclaw/capability_adapter.py` 是中性 reviewed-session adapter，fake transport 不调用 provider。`evaluation.py` 从状态 checkpoint 独立判断业务危害，`analysis.py` 只从实际事件产生 occurrence，`runner.py`/`reporting.py` 支持离线 replay 与完整分母报告。

当前 F1 配置是 `configs/capability/f1_status_acceptance.json`。真实兼容性模板 `configs/capability/provider_compatibility.disabled.json` 固定 benign case、模型、三次 Victim HTTP 上限、零重试、300 秒墙钟与唯一输出，但 `execution_enabled=false` 且没有授权引用。

---

## 5. v3 表示层：`flow/`

| 文件 | 作用 |
|---|---|
| `models.py` | 定义 v3 的 profile、domain、artifact、port、resource version、effect、claim、slice、macro、intervention、report 和 manifest |
| `profile.py` | 加载并验证 observation profile，固定分析边界 |
| `registry.py` | 加载 v3 registry，核对 primitive、relation 和组件版本 |
| `analysis.py` | 纯函数分析与稳定身份辅助逻辑 |
| `__init__.py` | 明确 v3 子包接口 |

配置 `configs/flow/observation_profile_v3.json` 固定观察语言：记录可见的人/Agent/模型/工具/环境事件，把未观察内部步骤保留为 opaque。`registry_v3.json` 固定三原语、七种关系以及 projector/verifier/macro 的版本。

这两个文件分别 hash，分析产物记录实际版本。修改理论定义时不能无声改变旧分析结果，应生成新的分析目录和版本身份。

---

## 6. 从 legacy observation 到 v3 effect graph

| 文件 | 作用 |
|---|---|
| `interactions/models.py` | 共享的原始轨迹、规范化事件、artifact 和 legacy graph 合同 |
| `interactions/normalizer.py` | 将 bridge/source events 转成统一 InteractionGraph |
| `interactions/flow_v3.py` | 将中性 normalized observations 投影为多效果 v3 graph，不继承 legacy verdict |
| `interactions/provider_flow_adapter.py` | 把严格 provider boundary evidence 转成 v3 verifier 可用事实 |

数据流为：

```text
source/bridge events
  → RawInteractionTrajectory
  → normalized InteractionGraph
  → neutral observations
  → projected EffectGraph + dependency claims + unresolved gaps
  → independent verification
```

Projector 支持一个事件产生多个效果、多个源事件支撑一个效果、重复日志去重和事务分组。缺 commit/version、失败或 no-op 写入、不完整 restart、读取来源含糊时应产生 unresolved reason 或 unknown，而不是自动补全链路。

---

## 7. v3 verifier、slice、macro 与准入

### 7.1 验证：`verification/flow_v3.py`

纯 verifier 按 relation 分派证明义务，重新计算 verdict。Provider 派生关系复用严格的 request-context 和 exact-projection verifier；experimental exact rule 默认禁用且只允许 synthetic policy。

### 7.2 切片：`extraction/flow_slice.py`

从显式 sink port 反向得到有界 dependency slice，并保留：

- fan-in 与 fan-out；
- 外部前置条件；
- effect groups 和偏序；
- `ALL`、`ANY`、`K_OF_N` join；
- graph/reference consistency 与 replay consistency 的不同状态。

`--terminal-outputs` 只是显式选择没有作为 claim source 的输出端口；observed `ALL` join 是分析要求，不证明现实中存在未观察的替代分支。

### 7.3 宏：`extraction/flow_macros.py`

v3 目前实现两个具体绑定：

- `PersistRecall`：持久更新、生命周期边界、严格 read-from 与后续使用；
- 多源 `Bind`：多个输入参与参数或输出派生。

原有九个叙述性宏并未全部迁移；其余七个在 v3 中明确 unsupported，不能根据名称、数量或路径形状猜测。

### 7.4 分层准入：`verification/flow_admission.py`

四个 profile 逐级表达不同问题：

1. descriptive：结构和观察是否足以描述；
2. verified dependency：关键依赖是否 verified；
3. cross-session propagation：是否有严格跨会话传播证据；
4. intervention comparison：是否实际完成干预对照。

低层通过不能满足高层。single-session 正常样本可以有描述或规划参考价值，不需要伪造跨会话能力。

### 7.5 报告：`reporting/flow_v3.py`

公共报告只提供汇总事实与限制；私有 evidence locator 留在 mode-0600 的内部图和 manifest 中。报告不能把 unknown 静默转换成 failed 或 passed。

---

## 8. v3 离线工作流：`execution/flow_reanalysis.py`

`flow reanalyze` 接受单个 normalized graph 或 sealed collection，依次完成输入验证、投影、claim 验证、显式 sink 切片、分层准入、macro 尝试、公共报告和 manifest 密封。

典型命令：

```bash
python -m stac_attack_lab.cli flow profile-validate
python -m stac_attack_lab.cli flow reanalyze \
  --input <interaction_graph.json-or-sealed-collection> \
  --output-root <new-analysis-parent> --terminal-outputs
python -m stac_attack_lab.cli flow analysis-validate --analysis <analysis-dir>
python -m stac_attack_lab.cli flow inspect --analysis <analysis-dir>
python -m stac_attack_lab.cli flow slice \
  --graph <effect-graph.json> --sink-port <port-id> --output <new-file>
```

每次 reanalysis 写入新目录；相同输入和版本生成稳定 `analysis_key`，但不会覆盖旧分析。collection seal 和 legacy registry 检查仍必须通过，legacy verdict 不被继承。退出码 10 表示请求的 profile 未满足或 slice 截断，输入/配置/程序错误返回 2。

---

## 9. Provider 边界证据

| 文件 | 作用 |
|---|---|
| `environments/safeclaw/evidence_policy.py` | 唯一 provider evidence policy 合同；默认 disabled |
| `execution/provider_evidence.py` | 纯验证 request lifecycle、bundle、selector、投影和 exact rule |
| `environments/safeclaw/provider_relay.py` | 在真实 HTTP 边界预扣预算、过滤工具、转发并持久化证据 ledger |
| `interactions/provider_flow_adapter.py` | 将通过验证的边界事实适配到 v3 claim verifier |
| `tests/unit/test_provider_evidence.py` | 身份错配、乱序、重复、篡改、JSON/selector 和重新 hash 后语义矛盾等反例 |

一个请求上下文要求 open → prepared → attempted → response → completed close 的唯一、同身份生命周期。batch、request、attempt、control/action、逻辑/实际 session、workspace、source/consumer call 与 candidate refs 必须一致。

持久化在网络 I/O 前 fail closed。收到上游响应后若证据落盘失败，不允许自动重试或伪造 502。Disabled mode 只保留 hash/长度；受控 synthetic experimental mode 才能保存配置允许的有界字节。Base64 和低熵 secret hash 都不是安全脱敏。

当前本地 fake HTTP 验证了支持的解析与生命周期子集；真实 provider payload 兼容性、网络隔离、清理和 ledger 闭合仍需单独授权的有界运行。

---

## 10. 正常交互采集：`interactions/benign.py` 与 `execution/benign_collection.py`

这是项目调整后的重要新主线。它从合法、合作型行为中采集正常传播结构，避免只从攻击成功轨迹构建先验。

### 10.1 严格合同

`BenignScenario` 描述合法目标、授权操作、正常完成条件、follow-up/lifecycle 限制、domain/surface inventory 以及来源映射。Benign 配置拒绝 `public_attack_goal` 等 adversarial-only 字段。

SafeClaw-derived 场景必须绑定源任务 hash，并逐项记录 removed/replaced/retained 字段。`neutralize_source_task()` 只允许审查过的路径；源 hash 不符或未审查替换会失败。独立 synthetic 场景不能声称 upstream task 身份。

### 10.2 两种 source mode

| source mode | 用途 | 网络 |
|---|---|---|
| `synthetic_fixture` | 三个确定性工程场景：只读、多源合成、合法跨会话 memory | 无真实模型请求 |
| `safeclaw_derived` | 经审查、脱敏的正常任务，通过生产 SafeClaw driver/bridge/relay 采集 | 只有配置启用且命令显式授权才可运行 |

### 10.3 合作型 policy

`prompts/benign/cooperative_policy.md` 只接收合法目标、授权操作与公开进度。Scripted cooperative policy 是确定性的，本身不调用模型，也不接收安全 evaluator、攻击目标或隐藏成功条件。

### 10.4 采集后的结论

`BenignTraceAssessment` 分开报告：

- observation 是否有效；
- 正常任务是否完成；
- 是否可作为 planning reference；
- verified/unknown dependency 数量；
- cross-session capability；
- security outcome（当前固定 `not_evaluated`）。

single-session trace 不要求跨会话门。声称跨会话能力时仍必须有严格 read-from；普通时间顺序或相同内容不能替代。

### 10.5 当前配置

- `configs/benign_collection/synthetic_stage_a.disabled.json`：纯离线 fixture 配置；
- `configs/benign_collection/live_pilot.disabled.json`：正常 SafeClaw pilot 禁用模板；
- `configs/benign_scenarios/scenarios_v1.json`：三个合成场景；
- `configs/benign_scenarios/live_pilot_v1.json`：一个本地状态摘要场景；
- `configs/benign_runtime_tasks/normal_local_summary_v1.json`：脱敏正常 runtime task；
- `configs/task_sets/benign_runtime_tasks_v1.json`：任务集合与 pinned upstream 身份。

live 模板是单会话、最多 2 次 target 请求、1 次 embedding、零自动重试、300 秒墙钟，且 `execution_enabled=false`。模板存在不代表运行授权。

---

## 11. 统一 readiness：`execution/readiness.py`

`doctor` 是只读离线诊断入口。它将以下状态分开：

- `implementation_ready`；
- `config_valid`；
- `environment_ready`；
- `execution_enabled`；
- `authorization_state`；
- `existing_run_state` 与 launch reservation；
- failed、pending、blocked 和第一个可行动 blocker；
- `can_prepare / can_collect / can_analyze / can_evaluate`。

禁用配置可以“准备就绪”，但不能 collect。旧 run 如果执行完成而 admission 失败，会被只读分类为 `execution_complete_admission_failed`，不会被修复程序重写。

Compatibility probe 只检查一次预注册请求/响应形状；它不要求 accepted sample 或跨会话证据，也不授权 pilot。外部 preflight 命令有界，并区分命令缺失、权限、timeout、daemon 不可达和 image 缺失。

典型命令：

```bash
python -m stac_attack_lab.cli doctor \
  --config configs/benign_collection/synthetic_stage_a.disabled.json
python -m stac_attack_lab.cli doctor \
  --workflow-kind benign_collection \
  --config configs/benign_collection/live_pilot.disabled.json
```

---

## 12. SafeClaw 环境与 bridge

### 12.1 `environments/safeclaw/`

| 文件 | 作用 |
|---|---|
| `contracts.py` | 任务描述、公开任务视图、binding 和 episode result |
| `task_adapter.py` | 将 upstream task 转为框架任务与公开视图 |
| `materializer.py` | 只在允许 JSON pointer 上构造临时运行任务 |
| `preflight.py` | 检查 upstream、patch、Docker、镜像、环境和磁盘 |
| `interactive_driver.py` | 管理 bridge 子进程、动作、观察、预算、deadline 与本批资源清理 |
| `observations.py` | 生成公开且受限的 observation |
| `trajectory.py` | 上游记录到公共事件的映射辅助 |
| `redaction.py` | 凭证/内容脱敏与可核验身份保留 |
| `provider_relay.py` | Provider 边界预算、认证、工具过滤和 ledger |
| `ark_embedding_proxy.py` | OpenAI embedding 协议到 Ark 多模态文本 embedding 的适配 |
| `evidence_policy.py` | Provider evidence 开关、selector 和保存范围合同 |

### 12.2 `integrations/safeclaw/`

- `construction_bridge.py`：采集与 normal adapter 共用的上游运行桥；
- `formal_bridge.py`：legacy formal 的逐 stage 执行桥；
- `patches/a11f5cce-safety.patch`：应用于临时副本的安全 patch；
- `upstream/SafeClawArena/`：固定 commit 的外部 checkout，不属于主包。

正常采集 adapter 复用生产 driver/bridge/relay，但不包含 Construction Attacker 或安全 evaluator。Patch 应用于临时副本，不能修改 upstream 源目录。

### 12.3 三类服务角色

Planner/Attacker、Victim chat 和 Embedding 各自使用独立配置与预算。聊天服务正常不能证明 embedding/memory 链路正常；决策次数也不等于实际 HTTP attempts。

---

## 13. Legacy v2：仍然存在的样本构建路径

Legacy 并未删除，因为正式评测仍依赖它。

### 13.1 四类 legacy primitive

`primitives/core.py` 定义 `TRANSFER / TRANSFORM / MUTATE / CONTROL`，`primitives/macros.py` 与 `configs/primitives/registry.yaml` 定义 Ingest、Adopt、Persist、Recall、Select、Bind、Act、Record、Recover 等宏。

这是 legacy 合同。不能把 `CONTROL → UPDATE` 或 `TRANSFORM → DERIVE` 当作无条件名称迁移；v3 需要重新投影和重新验证。

### 13.2 Legacy 采集与抽取

| 模块 | 作用 |
|---|---|
| `interactions/construction.py` | Construction Attacker 的公开 observation、动作和循环 |
| `interactions/collector.py` | task/seed 采集、轨迹持久化和失败记录 |
| `interactions/safeclaw_collection.py` | SafeClaw adapter |
| `extraction/occurrences.py` | 从 InteractionGraph 提出 primitive occurrences |
| `extraction/chains.py` | 构建候选链 |
| `extraction/filtering.py` | G0–G8 过滤并保留 reason codes |
| `datasets/chain_builder.py` | 将 candidate 变为 chain sample |
| `datasets/library.py` | 构建、审计、加载和冻结 legacy library |
| `execution/sample_generation.py` | collect → mine → audit → freeze 编排 |
| `execution/construction_admission.py` | 独立检查完整性、实际身份和持久化读写使用证据 |

G0–G8 依次覆盖 schema/type、occurrence evidence、causal edge、environment binding、引用一致性、attack relevance、split/privacy、portability/dedup、coverage/diversity。门名不应被解读为超出实际代码判据的能力。

### 13.3 四个容易混淆的结论

1. `accepted candidate`：通过当前 G0–G8 策略；
2. `library audit passed`：库结构、hash、引用和数量满足配置；
3. `construction admission passed`：完整轨迹、实际身份和跨会话读写使用等工程证据满足；
4. `official attack succeeded`：官方 evaluator 给出终点判定。

它们互不替代。accepted 短链不等于完整跨会话机制，也不等于攻击成功。

---

## 14. Legacy Planner、正式执行和验证

### 14.1 `planning/`

- `formal_base.py`：预算、assignment、Planner 输入、trajectory、ablation 与计划合同；
- `formal_scheduler.py`：条件分配、兼容样本排序和 pair invariant；
- `binding_planner.py`：抽象槽位到公开任务对象的 binding；
- `formal_baselines.py`：NoSample、Fixed、RandomCompatible、RuleBased；
- `formal_llm.py`：LLM Planner 提案与结构验证；
- `sample_selector.py`：能力和预算兼容性筛选。

Scheduler 固化 task、condition、seed、budget 和分配样本；Planner 在该 assignment 内制定计划。合法 binding 不保证具体 payload 成功。

### 14.2 `execution/`

- `safeclaw_formal.py`：正式矩阵总编排；
- `formal_attacker.py`：独立 Attacker 的输入和结构化 realization；
- `formal_action_loop.py`：逐 stage 执行动作与记录；
- `formal_interactive_episode.py`：将计划接入环境 episode；
- `deadline.py`：POSIX 主线程墙钟 deadline；
- `revalidation.py`：生成新分析/复验目录，离线重放与可选受权 live 路径。

Formal 配置当前明确接受 `legacy_chain_v2`。遇到 v3 graph 应拒绝，而不是压成旧路径执行。

### 14.3 `verification/`

Legacy verifier 分别检查 occurrence、typed edge、macro 和 action lineage；`safeclaw_official.py` 解析官方判定；`formal_aggregate.py` 汇总机制结果与终点结果。

机制完整、终点成功、terminal-only shortcut、环境/API error、not reached 和 not observable 都要分开保存。

### 14.4 正式矩阵

`configs/experiments/formal_evaluation.yaml` 当前描述 assigned sample、no sample 和 dependency ablation 三类配对条件。Legacy slot/source ablation 不能自动称为单边因果干预；只有实际记录修改范围、pair invariants 和执行偏差后，才能报告对应 intervention 结论。

---

## 15. 记录、报告与统计

| 文件 | 作用 |
|---|---|
| `recording/events.py` | 公共事件记录辅助 |
| `recording/model_calls.py` | 模型调用、prompt 身份、attempt 和脱敏投影 |
| `recording/formal_run_recorder.py` | formal case/run 持久化和完整性审计 |
| `reporting/flow_v3.py` | v3 公共汇总报告 |
| `reporting/formal_report.py` | legacy formal 报告重建 |
| `reporting/formal_metrics.py` | 按条件的机制、官方、观测覆盖和配对差异 |
| `reporting/statistics.py` | Wilson 区间与 McNemar exact test |

统计必须保留所有 attempts 分母，并分别列出 infra failure、incomplete、unsupported、verified negative 与可分析子集。usage/cost 缺失时保留 unknown，不能用 0 填充。

---

## 16. Schema、配置和测试怎样配合理解

### 16.1 Schema

`schemas/` 现在同时包含：

- v3：effect graph、dependency slice、flow registry/profile、macro binding、intervention、analysis manifest/report；
- benign：scenario、policy observation/action、collection config、source/preparation manifest、trace assessment；
- readiness/provider：workflow readiness、compatibility assessment；
- legacy：interaction graph、occurrence、chain sample、library、Planner、binding、formal result。

修改严格模型后运行 `make schemas` 并审查差异；不要直接改生成文件来绕过合同。

### 16.2 测试路由

| 测试 | 首要含义 |
|---|---|
| `test_flow_v3.py` | 三原语对象、projector、claim verifier 与反例不变量 |
| `test_flow_v3_phase2.py` | slice、admission、macro、manifest 和 CLI workflow |
| `test_provider_evidence.py` | request-boundary 与 exact projection 证据 |
| `test_benign_collection.py` | normal scenario、neutralization、fixture/live adapter 与评估 |
| `test_workflow_readiness.py` | doctor、路径、禁用状态和历史 run 分类 |
| `test_interaction_normalization.py` | 源事件到中性图的证据保真 |
| `test_construction_admission.py` | legacy 工程准入和跨会话证据要求 |
| `test_formal_*` | legacy Planner、scheduler、verification、recorder、metrics |
| `test_safeclaw_adapter_contract.py` | SafeClaw adapter 集成合同 |
| `test_safeclaw_formal_pipeline.py` | legacy formal 端到端组合 |

Synthetic/fake 正例只证明工程实现，不证明真实 provider、独立人工标注或论文实验结果。

---

## 17. 运行产物与不可变性

### 17.1 v3 analysis 典型结构

```text
<analysis-root>/
├── graphs/*.effect_graph.json
├── slices/*.json
├── admission/*.json
├── macros/*.json
├── reports/*.json
└── analysis_manifest.json
```

### 17.2 benign collection 典型结构

```text
<run-root>/
├── preparation/source-mode manifests
├── raw collection / trajectories
├── normalized interaction graphs
├── analyses/<new-v3-analysis>/
├── benign_trace_assessments.json
├── preflight / ledgers（live 时）
└── summary
```

### 17.3 Legacy library 典型结构

```text
<build-root>/
├── interactions/raw/
├── interactions/normalized/
├── extraction/
├── library/
├── sample_generation_manifest.json
├── mining_stage_manifest.json
└── library_audit_report.json
```

Historical raw、ledger、bridge responses、sealed manifest 和 frozen library 不原地修改。新 reanalysis 使用新目录，并记录输入 hash、policy/profile、处理源码和命令。SHA256 只证明相对于 manifest 的一致性，不证明 producer 真实或抵抗所有可信输入的协同重写。

---

## 18. 当前实现状态与真实边界

依据 `docs/IMPLEMENTATION_PROGRESS.md` 顶部权威状态：

### 已实现并有离线工程验证

- Primitive v3 并行合同、三原语、多效果投影和独立 relation verifier；
- 显式 sink slice、四层 admission、PersistRecall 与多源 Bind；
- provider evidence 的严格 policy/lifecycle/bundle/projection 校验；
- 正常交互 Stage A：合成 fixture、来源中和、共同 collector/normalizer、v3 reanalysis；
- 正常 SafeClaw adapter 的生产 driver 合同接入；
- `doctor` 统一 readiness、禁用准备、绝对路径/YAML 和只读历史分类；
- fake driver / local fake HTTP / 单元、集成和全量质量门的历史验证记录。

### 尚未实现或尚未获得对应证据

- v3 FlowPattern library build/audit/freeze；
- v3 Planner 与 formal 执行；
- 其余七个 v3 macro matcher；
- 真实 intervention execution；
- 真实 provider payload 兼容性、运行网络隔离、容器清理和 ledger closure 的本批证据；
- 正常 live pilot、本轮攻击 pilot/main/freeze/formal；
- v3 official outcome。

当前正常 live 配置仍禁用。`execution_enabled=true`、`--authorize-live`、历史授权或测试通过都不能自行创造新批次授权。

---

## 19. 文档阅读地图

| 文档 | 何时读 |
|---|---|
| `AGENTS.md` | 协作方法、证据纪律、授权与实验安全 |
| `docs/基于文献的Primitive重构论证.md` | 三原语理论来源、适用空间与不夸大边界 |
| `docs/Primitive重构代码修改建议.md` | 从 legacy 到 v3 的差距和迁移设计 |
| `docs/PRIMITIVE_V3_IMPLEMENTATION.md` | v3 当前实现和命令 |
| `docs/BENIGN_COLLECTION_STAGE_A.md` | 正常交互采集合同与离线 Stage A |
| `docs/PILOT_READINESS_IMPLEMENTATION.md` | doctor、normal live adapter 和兼容性边界 |
| `docs/EXPERIMENT_PROTOCOL.md` | legacy 研究门禁、配对设计和指标 |
| `docs/PROMPTS.md` | Planner/Attacker 的公开输入边界 |
| `docs/LINUX_TMUX_RUNBOOK_ZH.md` | Linux/tmux 操作、日志、停止与恢复 |
| `docs/IMPLEMENTATION_PROGRESS.md` | 顶部为当前事实；下方历史记录不得覆盖当前结论 |
| `docs/IMPLEMENTATION_WORKPLAN.md` | 顶部为当前剩余工作和验收条件 |
| `SECURITY.md` | 授权目标、凭证、隔离与清理边界 |

---

## 20. 推荐的逐步讲解顺序

### 第一阶段：理解新理论

1. 第 0–2 章：双轨架构、三原语、对象和七种关系；
2. 对照 `flow/models.py` 逐类解释；
3. 用 read-only、多源合成和跨会话 memory 三个例子手工画 effect graph。

### 第二阶段：理解证据怎样成为 verdict

1. 第 6–9 章：projector、verifier、slice、admission 和 provider evidence；
2. 选一个 claim，逐字段解释为什么 verified、refuted 或 unknown；
3. 删除或矛盾化证据，观察为什么不能保持 verified。

### 第三阶段：理解正常传播采集

1. 第 10–11 章：scenario、neutralization、cooperative policy 与 doctor；
2. 沿 synthetic fixture 走一次 raw → normalized → v3 → assessment；
3. 再比较 live adapter 多出的 preflight、provider、budget 和 cleanup 责任。

### 第四阶段：理解旧系统仍在做什么

1. 第 13 章：legacy occurrence、chain、G0–G8 和 library；
2. 第 14–15 章：Scheduler、Planner、Attacker、机制 verifier、官方 evaluator 和统计；
3. 明确 legacy 与 v3 不能自动映射的部分。

### 第五阶段：跟踪未来迁移

1. v3 FlowPattern library 的 public/private view、origin/split audit 和 immutable freeze；
2. graph-prior 条件与 dry-run assignment；
3. v3 Planner/formal capability 接入；
4. 有真实修改范围和配对不变量的 intervention；
5. 分别报告工程兼容性、runtime review、mechanism 与 official outcome。

后续可以直接按模块提问，例如：

- “从 `EffectGraph` 的类定义开始逐字段讲”；
- “用 benign-memory 场景画出 UPDATE、read-from 和 DERIVE”；
- “沿 `flow reanalyze` 调用链逐函数解释”；
- “对比 legacy G2 causal edge 和 v3 `data_dep` verifier”；
- “解释 normal live pilot 为什么只需要兼容性门，不需要 accepted attack sample”。
