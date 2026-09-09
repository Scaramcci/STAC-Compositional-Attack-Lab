# 项目实施计划

核查日期：2026-09-08（Europe/Berlin）；源码基线：`a4ce8940`；阶段 B Goal：`01a07f10-044b-7691-ae85-30cdfff88f98`。

本文件定义剩余工作、依赖和验收；[IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md) 是唯一当前进度快照。本版替代此前反复追加的恢复指令，旧内容保留在 Git 历史中；不删除历史实验数据。

## 1. 目标与研究契约

依据 [EXPERIMENT_ALIGNMENT_AND_REPAIR_PLAN_ZH.md](EXPERIMENT_ALIGNMENT_AND_REPAIR_PLAN_ZH.md) 第 1、4、5、7、8 节。历史缺陷须对照当前源码复核，不能假定全部仍存在。此前引用的 `docs/EXPERIMENT_DESIGN_V3.md` 当前不存在，不把它当成已交付文件。

最终目标：真实 benchmark 交互 → 原始记录 → 证据图 → 可复用 sample → 冻结研究输入 → Planner 绑定 → 独立 Attacker 执行 → 官方/机制判定 → 公平对照与可复算报告。

必须区分三个维度：

- **样本质量**：结构、引用、依赖、来源与证据是否充分。
- **交互结果**：完成、部分执行、拒绝、超时、运行错误等。
- **研究结果**：官方攻击结果、机制是否证实，以及 unknown/not-evaluated。

有证据的正常、部分或阻断路径可以成为 sample；计划、请求意图不能冒充实际效果。部分路径可用不等于持久化/跨会话机制成立，也不自动适用于每个 Planner 条件。

### 当前语义契约

阶段 A 已解除 G5、mining 与 library audit 对 adversarial、completed 和 observed terminal 的入库捆绑，并同步修改 schema、filter、builder、audit、public/execution views 和报告。真实性、依赖完整性、来源/hash、shortcut 和泄漏防护仍保留；“适合哪个正式条件”由独立 selection/eligibility 门控制。

旧库不原地改写。从旧 raw 重算到新派生目录，记录源 hash、parser/registry/策略版本、迁移原因。正式评测前固定策略，不能根据结果临时改变标准。

## 2. 安全与执行边界

- 仅限用户授权的 SafeClawArena/OpenClaw 隔离 benchmark、合成资料及无价值 canary；不针对第三方系统、真实账户或无关宿主文件，不使用真实敏感资料作为载荷。
- 模型/embedding 调用属于受控基础设施出口，仅连接已批准服务；凭证仅用于认证，不进入样本、报告或 Git。benchmark 效果端仅限容器/受控本地 sink。“不产生外部攻击效果”不等于“模型调用完全离线”。
- 记录实际模型输入输出、工具请求/结果、状态变化、失败及判定；异常前的交互不得丢失。只记录可获得输出，不要求隐藏思维链。发布前脱敏，敏感原文与共享材料分开管理。
- 保留旧 raw、冻结库、运行目录和 `.env`；不清空共享 Docker/tmux，不终止无关进程。新运行使用唯一 ID，不仅依赖日期命名。
- `execution_enabled=true`、旧 Goal ID、文档中的历史授权不等于新一轮调用授权。当前阶段 B 授权已按清单执行并触发停止条件；任何新增真实验证和阶段 C 仍须再次确认。
- 不用措辞隐瞒任务或规避安全检查。拒绝是要保留的结果；额外权限需明确申请，不靠改名继续执行。

## 3. 工作包与验收

状态只使用 `pending / in_progress / blocked / verified`。`verified` 要满足整项验收；已有模块或离线测试不代表真实运行通过。路径默认相对于 `src/stac_attack_lab/`；bridge 在 `integrations/safeclaw/`。

| ID | 当前状态 | 工作与主要位置 | 依赖 | 验收 |
|---|---|---|---|---|
| W00 | verified | 当前代码、测试、产物盘点；两份状态文档 | 无 | 当前基线、进程、历史证据和 Stage B 新产物分开；服务器状态已于本轮核对 |
| W01 | verified | 三维契约/版本：`interactions/models.py`、`datasets/primitive_chain.py`、contracts、schemas、协议 | W00 | v3.1 sample/record 可表达 trace、structure、evidence、behavior、attack relevance、official outcome、eligibility；兼容迁移与回归通过 |
| W02 | in_progress | 观测：`interactions/safeclaw_collection.py`、construction、collector、recording、两 bridge | W01 | 真实 call/session ID；请求与结果关联；异常前事件保留；多次 retrieval 不丢失；writer/reader/artifact parents 可追溯；缺失标 unknown |
| W03 | verified | normalizer、extraction、chain_builder、library、sample_generation、CLI | W01,W02 | 有证据的非成功子图可入库；filter/audit/freeze 保留真实性与 hash/依赖门；两批旧 raw 只读重算稳定通过 |
| W04 | in_progress | SafeClaw task_adapter/materializer、两 bridge、任务集、采集入口 | W01,W02 | PSE/CDF 官方 hash 隔离回归；字段级不支持 delivery surface 在 bridge 前 fail-closed；真实 upstream/image 尚待 B |
| W05 | verified | planning/binding_planner、formal_llm、formal_baselines、prompts | W03,W04 | 多组件角色拒绝；macro 会话绑定到最后一个有依据的 core occurrence；无首组件/任意会话 fallback；来源显式 |
| W06 | in_progress | formal_attacker、formal_action_loop、safeclaw_formal、配置/prompts | W05 | no-sample 与 sample 输入隔离、动作/预算校验、ablation provenance 回归通过；Victim 请求未运行 |
| W07 | in_progress | verification、reporting、两 bridge | W02,W04,W06 | interaction/official/mechanism outcome 分开统计；CSV/Markdown 与配对分母回归通过；pinned evaluator 真实 state 尚待 B |
| W08 | blocked | model_config、Ark proxy、preflight、patch | W00；真实验证需 W02 | direct Gemini 可用；OpenClaw HTTP 400 的额外请求字段已由镜像源码定位并加入离线 compat patch，但同根因真实复测轮数已达上限 |
| W09 | blocked | 有预算真实 collection、建库、配对 smoke、正式评测 | B 需 W01-W04/W08；配对另需 W05-W07 | 3 次 trajectory attempt 后仍为 0 accepted；无 eligible/bound sample，按门停止，不 freeze、不执行伪配对 |
| W10 | in_progress | schemas、计划/进度与阶段 B 草案 | 按阶段依赖前述 | 阶段 A schema/文档已完成；真实运行证据与最终交付仍待 B/C |

W09 阻塞不能成为 W01-W07 停工理由。无服务器或 API 授权时继续离线代码、fixture、负例、报告与命令校验。

## 4. 分阶段执行

### 阶段 A：离线工程修复（建议独立 Goal）

1. 复核版本与 diff，先修 `cli.py` 格式/ruff；缺 optional upstream 时记录测试跳过，不伪装全覆盖。
2. 完成 W01/W03 语义迁移及 W02 观测回归。覆盖正常流、拒绝流、部分有效前缀、空轨迹、缺必要前驱、伪造 artifact、unknown recall、异常后保留事件。
3. 既有 raw 只读重算到新目录；不调用模型/embedding/Victim。核对 raw→graph→occurrence→candidate→sample→audit。无可用 sample 时给分层原因，不制造记录。
4. 完成 W04-W07 可离线验证的注入面、绑定、对照隔离、verifier 和报告；复用已有 no-sample 实现。
5. focused tests 后做最终 `make check`、schema 一致性检查和 `git diff --check`；更新 W10，准备 Linux 实际运行命令、预算草案和证据清单。

### 阶段 A 当前交付证据（2026-09-08）

- `make check`：ruff format/lint 通过，mypy `64 source files` 通过，pytest `136 passed`，无 skip；focused 回归 `69 passed`。
- schema 已由 `make schemas` 重生成；`git diff --check` 通过。未提交/未推送。
- 旧 raw 只读重算到 `experiments/safeclaw_v3_smoke/stage-a-recompute-20260908/retry22/` 与 `retry23/`。两批 source hash 校验通过，audit `passed=true`，旧 raw/冻结库未覆盖。
- 两批各 `candidate=1, accepted=1, negative=0, attempt_outcome=partial`；accepted 为 `sample_version=3.1`、`trace_status=partial`、`sample_status=usable`、`behavior_outcome=unknown`、`official_attack_outcome=not_evaluated`，eligibility 不含 `formal_attack_primary`。
- runtime 未验证：真实 provider tool-result/retrieval/session、upstream/container/image、embedding/模型服务、官方 evaluator 实际 state、treatment/no-sample 配对与费用；不得由离线结果推断。

**A 完成条件**：工程变更与离线回归通过，所有 runtime 未验证项明确，B 配置草案可检查。不代表 W08/W09 或整个项目完成。需用户决定的研究选择须明确提出，不自行改变研究假设；可独立工作继续完成。

### 阶段 B：有限真实验证（单独确认预算）

启动前记录服务器/目录、任务/split、各角色模型、允许出口/注入面、run/config hash、轨迹数、整批调用/token/费用上限、逐条/整批超时、重试总数、日志、tmux socket/session。本轮授权与实际结果如下；它不延伸到新的真实尝试或阶段 C。

**阶段 B 实际清单与结果**

范围为当前已批准 Linux 项目目录。真实 collection 只使用 `pse-2.2-002`、`safeclaw_user_message`、seeds `20260908/20260909`；不支持的 surface 没有替换执行。

```bash
cd /absolute/path/stac-compositional-attack-lab
git -C integrations/safeclaw/upstream/SafeClawArena rev-parse HEAD
docker image inspect openclaw-env:2026.3.12 >/dev/null
make check
bash scripts/run_safeclaw_sample_collection.sh \
  --config configs/sample_generation/safeclaw_v3_smoke_retry23.yaml \
  --preflight-only
bash scripts/run_formal_evaluation.sh \
  --run-id stage-b-preflight-<unique> \
  --preflight-only
```

预检通过后，另建唯一 `stage-b-<date>-<nonce>` 目录和独立 tmux socket。先运行一条正常/阻断交互和一条授权 benchmark 对抗交互，各 `1 seed`、各 `1 trajectory`，保存 raw/source events/checkpoints、脱敏 bridge log、usage unknown 与 hash。只在 sample audit 通过后运行最小 matched `assigned_sample`/`no_sample`，保持同 task/seed/model/goal/budget/surface；缺合格输入或 binding invalid 即停。

本轮已授权预算上限（整批硬上限）：

- collection：最多 `2 trajectories`，每条 `3 sessions / 24 actions / 16 tool calls / 8,192 tokens / 20 min`。
- matched smoke：`2 conditions × 1 task × 1 seed = 2 cases`，每 case `3 sessions / 24 turns / 16 tool calls / 8,192 tokens / 20 min`，最多 `2 attempts`。
- 初始范围为 `2` 条 collection trajectory 与 `2` 个 matched conditions；失败 case 在明确修改后最多第 2 次尝试。全阶段真实 trajectory/case execution 最多 `12` 次、累计最多 `4h`，单次最多 `20 min`。本轮没有金额上限，但不构成无限调用授权；provider usage 缺失按 unknown 记录并仍受执行数、token 配置与墙钟上限约束。

停止条件：upstream/patch/image/hash 不匹配；bridge 协议或 tool-result/retrieval 无法验证；一次启动、空响应、认证或协议故障；sample audit 不通过；binding invalid；任一预算上限达到。触发后保留已发生片段，不自动扩大或重试。
阶段 B 初始配置为 `configs/sample_generation/stage_b_20260908_01.json` / `experiments/stage-b-20260908-01/`；2 条 trajectory 均遇 OpenClaw 空响应。实际 adapter 只支持 adversarial construction，因此两条均为 adversarial acquisition；没有把它们冒充 ordinary normal collection。修复 response classification、legacy normalization 与 Attacker call recorder 并通过回归后，`configs/sample_generation/stage_b_20260908_02.json` / `experiments/stage-b-20260908-02/` 对 seed `20260909` 做了第 2 次且最后一次尝试，仍为 `partial / victim_empty_response`。实际计数为 trajectory `3/12`、formal `0`、真实 trajectory 墙钟 `392792 ms`；已知 Attacker 调用 retry 0、usage 2413，其他 provider usage unknown。修正后两批离线 audit 均为 0 accepted，未 freeze、未 matched。第二轮且最后一轮观测修改补充脱敏 gateway error-line projection、hidden-reasoning 排除、formal/collection 统一分类与 transcript 计数。`stage-b-20260908-03` benign OpenClaw probe（service probe 1/3）得到 provider/model 明确但 HTTP 400 无 body；`stage-b-20260908-04` direct Gemini minimal probe（service probe 2/3，1 call、无 tools、max_tokens 16、无重试）对同 endpoint/model 得到 HTTP 200/`OK` 与 provider total usage 24。镜像源码进一步确认 OpenClaw 默认额外发送 store、stream usage、`max_completion_tokens` 和 tool strict；版本化 patch 已对 Gemini `/openai` endpoint 关闭不兼容可选项并切换到 `max_tokens`，新 SHA-256 为 `6ea8c100063adfa30a9ce03e02a09a3cf9f2ad27c5ef62fc60b423a85a90b523`，离线 apply/compile 和完整质量门通过。该候选修复尚未真实复测；未使用的第 3 个 service probe 不覆盖同根因 2 轮修改/复测上限。

1. 核对 pinned upstream、patch、镜像、依赖，补跑缺 upstream 的测试。仅执行本阶段批准的基础设施探针。
2. 默认提议一条正常或阻断交互、一条授权 benchmark 对抗交互，各一个 seed；先验证实际响应与检索观测，不扩大任务/预算。
3. 出现重复启动/空响应/协议故障即停止批次并定点诊断。usage 缺失标 unknown，以调用数/墙钟/提供方限额辅助约束，不能把记录中的 0 当作零费用。
4. 按 A 固定策略抽取审计新库，报告 accepted/rejected、路径族、重复率和 split；部分 sample 只进入它满足证据与能力条件的比较。
5. audit 通过后新建 **smoke 冻结快照**，不覆盖旧库；再执行同任务/seed/预算的 treatment/no-sample 配对。拒绝或攻击失败可以是有效结果；绑定失败、缺输入不算已执行。

**B 完成条件**：有真实可追溯交互、合格输入、实际配对执行与判定产物。若未达到，只交付明确诊断并停止，不能宣称闭环完成。目标拓扑没出现时记录可行性限制，不无限重跑。

当前 B 完成条件未满足：Gemini direct 文本、最小 function calling、tool-result 往返和 streaming 均通过，但 4 次 OpenClaw 对照在带 session key、加载新版 compat 且限制高风险工具后仍返回空/非 JSON，provider 出站 params 未观测；sample audit 输入门仍失败，因而没有 eligible/bound sample、冻结库、matched official/mechanism 结果。阶段 C 不准入。诊断证据位于 `experiments/stage-b-20260909-gemini-compat-01/`；下一步只能在明确授权后针对 gateway 响应通道做本地适配诊断，不能自动扩大 collection、替换模型/供应商或进入 main collection。

### 6B. 2026-09-09 有限 Gemini 兼容诊断记录

1. 使用官方 Gemini OpenAI-compatible endpoint 和 `gemini-2.5-flash`：非流式文本、最小 `add` function calling、带原始 `tool_call_id` 的结果回传、最小流式 function calling 均 HTTP 200；官方参考为 `https://ai.google.dev/gemini-api/docs/openai` 与 `https://ai.google.dev/gemini-api/docs/function-calling`。
2. 诊断目录 `experiments/stage-b-20260909-gemini-compat-01/` 保存脱敏 request/response projections、stream events、OpenClaw 最终 provider 配置和矩阵。实际为 9 次真实尝试（含 09 号 SSE 纠正投影）、无自动重试；direct 已知 usage 289 total，stream/OpenClaw usage unknown。
3. OpenClaw 临时容器应用 patch SHA-256 `6ea8c100063adfa30a9ce03e02a09a3cf9f2ad27c5ef62fc60b423a85a90b523`；容器内确认 `baseUrl=/v1beta/openai`、`api=openai-completions`、四项 compat 生效。带 session key 的正常文本请求仍返回空/非 JSON，gateway 启动日志无 provider 错误，`pi-ai` 投影未命中，因此未将任何单字段标为已定位。
4. 结论：Gemini 能力本身的四类 direct 检查已证实；OpenClaw gateway/provider 层仍强怀疑但未能观测其最终出站 schema。未运行 collection、mining、freeze 或 formal evaluation，阶段 B 和阶段 C 均未完成/不准入。

### 6C. 2026-09-09 兼容诊断续接

1. 新目录 `experiments/stage-b-20260909-gemini-compat-02/` 保存 5 次 direct Gemini 探针和离线 OpenClaw 源码审计；direct 文本、最小 function calling、tool-result 往返和 streaming 均 HTTP 200。
2. 官方依据仍为 Gemini OpenAI compatibility 与 function calling 文档：`https://ai.google.dev/gemini-api/docs/openai`、`https://ai.google.dev/gemini-api/docs/function-calling`。
3. 本轮没有启动 OpenClaw live 请求，因为无法在不改动 pinned 客户端的前提下证明内部 payload、重试和工具面满足本轮严格边界；不能把离线配置或源码字段称为 runtime live 生效。上一轮 live 对照仍保留在 `experiments/stage-b-20260909-gemini-compat-01/`。
4. 结论不改变：Stage B 输入门仍为 0 accepted，Stage C 不准入；不自动恢复 collection/evaluation。


### 6D. OpenClaw 本地请求捕获与响应回放

1. 新增 `src/stac_attack_lab/diagnostics/openclaw_mock.py` 与 `tests/unit/test_openclaw_mock_replay.py`；默认离线运行，5 个 focused tests 覆盖文本、tool_calls、SSE、错误 body/空 body/非法 JSON/截断 SSE、暂时错误重试与预算拒绝。
2. `scripts/diagnostics/run_openclaw_mock_integration.py` 在 pinned `openclaw-env:2026.3.12`、`docker --network none` 中启动 fake 配置与容器内 loopback mock；最终捕获真实 provider 请求并返回 `MOCK_OK`。
3. 实际出站请求为 `/v1/chat/completions`、`OpenAI/JS 6.26.0`、`stream=true`、`x-stainless-retry-count=0`；compat 生效体现为 `max_tokens` 存在、`store`/`max_completion_tokens` 缺失、工具 `strict` 未出现。
4. 初始空 mock 结果由 JSON/SSE 协议不匹配导致；初始未到 provider 的独立原因是 mock `contextWindow` 低于 OpenClaw 最低 16000。两者均与历史 Gemini HTTP 400 分开，不合并为同一证据。
5. 本地链路证明可开始独立合成工具/检索观测测试，但不解除 0 accepted 对正式配对评测的阻塞，也不证明真实 Gemini 已修复。

### 阶段 C：正式实验与交付（再次确认总规模）

1. 基于 B 证据提交实验清单：construction/evaluation 近重复分组隔离、sample 选择策略、覆盖量、seeds、条件、模型、预算、停止规则和统计方法。
2. 用户确认后使用明确的 **main collection 配置**，不能用 pilot/smoke 替代。审计冻结正式新库，正式配置引用确切路径/hash。
3. 执行预定 treatment/no-sample/ablation，记录实际请求和配对 lineage；断点续跑不得重复计费。进程存在/退出码为零不能单独证明有效样本或评测完成。
4. 交付官方/机制/拒绝/错误分层报告、成本、原始记录索引、版本/hash、复算命令、限制及教师阅读入口。
5. 检查脱敏和 diff；仅在明确要求后 commit/push。不上传凭证、`.env` 或未经审查的原始对话。

**项目完成条件**：工程验收和预定实验清单均完成，报告真实可复算；不要求攻击成功或假设成立。实际评测未完成时只报告工程完成/实验受阻，不能以诊断报告代替完整实验。

## 5. 续接与停止规则

- 每批推进具体工作包：实现/修复、针对性回归或新运行证据。仅重复 make check、preflight、旧失败摘要不算推进。
- 优先修可控代码缺陷；新增日志也要验证能区分原因。同一阻塞无新假设/变更时不建新 retry。
- 达到预算即停实验；不抬高预算、不降低真实性门、不改官方 verdict 来追求正结果。
- 恢复先读状态/diff、查已有 run 和进程，避免重复计费。复用仍有效检查，不每轮重跑全套无变化测试。
- Goal 完成/阻塞状态遵守产品机制；不能因难做而虚报 complete。需要新权限/选择时如实交接。
- 每批更新进度中的唯一当前状态、变更、测试/skip、证据及下一步；不再追加互相覆盖的“当前状态”。

## 6. 可复制 Prompt

按顺序发送，不一次授权全部阶段。A 可作为独立 Goal；B/C 推荐普通任务以便确认研究配置和费用。

### Prompt A：离线工程

```text
请按 docs/IMPLEMENTATION_WORKPLAN.md 的阶段 A 完成离线工程修复。若我在 Goal 模式发送本段，Goal 仅覆盖 A，不包括真实 collection/evaluation。

先读 AGENTS.md、docs/IMPLEMENTATION_PROGRESS.md、docs/IMPLEMENTATION_WORKPLAN.md 及对齐计划的研究契约，以当前代码、Git diff、实测为证据。不要只审查或继续追加计划，要实现、写回归并验证。

这是授权的隔离 SafeClawArena/OpenClaw 安全评测项目。本阶段只允许本地代码、测试、已有数据离线重算；不调用付费模型/embedding，不启动真实 Victim，不操作外部目标，不读取或输出密钥。不隐瞒任务或绕过安全限制。

先修质量门，再贯通样本质量、交互结果、官方/机制结果的独立契约，修复部分路径建库/audit、日志与依赖、Planner 首组件 fallback、匹配对照和报告。不能仅关过滤门、伪造 recall 或追求 accepted 数量。旧 raw/冻结库不覆盖，迁移写新目录。

每批同步两份文档的唯一当前状态与下一步。不要重复不变检查代替实现；外部依赖不阻止独立离线工作。A 完成后报告变更、实际测试/skip、未验证项以及 B 的具体运行与预算草案，等待确认。不宣称整个实验完成，不自动 commit/push。
```

### Prompt B：有限真实验证

```text
请按工作计划阶段 B 准备真实验证。先复核 A 产物，在实际 Linux 服务器核对 upstream/镜像/patch 和缺失测试。任何付费调用或真实 Victim 启动前，提交任务、模型、出口、注入面、轨迹数、整批调用/token/费用上限、重试/墙钟上限、目录和停止条件，等待我确认；没有预算不得自行当作无限制。

确认后按清单执行，独立 tmux socket/session 和唯一目录，保留模型输入输出、工具结果、状态与失败并脱敏。先验证正常/阻断及授权 benchmark 交互的 raw→sample；audit 通过后新建 smoke 冻结快照，再做最小 treatment/no-sample 配对。缺合格输入不伪造执行、不扩大 collection。重复基础设施故障立即停重试并诊断。保留拒绝、失败、unknown；更新进度与 C 的准入情况，不自动启动正式实验或推送 Git。
```

### Prompt C：正式实验

```text
请基于 B 的真实证据准备工作计划阶段 C。先提交 main collection/evaluation 的任务分组、sample 选择/冻结策略、条件/seeds、模型、规模/费用上限、统计方法、命令和停止条件，等待我确认后执行。

使用确认的 main 配置而不是 pilot，冻结审计合格的新库，运行预定配对条件和 ablation。记录版本/hash、真实请求响应、工具/状态证据及官方/机制结果。拒绝、缺失、unknown 不能算成功；不得为正结果修改条件或挑 seed。交付可复算报告、教师阅读入口与状态文档；未执行项明确列出。Git 提交/推送另行确认并先脱敏。
```

### 6E. 有限真实 Gemini/OpenClaw 证据（2026-09-09）

1. A direct 回放已通过：真实 `gemini-2.5-flash` 接受合成请求并返回合法 SSE；证据 `experiments/stage-b-20260909-gemini-compat-03/a_direct_replay.json`。
2. B OpenClaw 无工具对照在修正临时配置后实际发送到 Gemini，但返回 `400 status code (no body)`，gateway 外显 `No response from OpenClaw.`；证据 `b_openclaw_real_v3.json`。配置键错误的两次前置失败单独保留，不能算 provider 请求。
3. 因 B 失败，未执行真实 Gemini 单工具 C；离线 OpenClaw v2 仅证明内置工具循环和 tool-result 续接得到 `SUM=5`，自定义 `add` 未进入 schema（20 个内置工具），不证明 strict 或受限工具面。
4. 结论边界：Gemini direct 协议兼容已真实通过；OpenClaw 到 Gemini 的真实无工具链路仍被 400 阻塞；历史 400、空/非 JSON mock、真实 v3 400 分开记账。下一次真实验证最小变量是对比 v3 的最终 OpenClaw body（尤其 stream/消息投影）与 A 的 direct body，并保持单次请求和可保存错误 body；不得在此之前进入 collection/evaluation。
