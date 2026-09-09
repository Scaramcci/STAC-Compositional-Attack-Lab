# 项目实施进度

核查日期：2026-09-09（Europe/Berlin）；源码基线：`a4ce8940`；阶段 B Goal：`01a07f10-044b-7691-ae85-30cdfff88f98`。

本文件是唯一当前进度快照；依赖与验收见 [IMPLEMENTATION_WORKPLAN.md](IMPLEMENTATION_WORKPLAN.md)。阶段 A 已完成；阶段 B 已在当前 Linux 项目目录做有限真实 collection 与一次诊断复测。未操作外部目标、真实账户或无关宿主文件，未输出密钥，未覆盖旧 raw/冻结库，未 commit/push。

## 1. 当前结论

**阶段 B 尚未达到完成条件：Gemini direct 文本与最小工具链可用，但 OpenClaw gateway 对照仍返回空/非 JSON；输入门为 0 accepted，因此未 freeze、未执行 matched pair，Stage C 不准入。**

- 质量门已修复：`make check` 全部通过，pytest 为 **153 passed、0 skipped**。
- sample v3.1 已将样本质量、交互行为、攻击相关性、官方攻击结果和 evaluation eligibility 分开；部分/阻断/正常的有证据子图可以入库，但不会自动进入正式攻击主分析。
- filter、builder、library audit 共同重算并校验这些状态；伪造引用、必要依赖缺失、shortcut、来源/hash 不一致仍拒绝，未通过关闭真实性门换 accepted 数量。
- observation 保留全部显式 retrieval 及 parent/evidence/request lineage；不可观测 recall 仍为 unknown。tool request、observed effect 和执行结果不再混作成功。
- Planner 不再取第一个 component 或任意 macro/session fallback；多组件角色明确拒绝，macro 会话来自最后一个有观测依据的 core occurrence。
- formal report 分开 interaction、official attack 与 mechanism outcome，并对 matched task/seed 条件做配对校验与 delta；不匹配 pair 明确拒绝。
- 构造 bridge 实际只支持 `safeclaw_user_message`。配置中声明但尚未实现的 local sink/new-session delivery 不再静默降级为用户消息，而是在 bridge/Victim 前 fail-closed。

## 2. 本轮实测

| 检查 | 结果 | 说明 |
|---|---|---|
| `git rev-parse --short HEAD` | `a4ce8940` | 阶段 B 修改前源码基线；工作区有未提交改动 |
| `make check` | 通过 | ruff format/check、mypy、pytest 均执行 |
| ruff | 通过 | 107 files formatted；lint 无问题 |
| mypy | 通过 | 65 source files |
| pytest | 153 passed、0 skipped | 约 5 秒；覆盖空响应、认证/限流/超时/拒绝、legacy raw、call ledger、formal bridge projection 与 Gemini compat patch |
| Stage B preflight | 通过 | env 名称非空、角色模型、upstream commit、patch、Docker image 与磁盘均通过；未打印值 |
| PSE evaluator probe | 通过 | pinned evaluator 三个合成状态分数为 0.0/0.6/1.0；仅为 evaluator 探针，不是攻击结果 |
| secret scan | 通过 | 四棵 Stage B 输出树 exact key 与模式扫描 0 findings |

质量门是离线证明；Stage B raw/model call ledger 是真实运行证明。后者证明 Attacker 成功和 Victim gateway 空响应，不证明真实 retrieval、机制或攻击成功。

## 3. 工作包状态

| 工作包 | 状态 | 阶段 A 证据 / 剩余边界 |
|---|---|---|
| W00 | verified | 当前源码、测试、历史 retry22/23 与 upstream 已重新盘点 |
| W01 | verified | v3.1 三维状态与兼容 schema、正反回归通过 |
| W02 | in_progress | call/session/response ID、空/超时/认证/限流/拒绝分类与 unknown 回归通过；真实 retrieval/tool-result stream 仍不可得 |
| W03 | verified | 部分路径建库、audit 一致性、隔离幂等重算通过 |
| W04 | in_progress | upstream/image/patch/容器与 user-message bridge 已真实运行；新版 compat 配置已进入容器，但 OpenClaw 对照未产出可观测 provider request/JSON response |
| W05 | verified | component/session 映射有明确依据，无任意 fallback |
| W06 | in_progress | Attacker 真实请求及 call ledger 通过；Planner/formal Victim 因无合格 sample 未运行 |
| W07 | in_progress | evaluator 离线探针通过；matched official/mechanism 结果因输入门未通过而未生成 |
| W08 | blocked | Gemini direct 文本、function calling、tool-result、streaming 均通过；OpenClaw compat 配置已加载，但 gateway 返回空/非 JSON，出站字段仍未观测 |
| W09 | blocked | 真实 collection 已停止于 0 accepted；没有 `formal_attack_primary` 输入，不能运行 matched smoke |
| W10 | in_progress | Stage B 配置、raw、审计、handoff 与 C 准入已更新；完整 B/C 交付仍受 W08/W09 阻塞 |

## 4. 隔离重算证据

旧 raw 仅只读，新的派生产物位于：

- `experiments/safeclaw_v3_smoke/stage-a-recompute-20260908/retry22/`
- `experiments/safeclaw_v3_smoke/stage-a-recompute-20260908/retry23/`

两批在处理前均通过 collection/source hash 校验；各为 `candidate=1, accepted=1, negative=0, attempt_outcome=partial`，audit 均 `passed=true`。

| 来源 | mining manifest hash | library tree hash | sample 状态 |
|---|---|---|---|
| retry22 | `2739f3abc4170c4705a2279757e9e6b6058d91353850df80eeee9751acd1be71` | `ddc8c09940220e4a96fa410c3b8d280548f7bd18cd476818922ac248c3229fd6` | partial / usable / official not_evaluated |
| retry23 | `708641e2493ffed11efe12ce55a29067c4ca0989da91a93295fb0c33349778f4` | `757cbcadc3943b1e7ff6d7da6a735228c58426307c84eec1c8f146638bc1d899` | partial / usable / official not_evaluated |

两条 sample 均为 `structure=valid, evidence=observed, behavior=unknown, attack_relevance=established`，eligibility 为 `mechanism_analysis/adversarial_sample/partial_path_analysis`，明确不含 `formal_attack_primary`。它们不是完整持久化、跨会话 recall 或官方攻击成功的证据，也未 freeze。

## 5. 当前运行时边界

- pinned upstream 只提供 assistant tool calls，没有结构化 tool-result/retrieval stream；实际 retrieval 仍为 unknown，不能由文件存在或请求意图推断。
- 本轮实际 source adapter 仅支持 `adversarial_trace` construction；两条初始轨迹均为 adversarial acquisition。空响应是有效阻断/诊断结果，但不等于已完成 ordinary normal collection；未静默替换为 fixture 或其他 surface。
- upstream commit、patch、镜像、容器生命周期和角色 env mapping 已实测。benign OpenClaw probe 的脱敏 gateway diagnostics 明确为 `provider=openai/model=gemini-2.5-flash/HTTP 400 (no body)`；同 endpoint/model 的 direct minimal Gemini probe 为 HTTP 200/`OK`。镜像源码审计确认 OpenClaw 会额外发送 `store:false`、stream usage、`max_completion_tokens` 和 tool `strict:false`；HTTP 400 无 body，故不能进一步断言其中哪个单字段被拒绝。
- 版本化 safety patch 已为 Gemini `/openai` endpoint 设置 OpenClaw 原生 compat：关闭 store、stream usage 和 tool strict，并改用 direct probe 已验证的 `max_tokens`。新 patch SHA-256 为 `6ea8c100063adfa30a9ce03e02a09a3cf9f2ad27c5ef62fc60b423a85a90b523`；patch apply、patched judge compile 和完整离线质量门通过，但没有消耗第 3 个真实 probe，运行时状态仍为 unverified。历史 raw 继续绑定旧 patch hash `53c31a4d...`，未改写。
- Attacker 诊断复测 usage 为 2413 tokens、retry 0；direct Gemini probe usage 为 prompt 12、completion 1、provider total 24、retry 0。初始 Attacker usage、OpenClaw 内部 Victim usage/费用、embedding 调用/usage 为 unknown。gateway 的零 usage 不当作零费用。
- 未运行 matched assigned-sample/no-sample、正式 official/mechanism evaluation 或 dependency ablation；原因是新库 0 accepted，而非执行成功或攻击失败。
- 正式配置仍指向 `data/primitive_libraries/frozen/safeclaw-main`；阶段 A 新库未冻结且不应替换它。

## 5A. 2026-09-09 Gemini/OpenClaw 有限兼容诊断

- 诊断目录：`experiments/stage-b-20260909-gemini-compat-01/`；未运行 collection、mining、freeze 或 formal evaluation。共 9 次真实请求尝试（5 次 direct Gemini、4 次 OpenClaw 对照；含 09 号 SSE 纠正投影），上限 12；每次无自动重试。
- 官方格式依据：Gemini OpenAI compatibility 的 function calling 示例使用 OpenAI `tools`/`tool_choice=auto`，官方 function-calling 文档要求工具结果携带对应 call ID。[OpenAI compatibility](https://ai.google.dev/gemini-api/docs/openai)、[Function calling](https://ai.google.dev/gemini-api/docs/function-calling)。
- direct 结果：普通非流式文本 HTTP 200；最小 `add(a,b)` 非流式 HTTP 200 并返回结构化 tool call；保留 `tool_call_id` 回传本地结果 5 后 HTTP 200；最小流式请求 HTTP 200 并返回结构化 tool call。direct 已知 usage 为 36、123、130 total tokens；stream usage unknown。
- OpenClaw 结果：新版 patch SHA-256 `6ea8c100...` 已应用，容器最终 provider 配置明确为 `baseUrl=/v1beta/openai`、`api=openai-completions`、`supportsStore=false`、`supportsUsageInStreaming=false`、`maxTokensField=max_tokens`、`supportsStrictMode=false`。带 session key 且限制高风险工具后，gateway 仍返回空/非 JSON，provider usage unknown；本地 `pi-ai` 序列化投影未命中，gateway 日志只有启动信息。
- 结论边界：已证实 Gemini 基础文本、function calling、tool-result 往返和 streaming 能力正常；强怀疑问题在 OpenClaw gateway/provider 请求层。尚未证实具体单字段或字段组合，也无法声称 patch 已真实修复。诊断摘要与每次投影见 `diagnostic_summary.json` 及 `01_*` 至 `08_*` 文件。

## 5B. 2026-09-09 Gemini/OpenClaw 兼容诊断续接

- 新诊断目录：`experiments/stage-b-20260909-gemini-compat-02/`；本轮执行 5 次 direct Gemini 请求，未运行 collection、mining、freeze 或 formal evaluation。
- direct 结果：非流式文本 HTTP 200/`stop`；最小 `add(a,b)` HTTP 200/结构化 `tool_calls`；保留同一 `tool_call_id` 回传本地结果 5，HTTP 200/最终文本；正确逐行解析的最小 streaming function call HTTP 200/`tool_calls`。已知 usage total 为 20、117、58；stream usage unknown。
- compat 配置仍为 `supportsStore=false`、`supportsUsageInStreaming=false`、`maxTokensField=max_tokens`、`supportsStrictMode=false`；patch SHA-256 仍为 `6ea8c100...`。本轮离线审计 pinned `openclaw@2026.3.12`、`@mariozechner/pi-ai@0.57.1`，确认源码存在这些 compat 字段及默认 `strict:false` 生成路径。
- 本轮未启动 OpenClaw gateway：运行时审查无法证明内部请求的完整 payload、自动重试和工具面严格受限。上一轮 4 次 live OpenClaw 对照仍是唯一 live 证据，均空/非 JSON；因此 compat patch 仍未真实验证成功。
- 结论边界：Gemini 能力四类 direct 检查再次证实；OpenClaw gateway/provider 请求层及字段组合仍强怀疑，具体单字段、消息历史/工具 schema 差异和 patch live 效果尚未证实。


## 5C. 2026-09-09 OpenClaw 本地 mock 捕获与回放

- 新增离线 mock/replay 实现：`src/stac_attack_lab/diagnostics/openclaw_mock.py`；focused tests：`tests/unit/test_openclaw_mock_replay.py`（5 passed）。覆盖非流式文本/tool_calls、空正文带 tool_calls、普通/SSE 文本、分片 arguments、400 可读错误、空 body、非法 JSON、截断 SSE、超时/暂时错误与显式重试上限。
- 新增隔离集成命令：`python3 scripts/diagnostics/run_openclaw_mock_integration.py`。使用 `openclaw-env:2026.3.12`、`docker --network none`、容器内 loopback mock、fake token、独立临时配置；证据：`experiments/stage-b-20260909-openclaw-mock-01/integration_result.json`。
- 首次集成未到 provider 的原因已证实为合成模型 `contextWindow=4096` 小于 pinned OpenClaw 最低 16000，gateway 日志为 `Model context window too small`；提高临时值到 200000 后，mock 收到 1 次真实请求。
- 捕获请求：路径 `/v1/chat/completions`，客户端 `OpenAI/JS 6.26.0`，`x-stainless-retry-count=0`，消息角色为 `system,user`，`stream=true`。加载四项 compat 后最终 body keys 为 `max_tokens,messages,model,stream,tools`，明确无 `store`、无 `max_completion_tokens`、无工具 `strict:false`。mock 返回合法 SSE 后 gateway 正确返回 `MOCK_OK`。
- 对照回放：同一路径若 mock 返回普通 JSON 而请求 `stream=true`，OpenClaw 对外返回 `No response from OpenClaw.`；因此“空响应”可由流式协议响应不匹配产生，不能直接等同 Gemini HTTP 400。
- 该本地 mock 只证明 OpenClaw gateway 请求/响应链路和协议处理，不证明 Gemini 接受相同请求；历史真实 HTTP 400、上一轮空/非 JSON 与本地 mock 结果分开记录。

## 6. 当前：阶段 B 有限真实验证

用户已授权当前 Linux 项目目录内的阶段 B。阶段 A 质量门已在当前版本复核；真实调用严格受本节清单和停止条件约束。只有新 sample 同时通过 audit、`formal_attack_primary` eligibility 与 binding 才能创建 smoke 冻结库并执行 matched `assigned_sample`/`no_sample`。

当前输入门未通过，因此 matched smoke 尚未执行；这不冒充闭环完成。空响应根因只允许在明确代码修改与回归后做一次有限诊断复测。
## 6A. 阶段 B 当前运行清单（2026-09-08）

- 初始配置/输出：`configs/sample_generation/stage_b_20260908_01.json`、`experiments/stage-b-20260908-01/`；诊断复测配置/输出：`configs/sample_generation/stage_b_20260908_02.json`、`experiments/stage-b-20260908-02/`。两者均为唯一新目录，不复用或覆盖旧 raw、`safeclaw-main` 或冻结库。
- 角色映射：Victim `gemini-2.5-flash`/Gemini (`GEMINI_BASE_URL`)，Attacker 与 Planner `gpt-5.5`/OpenAI-compatible (`OPENAI_BASE_URL`)，embedding `ark_multimodal` 豆包 (`SAFECLAW_EMBEDDING_BASE_URL`/`SAFECLAW_EMBEDDING_MODEL`)。变量仅确认非空，值不写入日志。
- 初始范围：`pse-2.2-002` construction task，seed `20260908`、`20260909`，最多 2 trajectories；delivery surface 仅 `safeclaw_user_message`。当前不支持的 local sink/new-session delivery 不会替换执行。
- 每 trajectory 上限：3 sessions、24 turns/actions、16 tool calls、8192 tokens、1200 seconds、2 consecutive retries；每模型请求初始 1 次，最多 2 次瞬时错误重试，认证/权限/拒绝/无效配置不重试。
- 已执行：初始 2 条真实 collection trajectory（seeds `20260908/20260909`）及 seed `20260909` 的一次诊断复测，共 `3/12` trajectory attempts、`392792 ms`，formal case 0。两条初始轨迹的 provider usage 不可得；复测 Attacker usage 为 prompt 1570、completion 843、total 2413、retry 0。Victim/embedding usage 仍为 unknown。
- 修复与重算：bridge 现区分 empty/timeout/observed text/tool call，记录可得 response ID/hash/finish reason/脱敏投影；空响应使 step/trajectory partial。legacy normalizer 防止旧 raw 的空响应伪装为 passed。修正后重算目录 `experiments/stage-b-20260908-01/recomputed-library-v2/` 为 0 accepted，两个候选均以 `candidate_occurrence_not_observed` 被 G1 拒绝；audit 如实失败于 `accepted_sample_target_not_met:0:1`。
- 诊断复测：`partial / victim_empty_response`，1 session/turn、49.618 秒；response ID 与 `finish_reason=stop` 可见，gateway usage 为零但标记 unverified。离线 mine 为 1 negative/0 accepted，G1 原因 `candidate_occurrence_not_observed`；audit 失败 `accepted_sample_target_not_met:0:1`。证据索引为 `experiments/stage-b-20260908-02/stage_b_handoff.json`。
- 全阶段上限未耗尽，但同一 trajectory case 已达 2 次尝试，后续不再运行 collection/formal case。`stage-b-20260908-03` benign OpenClaw probe 为 HTTP 400，`stage-b-20260908-04` direct Gemini probe 为 HTTP 200；两者均 1 call、无重试，输出树 secret scan 0 findings。最终计数：trajectory `3/12`、formal `0`、该根因 service probe `2/3`、真实 trajectory 墙钟约 `6m33s/4h`。未使用的第 3 个 service probe 不覆盖同根因 2 轮修改/复测上限，因此不在本轮调用。
- 停止条件已触发：OpenClaw 请求 HTTP 400、sample audit 0 accepted、binding 输入缺失。已保留全部产物并停止，不使用第 3 个 probe，不 freeze、不执行 matched pair。

## 7. 续接记录

- 2026-09-09 / `a4ce8940`：按新增授权完成有限兼容诊断；5 个 direct Gemini 探针 HTTP 200（含工具调用、tool-result、streaming，含一次 SSE 纠正解析），4 个 OpenClaw 对照均未产生可观测 provider request，最终返回空/非 JSON。共 9/12 请求，direct 已知 usage 289 total、OpenClaw usage unknown。未运行 collection/mining/freeze/formal，0 accepted、Stage C 不准入。

## 5D. 2026-09-09 有限真实 Gemini/OpenClaw 验证

- 本轮未重复 direct Gemini；先补离线 parser 回归（6 passed），确认 SSE tool-call 按 index/ID 合并为单一调用，`json.loads(arguments)=={"a":2,"b":3}`，并覆盖 transport failure 的显式重试上限。
- 隔离 pinned `openclaw-env:2026.3.12` 工具实验：`tool_integration_result_v2.json` 中 gateway 真实执行一次本地工具循环，provider 捕获 2 轮消息角色含 `assistant,tool`，最终 `SUM=5`；但出站 schema 是 20 个内置工具，未出现自定义 `add`，故只能证明结果续接，不证明 add 白名单注册或 strict 语义。v3 保留了一次 mock 启动失败（0 provider 请求）作为负证据。
- A direct 结构回放（`experiments/stage-b-20260909-gemini-compat-03/a_direct_replay.json`）使用合成 system/user、`tools=[]`、`stream=true`、`max_tokens=1024`，真实 Gemini `gemini-2.5-flash` 返回 HTTP 200、`Content-Type: text/event-stream`、`finish_reason=stop`、`[DONE]`，1 次请求；raw SSE 在 `a_direct_replay_sse.raw`，未保存认证信息。
- B OpenClaw 无工具对照：首次临时配置错误（`agents.defaults.contextWindow`）在 provider 前失败，保留于 `b_openclaw_real.json`/`v2`；修正后 `b_openclaw_real_v3.json` 的 gateway 健康且实际到达 Gemini，OpenClaw 日志为 `400 status code (no body)`，对外 `No response from OpenClaw.`。这是已证实的真实 Gemini 400，不能与本地 JSON/SSE 不匹配或历史 400 证据合并。
- 真实 provider 请求计数：A=1，B 修正后=1；两次配置前置失败均 provider=0；本轮未执行 C（真实单工具）以遵守前一步失败停止规则。OpenClaw 内部 retry 在无 provider proxy 时不能观测，故不宣称可控；此前 mock 成功请求的 `x-stainless-retry-count=0` 仅为本地证据。
- compat 四字段在临时配置层存在且模型配置读取成功；本地 mock 无工具请求最终体现 `store`/`max_completion_tokens` 省略、`max_tokens` 存在、空工具无法验证 strict。真实 B 的 400 尚不能归因到单字段或证明组合修复无效。0 accepted 仍阻止正式配对评测，但不阻止独立合成工具/检索观测测试。
