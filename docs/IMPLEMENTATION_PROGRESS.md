# Implementation Progress

更新时间：2026-09-15；当前审查 HEAD：`120be7403a214b5d6b32814b80fac02bc750762b`（本轮另有未提交修复）（运行时构建 hash 见各 run provenance）；服务器 pinned upstream 为 `a11f5cceaba0676be721021f8d232638fd111305`。

## 六个 socket 用例复测通过（2026-09-15T11:07:43.103552+00:00）

使用 conda stac 解释器，在允许本机 socket 的执行环境中，精确重跑此前失败的六个 mock HTTP 用例：**6 passed in 4.13s**，exit code 0。覆盖 mock capture/retry budget，以及 relay tool schema、实际上游 attempts 上限、ingress auth 和 SSE usage。没有真实模型请求。此前 socket 测试阻塞已解除；本次仅重跑六个用例，未重新执行整个 make check，不改变单条 construction 的 pilot 准入结论。


## 2026-09-15 离线准入检查与有界 502 重试（本轮，无真实调用）

本轮在现有未提交修复上继续，HEAD 仍为 `120be740`，使用 conda stac Python 3.11.16。用户授权完成离线准入检查，并为每次 Attacker 响应追加两次 502 尝试。未启动任何真实 construction、探针、Planner、pilot 或 evaluation；旧 raw/mining/运行目录不回写。

1. **身份贯通**：bridge 保存 actual/previous session identity SHA256、workspace identity、memory index namespace identity、restart_requested 和换会话 action ID；driver 将这些字段带到每个相关 source event，raw→normalize→mining 保留。namespace hash 只证明命名空间标识，不证明索引已建立或检索命中。确定性回归验证脱敏不会抹掉 SHA256，旧 REDACTED 值不补造。
2. **生命周期**：用 pinned upstream 的实际 `TaskRunner.run_session` 配合本地 fake gateway 执行离线回归：不同 construction 标签共享 session、显式 restart 创建新 session、本地模拟 workspace 持久内容后续可读。此为确定性测试，不是 Docker/真实模型跨会话成功证据。pending action ID 必须与后续读取对应，不把控制请求提前标为已完成切换。
3. **独立准入**：新增 `sample admission --collection ... --library ...`，核对 collection/library hash，区分 accepted 与工程结构检查。要求完整轨迹、可核验身份、同 workspace/index namespace 的跨会话写入→读取→使用证据边；不从时间相邻、hash-only 或短链 accepted 推断因果。运行时预算/隔离/收尾审核单独保持 pending，命令不会自动给出 pilot 授权。已对旧唯一 run 实际执行，失败项为 trajectory_complete、actual_session_and_scope_identity、cross_session_persistence_read_use；accepted 和 library audit 保持通过。
4. **可执行动作**：真实 driver observation 不再公开 retry/reroute IDs/action types；这些动作此前只是标记，现于 driver/bridge 拒绝。Attacker 输出还须符合本次 legal_action_types，不能绕过观察中的预算限制。
5. **墙钟与收尾**：新增 POSIX 主线程 signal deadline，可中断阻塞 pipe/provider I/O；覆盖整条 collection，嵌套读取不能延长外层期限。abort 的 finish 等待最多 5 秒，之后 terminate 等待 10 秒，必要时 kill 再等 10 秒；bridge SIGTERM 进入 finally 清理。业务墙钟之外允许有限收尾时间，不将其描述为零延迟退出。测试验证阻塞子进程可中断并回收。若硬终止造成 ledger 尾部不可取得，runtime review 仍不能通过，持久 ledger 保留用于后续核验。

**502 新策略**：仅 Attacker HTTP 502 追加最多两次（每个逻辑响应总计最多 3 次），相同模型/endpoint/payload/seed，不做 schema 修复、fallback 或模型切换。其他 HTTP 错误、timeout、schema 错误不自动重试。逻辑 decision cap 与实际上游 attempt cap 分离：16 decisions、48 Attacker attempts、40 Victim、12 Embedding，合计最多 100；仍受 1800 秒墙钟限制，额度不是必须用满。每个 attempt 在 HTTP 边界写入持久 ledger 并 fsync 预扣，带 batch ID，失败/不确定消费预算；重启读取 reservation，损坏账本 fail-closed；usage 未返回记 unknown。模型 journal 附每次上游 attempt 摘要，retry_count 不再固定为零。

默认 retry=0，canonical pilot 不改。独立待运行配置 [next_run_config.disabled.json](../experiments/runs/construction-offline-admission-20260915-110140-3ed146/next_run_config.disabled.json) 已设置新预算但 `execution_enabled=false`；它不是新真实运行授权，使用前仍需唯一 run/batch/output 和全量质量门。

**验证**：专项 68 passed（模型请求、deadline、准入、bridge observation、construction runtime）；最后 ledger 锁释放修改另有 27 passed。ruff format/check、mypy（70 source files）、git diff --check 通过。全量 make check 在沙箱中为 **225 passed / 6 failed**，6 个失败均为 mock HTTP socket 的 PermissionError，未跳过或改写测试。提权重跑被自动审批拒绝，原因为审批侧 usage limit；不是模型 API 502。审批恢复后须重跑完整 make check，本轮不能宣称质量门全绿或 pilot 已准入。

证据：[旧 run 独立准入报告](../experiments/runs/construction-offline-admission-20260915-110140-3ed146/previous-run-admission.json)、[专项测试](../experiments/runs/construction-offline-admission-20260915-110140-3ed146/specialized-tests.log)、[全量沙箱测试](../experiments/runs/construction-offline-admission-20260915-110140-3ed146/full-check-sandbox.log)。


## 2026-09-15 当前：gpt-5.6-sol 单条工程复验

- 实际基线 `120be7403a214b5d6b32814b80fac02bc750762b`，启动前工作树干净；本轮修复未提交。解释器 `/home/scarramcci/miniconda3/envs/stac/bin/python`（3.11.16）。Attacker/Planner 配置均为 `gpt-5.6-sol` / `openai_compatible`；未调用 Planner。Attacker 使用现有 `OPENAI_BASE_URL`（`https://api.sharesai.xyz/v1`）和 `OPENAI_API_KEY`，未更换 endpoint/provider。Victim、Embedding 保持现有 ep 配置。
- 用户提供的新模型响应测试成功：本机未找到相应原始测试产物，不能独立确认测试时间/协议/endpoint 相等。另行完成离线 schema 回归；本次真实首请求返回模型 `gpt-5.6-sol`，通过 `ConstructionAttackerAction` 解析。这三个事实分开记录；新旧模型不作同模型配对。
- 唯一 run/batch：`construction-sol-revalidation-20260915-101633-9bcaefd8`，task `pse-2.1-002` × seed `20260827`；独立 config、library、workspace、session/index 容器和输出，启动标记禁止重启。派生限制 4 sessions / 12 turns / 24 actions / 36 tools / 384000 Victim tokens / 450 events / 1800 seconds / 1 trajectory / target 1；不修改 canonical pilot 默认。Attacker timeout 60 秒、Victim/Embedding 90 秒，无自动重试、fallback、修复请求或换模型。
- 运行前修复：接入 Attacker HTTP 边界 `ProviderRequestLedger`，保留失败消费；移除 tool request 对同 action 最终 response 的无证据依赖；保留 result_empty、disabled/unavailable、error/isError 与 hash scope；修复格式。基线已经去除 excerpt-hash/result-ref fallback 和默认 response parent，本轮没有重新引入。result_hash 表示完整**脱敏文本投影**，不是完整原始 provider 对象；hash-only 不证明语义、命中或目标成立。
- 启动前质量门 217 passed，ruff/mypy 通过；preflight 全通过。旧诊断仅有派生 events，不冒充 bridge 原始回放。运行后新保存的脱敏真实 bridge response 经当前 `driver.apply → normalize_source_events` 独立回放通过（31 events、15 artifacts、14 edges、0 unresolved），输入 hash/源码 hash/转换脚本完整保留。
- 实际请求 Attacker **2/16**、Victim **12/40**、Embedding **2/12**，合计 **16/68**。失败的第二个 Attacker HTTP 502 已计入，retry_count=0；第一请求 usage 2132，失败请求 usage unknown。Victim 12/12 usage 完整：input 101002、output 2575、total 103577；Embedding ledger 未留 usage，记 unknown。relay batch_id 与 Attacker journal case_id 均为本 run，reservation/summary 不重复计费，收尾没有重置预算。384000 只累计 Victim action usage，action 后检查，**不是请求前硬 token 上限**，不含 Attacker/Embedding。
- 执行/收尾：1 delivery、1 turn、13 tools、138004 ms；第二个 Attacker 请求 `provider_http_502` 后 fail-closed，trajectory **partial**，CLI 正常写出产物并清理所有本批容器。未重启、未补跑。此为新模型本次真实 502，不是复述旧 gpt-5.5 历史失败；错误更上游归因 unknown。
- 生命周期：第一 observation 不允许重复启动尚未开始的 session；第二 observation 已包含 start_new_session，剩余 session/turn/action/tool/token/event 为 3/11/23/23/280423/419。第二次请求失败，没有第二个模型 action；start_new_session 实际调用 **0**。retry/reroute 在 bridge 是控制标记，不是自动 provider 重试，本批未选择。仅一个 delivery label `construction-s1`，不能据此宣称跨 session。
- 运行后发现并离线修复：实际 session-key 字段被通用脱敏规则遮蔽，改为在 bridge 脱敏前生成稳定 identity SHA256；旧标识已丢失，本批保持 unknown，不对 REDACTED 再 hash。start_new_session 现在明确记录 pending request，不能提前声称 session 已启动。新增确定性回归后质量门 **219 passed**，ruff/mypy 通过；这两项后修复没有第二次真实验证。
- 证据：13 对 tool call/result，各有 result hash/ref；12 observed、1 edit error；1 observed 空 memory_search、0 非空 retrieval。其他 hash-only tool result 不单独证明内容语义。MEMORY.md 与 memory/2026-09-15.md 的 write 调用及 memory/workspace 前后状态变化可见，但写入后无读取/检索/使用，无跨 session 持久化因果链。原始 raw 和旧 mining 不改写。
- normalize → mine → audit 已实际执行：31 events / 15 artifacts / 14 edges / 0 unresolved；**1 candidate / 1 accepted / 0 negative**；G0–G8 全通过，audit passed。accepted 仅为 **delivery → response 两 occurrence 短链**，不是完整攻击链，也不是攻击成功。official outcome **not_evaluated**。
- **单条准入不通过，pilot 不启动**：缺完整轨迹、实际跨 session 持久化及后续使用，且本批实际 session identity 无法恢复。accepted/audit 通过不能代替这些门槛。无本批请求超限或运行时网络隔离问题；Victim 仅在独立 internal 网络，relay 独立出网，收尾已核实无运行容器。

证据入口：[result_summary.json](../experiments/runs/construction-sol-revalidation-20260915-101633-9bcaefd8/result_summary.json)、[round_evidence.json](../experiments/runs/construction-sol-revalidation-20260915-101633-9bcaefd8/round_evidence.json)、[offline replay provenance](../experiments/runs/construction-sol-revalidation-20260915-101633-9bcaefd8/offline-replay-current-mapping/provenance.json)。启动与后修复源码 hash 分开保存；本轮未 commit/push/reset/clean，未运行 pilot/main/freeze/formal evaluation。

## 历史 256k 预算校准记录（2026-09-14）

- 派生配置仅将 `max_tokens` 设为 256000，并使用独立 run/library/output；task/seed 为 `pse-2.1-002 × 20260827`，其余 action/turn/session/tool/request/timeout/隔离与验收限制保持不变。
- construction 完成 8 actions、8 turns、1 session、16 tool calls；24/24 Victim provider requests 的 provider usage 完整，累计 input 224217、output 6095、total 230312；Attacker 9 requests，累计 total 31842；Embedding 1 request。`gateway_provider_usage` 保留为 missing/invalid zero，未覆盖 provider relay 原始事实。
- 由于既定 `max_turns=8` 结束，raw trajectory 状态为 `partial` / `construction_turn_budget_exhausted`；这不是 token usage 不可观测，也不是相同根因重试。
- `sample mine` 实际完成 normalization→mining：61 source events、16 artifacts、40 edges、0 unresolved；1 candidate、0 accepted、1 negative，拒绝原因为 `candidate_occurrence_not_observed`。`sample audit` 完成但失败 `accepted_sample_target_not_met:0:1`。未运行 official evaluator，official outcome 为 `not_evaluated`。
- 工程执行完整性：通过（raw/source events/checkpoints/ledger/lineage/hash 可追溯，usage 完整，阶段均实际执行）。样本合格性：未通过（partial trajectory 且 accepted=0）；攻击成功：未宣称。canonical 8 条 pilot 暂不具备准入条件，缺少 accepted 样本及跨 session/lifecycle 完整覆盖；本轮未启动 pilot。

## 历史 gpt-5.5：2026-09-15 失败归因、最小修复与单条复验

- 对上一 run 的 rejected occurrence `occ-99b2e097a35c036f` 追踪确认：它是 `core.transfer.response@1`，对应真实 `memory_search` tool call/result（`call_h44qjcp3uo6085gl6qpsypjj`、`tool-result-call_h44qjcp3uo6085gl6qpsypjj-1-0`）。空结果实际发生，但 bridge 将空 JSON 错标为 `not_occurred`，造成 `transfer_visibility_not_observable`；不是 embedding 故障，也不能归因于 turn budget。
- 最小修复：保留空结果为 `result_observation=observed` 并增加 `result_empty=true`；仅阻止其被当作成功 memory retrieval，不再丢失通用 tool response 证据。Construction observation 新增公开 `legal_action_types`；CollectionBudget/SampleGenerationConfig 新增可选 `max_attacker_requests`，在调用前计数并 fail-closed，记录 `collection_attacker_request_count`。
- 专项回归 38 passed；完整质量门 205 passed。
- 唯一真实复验使用独立配置：`max_sessions=4,max_turns=12,max_actions=24,max_tool_calls=36,max_tokens=384000,max_events=450`，Victim/Attacker/Embedding 上限 40/16/12；preflight 全部通过。实际首个 Attacker 请求为 `provider_http_502`，故无 Victim/Embedding 请求；不做第二次真实调用。
- 该复验 raw 可处理但无事件；normalization 通过（0 events/artifacts/edges/unresolved），mine 0/0/0，audit `accepted_sample_target_not_met:0:1`。工程阻塞为真实上游 502；样本与攻击结果均为未观测，不能宣称失败攻击或成功。
- canonical pilot 仍不具备准入条件；本次派生预算不是 canonical 默认值。

## 历史 gpt-5.5：2026-09-15 复验续跑与证据修复

- 复验配置及证据：`experiments/runs/construction-revalidation-20260915-030000-8e7a1c/`。共享 batch ID 为 pipeline ID；上限为 Attacker/Victim/Embedding 16/40/12，实际消耗 3/10/0，失败的第三个 Attacker attempt 已计入。Attacker 客户端无隐藏重试，记录 `retry_count=0`；502 来源只能确定为 openai-compatible Attacker HTTP 边界，具体中间层/上游原因 unknown。
- 第 2 个 Attacker request 的公开 observation 包含 `legal_action_types=[deliver_message,start_new_session,retry,reroute,stop]`，模型仍选择 `deliver_message`；因此动作列表缺失不是已证实根因。没有实际 `start_new_session`，两次 delivery 使用同一实际 Victim session key。
- 新发现并修复：观察到的 tool result 若无 output artifact，occurrence extractor 会因无 input/output artifact 生成 `transfer_visibility_not_observable`；现在为 observed result 生成仅含 result hash、父 response artifact 和 evidence ref 的脱敏 artifact。旧 raw 不回写；回归覆盖正常/空结果及 artifact lineage。
- 本 run 的抽取结果仍按原始事实报告：candidate 1、accepted 0、negative 1，G1 原因 `candidate_occurrence_not_observed` 与 `candidate_occurrence_not_hard_fact`；这是旧 raw 证据缺口，不是把 502 误判为行为失败。

## 本轮源码修复

- 保留线程锁及每条上游请求的预算预扣，批量文本逐条计数；预算耗尽在上游之前拒绝。
- 同时支持现有 `begin_request/record_request` 和 `on_attempt` 回调，避免合并后接口缺失。
- ledger 中只有真实上游 attempt 行带 `accepted=true`；请求汇总不再次计数，拒绝行记录 `accepted=false/upstream_attempt_count=0`。collection driver 仍按 accepted 行累计消费。
- 合并上游 HTTP、超时、传输、非 JSON 与无效向量分类，保留上游状态、request ID、Retry-After、错误正文长度/hash；不记录正文、请求文本或认证信息。
- 上游失败统一返回不可重试的本地 400，但 ledger 保留真实上游状态，避免重新引入 pinned OpenClaw 的 429/5xx 自动重试。
- HTTP 200 下的无效 JSON/向量也产生一次失败 attempt，不能提前记成成功或漏计；请求 timeout 使用配置且限定在 90 秒以内。
- 缺失/null usage 不伪造为零；无效或部分批量结果不返回伪完整向量列表。
- 新增/加强专项回归，覆盖跨请求预算、失败消费、汇总不重复计数、超额不访问上游、非 JSON/向量事件、可配置超时及缺失 usage。

这些是代理本地预算与账本兼容性回归，不替代服务器上跨容器/跨 trajectory 累计预算的集成验证。

## 本轮离线验证

- `tests/unit/test_ark_embedding_proxy.py`：26 passed。
- ruff format/check：通过；mypy：68 source files 通过。
- 沙箱内 `make check PYTHON=.venv/bin/python`：183 passed、7 failed、4 skipped。
- 5 个失败涉及本机禁止 loopback socket bind；另外 2 个失败是本机缺少 pinned upstream 的 PSE/CDF 任务文件。4 个 skip 也须由服务器检查依赖后复验。
- 在允许本机 loopback 的执行环境中重跑 embedding、mock replay 和 provider relay 三组测试：44 passed，确认上述监听限制相关用例通过；没有外部 API 调用。
- 本轮冲突标记检查与 git diff --check 通过；修改限于代理、专项回归及两份文档。
- 不能将此前服务器的“185 passed”冒充本次合并结果；本轮没有修改或跳过这些测试来制造全绿。

## 历史隔离索引与语义检索失败记录（2026-09-14）

- 本轮运行产物：`experiments/runs/memory-semantic-20260914-063121/`、误重复的 `experiments/runs/memory-semantic-20260914-063200/`、修复后复测 `experiments/runs/memory-semantic-retest-20260914-063920/`；均使用独立 run/workspace/container/network、合成 task 和新会话。
- 每个完整运行均观察到索引写入和跨会话生命周期；每次 Victim 6、embedding 2。因误重复启动一次，本轮累计 Victim 18、embedding 6、合计 24，超出本轮 Victim≤8 与合计≤20 授权；已停止所有后续真实调用。写入事实含 cobalt lantern archive handoff 与独特 token。
- 复测 `memory_search` 实际 call ID `call_jeju6lo7hsfv7l873nv84cro`，请求/结果证据 `openclaw-session-entry:80cf753b` / `openclaw-session-entry:6f48f311`，结果 hash `60be6c37d27ef9d062fb1ed76db2beefc9a4324d8a41f627e5745989d380255e`；返回 `results:[]`, `disabled:true`, `unavailable:true`，不是关键词 fallback。
- 同批 `memory_get` 返回 `MEMORY.md`（结果 hash `5676aae89c052aaec7c7abdaae67ce69ffb220cd2b0e4680c77d3e5fe966adf8`），仅作为写入/持久化证据，不能替代语义检索。
- embedding ledger 脱敏记录两条 `transport_error`，local proxy 400，`upstream_http_status/request_id` 均未知；gateway 明确记录 `openai embeddings failed` 于 session-start 与 search。
- 历史结论（修复前）：写入工具和持久化状态有证据，但向量索引 embedding 未通过；语义 `memory_search` 未通过。阻塞为 embedding 出口 transport error，需服务器网络/endpoint 可达性处理；在预算偏差审计和新授权前不得再运行真实调用。

## 已有服务器证据（历史记录，未在本轮重跑）

| 环节 | 已记录结果 | 边界 |
|---|---|---|
| OpenClaw→relay→Ark | 正常文本与唯一 add 往返成功，共 3 次 HTTP；无错误的 /api/v3/v1 | 不代表 memory 或研究实验完成 |
| 2026-09-11 合成 memory | 两次各 Victim 6 + embedding 5；read/write、跨会话 memory_get 返回 canary | memory_search 失败；embedding 的历史具体上游原因未确证 |
| 2026-09-14 direct embedding | HTTP 200，2048 维、非空有限向量、usage 可得 | 只证明当次 direct 请求 |
| 2026-09-14 proxy conversion | HTTP 200，2048 维，1 次上游 attempt | 只证明当次代理转换，不证明 OpenClaw 索引/搜索 |
| construction / mine / audit | 该 memory 批次未执行 | 不是 accepted=0，更不是成功采集 |
| formal evaluation | 未执行 | 缺少审计合格的正式冻结库及配对执行证据 |

历史目录由服务器保存，可能不随 Git 同步：
- `experiments/runs/memory-observation-20260911-a/`
- `experiments/runs/memory-observation-20260911-b/`
- `experiments/runs/memory-embedding-chain-20260914-030258/`

缺失目录标为无法复核，不能补造。错误观测缺陷已经修复，不等于历史检索失败根因已经确定。

## 仍保留的工程约束

- Ark Victim 为 `ep-20260909180104-hmx9m`；Attacker/Planner 使用 gpt-5.6-sol；embedding 使用独立变量，不混用凭证。
- 新输出统一 `experiments/runs/<run-id>/`，保留 runtime config、差异/hash、版本、请求 ledger。
- 消息投递只支持 `safeclaw_user_message`；新会话是 lifecycle action，local sink 是效果目标，不冒充 delivery surface。
- 工具范围与本地执行限制一致；Victim 无直接上游出口，外部请求经认证、预算控制与 ledger。
- recall 必须由真实工具结果和来源支持。memory_get、纯关键词 fallback、模型回答不能替代语义 memory_search。
- 只有通过质量、来源、依赖与相应 eligibility 检查的样本才能进入对应实验，usable 不等于 formal_attack_primary。

## 下一步

当前单条准入未通过；本批虽 accepted=1/audit passed，仍缺完整轨迹、真实跨 session 后续使用及可核验 session identity。后续任何真实运行需新授权，不自动追加或启动 pilot。


## 本轮独立 embedding relay 闭环（2026-09-14）

- `a11f5cce-safety.patch` 已删除 Victim 内启动旧 Ark adapter 的路径；若未先由 relay 注入内部配置，`_apply_model_config` 以 `embedding_adapter_must_run_in_provider_relay` fail-closed。标准 `git apply --check` 对 pinned upstream 通过。
- `ContainerProviderRelay` 继续负责唯一 embedding adapter 进程：relay 容器连接可出网 bridge，Victim 仅连接 `--internal` 网络；启动顺序为网络/容器、chat relay、embedding relay、双健康检查后才向 Victim 注入内部 URL 和随机 ingress token。上游 embedding key 只留在 relay runtime；非 Ark embedding provider 现在显式拒绝，避免把 raw key 交给 Victim。construction bridge 同时移除 Victim-local ledger fallback，缺 relay 时显式失败。
- embedding/provider relay ledger 增加持久 batch ID、跨重启序号和原子预占；预占在实际上游调用前 `fsync`，因此崩溃或发送结果不确定时保守计费。账本 lock 文件拒绝重复实例；账本损坏、不可读或写入失败均 fail-closed。预算拒绝行不访问上游，隐藏重试无法绕过出口。
- 补充了 mock 跨重启预算、超额拒绝、损坏账本和生命周期检查；未调用真实模型 API，未运行 collection/construction/pilot/mining/freeze/evaluation。

## 本轮验证结果

- `make check PYTHON=.venv/bin/python`：`194 passed`；ruff format/check、mypy（68 source files）、Python 编译和 `git diff --check` 通过。
- 专项 `test_ark_embedding_proxy.py`、`test_provider_relay.py`、`test_safeclaw_formal_bridge.py`：`36 passed`；pinned patch 单元测试已更新为验证旧 Victim adapter 路径被拒绝。
- 仅做离线/mock socket 与本地文件验证；没有真实上游请求。当前工作树仍有未提交修改，按要求未 commit/push。

## 下一轮有限真实测试条件

具备条件：拓扑、内部认证、上游凭证隔离、预算持久化和健康检查代码闭环，且离线质量门全绿。仍需在服务器上由用户明确授权一个新的有限批次，并先确认 Docker 网络权限、relay 上游 endpoint/allowlist 可达、持久 ledger 路径可写且无残留 lock；本轮不自行启动真实 embedding 或 memory_search。


## 2026-09-14 真实 memory relay 诊断（本轮授权）

- 预检通过：无运行中的 SafeClaw/Victim/relay 或 CLI 子进程；旧 tmux 仅为已完成 shell。Docker 可用，镜像 `openclaw-env:2026.3.12` digest 为 `sha256:3f0d4246a528d64d3b97c1a5b708200668d8362d7a3c4d9d65c5b2a8935dee99`，pinned upstream 为 `a11f5cceaba0676be721021f8d232638fd111305`，Ark endpoint DNS 可解析。历史空 lock 文件仍保留，未盲删。
- 唯一新 run：`experiments/runs/memory-relay-diagnostic-20260914-100746-956a0bca/`，batch ID `ed1641292c5744ff8e55243d8ef0089f`。运行在真实请求前的 `apply_model_config` 阶段 fail-closed：relay 注入 Victim 的内部 embedding 配置缺少 `embedding_provider`/`embedding_model`，触发 `incomplete_embedding_model_config`。
- 因此 A（relay embedding probe）、B（Victim 内部 embedding probe）、C（完整合成 memory）均未执行；Embedding 实际请求 `0/12`，Victim 实际请求 `0/8`，合计 `0/20`。没有自动重试，没有新增 batch，没有真实 provider 响应或索引证据。
- 已完成最小离线修复：relay `start()` 回填内部 `embedding_provider=openai` 与 `embedding_model`，保留内部 URL/ingress token；同时保留本轮统一 batch ID、A→B→C gate 和脱敏 run metadata。修复后 `make check PYTHON=.venv/bin/python` 为 `194 passed`，ruff/mypy/format 全部通过。
- 运行产物已扫描：未发现 `SAFECLAW_API_KEY`、`SAFECLAW_EMBEDDING_API_KEY` 或 Authorization literal；失败后容器/relay 已清理。不得把本轮标记为真实 embedding 或 memory_search 通过。


## 2026-09-14 修复后真实 memory 链路通过

- 修复后 run：`experiments/runs/memory-relay-diagnostic-20260914-104102-8a963628/`，batch `a7ad7fbd85924068a42eb09d5b4bc0fb`。A relay probe 和 B Victim-internal probe 均 HTTP 200，2048 维、finite/non-empty，usage `prompt_tokens=27,total_tokens=27`；A/B 共记录两次真实 embedding attempts，之后才执行 C。
- C 真实合成场景通过：写入 `MEMORY.md`，跨会话新 session 的 `memory_search` 返回非空 `results`，命中 `MEMORY.md#L1`，包含本轮 cobalt-lantern 事实和随机 canary；结果 `mode=hybrid`、`provider=openai`、model 有值，且索引/查询 embedding ledger 共 4 次成功 upstream attempts。查询 arguments 不含 canary 答案。
- source event 证据已按实际 bridge→driver 路径核对：`provider_tool_call_id`、`request_event_id`、request/result `openclaw-session-entry` refs、result hash 和 result excerpt 均成对存在；多次工具调用未按名称覆盖。`memory_get` 仅作为辅助证据，不替代 memory_search。
- 本轮真实请求合计：失败的首次修复复测 Embedding 2（上游 401，Victim 0；当时旧控制流也调用了 B，已在离线代码中收紧 A→B gate）；最终通过 run Embedding 4、Victim 6。累计 Embedding 6、Victim 6，未运行其他实验流程。
- 真实 401 根因是 adapter 上游 Authorization 错用了内部 ingress token；已修复为 relay 内保管的 embedding upstream key，内部 ingress token 仍只用于 Victim→relay。probe 解析已修复为严格检查 OpenAI-compatible `data[]`。Docker 外层 probe timeout 与内部 HTTP timeout 分离；relay ledger 改用 named volume，容器 rm 后保留账本，损坏 JSONL 读取 fail-closed。
- 通过 run 产物未发现 API key 或 Authorization header；真实资源已清理，证据 volume 保留以避免丢失审计记录。


## 2026-09-14 usage 可观测性修复与复测

- 根因：`relay_runtime_from_model_config()` 未传递 `provider_compat=ark`，且 bridge/source event 未保留 provider usage 选择结果；gateway 返回全零 usage。
- 修复：provider relay 解析非流式 JSON 与 SSE 最终 usage-only chunk；仅 Ark 请求启用 `stream_options.include_usage=true`，Gemini 保持 `supportsUsageInStreaming=false`；relay runtime 传递 provider compatibility；bridge 按 action ledger 游标聚合多次 provider 请求并保留完整性、来源、已知小计和缺失/失败计数；source events 保留 provider/gateway usage。
- 受影响回归及全量质量门通过；最终复测 run `experiments/runs/construction-usage-retest-20260914-123000-e7f4a2/` 中 Victim provider 6/6 usage 完整，总计 input 43798、output 1528、total 45326。gateway usage 保留为 missing/invalid zero，不作为 token 依据。
- 最终 construction 因配置 token budget 24000 被真实累计 45326 tokens 触发保护，未进入后续 lifecycle/effect；不是 usage 不可观测。
