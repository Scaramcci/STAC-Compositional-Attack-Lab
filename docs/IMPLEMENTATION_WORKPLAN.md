# Implementation Workplan

更新时间：2026-09-14。当前证据和本地测试限制见 [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md)；memory relay 已通过，usage 可观测性已修复并完成 256k 预算单条 construction 校准。仅保留一套执行顺序。

## 2026-09-14 256k 预算校准结果

独立派生 run `construction-budget-calibration-20260914-130000-f2a9c7`（`pse-2.1-002 × 20260827`）仅提高 `max_tokens` 至 256000，完成 8 actions/turns、1 session、16 tool calls；24 次 Victim provider requests usage 全部完整（224217 input、6095 output、230312 total），Attacker 9 次（31842 total），Embedding 1 次。既定 `max_turns=8` 触发 `construction_turn_budget_exhausted`，trajectory 为 partial；不是 usage 观测失败。normalization→mine→audit 实际执行，结果 1 candidate/0 accepted/1 negative，audit 因 accepted target 0/1 失败。工程执行完整性通过，样本合格性不通过；official outcome 保持 `not_evaluated`。未启动 canonical pilot，仍需完整 accepted 样本及 lifecycle/cross-session 覆盖后再准入。

## 1. 同步与离线复核

- 同步冲突合并修复，检查 Git diff 与冲突标记；不能以 git status 干净代替源码内容检查。
- 使用服务器实际 stac 解释器运行专项测试和 make check，验证 pinned upstream 用例，记录 commit、解释器及通过/失败/skip。
- 重点验证 embedding 的预算预扣、accepted 行计数、错误汇总不重复扣费、无效向量不漏计，以及本地 400/真实上游状态分离；usage 观测现已扩展到 Ark chat relay→bridge→driver。
- 保留线程锁、跨 run 的 driver 预算契约和结构化观测，不能简单选取某个冲突分支覆盖。
- 不重复已有效的 direct chat/embedding 探针来代替索引诊断。

## 2. 隔离索引与语义 memory_search 验证（已完成）

direct embedding、代理转换及 OpenClaw 实际使用链均已有修复后成功证据；本阶段已完成，不能用历史失败记录覆盖当前结论。

- 独立 workspace/session/index，放入少量合成事实与独特 canary；不读取真实用户文档。
- 检查索引确实完成、索引分片/查询 embedding 的实际上游请求成功、维度和模型一致。
- 以语义相关但不包含 canary 答案的查询运行 memory_search；新会话不能通过对话历史直接知道答案。
- 断言返回片段对应本次写入的事实，带正确来源路径/范围、结果 hash 和 call ID。
- 区分向量搜索、关键词 fallback、memory_get、错误及 unknown。仅工具返回非空不等于通过。
- 保留真实工具调用/结果、索引证据、请求阶段和关联 ID；不要从文件存在或模型回复推断 recall。
- 必要时做最小 instrumentation 修复和回归；真实错误按 upstream 状态分类，不直接归咎配额或 Victim 限流。
- 历史结果（已保留）：索引写入和跨会话 memory_get 有证据；语义 `memory_search` 曾返回 disabled/unavailable（embedding transport_error），因此当时第 2 步未通过。修复后真实 run `memory-relay-diagnostic-20260914-104102-8a963628` 已通过第 2 步；历史误重复运行的超预算产物仍保留，不作为当前通过依据。

验收：索引与真实语义搜索均有证据；当前已由上述修复后 run 满足。缺少 frozen library 不阻止本步骤。

## 3. 单条 construction（本轮已完成）

第 2 步已通过；本轮已运行 1 task × 1 seed 的有限 construction，使用 canonical pilot 派生配置和唯一目录。usage 复测已证明 provider relay usage 可完整支撑 action token_count；最终 attempt 因真实 token budget guard 为 partial。
验证 lifecycle、provider/embedding 跨运行累计预算、脱敏、raw/source events/checkpoints 完整。
对本轮 raw 显式 normalize/mine/audit，分开报告质量、行为、官方结果及 eligibility；最终 attempt 的 token usage 完整，但因真实 token budget guard 为 partial，未进入后续 lifecycle。

## 4. Pilot、main 与冻结（逐阶段准入）

- 单条闭环证据经审查并获准后，运行 canonical 8 条 pilot，保留 complete/partial/error 和所有失败分母。
- pilot 目标至少 2 个 accepted；不足时报告证据缺口，不用 fixture/旧库补量，不降低真实性门。
- pilot 通过且规模获准后运行 main，目标至少 30 个 accepted；数量不能代替来源隔离、拓扑覆盖与正式条件 eligibility。
- 审计合格后冻结新的 main library 到正式配置指定位置，记录 immutable manifest/tree hash。
- schema/hash/任务划分等变化需新版本和派生目录，不改写旧原始证据。

## 5. Formal matrix 与报告

仅在对应 frozen library、eligibility、binding、模型和预算门通过后，执行已确认的 task/condition/seed matrix；现有计划为 1 task × 3 conditions × 5 seeds，启动前核对真实配置。
完整保存 matched pairs、Planner/独立 Attacker journals、官方与机制 verdict、错误与拒绝。
运行 audit-run/report，提供可复算命令和教师阅读入口。不把诊断成功当作攻击/机制成功。

## 停止与权限边界

- 本计划不是新一轮真实调用授权；实际批次须指定请求总数、各角色上限、墙钟、重试和输出目录。
- 凭证泄漏、预算无法证明、容器所有权不清、端口冲突时停止相关运行并诊断。
- frozen library 缺失只阻止依赖它的 formal 步骤，不阻止第 2、3 步。
- 正常检索失败不触发无限重试或自动更换模型。具体账户/权限问题交给用户处理，其他可独立离线工作继续。
- 更新唯一当前状态；历史测试与当前验证分开。未经要求不 commit/push，不恢复已清理的历史数据。


## 本轮完成记录（2026-09-14）

第 1 步已完成：safety patch 可应用于 pinned upstream，Victim 内旧 adapter 路径改为显式拒绝；独立 relay 负责 embedding，Victim 无上游 embedding key 和直接公网接口。第 2 步的离线部分已完成：provider/embedding relay 使用持久 ledger、batch ID、单实例锁和 crash-conservative 原子预占，损坏/写入失败 fail-closed；所有实际上游 attempts 在预算内计费。`make check` 为 194 passed，未调用真实模型 API。

历史记录（2026-09-14，已完成）：此前曾需用户新授权后检查 Docker 网络实际隔离、relay endpoint allowlist 和持久 ledger 权限；该授权及修复后验证已完成，不再作为当前下一步。


## 本轮真实诊断结果（2026-09-14）

A/B/C 未执行。唯一 run 在真实请求前的 pinned judge 配置阶段因 relay 注入字段不完整而 fail-closed；实际请求计数为 Embedding 0/12、Victim 0/8、合计 0/20。最小代码修复已完成并通过 `make check`（194 passed），但按授权边界不自动复测。下一次需要新的明确真实调用授权，先复核修复后的 relay→Victim 配置，再按 A→B→C 顺序执行。


## 修复后真实诊断结果（2026-09-14）

A/B/C 已通过：relay/Victim embedding 均成功，向量索引建立，跨会话 `memory_search` 返回本轮事实的非空 hybrid 结果，具备 call/result/source/hash 证据。首次修复复测的 401 根因已修复；诊断脚本现在严格 A 成功后才调用 B、A/B 成功后才进入 C。最终通过 run 的 Embedding 4、Victim 6；含首次 401 失败 run 合计 Embedding 6、Victim 6。未运行 construction、pilot、main collection、mining、freeze 或 evaluation。

最小 construction 已在独立授权下完成（2026-09-14）；本轮不自动推进 canonical pilot。


## 2026-09-14 usage 可观测性修复复测记录

Ark 真实 SSE 探针返回 `[DONE]` 前的 usage-only chunk，完整 usage 为 `prompt_tokens=39, completion_tokens=33, total_tokens=72`；最终 construction run `construction-usage-retest-20260914-123000-e7f4a2` 的 6 次 Victim provider attempts 全部解析成功。未运行 canonical pilot、main collection、freeze 或 evaluation。
