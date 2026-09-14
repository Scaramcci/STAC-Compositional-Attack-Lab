# Implementation Progress

更新时间：2026-09-14；本轮代码基线：`e0354e6`。服务器 pinned upstream 为 `a11f5cceaba0676be721021f8d232638fd111305`。

## 当前结论

- 已合并 `ark_embedding_proxy.py` 和工作计划中的遗留冲突，保留预算控制与结构化错误观测两边的必要实现。
- direct embedding 与代理转换已有历史成功证据。本轮完成一次隔离索引/语义检索验证及一次最小修复后复测；索引写入成功，但语义 `memory_search` 因 embedding 上游 transport error 不可用，未通过。
- 当前阻塞：等待 embedding 出口 transport error 的服务器网络/endpoint 处理；处理后需获得新授权再复核语义检索。不得跳到 construction 或完整 pilot。
- frozen primitive library 尚缺失，只阻止依赖该库的正式评测；不阻止独立 memory 验证或 construction。不能形成“先有冻结库才能采集”的循环。

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

## 本轮隔离索引与语义检索证据

- 本轮运行产物：`experiments/runs/memory-semantic-20260914-063121/`、误重复的 `experiments/runs/memory-semantic-20260914-063200/`、修复后复测 `experiments/runs/memory-semantic-retest-20260914-063920/`；均使用独立 run/workspace/container/network、合成 task 和新会话。
- 每个完整运行均观察到索引写入和跨会话生命周期；每次 Victim 6、embedding 2。因误重复启动一次，本轮累计 Victim 18、embedding 6、合计 24，超出本轮 Victim≤8 与合计≤20 授权；已停止所有后续真实调用。写入事实含 cobalt lantern archive handoff 与独特 token。
- 复测 `memory_search` 实际 call ID `call_jeju6lo7hsfv7l873nv84cro`，请求/结果证据 `openclaw-session-entry:80cf753b` / `openclaw-session-entry:6f48f311`，结果 hash `60be6c37d27ef9d062fb1ed76db2beefc9a4324d8a41f627e5745989d380255e`；返回 `results:[]`, `disabled:true`, `unavailable:true`，不是关键词 fallback。
- 同批 `memory_get` 返回 `MEMORY.md`（结果 hash `5676aae89c052aaec7c7abdaae67ce69ffb220cd2b0e4680c77d3e5fe966adf8`），仅作为写入/持久化证据，不能替代语义检索。
- embedding ledger 脱敏记录两条 `transport_error`，local proxy 400，`upstream_http_status/request_id` 均未知；gateway 明确记录 `openai embeddings failed` 于 session-start 与 search。
- 结论：写入工具和持久化状态有证据，但向量索引 embedding 未通过；语义 `memory_search` 未通过。阻塞为 embedding 出口 transport error，需服务器网络/endpoint 可达性处理；在预算偏差审计和新授权前不得再运行真实调用。

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

- Ark Victim 为 `ep-20260909180104-hmx9m`；Attacker/Planner 仍为 gpt-5.5；embedding 使用独立变量，不混用凭证。
- 新输出统一 `experiments/runs/<run-id>/`，保留 runtime config、差异/hash、版本、请求 ledger。
- 消息投递只支持 `safeclaw_user_message`；新会话是 lifecycle action，local sink 是效果目标，不冒充 delivery surface。
- 工具范围与本地执行限制一致；Victim 无直接上游出口，外部请求经认证、预算控制与 ledger。
- recall 必须由真实工具结果和来源支持。memory_get、纯关键词 fallback、模型回答不能替代语义 memory_search。
- 只有通过质量、来源、依赖与相应 eligibility 检查的样本才能进入对应实验，usable 不等于 formal_attack_primary。

## 下一步

按 [IMPLEMENTATION_WORKPLAN.md](IMPLEMENTATION_WORKPLAN.md) 的第 1、2 步推进。对新写入合成事实使用不给出答案的语义查询，确认索引、向量调用、命中片段、来源和 call/result 配对。服务器真实验证须有新批次范围和预算，不从文档自动推断无限授权。


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
