# Implementation Progress

基线：Git HEAD `4456194ae8e98c0ced43975aa4f4c8cca672f946`；整理前工作区干净。最近执行日期：2026-09-11。

## 已实施

- 将所有新生成输出统一到忽略的 `experiments/runs/<run-id>/`，launcher 使用显式或 UUID run ID；删除日期化 retry/smoke 配置、固定容器名诊断和旧实验输出。完整清单及恢复方式见 [CLEANUP_MANIFEST.md](CLEANUP_MANIFEST.md)。
- 保留 benchmark 原始任务、task split、primitive registry、schemas、最小脱敏 fixtures、pinned SafeClawArena、官方 evaluator、许可证和来源说明。
- 唯一 Victim 环境配置为 `configs/environments/safeclaw.yaml`：Ark endpoint `ep-20260909180104-hmx9m`、API root `/api/v3`、1024 max output；Planner/Attacker 仍为 `gpt-5.5`，embedding 仍使用独立变量。
- 修复 pinned safety patch 的 API root 处理：明确的 `/api/v3`、`/v1`、`/openai` 原样传递，只追加 Chat Completions resource；未使用全局字符串替换。
- 增加独立 sibling provider relay。Victim 只获得一次性 relay token；真实 Ark key 只进入 relay。relay 覆盖 OpenClaw 实际 HTTP、无内部重试、执行硬请求上限、过滤最终工具数组并写入不含请求正文/key 的 ledger。
- OpenClaw 配置禁用 browser；gateway 动态发布到宿主 loopback，固定端口冲突直接失败；Victim、relay 和网络均按 UUID 命名并由所属 bridge 清理。
- bridge 的 finish/step 记录 provider ledger；即使 relay 在 runner 初始化前失败，也会删除已启动 Victim。新增 URL、过滤、预算、SSE/错误转发与 bridge 配置回归。
- 统一诊断入口为 `scripts/diagnostics/run_openclaw_diagnostics.py`，覆盖 offline 和受控 live 两种模式。
- canonical pilot `--preflight-only` 在真实 `.env`、pinned commit、patch、Docker image 和磁盘条件下通过；`execution_started=false`。Collection launcher 现在要求/生成唯一 run ID，并将输出隔离为 `experiments/runs/<run-id>/<library-version>/`。

## 实际验证

离线 OpenClaw `2026.3.12` → relay → mock 在 Docker internal network 中通过：

- OpenClaw 最终发送的工具严格为 `[add]`，没有 20 个内置工具泄漏；
- SSE 中分片的 `{"a":2,"b":3}` 被正确合并；call ID 保持一致；本地结果 `5` 被回送；插件恰好执行一次；
- 错误 tool result 返回 400，不固定伪造成功；
- relay 观察到 3 个真实上游 HTTP 请求，第 4 个尝试在上游前以 429 拒绝；ledger 为 `true,true,true,false`；
- 验证路径是 `/v1/chat/completions`，无双 `/v1`；容器和网络在成功后清理。

真实 OpenClaw → relay → Ark 也通过，共 3 次 provider HTTP，无重试：

- 无工具文本：1 次请求，HTTP 200，最终文本 `ARK_TEXT_OK`，provider 工具列表为空；
- 唯一 `add` 往返：2 次请求，均 HTTP 200，唯一工具为 `add`，参数 `2,3`，相同 tool call 流程回传结果 `5`，本地恰好执行一次，最终回答包含 `5`；
- 三个 ledger 路径均为 `/api/v3/chat/completions`，证实没有错误的 `/api/v3/v1`；
- gateway 返回 usage 全零，不能证明 provider usage，因此按契约记为 `unknown`。

这只是协议与生命周期验证，不是 collection、攻击 payload 或 formal evaluation。未调用 Attacker、Planner 或 embedding。

## 当前状态与阻塞

`data/primitive_libraries/frozen/safeclaw-main` 尚不存在。因而 main sample gate 与 formal matrix 尚未运行，不能报告 accepted sample、ASR、迁移性、机制成功率或官方 paired effect。正式入口应在首个 Victim episode 前 fail closed。

实际 gate probe 返回 `primitive_library_audit_failed:missing_library_manifest`（exit 2），未创建 case、未启动 Victim、未发 provider 请求，符合该前置条件。

## 2026-09-11 采集一致性与有限验证

- pilot/main 以及 construction task set 的实际消息投递面收敛为唯一已实现的 `safeclaw_user_message`。`start_new_session` 继续作为独立 lifecycle action；`safeclaw_local_action_sink` 继续作为隔离容器内的组件/效果目标，不再伪装成 delivery surface。preflight 会在任何付费调用前拒绝额外 surface 或空/不匹配工具范围。
- construction 的 provider 与 OpenClaw 本地工具范围均固定为 `read,write,edit,exec,memory_search,memory_get`。`exec` 仍只能作用于无宿主挂载的 Victim；relay 网络改为 internal，Victim 的默认 bridge egress 被移除，只有带认证、ledger 和硬预算的 relay 容器拥有上游出口。
- provider 请求预算明确为整个 collection run；driver 跨 trajectory 累积已接受请求，不因重建 relay 或新会话重置。Ark embedding proxy 增加独立硬预算、无正文/凭证 ledger 和 90 秒以内超时；对 upstream 429/5xx 返回本地非重试错误，阻止 pinned OpenClaw 的四次自动 embedding 重试。上游原始类别仍保存在 ledger。
- bridge 现在解析 pinned OpenClaw session JSONL 的 `toolCall`/`toolResult`，保留 call ID、工具名、参数/result hash、请求/结果 entry evidence ref，并生成配对 tool-result event。只有 `memory_search`/`memory_get` 的真实结果可产生 retrieval；文件存在、模型文字、空结果、`disabled/unavailable/error` 都不能证明 recall。拒绝、错误、未返回、未发生和不可观测分别表达。
- launcher 将 canonical 配置派生文件和 derivation metadata（源/运行时 SHA-256 与唯一 `output_root` 差异）保存在 `experiments/runs/<run-id>/`，不再使用执行后删除的临时配置。

服务器质量门：沙箱内 5 个 loopback 测试因 `PermissionError` 失败；同一 `conda` `stac` 解释器在服务器常规权限下为 `176 passed`，ruff format/check 与 mypy 均通过。pinned upstream PSE/CDF 用例实际执行，没有 skip；Mac 记录的 upstream 缺失是环境差异，不是当前代码失败。

canonical preflight 位于 `experiments/runs/preflight-20260911-surface-observation/`，全部检查通过，`execution_started=false`，真实请求 0。

合成普通写入/检索只执行两次（初始 + 一次明确修复后的复测）：

- 初始 `experiments/runs/memory-observation-20260911-a/`：Victim 6、embedding 5，共 11 次。真实 `read`/`write` 与跨会话 `memory_get` 返回 canary；`memory_search` 明确返回 `disabled/unavailable`，旧判定曾误报 passed，已由同目录 `diagnostic_reassessment.json` 明确覆核为 failed。
- 复测 `experiments/runs/memory-observation-20260911-b/`：Victim 6、embedding 5，共 11 次。错误分类已正确，`memory_search_result_observed=false`，gateway 明确记录 embedding 重试后失败；`memory_get` 仍返回 canary，不能替代索引/语义搜索通过。第二 victim step 因该日志分类为 `victim_rate_limited`。
- 本批真实上游 HTTP 合计 22/40；provider/gateway usage 均未可靠报告，usage 保持 `unknown`。产物脱敏扫描未发现 Authorization/Bearer/key，所属容器与网络均已清理。

由于 A 的索引/`memory_search` 必要观测链未通过，按授权顺序没有启动 construction collection，也没有调用 gpt-5.5 Attacker。因此没有本轮 raw 可供 normalize/mine/audit；不是 accepted=0，而是 collection 未执行。未使用第三次合成尝试、未提高预算、未更换模型/供应商，也未启动 pilot/main、freeze 或 formal matrix。
