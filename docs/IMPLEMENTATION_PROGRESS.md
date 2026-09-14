# Implementation Progress

基线：Git HEAD `4456194ae8e98c0ced43975aa4f4c8cca672f946`；整理前工作区干净。执行日期：2026-09-10。

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

### Embedding 链路专项诊断（2026-09-14）

仓库当前没有 `experiments/runs/memory-observation-20260911-a/` 或 `-b/`；因此无法从本地复核用户所述两次运行的 embedding ledger、代理日志、OpenClaw tool result 和时间线。现有代码证据显示，旧代理只返回 `ark_upstream_http_error`/`ark_embedding_failed`，未分别保留上游 HTTP 状态、provider code、request ID、Retry-After 与耗时，且错误分类可能把 gateway/provider 故障投影得过粗。

本轮对 `ark_embedding_proxy.py` 做了最小观测修复：上游 HTTP 401/403、404、429、其他 HTTP、超时、传输错误、非 JSON 和向量 schema 错误分别分类；错误正文只保留长度/hash，provider code 采用白名单字符和长度限制，message 使用固定安全类别；记录 `upstream_http_status`、`local_proxy_status`、`endpoint_path`、`stage`、`association_id`、`request_id`、`retry_after`、attempt 数和耗时。认证头、API key、请求文本、完整 URL 不写盘。

回归：`tests/unit/test_ark_embedding_proxy.py` 与观察分类共 31 项通过（随后单文件 23 项通过）。

受控 direct 验证（合成文本，1 次 embedding 上游 HTTP）成功：HTTP 200、`/embeddings/multimodal`、维度 2048、向量非空且有限、usage 可得；request ID 已脱敏保存在 `experiments/runs/memory-embedding-chain-20260914-030258/direct_embedding.json`。代理转换验证（再 1 次 embedding 上游 HTTP）成功：本地 `/v1/embeddings` 返回 200，转换维度 2048；ledger 在 `.../proxy_embedding_ledger.jsonl` 中记录上游/本地状态和 `upstream_attempt_count=1`。

本轮未启动索引或 memory_search，未运行 collection/mining/freeze/formal evaluation；因此索引完成和语义检索仍为 unknown，不能报告 recall 或 accepted 数。未调用 Victim、Attacker 或 Planner。

`data/primitive_libraries/frozen/safeclaw-main` 尚不存在。因而 main sample gate 与 formal matrix 尚未运行，不能报告 accepted sample、ASR、迁移性、机制成功率或官方 paired effect。正式入口应在首个 Victim episode 前 fail closed。

实际 gate probe 返回 `primitive_library_audit_failed:missing_library_manifest`（exit 2），未创建 case、未启动 Victim、未发 provider 请求，符合该前置条件。
