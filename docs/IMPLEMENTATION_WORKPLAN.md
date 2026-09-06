# Implementation workplan

Updated: 2026-09-06

依据：`EXPERIMENT_ALIGNMENT_AND_REPAIR_PLAN_ZH.md`。本文件是执行计划，不是完成声明。
基线 HEAD：`05afd4b9b4e4b38f928aa306cde1afe91fd586ef`；初始工作区干净。
SafeClawArena：`a11f5cceaba0676be721021f8d232638fd111305`，已核对。

## 范围与迁移约定

仅在授权、隔离 SafeClawArena 中采集和评测。sample 可用性、行为结果、官方攻击结果独立；计划路径与实际观测独立。保留 collection/extraction 内部分层。
旧 raw、运行目录、冻结库和 .env 不覆盖；协议变更使用 v3 新写和新派生目录，记录源文件 hash 与解析器版本。旧数据只读，缺失事实标 unknown，不补造 lineage/recall。新旧语义不得无标识混库。
模型角色暂保留版本化默认值；后续独立映射服务和凭证环境变量，不把 SharesAI 的模型配置与 Gemini 混用。

## 文件级任务与验收

所有源码相对于 `src/stac_attack_lab/`，bridge 相对于 `integrations/safeclaw/`。状态仅使用 pending / in_progress / blocked / verified。

| 任务 | 状态 | 文件级工作 | 依赖 | 验收与迁移 |
|---|---|---|---|---|
| W00 | in_progress | 本文件、IMPLEMENTATION_PROGRESS.md；新增历史诊断文档；tests/unit/test_adversarial_collection_runtime.py 增加真实 driver 的模拟 bridge 回归 | 无 | 记录历史原始产物搜索范围、阶段/gate 原因，区分历史/复现/假设；无数据不得编造统计 |
| W01 | pending | docs/EXPERIMENT_DESIGN_V3.md；interactions/models.py、datasets/primitive_chain.py、contracts.py、schemas/、configs/primitives/registry.yaml | W00 | observed prefix、blocked、missing evidence 独立表达；版本化双读/新写，旧库不重新贴标签 |
| W02 | pending | interactions/safeclaw_collection.py、collector.py、construction.py、models.py；recording/；construction_bridge.py、formal_bridge.py | W01 | 每动作持久化与崩溃恢复；真实 session/call ID；无 read 不生成 recall；等长和子目录变更可见；deadline、usage unknown、错误不冒充 stop；新 observation 协议 |
| W03 | pending | interactions/normalizer.py；extraction/occurrences.py、chains.py、filtering.py；datasets/chain_builder.py、library.py；execution/sample_generation.py；cli.py | W02 | observed subpaths 与必要 DAG 前驱；局部缺失隔离；独立 outcome；确定性重算；episode/sample/topology 分开统计；collect 自动 extraction 入口；新派生版本保留源 hash |
| W04 | pending | environments/safeclaw/task_adapter.py、materializer.py；两 bridge；configs/task_sets/；interactions/construction.py；cli.py | W01,W02 | 字段级允许注入面、保留合法任务及官方字段 hash；PSE 和另一类有限覆盖；人提交动作同样校验记录；不支持明确拒绝 |
| W05 | pending | planning/formal_llm.py、formal_baselines.py、binding_planner.py；prompts/formal/trajectory_planner.md | W03,W04 | 两种 sample 在同任务有可追踪映射差异；无 first-component fallback；能力约束；记录 LLM/fallback 及失败 |
| W06 | pending | execution/formal_attacker.py、formal_action_loop.py、safeclaw_formal.py；planning/formal_baselines.py；configs/models/、experiments/；prompts/formal/ | W05 | 无 sample 仍同模型/目标/预算/注入面生成执行攻击；一次动作允许多个 observed primitive；ablation 从冻结 treatment 派生且检查实际请求 |
| W07 | pending | verification/occurrence.py、edges.py、safeclaw_official.py、formal_aggregate.py；reporting/formal_metrics.py、formal_report.py、statistics.py；两 bridge | W02,W04,W06 | pinned evaluator 实际状态验证；官方与机制结果分开；错误、拒绝、机制未知分别报告；明确分母与 task 聚类 |
| W08 | in_progress | environments/safeclaw/model_config.py、ark_embedding_proxy.py、preflight.py；execution/sample_preflight.py；safety patch；tests/unit/test_safeclaw_embedding_config.py、test_ark_embedding_proxy.py | W00 | patch 不改官方判定；源码已追踪；镜像/模型/维度/适配源码 hash 纳入 fingerprint；宿主、容器、真实 OpenClaw indexing/search 分别验证 |
| W09 | pending | 新 experiments/ 与 generated/v3 派生目录；小规模专用配置；诊断记录 | W02-W04,W08；主比较另需 W05-W07 | 先正常/阻断一条，再授权攻击一条；检查 raw→graph→sample；零可用即诊断停止扩量；不覆盖历史，不把 synthetic 当真实 |
| W10 | pending | README.md；docs/EXPERIMENT_PROTOCOL.md、PROMPTS.md、PROJECT_GUIDE_ZH.md、LINUX_TMUX_RUNBOOK_ZH.md；configs/README.md、schemas/；本规划和进度 | 前述验证或如实列未完成 | 文档与实际可运行范围一致；交接命令、证据和限制完整；不声称单测通过即完整实验成功 |

## 执行规则

每批先缺陷回归再实现，验证后立即追加进度。长任务启动前记录 run ID、命令、日志、PID/tmux、预算及终止条件。恢复先读规划/进度/Git diff，再查进程，不能重复启动计费任务。
未解决假设：历史失败日志是否存在于不可读目录；实际 OpenClaw 工具日志完整性；PSE 原固定 payload 与官方 regex 的可替换边界；容器模型网络和 memory search 兼容性。以上不能由 synthetic 测试推断为已通过。
