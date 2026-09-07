# Implementation workplan

Updated: 2026-09-07 (retry18 continuation)

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
| W00 | verified | 本文件、IMPLEMENTATION_PROGRESS.md；历史产物与失败原因盘点；runtime 回归 | 无 | 历史证据、当前复现与假设已分开记录 |
| W01 | verified_for_retry18 | docs/EXPERIMENT_DESIGN_V3.md；interactions/models.py、datasets/primitive_chain.py、contracts.py、schemas/、configs/primitives/registry.yaml | W00 | v3 sample schema/acquisition enum 已完成；独立 status fields 与完整新输出目录仍待贯通 |
| W02 | verified_for_retry18 | interactions/safeclaw_collection.py、collector.py、construction.py、models.py；recording/；construction_bridge.py、formal_bridge.py | W01 | 已完成 partial observation 保留、无证据不生成 recall；bridge retrieval 协议与真实 session/call ID 仍待完善 |
| W03 | verified_for_retry18 | interactions/normalizer.py；extraction/occurrences.py、chains.py、filtering.py；datasets/chain_builder.py、library.py；execution/sample_generation.py；cli.py | W02 | 已完成 observed admission 解耦与 `sample collect-and-mine` 入口；DAG 前驱/版本化 v3 产物仍待完善 |
| W04 | pending | environments/safeclaw/task_adapter.py、materializer.py；两 bridge；configs/task_sets/；interactions/construction.py；cli.py | W01,W02 | 字段级允许注入面、保留合法任务及官方字段 hash；PSE 和另一类有限覆盖；人提交动作同样校验记录；不支持明确拒绝 |
| W05 | pending | planning/formal_llm.py、formal_baselines.py、binding_planner.py；prompts/formal/trajectory_planner.md | W03,W04 | 两种 sample 在同任务有可追踪映射差异；无 first-component fallback；能力约束；记录 LLM/fallback 及失败 |
| W06 | pending | execution/formal_attacker.py、formal_action_loop.py、safeclaw_formal.py；planning/formal_baselines.py；configs/models/、experiments/；prompts/formal/ | W05 | 无 sample 仍同模型/目标/预算/注入面生成执行攻击；一次动作允许多个 observed primitive；ablation 从冻结 treatment 派生且检查实际请求 |
| W07 | pending | verification/occurrence.py、edges.py、safeclaw_official.py、formal_aggregate.py；reporting/formal_metrics.py、formal_report.py、statistics.py；两 bridge | W02,W04,W06 | pinned evaluator 实际状态验证；官方与机制结果分开；错误、拒绝、机制未知分别报告；明确分母与 task 聚类 |
| W08 | verified_preflight | environments/safeclaw/model_config.py、ark_embedding_proxy.py、preflight.py；execution/sample_preflight.py；safety patch；tests/unit/test_safeclaw_embedding_config.py、test_ark_embedding_proxy.py；victim/attacker model env mapping | W00 | upstream/patch/model preflight 已通过，victim Gemini 与 attacker/planner SharesAI 已分离；Docker image、容器、真实 OpenClaw indexing/search 仍阻塞 |
| W09 | in_progress | 新 experiments/ 与 generated/v3 派生目录；小规模专用配置；诊断记录 | W02-W04,W08；主比较另需 W05-W07 | 先正常/阻断一条，再授权攻击一条；检查 raw→graph→sample；零可用即诊断停止扩量；不覆盖历史，不把 synthetic 当真实 |
| W10 | pending | README.md；docs/EXPERIMENT_PROTOCOL.md、PROMPTS.md、PROJECT_GUIDE_ZH.md、LINUX_TMUX_RUNBOOK_ZH.md；configs/README.md、schemas/；本规划和进度 | 前述验证或如实列未完成 | 文档与实际可运行范围一致；交接命令、证据和限制完整；不声称单测通过即完整实验成功 |

## 执行规则

每批先缺陷回归再实现，验证后立即追加进度。长任务启动前记录 run ID、命令、日志、PID/tmux、预算及终止条件。恢复先读规划/进度/Git diff，再查进程，不能重复启动计费任务。
未解决假设：历史失败日志是否存在于不可读目录；实际 OpenClaw 工具日志完整性；PSE 原固定 payload 与官方 regex 的可替换边界；容器模型网络和 memory search 兼容性。以上不能由 synthetic 测试推断为已通过。

## 本轮执行增量（2026-09-06）

| 阶段 | 状态 | 文件级任务 | 依赖 | 验收 |
|---|---|---|---|---|
| 第一阶段质量与采集闭环 | in_progress | `Makefile`/ruff、`interactions/safeclaw_collection.py` driver protocol、`interactions/models.py`/`datasets/primitive_chain.py` v3 契约、SafeClaw bridge、模型映射与 preflight、任务注入面 | W01-W04,W08 | `make check`、mypy、focused regression；新 v3 派生目录不改旧数据；容器/embedding 证据分层记录 |
| 第二阶段真实小采集 | pending | 新配置与 `experiments/safeclaw_v3_smoke/` 产物；raw→graph→occurrence→candidate→sample 诊断 | 第一阶段通过 | 一条正常/阻断和一条授权攻击，预算/停止条件固定；零 sample 则停扩量 |
| 第三阶段正式闭环 | pending | planner/attacker no-sample contract、ablation provenance、official/mechanism reporting | 第一、二阶段 | 同任务 treatment/no-sample smoke；官方 verdict 与 mechanism verdict 分离；不冻结库 |

## 持续执行目标（2026-09-06，Goal 01a07658-0c73-7fa3-b4d4-391c6bd0571f）

目标：持续执行本计划直到正式 SafeClawArena evaluation 形成可审计的端到端产物；过程中不得以单元测试、preflight、零样本或失败运行替代实验完成声明。

恢复顺序固定为：

1. 修复并验证 `apply_model_config` 失败：读取 retry5 脱敏 detail，核对 pinned safety patch 与 reset/model-config 输入；添加失败前回归测试，完成 `make check`。
2. 用全新 v3 输出目录重跑一条同预算 smoke；逐层核对 raw trajectory、source events、graph、occurrences、candidate、sample。任一必要证据缺失时停止扩量并记录 gate 原因。
3. 完成 W02-W04/W08：真实 tool/session/call/retrieval/artifact lineage 协议、任务和注入面适配、Ark/OpenClaw indexing/search 集成验证。
4. 完成 W03/W09 小规模 collection：正常/受阻交互与隔离攻击交互分别记录；保留 accepted/rejected 原因，确认 synthetic 与真实产物分离。
5. 完成 W05-W07：planner sample 绑定、同任务不同 sample 的计划差异、同模型同预算同注入面的 no-sample attack、ablation provenance、官方 evaluator 与 primitive verifier 分离。
6. 运行最小 treatment/no-sample 配对 smoke，确认端到端产物后，才允许启动大规模 collection/evaluation。大规模任务必须使用独立 run ID、配置 hash、日志、预算和停止条件；不覆盖旧目录，不冻结库，不输出密钥。
7. 大规模运行结束后生成正式报告，分别报告官方结果、机制结果、错误/拒绝/不可观测/失败、样本接受率和证据缺口，并回写本计划与进度文件。

大规模运行准入条件：`make check` 通过；固定镜像/上游/patch/hash 已记录；真实小规模 raw→sample 闭环通过；treatment/no-sample smoke 均实际执行；关键产物可回溯；无未解释的启动或协议失败。若条件不满足，只继续修复和小规模验证，不启动计费大实验。

每次续接先执行：读取本文件和进度文件、`git diff --stat`、检查 SafeClaw/Docker/模型进程，再从“下一条可执行动作”继续。长运行必须先写 run ID、命令、日志、PID/tmux、预算、超时和停止条件。

## 当前执行增量（retry7 后）

- W08/W09：blocked pending concrete Ark proxy readiness diagnosis. The pinned patch remains unchanged and hash-verified; no unreviewed patch variant is accepted.
- Required next repair: preserve a redacted process-state/launch diagnostic compatible with the existing patch format, reproduce the full reset/model-config order, then run one fresh bounded smoke. Do not start large collection until readiness, victim interaction, and raw-to-sample evidence pass.

## 当前执行增量（Ark adapter launch repair）

- W08: implementation repair complete for the previously unobservable detached Ark adapter launch; patch is cleanly applicable and hash recorded. Real container verification still required.
- W09: remains gated. Next action is a fresh retry8 bounded smoke with this patch and a new output directory; success requires bridge ready plus observed victim/tool/retrieval evidence, not merely preflight.

## 当前执行增量（retry9 后）

- W02/W09: real container startup now reaches a victim session and persists observations; retry9 exposed malformed attacker action handling. The fix converts structured-action validation failure into an explicit fail-closed stop with reason.
- Next acceptance: retry10 must use the updated 18790 adapter patch and produce a ready session without uncaught validation error; then inspect tool/retrieval/state evidence before mining.

## 当前执行增量（retry10 后）

- W08: real container and Ark proxy integration now verified through retry10 bridge startup and victim interaction; port 18790 is used because the fixed image occupied 18792.
- W09: first bounded real collection and extraction succeeded for one task: 1 candidate and 1 accepted v3 sample with all G0-G8 evidence gates passing. The trajectory is partial, so this is sample usability evidence, not attack success.
- Next gate: run a second bounded real interaction with a distinct fresh run ID (normal/blocked or isolated attack as configured), verify no duplicate/overwrite behavior, then complete planner/sample binding and treatment/no-sample smoke before any scale-up.

## 当前执行增量（formal gate review）

- W05/W06/W07: offline formal planner/scheduler/e2e contracts verified (14 tests), including sample identity and no-sample assignment metadata. Formal runtime remains gated by the explicit frozen-library requirement and real SafeClaw evaluator prerequisites.
- W09: one real v3 sample is available from retry10, but it remains an unfrozen construction artifact. Promotion/freeze is a separate audited data migration step and must retain source hashes, gate decisions, and provenance.
- Next action: implement or document an explicit audited sample-library promotion path, then run the smallest treatment/no-sample paired formal smoke with identical task/model/budget/injection surface. Do not start large collection/evaluation before that smoke passes.

## 当前执行增量（formal smoke gate）

- Formal paired smoke is blocked by sample capability, not no-sample semantics: full-budget scheduler compatibility is possible, but planner correctly rejects the short retry10 path for long-horizon attack family.
- W09 next: collect a fresh bounded trajectory with `max_actions=8`, `max_turns=4`, `max_sessions=2` for the same construction task. Accept only observed persistence/session-boundary evidence; otherwise record rejection and stop expansion.

## 当前执行增量（retry11 extraction review）

- W03/W09: state-write observations are retained, but causal graph admission requires artifact/state lineage; no synthetic ingress→workspace edge is added. Retry11 sample is therefore unsuitable for the official long-horizon attack family despite G0-G8 acceptance for its observed short path.
- Next action: bounded collection on one distinct train construction task using the same budget and fresh output, then compare extraction gates. Large collection remains prohibited until a sample with traceable persistence/recall capability and formal paired smoke succeeds.

## 当前执行增量（retry12 后）

- W09 runtime/extraction: two distinct train tasks now have real accepted short-path samples; startup, observations, normalization, gates, and v3 promotion are operational. Neither sample supports the official long-horizon family because persistence/recall causal lineage is absent from the public view.
- W05-W07/W10 gate: formal paired smoke cannot be honestly run to execution with these samples; planner rejection is preserved. Do not expand collection ad hoc or start large billing runs. Next engineering action is to repair/extend the real retrieval/state lineage protocol so an observed memory retrieval can be represented, then collect one bounded task again and rerun the paired smoke.

## 当前执行增量（retry12 后）

- Retry12 confirms the runtime is repeatable across two train tasks, while the current construction bridge does not expose an explicit memory retrieval event from OpenClaw responses. State write evidence is preserved, but without causal artifact lineage it cannot satisfy the long-horizon sample macro.
- Before any formal or large run, implement and test an explicit bridge retrieval protocol (observed/unknown distinction, session/call IDs, artifact parents), then collect one bounded trajectory and rerun the formal paired smoke. Keep the Goal active and resume from this point.

## 当前执行增量（retrieval protocol）

- W02/W03: explicit retrieval protocol now distinguishes `observed` payloads from `unknown`/`not_observable`; the pinned upstream currently supplies only the latter. No recall lineage is fabricated.
- W09 next gate: run one fresh bounded collection using the protocol and verify unknown retrieval events are retained in raw/source/graph artifacts and cannot produce a recall primitive. Formal paired smoke remains gated until an observed persistence/recall path exists.

## 当前执行增量（retry13）

- W02/W03/W09: retry13 verifies unknown retrieval evidence is retained end-to-end and excluded from observed recall admission. This closes the protocol distinction requirement without fabricating lineage.
- Formal gate remains unmet: current SafeClaw upstream does not expose memory-search hit/tool-result evidence through `run_session`; only explicit future bridge payloads may create recall. Keep collection/evaluation at bounded diagnostic scale until that evidence is available.

## 当前执行增量（gateway provenance）

- W02/W03/W07: bridge records bounded redacted gateway-log provenance and explicit unknown retrieval status. This makes lack of structured retrieval evidence auditable without changing official evaluator semantics.
- Formal gate remains: no structured tool-result/memory-hit lineage from pinned upstream. Next action is to run the smallest formal paired smoke only if a sample with observed persistence/recall appears; otherwise continue protocol-compatible collection diagnostics, never infer recall from marker text.

## 当前执行增量（no-sample contract audit）

- W06: blocked by confirmed implementation mismatch. The current no-sample path is legal baseline replay with zero attacker model calls, which cannot serve as the required no-sample attack control.
- Next engineering batch: add `NoSampleAttackerInput`/realization and execution path in `formal_attacker.py`, `formal_interactive_episode.py`, and `safeclaw_formal.py`; add regression tests proving same task/model/budget/surfaces and nonzero attacker generation, while sample data is absent. Do not run paired or large evaluation until these tests pass.

## 当前执行增量（baseline marker）

- W06/W07: existing no-sample replay is now unambiguously classified as a legal baseline control in recorded artifacts. This is a reporting integrity fix, not completion of the required no-sample attack.
- Next implementation: add a public-task-only no-sample attacker schema and execute it through the same interactive driver/action loop, with attacker model calls and matched budgets/surfaces recorded. Keep the baseline replay only as a separate auxiliary control.

## 当前执行增量（latest formal integrity）

- W06: current no-sample replay is explicitly classified as an auxiliary legal baseline and excluded from the required attack-control claim. A real public-task-only attacker path remains to be implemented.
- W05/W09: real collection and v3 mining are operational, but observed retrieval/persistence lineage is absent in current SafeClaw upstream outputs. Formal paired smoke is gated by planner capability checks; no large collection/evaluation may start until the no-sample attacker contract and a compatible evidence-backed sample exist.
- Recovery: read this section first, inspect `git diff`, then implement/test the no-sample attacker schema and execution loop before any new formal run.


## 本轮增量计划（2026-09-07）
- [x] 修复 no-sample 物化值与 treatment 不一致，并实现 public-task-only attacker contract；当前使用确定性公开任务策略，LLM attacker 仍待接入。
- [x] 明确区分 `legal_baseline_replay` 与未来 no-sample attack，禁止把 replay 计作攻击生成。
- [x] 更新 planner/e2e 回归断言，验证 no-sample 无 sample 且任务物化值匹配 treatment。
- [x] 补齐 `NoSampleAttackerInput`/`NoSampleAttackRealization` schema：输入只允许公开任务、预算、目标和允许注入面，禁止 sample/private metadata。
- [x] 将 no-sample 生成动作接入同一 victim driver，保留 session/call/action/evidence lineage 和异常续跑。
- [x] 运行 `make check`；paired smoke 已尝试但被真实 sample capability gate 拒绝，未生成 episode。
- [ ] 获取含 evidence-backed persistence/recall 的 frozen v3 sample 后，重新执行一对最小 treatment/no-sample SafeClaw smoke；只有真实产物和官方/机制双重结果齐全后，才评估扩大 collection。
- [x] 修复 collection stage manifest 的不稳定/迟到写入 hash 问题，并用 retry15 真实采集+mining 验证。
- [ ] 解决真实 state-writer 与 memory retrieval lineage 缺失；不得用 workspace 非空或 unknown retrieval 推断。
- 依赖：固定镜像 `openclaw-env:2026.3.12`（digest 已记录）、SafeClaw pinned commit、`.env` 中角色模型与 Ark embedding 配置、具备 observed retrieval/persistence lineage 的 sample。
- 验收：代码/离线测试通过不等于实验完成；正式 evaluation 仍需真实执行状态、pinned evaluator 和独立报告。


## Retry15 gate decision
- retry15 已完成真实 collection + mining，stage manifest 稳定性修复通过。
- G4 `missing_state_writer` 保持拒绝；不能由 workspace state diff 推断攻击写入。
- 下一步依赖：取得 pinned SafeClaw 的结构化 state-write/memory-search 结果及 lineage；随后新目录 bounded collection、freeze audit、paired smoke。


## Retry16 transcript audit
- [x] 审计 pinned judge 的 session transcript 并补充有界 provenance。
- [x] retry16 验证 unknown retrieval provenance 落盘，未制造 observed recall。
- [ ] 仍需外部结构化 tool result/state-write lineage；在此依赖满足前保持 G4 gate 和正式 evaluation 阻塞。


## Official evaluator smoke
- [x] Pinned PSE evaluator smoke completed with evaluator source hash and non-success score recorded.
- [x] Existing formal smoke run audit completed; zero evaluation results confirmed.
- [ ] Run paired treatment/no-sample only after evidence-backed long-horizon sample passes planner gate.


## Official CLI path repair
- [x] 修复并测试仓库根相对 task path 的 pinned evaluator CLI 解析。
- [x] 用此前失败命令复验 evaluator smoke。
- [ ] 在 accepted long-horizon sample 到位后运行 paired formal evaluation。


## No-sample accounting integrity
- [x] 修复 no-sample decision/model call 计数与 runner provenance。
- [x] e2e 与全量检查验证 control type、lineage 和计数。
- [ ] 在真实 accepted long-horizon sample 到位后运行 paired smoke，并单独记录 LLM/fallback/失败来源。


## No-sample LLM attacker
- [x] 接入独立 public-task-only LLM attacker、prompt、schema 和 recorder lineage。
- [x] 模型失败 fail-closed，禁止 fallback/replay substitution；测试替身路径单独标识。
- [ ] 获得 accepted evidence-backed long-horizon sample 后运行真实 SharesAI treatment/no-sample paired smoke。


## No-sample runtime hash
- [x] 修复 `runtime-computed` hash 占位值在模型响应解析阶段被错误拒绝的问题。
- [x] 增加回归测试并通过全量质量检查。
- [ ] 在 accepted long-horizon sample 到位后执行真实 SharesAI paired smoke。


## No-sample action validation
- [x] 校验 LLM no-sample 动作的公开 session、唯一性、turn budget、action type 和 injection surface。
- [x] 非法响应 fail-closed 并保持 model call lineage。
- [ ] 使用 evidence-backed long-horizon sample 运行真实 SharesAI paired smoke。


## Retry17 cross-topology gate
- [x] 在不同 PSE topology `pse-2.2-002` 验证 collection/mining 与 G4 gate。
- [x] 确认 missing state-writer / unknown retrieval 跨任务复现，保留 negative sample。
- [ ] 不再扩大 ad-hoc collection；获得结构化 lineage 后再做 bounded collection、freeze 和 paired smoke。


## Direct no-sample model contract tests
- [x] 用 fake model client 验证 runtime hash 重算和 public session gate。
- [x] 验证未知 session fail-closed。
- [ ] 真实 provider paired smoke 仍需 accepted long-horizon sample。


## 本批次完成（no-sample provenance and quality gate）
- [x] 文件：`src/stac_attack_lab/execution/formal_attacker.py`；目标：语义拒绝写入 recorder 失败来源；验收：invalid public session 等路径 fail-closed 且保留 reason code。
- [x] 文件：`tests/unit/test_formal_planner.py`；目标：runtime hash/public session contract 回归；验收：focused 12 passed。
- [x] 全量质量门：`make check`；验收：ruff、mypy、pytest 123 passed，日志 `/tmp/stac-make-check.log`。
- [ ] 真实验收依赖：pinned SafeClaw bridge 的结构化 state writer/retrieval lineage；在此依赖满足前禁止扩大 collection、freeze sample 或声称 formal evaluation 完成。


## 本批次完成（retry18 lineage repair and bounded collection）
- [x] 修复 unknown retrieval 诊断事件不产生虚假 state dependency；回归测试通过。
- [x] 使用固定 `openclaw-env:2026.3.12` 和 pinned SafeClawArena commit 执行 retry18 bounded collection；新输出目录、无旧数据覆盖。
- [x] 本地 raw -> normalization 验收：7 events、1 real state edge、0 unresolved links。
- [ ] Ark embedding mining：等待针对 retry18 collection-derived payload 的明确受控外部调用授权；授权前不得把 collection 当作 sample 提取完成。
- [ ] Formal paired smoke/evaluation：依赖 mining 产生 evidence-backed accepted long-horizon sample。

- [x] retry18 修复后的全量质量检查：ruff、mypy、pytest 124 passed；日志 `/tmp/stac-make-check-retry18.log`。


## 本批次完成（strict G5 gate repair）
- [x] 修复 miner 默认关闭 attack relevance 的缺陷，恢复 G5 语义门。
- [x] 独立 retry19 审计输出 candidate/negative/filter_decisions/library manifest，保留逐 gate 拒绝原因。
- [x] 证明 retry18 accepted 是旧错误派生；不删除旧数据、不将其用于 formal evaluation。
- [ ] 获得 completed terminal trajectory 后再 freeze v3 sample；当前没有 evidence-backed accepted long-horizon sample。

- [x] strict G5 修复后全量质量检查通过：pytest 124 passed；日志 `/tmp/stac-make-check-retry19.log`。

- [x] retry19 严格 extraction 后最终质量门通过；日志 `/tmp/stac-make-check-final.log`。


## 本批次完成（library accounting）
- [x] `source_split_summary` 覆盖 negative candidates，避免 rejection-only 运行丢失数据来源。
- [x] retry20 独立 mining audit 验证 train 来源计数与 accepted=0/negative=1 一致。
- [x] 全量质量门通过（pytest 124 passed，`/tmp/stac-make-check-retry20.log`）。
- [ ] completed terminal trajectory 和真实 retrieval/state lineage 仍是 sample freeze 与 formal evaluation 前置条件。


## 本批次完成（formal library readiness audit）
- [x] 确认 formal runner 强制 frozen library，缺失 `safeclaw-main` 时 fail-closed。
- [x] 审计现存 retry10 frozen manifest；确认其为严格 G5 修复前旧派生物，不用于正式 evaluation。
- [ ] 生成并冻结新的严格 gate v3 library，随后才可运行 treatment/no-sample paired smoke。

- [x] formal readiness audit 后质量门通过；日志 `/tmp/stac-make-check-readiness.log`。


## 本批次完成（accepted library semantic audit）
- [x] accepted sample 与 candidate/attempt/terminal 语义一致性纳入 library audit。
- [x] retry20 zero-accepted library audit/freeze fail-closed 验证。
- [x] 全量质量门通过（pytest 124 passed，`/tmp/stac-make-check-library-audit.log`）。
- [ ] 需要新的 completed terminal trajectory 才能生成并 freeze 正式 sample library。


## 本批次补充（partial root-cause audit）
- [x] 审计 retry15-18 的 partial failure categories 与 collection loop；确认 retry guard/无 response 路径被正确保留为 partial。
- [x] 明确不通过提高预算或关闭 gate 伪造 completed/sample。
- [ ] 等待 pinned runtime 提供真实 structured response/tool/retrieval lineage 后再重启 bounded collection。

- [x] partial root-cause audit 后全量质量门通过；日志 `/tmp/stac-make-check-root-cause.log`。


## 本批次补充（legacy frozen rejection）
- [x] 用新 semantic audit 实测拒绝旧 retry10 frozen partial sample。
- [ ] 新 completed terminal trajectory、严格 mining 与正式 freeze 仍待 pinned runtime structured lineage。

- [x] legacy frozen rejection 后全量质量门通过；日志 `/tmp/stac-make-check-legacy-rejection.log`。


## 本批次补充（formal gate CLI audit）
- [x] CLI audit 对 zero-accepted strict library fail-closed；未启动正式 runner/provider。
- [x] formal gate/preflight/e2e 相关测试 13 passed。
- [ ] 仍需新 completed terminal trajectory 和新 frozen library 才能进入 paired smoke/evaluation。


## 本批次完成（accepted-candidate hash binding）
- [x] accepted sample audit 改用 candidate hash 绑定并检测重复 hash。
- [x] legacy frozen retry10 继续 fail-closed；未修改旧数据。
- [x] 全量质量门通过（pytest 124 passed，`/tmp/stac-make-check-hash-audit.log`）。
- [ ] 新 completed terminal trajectory 与严格 frozen library 仍待 pinned structured lineage。


## 本批次完成（model and embedding mapping）
- [x] 核对并记录 SharesAI attacker/planner、Gemini victim、Ark embedding 的独立服务映射和凭证变量名。
- [x] embedding/preflight focused tests 23 passed。
- [ ] 真实 OpenClaw indexing/search 和新 completed terminal sample 仍待运行环境/lineage 条件。

- [x] model/embedding mapping audit 后全量质量门通过；日志 `/tmp/stac-make-check-mapping.log`。
- 2026-09-07 continuation: CLI repository-relative upstream path regression repaired and tested (2 focused passed; full pytest 121 passed, 3 skipped). W09/W10 remain gated: obtain pinned checkout and observed state-writer/retrieval lineage, then produce a strict completed sample, audit/freeze it, execute paired smoke, and only then start large collection/evaluation.
