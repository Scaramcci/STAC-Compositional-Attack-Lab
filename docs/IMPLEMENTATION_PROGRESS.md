# 项目实施进度

核查日期：2026-09-08（Europe/Berlin）；源码基线：`c3fd41a6`；阶段 A Goal：`01a07f10-044b-7691-ae85-30cdfff88f98`。

本文件是唯一当前进度快照；依赖、验收和阶段 B 草案见 [IMPLEMENTATION_WORKPLAN.md](IMPLEMENTATION_WORKPLAN.md)。本轮仅完成离线工程阶段 A：未调用模型或 embedding，未启动真实 Victim，未操作外部目标，未读取密钥，未覆盖旧 raw 或冻结库，未 commit/push。

## 1. 当前结论

**阶段 A 已达到离线完成条件；W08/W09、真实实验和研究假设仍未验证，等待用户确认阶段 B。**

- 质量门已修复：`make check` 全部通过，pytest 为 **136 passed、0 skipped**。
- sample v3.1 已将样本质量、交互行为、攻击相关性、官方攻击结果和 evaluation eligibility 分开；部分/阻断/正常的有证据子图可以入库，但不会自动进入正式攻击主分析。
- filter、builder、library audit 共同重算并校验这些状态；伪造引用、必要依赖缺失、shortcut、来源/hash 不一致仍拒绝，未通过关闭真实性门换 accepted 数量。
- observation 保留全部显式 retrieval 及 parent/evidence/request lineage；不可观测 recall 仍为 unknown。tool request、observed effect 和执行结果不再混作成功。
- Planner 不再取第一个 component 或任意 macro/session fallback；多组件角色明确拒绝，macro 会话来自最后一个有观测依据的 core occurrence。
- formal report 分开 interaction、official attack 与 mechanism outcome，并对 matched task/seed 条件做配对校验与 delta；不匹配 pair 明确拒绝。
- 构造 bridge 实际只支持 `safeclaw_user_message`。配置中声明但尚未实现的 local sink/new-session delivery 不再静默降级为用户消息，而是在 bridge/Victim 前 fail-closed。

## 2. 本轮实测

| 检查 | 结果 | 说明 |
|---|---|---|
| `git rev-parse --short HEAD` | `c3fd41a6` | 修改前源码基线；工作区有本轮未提交改动 |
| focused pytest | 69 passed | 三维契约、观测、mining/audit、Planner、配对、报告、task materializer |
| `make check` | 通过 | ruff format/check、mypy、pytest 均执行 |
| ruff | 通过 | 106 files formatted；lint 无问题 |
| mypy | 通过 | 64 source files |
| pytest | 136 passed、0 skipped | 4.92 秒；本工作区 pinned upstream 存在，因此相关测试未 skip |
| `make schemas` | 通过 | v3.1 sample/record 与 formal result schemas 已重生成 |
| `git diff --check` | 通过 | 无 whitespace error |

这些是当前本地 Linux 工作区的离线结果，不是服务器、容器、provider 或真实 Victim 运行证明。

## 3. 工作包状态

| 工作包 | 状态 | 阶段 A 证据 / 剩余边界 |
|---|---|---|
| W00 | verified | 当前源码、测试、历史 retry22/23 与 upstream 已重新盘点 |
| W01 | verified | v3.1 三维状态与兼容 schema、正反回归通过 |
| W02 | in_progress | 多 retrieval/lineage/unknown/attempted 回归通过；真实 provider 粒度待 B |
| W03 | verified | 部分路径建库、audit 一致性、隔离幂等重算通过 |
| W04 | in_progress | 字段 allowlist、PSE/CDF 官方 hash、未实现 surface fail-closed；真实 bridge 待 B |
| W05 | verified | component/session 映射有明确依据，无任意 fallback |
| W06 | in_progress | no-sample 信息隔离、预算/动作门、ablation provenance 通过；真实请求待 B |
| W07 | in_progress | 三类 outcome、分母和 matched delta 通过；官方 evaluator 实际 state 待 B |
| W08 | in_progress | 代码/配置在；当前服务器、镜像、patch、indexing/search 和服务可达性未验证 |
| W09 | blocked | 需要用户另行确认阶段 B 的服务器、出口、模型与费用预算 |
| W10 | in_progress | 阶段 A schemas/文档/阶段 B 草案已更新；真实运行与最终交付待 B/C |

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

## 5. 运行时未验证项

- construction bridge 仍无法从 pinned upstream 获得结构化 tool-result/retrieval stream；真实 recall 必须在 B 中观察到明确事件，否则保持 unknown。
- 未核对实际 Linux 服务器的 upstream commit、镜像、patch 应用、容器生命周期、宿主到 OpenClaw 的 indexing/search 链。
- 未验证模型/embedding endpoint、role separation、token usage 与费用；本轮没有读取环境变量或密钥。
- 未运行真实 normal/blocked collection、adversarial collection、官方 evaluator、matched assigned-sample/no-sample 或 dependency ablation。
- 正式配置仍指向 `data/primitive_libraries/frozen/safeclaw-main`；阶段 A 新库未冻结且不应替换它。

## 6. 下一步：等待阶段 B 确认

工作计划已给出可复制的预检命令和最小预算草案：先一条正常/阻断、一条授权对抗，各一个 seed；audit 通过后才做同 task/seed/model/goal/budget/surface 的两条件 matched smoke。含每个 smoke case 最多两次 attempt 时，整批草案上限为 6 个实际执行 attempt、49,152 declared tokens、120 分钟墙钟，费用上限仍需用户填写。

确认前不执行预检中会启动容器/Victim 的命令，不调用任何付费服务。阶段 B 若遇 upstream/patch/image/hash 不匹配、协议/检索不可验证、一次基础设施故障、audit/binding 失败或预算触顶，立即停并保留已有片段，不自动扩大。

## 7. 续接记录

- 2026-09-08 / `c3fd41a6`：完成阶段 A 实现、回归、schema 与 retry22/23 只读隔离重算；`136 passed, 0 skipped`。阶段 B 未启动，等待明确授权与费用预算。
