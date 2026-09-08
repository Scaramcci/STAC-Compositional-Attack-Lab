# 项目实施进度

核查日期：2026-09-08（Asia/Shanghai）；源码基线：`820cbf6`（update the plan）。

本文件是唯一当前进度快照；依赖与验收见 [IMPLEMENTATION_WORKPLAN.md](IMPLEMENTATION_WORKPLAN.md)。本轮只更新这两份文档，没有修改源码、启动 Goal、调用实验模型、运行服务器 collection/evaluation 或提交/推送 Git。

## 1. 当前结论

**已有工程骨架和较多离线测试，但质量门未通过，尚无本轮可确认的真实正式闭环。下一步是离线修复，不是继续扩大 collection。**

- 本机 `make check` 在格式检查处失败；独立 mypy 通过，pytest 为 **121 passed、3 skipped**。旧记录的“124 passed/全门通过”不能当作当前结果。
- 原设计允许有证据的部分/受阻 sample；当前 G5 与 library audit 仍要求 completed/terminal observed。代码与研究契约冲突必须先解决。
- bridge 当前返回空 retrieval 列表与 `memory_retrieval_observation="unknown"`。保留 unknown 正确，但不能声称真实检索链已证实。
- Planner 仍有首组件选择与 core node 回退首个 macro mapping；LLM no-sample 执行代码则已经存在，不能继续标为完全未实现。
- 本地有旧文档漏记的 retry23：partial、12 actions、17 source events、action budget exhausted；其目录下未发现 mining manifest。retry22 的 mining 为 candidate=1、accepted=0、negative=1。
- 本机缺少 upstream checkout 和正式配置指定的 `safeclaw-main` 冻结库。历史 Linux Docker/preflight 通过不等于当前本机/服务器环境已验证。

## 2. 本轮实测

审查开始时工作区干净。以下在本地 macOS checkout 执行，不是 Linux 服务器运行证明。

| 检查 | 结果 | 说明 |
|---|---|---|
| `git rev-parse --short HEAD` | `820cbf6` | 当前源码基线 |
| `make check` | 失败，exit 2 | ruff format 发现 `src/stac_attack_lab/cli.py` 未格式化；后续 make 步骤未执行 |
| `.venv/bin/ruff check .` | 失败 | `cli.py:58`、`:62` 两处 E501 |
| `.venv/bin/python -m mypy src` | 通过 | 64 source files |
| `PYTHONPATH=src .venv/bin/python -m pytest -q -rs` | 121 passed、3 skipped | 4.74 秒；upstream 未安装导致跳过，不能算通过 |
| skip 位置 | 2+1 个 | `tests/unit/test_safeclaw_embedding_config.py:72` 两个；`test_safeclaw_formal_bridge.py:50` 一个 |
| upstream 路径 | 不存在 | `integrations/safeclaw/upstream/SafeClawArena` |
| 正式库路径 | 不存在 | `data/primitive_libraries/frozen/safeclaw-main` |

没有核查远端进程；服务器是否有正在计费任务为 **unknown**。恢复前查实际 tmux socket/session、PID、日志和 manifest，不能重复启动。不能因本机缺路径便推断服务器也缺失。

## 3. 工作包现状

| 工作包 | 状态 | 已存在的实现/证据 | 剩余验收 |
|---|---|---|---|
| W00 盘点 | verified | 本轮代码、测试、retry21-23 核对 | 下次修改后刷新基线 |
| W01 契约 | in_progress | sample schema 有 3.0，其他 manifest/view 仍有 2.x | 三维结果贯通、版本兼容，不仅是 v3 命名 |
| W02 观测 | in_progress | partial 保留、零动作降级、unknown retrieval 分支 | 真实 call/session/retrieval lineage，多事件完整性 |
| W03 抽取/审计 | in_progress | CLI、candidate hash 绑定、重复检查与拒绝记录 | 修正完整终点对样本质量的一票否决；保留真实性门，DAG/迁移一致 |
| W04 注入面 | pending | task adapter/materializer 已有 | 字段级正确性、多类任务、人提交动作同规则待验收 |
| W05 Planner | in_progress | LLM/rule planner、binding 已有 | 无依据 fallback、结构差异与能力门回归 |
| W06 对照 | in_progress | ModelNoSampleAttacker、runner 接线和输入/动作校验 | 全链路公平预算、实际请求、ablation provenance |
| W07 评测 | in_progress | verifier/reporting 及测试骨架 | pinned 官方真实验证、机制分离、分母和可复算统计 |
| W08 环境 | in_progress | 角色独立变量、Ark proxy、历史记录 | 当前服务器/容器 indexing/search 未验证，本机 upstream 缺失 |
| W09 真实闭环 | blocked | 历史 partial raw 存在 | A 修复→B 有预算真实验证→C 批准正式运行 |
| W10 交付 | in_progress | 本轮统一两份文档 | 实现后同步 README/协议/runbook/schema |

### 关键源码定位

路径相对于 `src/stac_attack_lab/`，除非另有说明。

- `extraction/filtering.py`：`require_attack_relevance` 默认 True；G5 要求 adversarial、completed、terminal predicates 和 observed terminal。
- `execution/sample_generation.py`：显式传入 `require_attack_relevance=True`；不能只改这里，漏掉 library audit。
- `datasets/library.py`：candidate hash 关联与重复检查是已有正确保护；后续仍有 `accepted_sample_attempt_not_complete`、`accepted_sample_terminal_not_observed`、`accepted_sample_terminal_predicate_missing` 和 adversarial-only 限制。
- `integrations/safeclaw/construction_bridge.py`（仓库根目录下）：响应分支显式返回 retrieval unknown，只证明当前接口不可观测。
- `interactions/safeclaw_collection.py`：显式 retrieval 分支只取列表第一个元素，需覆盖多检索事件；没有真实事实时不能推断补齐。
- `planning/binding_planner.py`：`components[0]` 与 `next(iter(macro_component_mapping.values()), None)` 仍在；必须检验/修复映射依据。
- `execution/formal_attacker.py`、`execution/safeclaw_formal.py`：已有 LLM no-sample 生成和接线；下一步是信息隔离、公平性及执行证据，不是重新实现一套。

## 4. 运行产物索引

以下是本地已有历史产物的读取结果，不是本轮启动的运行。目录日期不等于本轮核实的真实执行时间。

共同前缀：`experiments/safeclaw_v3_smoke/`。raw 在对应 `interactions/raw/<collection-id>/trajectories/<trajectory-id>/raw_trajectory.json`，事件在同目录 `source_events.jsonl`。

| 产物目录 | 可核实结果 | 结论边界 |
|---|---|---|
| `retry21-generated/safeclaw-v3-smoke-retry21-v3/` | raw 写 complete/completed，provenance 却为 0 action/turn/session，events 0 行 | 历史空轨迹状态不可信；后续修复不改写原文件 |
| `retry22-generated/safeclaw-v3-smoke-retry22-v3/` | partial；6 actions、2 turns、2 sessions、11 events；`construction_consecutive_retry_guard_exhausted` | 有部分记录，不是完整机制证明 |
| 同上 `sample_generation_manifest.json` | candidate=1、accepted=0、negative=1，attempt partial=1 | 旧语义下抽取结果，不能直接推出部分路径无研究价值 |
| `retry23-generated/safeclaw-v3-smoke-retry23-v3/` | partial；12 actions、2 turns、2 sessions、17 events；`construction_action_budget_exhausted` | 尚未闭环；未发现 mining manifest，accepted 数不能写成 0 或 1 |
| `retry20-split-audit/` | 旧文档记载严格重算与 split 审计 | 可作为回归输入，不是新协议下已验证正式库 |
| `data/primitive_libraries/frozen/safeclaw-v3-smoke-retry10-v3/`（仓库根目录下） | 旧文档记载 frozen 后被较新 audit 拒绝 | 本轮未重跑该 audit；不能直接代替当前正式输入 |

retry22 的 ID 含 `20260909`、retry23 含 `20260910`，晚于本轮环境日期 2026-09-08。保留原 ID，不纠正或伪造原始时间；服务器时钟/命名来源待核对。以内容 hash 和 provenance 为依据，不以日期或编号证明成功。

retry22/23 provenance 的 token/tool-call 数为 0；这不足以证明没有调用或费用，预算计数完整性须单独验证。

`configs/experiments/formal_evaluation.yaml` 指向缺失的 `safeclaw-main` 库，条件是 assigned_sample/no_sample/dependency_ablation。配置存在、执行开关为 true 不代表执行过或完成。

## 5. 下一次从这里继续

**执行阶段 A，不开新 retry。**

1. 核对 Git diff 与版本，修 `cli.py` 质量门。缺 upstream 的 3 个测试保留明确说明，不能通过删除 skip 冒充覆盖。
2. 按对齐计划的三维契约写失败回归，联动 schema→filter→builder→audit/freeze→report；保留来源、hash、依赖和泄漏保护。部分 sample 的可用性与正式条件 eligibility 分开。
3. 修复结构化事件、必要前驱和 Planner 无依据 fallback；fixture/历史 raw 只读重算，输出到新目录。
4. 补 W04-W07 离线验收和文档；最终质量门通过后提交阶段 B 具体服务器命令/预算，等待确认。

不恢复旧“先修 retry5 apply_model_config”“保持 Goal 无限续跑”“必须得到 completed terminal 才能做其他工程”等指令。它们已不适合作为当前恢复点。

## 6. 续接记录

每批更新上述唯一当前状态，并在此留短记录：日期/HEAD、工作包、变更文件、测试/skip、证据路径、下一步。运行时另写 run ID、主机、命令、tmux/PID、日志、预算、超时和停止条件。长历史留在 Git/实验目录，不再重复复制。

- 2026-09-08 / `820cbf6`：审计并重写计划与进度；补 retry23、实际质量门、语义冲突、环境差异及日期异常。仅改两份文档，未改变代码或实验数据。下一步：阶段 A。
