# Implementation progress

Updated: 2026-09-06
Baseline commit: `05afd4b9b4e4b38f928aa306cde1afe91fd586ef`
Scope: W00-W10，目标 observation/sample/evaluation v3，尚未实现。

## 当前状态

- 当前任务：W00 基线与回归准备；W08 环境只读检查。
- 初始 Git status 为空，已有 safety patch、Ark adapter 及其单测均已被 Git 追踪。
- 仓库和父目录没有适用 AGENTS.md；upstream 的 configs/platforms/workspace/AGENTS.md 属于 Victim 工作区素材，不作为本仓库开发约束。
- 已读修复计划全文及 README、SECURITY、EXPERIMENT_PROTOCOL、PROMPTS、PROJECT_GUIDE_ZH、LINUX_TMUX_RUNBOOK_ZH、integration README。
- 已创建文件级工作规划，尚未修改实现或旧数据。
- 当前 Python 为 3.14.7；依赖与测试工具版本待核对。
- SafeClawArena HEAD 精确匹配固定版本；upstream dirty status 待查。
- Docker 沙箱内访问受限，批准沙箱外只读查询后成功连接 daemon；所需镜像不存在，不是用户需要 chmod socket。
- 默认 tmux socket 不存在；沙箱 ps 只显示命名空间内进程，不能据此保证宿主无实验进程。

## 历史证据

搜索 /home/scarramcci、/tmp、/mnt、/srv、/opt 下 raw_trajectory.json、source_events.jsonl、filter_decisions.jsonl 和 manifest。
当前发现 pytest 临时生成的 synthetic 记录；排除 /tmp/pytest-* 后，项目、/tmp、/mnt、/srv 搜索未发现真实 raw/source/filter 文件。搜索有不可读路径，不能宣称全服务器绝无数据。
历史真实 episode、occurrence、candidate、gate 失败计数目前为不可得，不是零。修复计划第 2.2 节的数字是此前 synthetic bridge 复现，不是历史统计；本轮尚未复现。

## 最近验证

| 命令/检查 | 结果 | 证据/限制 |
|---|---|---|
| git log -1 / git status --short | HEAD 如上；初始干净 | 本轮基线 |
| upstream rev-parse HEAD | a11f5cceaba0676be721021f8d232638fd111305 | 尚未证明镜像一致 |
| python3 --version | 3.14.7 | 尚未跑测试 |
| docker image inspect openclaw-env:2026.3.12 | exit 1, No such image | daemon 可访问；真实运行环境尚未准备 |
| tmux list-sessions（沙箱外） | exit 1, socket No such file | 仅默认 socket |
| git ls-files safety patch / Ark 源码和测试 | 三文件均存在且受追踪 | 尚未复验接口或实际 memory search |

## 正在运行的任务

无本轮启动的实验、模型调用或长测试；预算消耗为零。没有启动 Docker 容器。

## 下一次从这里继续

1. `git diff --stat` 并核对 upstream status、Python 依赖、宿主运行进程（只输出程序名，不泄漏命令行凭证）。
2. 阅读 interactions/safeclaw_collection.py、collector.py、construction_bridge.py 和对应单测，永久复现第 2.2 节与假 recall 缺陷。
3. 落盘诊断证据，定稿 W01 v3 契约后按 W02 开始小批修复。

## 变更日志（追加）

- 2026-09-06：完成首轮基线搜索，创建 IMPLEMENTATION_WORKPLAN.md / IMPLEMENTATION_PROGRESS.md。镜像缺失阻止立即进行真实 benchmark，但不阻止回归与修复。用户询问 Docker 权限，已说明只读授权有效，后续具体 Docker 操作由工具审批；无需放宽 socket 权限。下一动作：源码与回归基线。

- 2026-09-06 continued: 实际基线 HEAD 为 `63aca49feda4ff7b4ea0a2d0a1dcd95c0f2785f3`，工作区初始干净；生成目录仅有旧 tmux 日志/manifest，未发现 raw trajectory、source events 或 filter decisions，历史 gate 统计不可得。
- 2026-09-06 continued: W01/W03 第一批完成。`filter_chain_candidate` 新增 strict `require_attack_relevance` 开关；sample mining 显式使用 observation-based admission，仍要求直接/确定性证据且不把 attempted 改为 passed；sample builder 不再硬编码 adversarial terminal/persistent two-session 故事。验证：`tests/unit/test_chain_construction_filtering.py` 9 passed，`tests/unit/test_primitive_chain_library.py` 18 passed。下一步：补 SafeClaw driver 永久回归并修 collection 持久化。

- 2026-09-06 continued: W00 历史产物复查发现旧 `safeclaw-construction-main` 有 120 条 trajectory、24 条 collection failures；失败原因主要为 `ConstructionAttackerAction` 的 delivery surface/message 必填约束与 retry id shape mismatch。该数据属于旧运行，未覆盖或重新贴标签。
- 2026-09-06 continued: W02 第一批完成：`SafeClawSubprocessVictimDriver` 增加 append-only observed snapshot；`collect_adversarial` 在 driver 异常时保存已发生 events/checkpoints 并返回 partial/error `CollectedInteraction`；memory 非空不再自动推断 recall，仅接受 bridge 显式 `memory_retrievals`。验证：SafeClaw/runtime/formal bridge/filter/library focused suite 31 passed，`git diff --check` 通过。下一步：补充 bridge 的显式 retrieval 协议字段与 state/artifact lineage，再跑全量 unit suite。

- 2026-09-06 continued: W02/W03 增量：显式 retrieval 记录若包含 `content_hash`/`parent_artifact_ids`，driver 会保留其 lineage；缺失时仍不会把文件存在升级为 recall 事实。全量 unit + SafeClaw adapter integration：118 passed。未修改旧运行数据，未启动真实计费 benchmark。

- 2026-09-06 continued: 代码审查确认 no-sample 当前执行的是合法 baseline replay，尚未生成与 treatment 同模型/预算/注入面的攻击动作；这是 W06 未完成项，不能宣称对照已满足研究目标。新增 `sample collect-and-mine --config ...` 便捷入口，保留 collection 与 mining 内部职责。CLI/config 回归 4 passed。
- 2026-09-06 continued: W00 标记 verified；W02/W03 保持 in_progress。下一步：补 bridge 显式 retrieval/event 协议，随后设计 no-sample attacker execution contract，并增加正式对照回归。

- 2026-09-06 continued: broader validation completed: unit + integration + SafeClaw formal e2e = 119 passed; `git diff --check` passed. Current source changes are limited to observation/sample semantics, collection failure preservation, automatic collect-and-mine CLI, and documentation/status. No real benchmark run was started.
