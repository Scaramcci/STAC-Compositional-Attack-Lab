# Implementation Workplan

更新时间：2026-09-14。当前证据和本地测试限制见 [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md)。仅保留一套执行顺序。

## 1. 同步与离线复核

- 同步冲突合并修复，检查 Git diff 与冲突标记；不能以 git status 干净代替源码内容检查。
- 使用服务器实际 stac 解释器运行专项测试和 make check，验证 pinned upstream 用例，记录 commit、解释器及通过/失败/skip。
- 重点验证 embedding 的预算预扣、accepted 行计数、错误汇总不重复扣费、无效向量不漏计，以及本地 400/真实上游状态分离。
- 保留线程锁、跨 run 的 driver 预算契约和结构化观测，不能简单选取某个冲突分支覆盖。
- 不重复已有效的 direct chat/embedding 探针来代替索引诊断。

## 2. 隔离索引与语义 memory_search 验证（当前下一步）

direct embedding 和代理转换已有成功记录；接下来验证 OpenClaw 实际使用链，而不是直接开始 8 条 pilot。

- 独立 workspace/session/index，放入少量合成事实与独特 canary；不读取真实用户文档。
- 检查索引确实完成、索引分片/查询 embedding 的实际上游请求成功、维度和模型一致。
- 以语义相关但不包含 canary 答案的查询运行 memory_search；新会话不能通过对话历史直接知道答案。
- 断言返回片段对应本次写入的事实，带正确来源路径/范围、结果 hash 和 call ID。
- 区分向量搜索、关键词 fallback、memory_get、错误及 unknown。仅工具返回非空不等于通过。
- 保留真实工具调用/结果、索引证据、请求阶段和关联 ID；不要从文件存在或模型回复推断 recall。
- 必要时做最小 instrumentation 修复和回归；真实错误按 upstream 状态分类，不直接归咎配额或 Victim 限流。

验收：索引与真实语义搜索均有证据；或者明确交付具体失败与未知项。缺少 frozen library 不阻止本步骤。

## 3. 单条 construction（另行确认运行范围）

第 2 步通过后，运行 1 task × 1 seed 的有限 construction；使用 canonical pilot 派生配置和唯一目录。
验证 lifecycle、provider/embedding 跨运行累计预算、脱敏、raw/source events/checkpoints 完整。
对本轮 raw 显式 normalize/mine/audit，分开报告质量、行为、官方结果及 eligibility。未执行时不写 accepted=0。

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
