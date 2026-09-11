# Implementation Workplan

只列未完成工作；历史诊断与已完成修复见 [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md)。

1. 先解决当前 Ark embedding endpoint 的可观测上游失败（最近一次受控复测为 5 个实际 embedding HTTP，OpenClaw 日志显示 rate-limit/retry 后 search unavailable）。下一次动作必须先用不增加攻击面的只读/单请求诊断确认 HTTP 状态和响应 schema；不得进行第三次合成会话重跑。确认后再决定是否需要凭证/配额侧处理或代码适配。
2. embedding 恢复后，重新安排一个新的、明确授权的有限批次；先验证 `memory_search` 返回非空真实片段且 call/result/evidence 完整，再运行 1 task × 1 seed construction。当前 2026-09-11 批次已用 22/40 请求，但因 A 未通过而按顺序停止。
3. 对首次成功的有限 collection 显式执行 normalize/mine/audit，验收为 raw→sample→audit 如实保留工具结果、unknown/拒绝/错误边界、request ledger、hash 和 eligibility；usable 不自动等于 `formal_attack_primary`。
4. 经上述证据审查并由操作者确认后，运行 canonical 8 条 pilot；验收为 8 条预算内 trajectory 均有完整 lifecycle、provider/embedding ledger、脱敏检查和明确 complete/partial/error 状态。
5. 对 pilot 显式执行 normalize/mine/audit；验收为至少 2 个 accepted samples，或诚实记录未达门禁并停止。不得用旧库或 synthetic fixture 补数量。
6. Pilot 通过后运行 main collection；验收为至少 30 个 accepted samples、全部 provenance/hash/view separation 检查通过。
7. 将审计通过的 main library freeze 为 `data/primitive_libraries/frozen/safeclaw-main`；验收为 immutable manifest/tree hash 可复验。当前没有该库。
8. 仅在上述 frozen gate 通过后运行 1 task × 3 conditions × 5 seeds formal matrix；验收为完整 matched pairs、Planner/独立 Attacker journals、mechanism 与官方 verdict 并列、失败分母不丢失。
9. 对 formal run 执行 `audit-run` 和 report；报告区分协议失败、基础设施失败、机制未出现和官方失败，不把本次诊断结果计为正式实验结果。

停止条件：凭证或日志脱敏失效、provider 请求计数无法证明、容器所有权不明确、端口冲突、frozen library 缺失/审计失败，或预算达到上限。遇到这些条件先保留确定性证据并修复，不自动扩大请求、任务或时间预算。
