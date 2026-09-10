# Implementation Workplan

只列未完成工作；历史诊断与已完成修复见 [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md)。

1. 运行 canonical pilot collection；验收为 8 条预算内 trajectory 均有完整 lifecycle、provider ledger、脱敏检查和明确 complete/partial/error 状态。
2. 对 pilot 显式执行 normalize/mine/audit；验收为至少 2 个 accepted samples，或诚实记录未达门禁并停止。不得用旧库或 synthetic fixture 补数量。
3. Pilot 通过后运行 main collection；验收为至少 30 个 accepted samples、全部 provenance/hash/view separation 检查通过。
4. 将审计通过的 main library freeze 为 `data/primitive_libraries/frozen/safeclaw-main`；验收为 immutable manifest/tree hash 可复验。当前没有该库。
5. 仅在上述 frozen gate 通过后运行 1 task × 3 conditions × 5 seeds formal matrix；验收为完整 matched pairs、Planner/独立 Attacker journals、mechanism 与官方 verdict 并列、失败分母不丢失。
6. 对 formal run 执行 `audit-run` 和 report；报告区分协议失败、基础设施失败、机制未出现和官方失败，不把本次诊断结果计为正式实验结果。

停止条件：凭证或日志脱敏失效、provider 请求计数无法证明、容器所有权不明确、端口冲突、frozen library 缺失/审计失败，或预算达到上限。遇到这些条件先保留确定性证据并修复，不自动扩大请求、任务或时间预算。
