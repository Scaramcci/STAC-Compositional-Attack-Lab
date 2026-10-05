# 文档入口

第一次接触项目，请按下面的顺序阅读。当前源码路线是 `src/stac_attack_lab/attack_program/`；R1–R4 是同一主链的不同职责层。

## 当前使用说明

1. [仓库 README](../README.md)：研究目标、当前能力、安装和快速开始。
2. [项目结构与运行入门指南](PROJECT_STRUCTURE_ZH.md)：面向零基础读者，含术语、代码地图、离线练习、结果解释与排错。
3. [实验协议与证据边界](EXPERIMENT_PROTOCOL.md)：合成、fake、真实结果与正式研究门。
4. [安全边界](../SECURITY.md)和[协作规范](../AGENTS.md)：开始修改或运行前阅读。
5. [脚本参考](../scripts/README.md)：具体入口；其中历史批次说明不能作为新授权。

## 当前状态与整理依据

- [进度记录](IMPLEMENTATION_PROGRESS.md)：顶部为最新检查点，下方保留历史。
- [工作计划](IMPLEMENTATION_WORKPLAN.md)：当前下一步与以往计划。
- [结构与清理审查](rse/specs/research-repository-cleanup.md)：可删缓存、归档候选、活跃旧依赖及本轮验证。
- [primitive-only 开发采集计划](rse/specs/plan-primitive-development-campaign.md)：最近批次的固定范围，不是通用运行教程。

## 历史设计与审查

这些材料保留设计和验证背景；以其中日期、源码版本和批次为限，不作为今天重新执行真实实验的许可。

- [重构实施方案](AgentLAB_SafeClawArena_原语样本库与Planner实验重构实施方案.md)：原始设计动机，部分迁移路径已退役。
- [R4 runtime 任务书](ATTACK_PROGRAM_R4_RUNTIME_TASK.md)：2026-09-28 阶段目标和接口要求。
- [历史代码审查任务](SKILL_BASED_CODE_REVIEW_TASK.md)与[2026-09-28 审查记录](CODE_REVIEW_VALIDATION_20260928.md)。
- [设计、计划、验证与交接记录](rse/specs/)及[实施报告](rse/reports/)：按文件日期与对应批次查阅。

历史实验与 prompt 的冻结副本是复现证据。已退出主导航不等于可以删除；部分仍被当前脚本和测试读取。
