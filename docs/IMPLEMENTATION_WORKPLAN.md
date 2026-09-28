# 当前计划 — 2026-09-28 新版 attack_program

1. **已完成：** 迁移新版共享依赖，删除旧代码/Prompt/配置/脚本/schema/tests/docs，切换顶层入口与文档导航；删除后 42 项 R1–R3 集成测试、Ruff、mypy 通过，当前 schema 已生成。
2. **待查收：** 新源码 R3 synthetic 单命令演示、独立 replay/audit、残留引用与文档链接核对已完成；清理后的完整 `make check` 按用户要求由其终端运行并回传，助手查收。
3. **待做 R4 接口：** 按 [R4 runtime 任务](ATTACK_PROGRAM_R4_RUNTIME_TASK.md) 接可信开发候选、真实 runtime/relay 原始观测、预算/封存与独立复核。先完成离线与 fake 验证；真实模型/API、bind、正式库冻结、正式实验均需新批次明确授权。
4. **正式研究前置：** 核定独立 held-out test 组、预注册三臂任务/预算、建立真实证据库和独立准入。当前 synthetic 工程库与 scripted 结果不得作为真实成功率或视图收益。

历史运行数据保留只读；本次不 commit/push/reset/clean。
