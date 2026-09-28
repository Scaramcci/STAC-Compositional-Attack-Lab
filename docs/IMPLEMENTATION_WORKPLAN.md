# 当前计划 — 2026-09-28 代码整理查收

1. **已完成：** 范围与脏工作树基线、受控只读 skill 审计、共享写入模块、入口回归和运行文档；研究判定、预算、split、网络及执行授权未更改。
2. **正在查收：** 增加源码指纹后的受影响短时门已 26 passed；当前源码 R4 禁用候选已在新目录 prepare/validate 为 `valid_disabled`。用户终端的完整 `make check` 和唯一新 R2 synthetic 工程产物待回传；记录实际结果，不沿用旧测试数。旧 manifest/库只读。
3. **后续研究决策：** 邮件来源消费证据、独立 held-out 分组和硬金额预算分别提出反例与结果影响后再定；真实 binding/live 与正式研究仍需覆盖批次的明确授权。清洁环境复验未完成，不能宣称跨环境复现。

# 历史计划 — 2026-09-28 R4 本机验收后

1. **已完成：** v2 Docker/local-fake 真实 runtime/relay/工具/状态链三案 3/3、独立 replay/audit 3/3；唯一真实 development 候选已准备且 `valid_disabled`。真实请求数 0，bind/live 拒绝门实测有效。
2. **下一轮接口：** 在有覆盖该批次的明确授权后，设计真实 binding、有效期和运行入口，并补邮件读取的来源消费证据；继续按角色持久账本、绝对 deadline 和 owned cleanup 验收。当前 `execute_case(mode="real")` 与 bind/run-batch 仍显式禁用。
3. **研究前置：** 真实开发尝试取得原始证据后独立 replay；再讨论证据分级库、held-out 注册和三臂正式实验。本机 fake 的 synthetic 正例不进入正式研究库。

# 历史计划 — 2026-09-28 R4 继续验收

当前检查点：R4 短时 25 项相关回归、lint/typecheck/schema/shell 均通过；v1 Docker/fake 因隔离后的端口检查失败且已清理，v2 命令已交用户，待其运行并查收。确认 v2 三案与独立 replay 后再准备唯一禁用真实候选。

1. 代码整理任务按用户最新指示延后；保护现有 R4 未提交文件及历史封存证据。
2. 补齐实际状态采集、官方逐项检查与失败封存的最小反例，完成短时回归、schema 与运行导航。
3. 交用户一条 Docker/local-fake 三案总命令；收到退出码及产物后独立 replay/audit 并查收，再准备唯一默认禁用真实开发候选。无真实请求、bind 或 live。

# 当前计划 — 2026-09-28 R4 runtime

1. **已完成：** 清理查收、R4最小反例、从清理前 f1b4943 迁移 relay/evidence policy；文件候选和本机 fake 限定的有界 Attacker 入口。
2. **进行中：** 隔离 OpenClaw 双 session adapter、工具/状态采集、官方与独立判分、不可覆盖封存/重放已实现未作 Docker 验收；补 HTTP/账本/清理反例并准备默认禁用小批次。
3. **待验收：** 短时专项、schema/lint/typecheck；唯一Docker/local-fake总命令由用户终端执行并回传，助手独立查收后才标runtime ready。真实API/bind/live无授权。

# 当前计划 — 2026-09-28 新版 attack_program

1. **已完成：** 迁移新版共享依赖，删除旧代码/Prompt/配置/脚本/schema/tests/docs，切换顶层入口与文档导航；删除后 42 项 R1–R3 集成测试、Ruff、mypy 通过，当前 schema 已生成。
2. **待查收：** 新源码 R3 synthetic 单命令演示、独立 replay/audit、残留引用与文档链接核对已完成；清理后的完整 `make check` 按用户要求由其终端运行并回传，助手查收。
3. **待做 R4 接口：** 按 [R4 runtime 任务](ATTACK_PROGRAM_R4_RUNTIME_TASK.md) 接可信开发候选、真实 runtime/relay 原始观测、预算/封存与独立复核。先完成离线与 fake 验证；真实模型/API、bind、正式库冻结、正式实验均需新批次明确授权。
4. **正式研究前置：** 核定独立 held-out test 组、预注册三臂任务/预算、建立真实证据库和独立准入。当前 synthetic 工程库与 scripted 结果不得作为真实成功率或视图收益。

历史运行数据保留只读；本次不 commit/push/reset/clean。
