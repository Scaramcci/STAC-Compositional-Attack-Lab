# 下一轮任务：清理后验收与 R4 真实开发执行链接入

日期：2026-09-28。本文件接续 R3，不重复旧任务。旧路线代码清理已完成；实施前先读最新 AGENTS、SECURITY、PROGRESS、WORKPLAN，核对实际 git status/log。除当前 `attack_program` 与共享 HTTP client 外，旧 runtime/relay 模块已删除；按下文从可追溯版本迁移所需能力，不照抄旧模块路径。

## 1. 本轮目标

直接实施：**候选生成/导入→安全物化→隔离 SafeClawArena/OpenClaw→真实运行观测生产者→官方检查与独立分析→开发尝试封存→独立重放**。

先通过本机 fake provider 走真实 runtime，再准备一个可由用户执行的小规模真实开发批次。不是再做按 payload 关键词返回预置观测的演示；也不要求本轮攻击成功、正式三臂实验或大规模样本库。

当前已知 R3 主演示为3 assigned/3 completed、Planner/Victim HTTP均0、工程库3样本/5尝试。R3 ProductionPlannerTransport 用了生产客户端，但 SyntheticFixtureExecutor 仍按特定文本选择合成观测；这不能证明真实 Victim 接入。

## 2. 先查收清理，不与清理任务并行写文件

1. 核对清理者交接：保留/迁移/删除的模块、测试、脚本、配置及历史复现限制。
2. 用户已授权清理旧代码，不要因旧方案说“保留旧入口”就恢复全部旧模块。历史证据输出不删除、不改写。
3. 根据清理后代码验证 CLI help、模型/schema、R1/R2/R3专项与独立演示；处理 import 残留，更新 README/结构/脚本导航。
4. 新版质量门可以只覆盖仍受支持模块；删除旧模块的测试不等于修复旧失败，报告清理前后测试范围变化。不能跳过新主链失败制造全绿。
5. 新主链直接依赖的功能与下一步必需的 runtime 能力不同。检查以下能力是否仍在：provider relay、HTTP预扣/失败计数、deadline、隔离网络、状态快照、session实际身份、工具调用关联、seal及owned cleanup。
6. 若这些能力随旧目录删除，优先从已获授权清理前的可追溯版本提取必要实现到新中立模块，并保留相关语义测试；没有可靠来源则明确重建最小实现。不要恢复整个旧M3/legacy orchestrator，也不要只凭模块名宣称“复用完成”。
7. 不改写旧产物 source hash 以迁就迁移。旧产物可归档并记录需要旧代码版本读取；当前工程演示使用新输出和新指纹。

## 3. 最小任务和角色范围

优先采用当前已经支持、能物化和离线判分的 development 任务（如 pse-2.1-001），实际检查 catalog/split 后确定，不选新 test 任务来调试。

首个生产链仅做一份正常材料基线与一个开发攻击候选，彼此独立 workspace/run；若任务需要双 session，执行完整官方 session 流程。不是重新执行旧F1–F6，也不先跑36矩阵。

候选入口支持两种来源：
- 文件导入：先验证 runtime，避免攻击生成器问题遮蔽执行问题；
- 有界 Attacker：后续同一入口调用 OpenAI-compatible client 生成一个严格候选，经过相同 materializer。复用 R3 transport/ledger，按实际角色记 Attacker，不误记 Planner。

本轮实现两种入口并fake验证；首个真实批次可只用文件候选，Attacker=0。后续真正模型生成的开发探索另批授权。正常用户任务/可信规则/隐藏oracle不能由生成器修改。

## 4. SafeClawArena runtime adapter

核心合同/判分保持独立；adapter接受物化任务及本批配置，输出封存观测，不向 verifier直接提交passed标签。

必须核对 pinned upstream、task/schema/judge、安全patch和image身份；patch只用于临时副本。实际执行使用隔离模拟服务，不接真实账号。

必要观测包括：
- task/candidate/materialized hash、run与attempt身份；
- provider request/response边界、真实session key及顺序；
- 工具请求/result/call id与状态；
- 初末与必要中间文件快照、资源版本、写入提交与读取版本；
- 官方session_results/pre_state/post_state；
- cleanup范围、前后owned资源集合；
- 使用量来源、失败/不确定请求和异常阶段。

不存在的映射保持unknown。工具声称写入成功不代替版本证据；不同session标签不代替实际身份。不能把新建session当Recover，不把可达当语义消费。

按官方任务要求执行共享/重置session和前置条件；不能为了得到期望链擅改session逻辑。显式区分本轮输入材料由harness预置与Victim持久写入。

将 runtime 输出投影到当前 RawObservation 版本；source=real 必须来自已校验生产bundle，不接受用户提交JSON自报real。local_fake应包含实际生产链证据而不是替换source字段。

## 5. 安全、预算与执行状态

沿用或迁移已有机制，不另造并行账本：
- 角色分开HTTP尝试上限，失败/不确定请求照计；零隐藏重试、零fallback；
- per-request timeout、单episode激活后的绝对deadline、批次授权有效期；人工等待不提前消耗未激活episode的运行时间；
- 本批唯一身份、原子launch、重复启动零请求拒绝；部分运行先查账本和进程，不自动重发；
- Victim不得直接访问公网，provider出口由受控relay代理；实际网络拓扑首请求前校验；
- 仅清理本批owned容器/网络/卷，异常也保留账本与诊断；
- secret scan与public/private投影、凭证不落盘、不打印完整环境变量。

不把embedding作为通用前置。如果选中任务/runtime确实需要，说明具体依赖并显式纳入预算，禁止意外发送。首批优先不依赖embedding。

行为未成功保留结果；基础设施错误不算攻击失败。清理或证据链失败停止依赖后续，但不删除已有观测。

## 6. 判分、样本及重放

官方实际检查结果与独立危害、效用、原语、传播贡献分列。缺观测不升级。当前PSE专用规则不适用于其他任务时明确unsupported/unknown。

真实开发attempts进入可重放归档，但本轮不自动冻结正式研究库。source/分级与synthetic库严格隔离。即便真实攻击成功，也需后续明确冻结policy；失败同样是有效开发观察。

独立replay读取封存的原始边界/状态/任务，重建观测和结果。可复用当前replay，但不能只重放已经投影的verdict。源版本漂移有明确兼容说明，历史hash保持原样。

## 7. 本机生产链验收

新增本机fake provider，支持实际OpenClaw所需JSON/SSE/tool调用格式，使用与真实入口相同的adapter、relay、collector、seal、verifier。

至少三案：正常执行、有证据的合成危害、工具拒绝或证据缺失。断言不同响应确实产生实际runtime动作/状态，不能预先写最终状态后称Victim提交。

先短时反例：默认disabled、缺授权/预算不足/非法物化零请求；send后异常仍计数；重复启动零请求；观测和候选hash不符；未知工具映射不生成Persist；错误session与cleanup失败。

集成要经过真实subprocess/container链。此类长时命令给用户运行，先完成所有代码和短时检查；给一个总Bash命令、唯一目录、退出码保存及查收命令，不让用户逐条手动协调每个阶段。

如果环境缺Docker等，交付准确阻塞与命令，不把纯fixture替代生产链验收。用户回传后先核对已有产物，不重复执行。

## 8. 编号入口与真实准备

在当前 scripts/attack_program 下提供薄入口（先检查已有编号避免冲突）：
- 零请求doctor；
- production-local-fake；
- prepare / validate / status；
- bind / run-batch（默认不可执行）；
- review / replay。

prepare冻结本批任务、材料/候选、角色配置、源码/模型/endpoint身份、HTTP和时间预算、输出。绑定不代表可无界运行；status给清晰下一条命令。

本轮可以交付 execution_enabled=false 的最小兼容批次。模型/endpoint从用户实际配置读取非敏感身份并核验，缺失则记录缺口，不默认挪用历史Annotation配置、不发可达性探针。

最终列出用户可审核的准确任务与每角色HTTP上限、重试、timeout、episode/batch时限、输出token参数、unique输出和成本控制性质。真实授权文案基于最终候选生成，禁止占位授权引用。无需此刻假定一个尚未验证的请求数。

## 9. 完成标准与边界

本轮分两个交付状态：
A. 代码/短时门通过、生产链fake待用户；B. 用户fake回传并独立查收通过、唯一真实禁用候选准备完成。没有fake查收不得宣称ready。

当前只授权代码、离线检查和本机fake；不授权任何真实模型/API/付费探针、bind/live、正式冻结或三臂真实实验，不commit/push/reset/clean。既有清理授权不扩大到历史证据删除。

持续更新PROGRESS/WORKPLAN顶部，AGENTS只更新稳定模块导航。最终回答实现文件、实际测试、产物、真实请求数、用户下一条命令及仍缺条件。

后续顺序：获授权真实小批开发→有界模型生成探索→证据分级研究库→独立held-out注册→真实三臂。无held-out不阻塞本轮development验证，但不能宣布正式研究闭环已完成。
