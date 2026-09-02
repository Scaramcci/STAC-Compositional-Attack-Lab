# Security

## Scope

本项目只允许在授权的 SafeClaw/OpenClaw 隔离 benchmark 中运行。任务必须使用 synthetic service、隔离容器和无价值 effect；禁止连接真实账号、生产数据或公网目标。

## Required controls

- SafeClawArena checkout 必须固定到配置声明的 commit。
- Safety patch 只应用于临时副本，不修改 upstream。
- Docker、模型、embedding、磁盘和 task hash 必须通过 preflight。
- Materializer 只能写入 task set 明确允许的 JSON pointer。
- Official evaluator、private oracle、credential 和 success condition 不得进入模型输入。
- Chat 与 embedding endpoint/key 使用独立环境变量。
- 日志和 artifact 在落盘前进行 secret scan 与 redaction。
- Frozen library 不得覆盖；任何修改都必须产生新版本。

## Fail-closed conditions

出现以下情况必须停止：preflight 失败、upstream/hash/patch 不一致、pilot 未达门槛、library audit 失败、public/private view 泄漏、secret scan 失败、pair invariant 失败或 formal matrix 不完整。

## Incident response

如果凭证或不安全 payload 被写入项目，应立即停止实验、删除受影响 artifact、轮换凭证，并重新生成相关 collection、library 和 run。
