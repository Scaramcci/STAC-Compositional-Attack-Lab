# Attack Program 实验协议与证据边界

## 当前工程范围

R1 对 pinned SafeClawArena task/schema/judge 建目录，明确可改的低信任输入与组级 split，安全物化候选，并从原始观测执行官方逐项检查和独立裁决。R2 记录全部开发尝试，形成九原语状态及 raw/structured 双公开视图，冻结 `synthetic_only` 工程库并独立 replay/audit。R3 从同一库共同检索，为 `no_library`、`raw_examples`、`primitive_examples` 三臂构造多样本请求，严格校验 Planner 计划、安全物化、执行适配、完整分母报告和独立 replay/audit。

当前 R2/R3 正例由 synthetic fixture 或 scripted transport 产生，属于工程验证。HTTP fake 仅验证生产 client、请求账本和解析器，不是模型实验。`unknown`、`incomplete`、`infra_failure`、`unsupported` 与 `verified_negative` 分列；不把缺证据当行为失败。工具请求、声称成功、实际提交与资源变化分开。内容 hash 仅证明一致性，不证明来源真实性或因果关系。

## 正式研究门

正式研究库需真实开发 producer、可信 runtime 原始观测、独立证据复核、去泄漏 public/private 视图及独立 held-out test 组。正式三臂需要预注册任务组、相同检索与执行预算、逐尝试分母及真实授权。未满足这些门时，报告只能标注 `engineering_only_synthetic`，不能报告视图收益、真实成功率或 intervention success。

真实模型/API、付费探针、bind、正式库冻结和正式实验按批次授权；`execution_enabled`、测试通过或历史授权都不能代替新批次授权。参见 [SECURITY.md](../SECURITY.md)。
