# 项目协作规范

本仓库当前唯一代码路线是 `src/stac_attack_lab/attack_program/` 的 R1–R3 离线工程链。开始任务先查 `git status --short`、`git log -3 --oneline`，读本文件、`SECURITY.md`、`docs/IMPLEMENTATION_PROGRESS.md` 和 `docs/IMPLEMENTATION_WORKPLAN.md` 顶部，保护已有修改。根据目标先看合同、入口和对应集成测试，再追实现。

用户授权决定执行范围。可自主完成离线实现、synthetic fixture、测试、schema、lint/typecheck、fake HTTP 与 replay/audit。真实模型/API、付费探针、真实 Victim、bind、正式库冻结或正式实验须有覆盖该批次的明确授权。测试通过与历史授权不创造授权。未要求时不 commit/push/reset/clean；不改历史 raw、账本、封存 manifest 或库。

研究结论分开记录运行状态、输入完整性、claim verdict、结构准入、runtime review、执行授权和官方结果。未知/缺证据/基础设施失败不是 verified negative。工具请求、工具声称成功、实际提交和资源变化分开；hash 一致性不证明来源或因果。Synthetic/fake 正例只证明工程链。统计保留全部尝试分母；public view 隔离 evaluator、private oracle 与凭证。

语义缺陷先写最小失败反例，再修实现。至少覆盖身份错配、缺证据、重复/乱序、unknown、篡改、错误版本与阶段异常；用实际链路测试验证新能力。运行受影响专项，再运行适当质量门；只记录实际执行命令和结果。schema 改动生成并审查差异。进度与计划顶部持续更新检查点，区分已实现、已验证、仅合成验证及仍需真实运行。

当前导航：[结构](docs/PROJECT_STRUCTURE_ZH.md)、[协议](docs/EXPERIMENT_PROTOCOL.md)、[脚本](scripts/README.md)、[安全](SECURITY.md)。Pinned SafeClawArena task/judge 和 safety patch 位于 `integrations/safeclaw/`；不能原地修改 upstream。模型 HTTP 边界账本位于 `src/stac_attack_lab/models/openai_compatible.py`。下一阶段 runtime 接口见 `docs/ATTACK_PROGRAM_R4_RUNTIME_TASK.md`。
