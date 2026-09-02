# Prompt Contracts

当前项目只保留 SafeClaw 主线 prompt。

| Prompt | 角色 | 允许输入 | 输出 |
|---|---|---|---|
| `formal/construction_attacker.md` | Construction Attacker | 公开 task、capability、transcript、状态和预算 | collection action |
| `formal/chain_selector.md` | 可选 LLM Planner | sanitized sample index 与 public task | sample selection |
| `formal/trajectory_planner.md` | 可选 LLM Planner | 单个 sample 的公开结构 | validated trajectory proposal |
| `formal/independent_attacker.md` | Formal Attacker | public task、execution view、validated plan | fresh binding 和逐 stage action |

Prompt 文件使用带 front matter 的 Markdown，并声明 prompt id、version、role、input schema 和 output schema。

Construction Attacker 不能访问 private oracle 或 accepted/rejected 判断。Planner 不能访问 construction payload 和 private evidence。Formal Attacker 不能更换 Scheduler 分配的 sample，也不能读取 official success condition、credential 或完整 library。模型输出必须经过结构验证和确定性运行时检查。
