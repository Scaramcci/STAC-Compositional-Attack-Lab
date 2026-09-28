# 当前项目结构

| 路径 | 用途 |
|---|---|
| `src/stac_attack_lab/attack_program/` | R1–R3 合同、物化、观测/裁决、开发样本、三臂 Planner、replay/audit、CLI |
| `src/stac_attack_lab/models/` | Planner 生产 OpenAI-compatible HTTP client 与请求账本 |
| `src/stac_attack_lab/{contracts,hashing,schema_registry,cli}.py` | 共享严格模型、哈希、当前 schema 与薄入口 |
| `configs/attack_program/` | 组级 split 与当前 Planner prompt |
| `scripts/attack_program/` | 离线命令包装与单命令演示 |
| `schemas/attack_program_*.schema.json` | 当前合同的生成 schema |
| `tests/integration/test_attack_program_*.py` | R1–R3 语义、完整链路、fake HTTP 回归 |
| `integrations/safeclaw/upstream/SafeClawArena/` | pinned 官方任务、schema 与 judge，只读输入 |
| `integrations/safeclaw/patches/a11f5cce-safety.patch` | 隔离安全补丁 |
| `experiments/runs/`、`data/` | 历史运行证据与输入，不随代码清理改写 |

新路线不读取旧 capability、flow、legacy Planner 或 formal 模块。当前演示仅 synthetic；真实 runtime 接口见 [R4 任务](ATTACK_PROGRAM_R4_RUNTIME_TASK.md)。
