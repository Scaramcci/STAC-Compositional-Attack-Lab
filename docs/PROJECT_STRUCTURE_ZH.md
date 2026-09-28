# 当前项目结构

| 路径 | 用途 |
|---|---|
| `src/stac_attack_lab/attack_program/` | R1–R4 合同、物化、观测/裁决、开发样本、三臂 Planner、runtime/relay、replay/audit、CLI；`file_io.py` 统一排他 JSON 写入 |
| `src/stac_attack_lab/models/` | Planner 生产 OpenAI-compatible HTTP client 与请求账本 |
| `src/stac_attack_lab/{contracts,hashing,schema_registry,cli}.py` | 共享严格模型、哈希、当前 schema 与薄入口 |
| `configs/attack_program/` | 组级 split 与当前 Planner prompt |
| `scripts/attack_program/` | 离线命令包装、单命令演示与 R4 本机 fake 验收 |
| `schemas/attack_program_*.schema.json` | 当前合同的生成 schema |
| `tests/integration/test_attack_program_*.py` | R1–R4 语义、离线链路、fake HTTP 回归；R4 Docker 长链另行验收 |
| `integrations/safeclaw/upstream/SafeClawArena/` | pinned 官方任务、schema 与 judge，只读输入 |
| `integrations/safeclaw/patches/a11f5cce-safety.patch` | 隔离安全补丁 |
| `experiments/runs/`、`data/` | 历史运行证据与输入，不随代码清理改写 |

新路线不读取旧 capability、flow、legacy Planner 或 formal 模块。R4 adapter 位于 `attack_program/r4_runtime.py`，必要 relay 从清理前 `f1b4943` 迁入 `attack_program/provider_relay.py`；R4 Docker/local-fake 三案已由用户运行并经独立 replay/audit 查收，真实模型/API、bind、live 均禁用。接口见 [R4 任务](ATTACK_PROGRAM_R4_RUNTIME_TASK.md)。
