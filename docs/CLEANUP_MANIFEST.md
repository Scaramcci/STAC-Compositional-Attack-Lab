# 项目清理清单

整理基线：Git commit `4456194ae8e98c0ced43975aa4f4c8cca672f946`，整理前工作区干净。

| 路径 | 原用途与引用核查 | 处置与理由 | 恢复方式 |
|---|---|---|---|
| `experiments/safeclaw_formal_smoke_retry10/` | 旧 formal smoke 输出；仅由同名旧配置和历史进度文档引用，代码、测试、CLI、schema 与构建不读取 | 删除；属于已授权旧运行派生产物 | `git restore --source=4456194 -- <path>` |
| `experiments/safeclaw_v3_smoke/` | retry 1–23、重算、日志与旧样本生成树；测试已使用 `tests/fixtures/`，无动态加载依赖 | 删除；旧 collection/样本/审计输出 | 同上 |
| `experiments/stage-b-20260908-01/` 至 `stage-b-20260908-04/` | 旧 Stage B collection 与兼容探针 | 删除；旧运行输出 | 同上 |
| `experiments/stage-b-20260909-ark-01/` | 旧 Ark direct 探针 | 删除；本次统一诊断入口会生成新 run ID | 同上 |
| `experiments/stage-b-20260909-gemini-compat-01/` 至 `-03/` | 仅服务历史 Gemini 排障 | 删除；Ark 已成为当前主线 | 同上 |
| `experiments/stage-b-20260909-openclaw-mock-01/`、`-02/` | 旧 mock 捕获结果 | 删除；回归事实转入确定性测试 | 同上 |
| `data/primitive_libraries/frozen/safeclaw-v3-smoke-retry10-v3/` | 旧 smoke 冻结库；仅由旧 formal smoke 配置引用 | 删除；不是当前正式库 | 同上 |
| `configs/sample_generation/safeclaw_v3_smoke*.yaml` | 旧 smoke/retry 一次性配置，共 20 项 | 删除；由 `pilot_collection.yaml` 与 `main_collection.yaml` 取代 | 同上 |
| `configs/sample_generation/stage_b_20260908_01.json`、`stage_b_20260908_02.json` | 日期化 Stage B 一次性配置 | 删除；由当前 Ark 配置取代 | 同上 |
| `configs/experiments/formal_smoke_retry10.yaml` | 指向被删除旧冻结库和旧输出 | 删除；正式入口必须对 `safeclaw-main` fail closed | 同上 |
| `scripts/diagnostics/run_ark_direct_probe.py`、`run_openclaw_mock_integration.py`、`run_openclaw_mock_tool_integration.py` | 日期化输出、固定容器名/端口、重复诊断逻辑 | 迁移后删除；统一为可指定 run ID 的 OpenClaw/Ark 诊断入口 | 同上 |
| `docs/EXPERIMENT_ALIGNMENT_AND_REPAIR_PLAN_ZH.md` | 已执行的旧修复计划与 Gemini 历史状态 | 合并仍有效约束后删除；避免与当前 workplan 重叠 | 同上 |
| `configs/environments/safeclaw_ark.yaml` | Ark 诊断副本 | 内容迁移至唯一 `configs/environments/safeclaw.yaml` 后删除 | 同上 |
| `experiments/safeclaw_runs/`、`data/primitive_libraries/generated/` | 两套旧输出根 | 迁移为空的统一 `experiments/runs/`；不搬运旧产物 | Git 恢复 `.gitkeep`；运行产物本就不应提交 |

保留：`tests/fixtures/**`（最小、脱敏、确定性）、`integrations/safeclaw/upstream/SafeClawArena`（忽略的 pinned checkout）、`integrations/safeclaw/patches/**`、upstream 许可证与来源说明、`configs/task_sets/**`、`configs/primitives/registry.yaml`、`schemas/**`、`.env` 和 `.git`。

删除前核查覆盖 import、CLI 参数、配置路径、测试、`rglob`/动态加载、Makefile 和 launcher。清理后必须再次运行完整测试与路径引用扫描；若出现依赖旧树的失败，则从上述 commit 只恢复所需最小数据并转成 `tests/fixtures/`，不恢复整棵实验目录。

清单中的删除与迁移均已执行。整理过程中产生的两次失败离线诊断仅含 synthetic 数据，已由通过版本替代并删除；它们未跟踪、不可通过 Git 恢复，也不包含研究原始任务或凭证。最终保留的本轮诊断位于被忽略的唯一 run ID 目录，后续可直接删除而不影响测试。
