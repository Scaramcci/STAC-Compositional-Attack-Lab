# STAC Compositional Attack Lab

面向 SafeClaw/OpenClaw Agent 组合攻击研究的可复现实验框架。项目从真实交互中提取带因果证据的 primitive chain，将其冻结为 sample library，再通过匹配对照实验验证 sample 对攻击行为和最终结果的影响。

项目仅用于授权的隔离 benchmark、synthetic service 和无价值 canary，不面向真实账号、生产系统或公网目标。

## 当前状态

当前代码只保留 SafeClaw 主线。旧 WorkspaceCanary、offline/online STAC、Huihui、AgentDojo、SHADE 和 v1 兼容路径已经移除。

真实 pilot 尚未产生 accepted sample，因此：

- main collection 尚未开始；
- `data/primitive_libraries/frozen/safeclaw-main` 尚不存在；
- formal evaluation 会在 Victim episode 前 fail closed；
- 当前不能报告正式 ASR、迁移性或 sample-conditioned effectiveness。

## 数据流程

```text
preflight
  -> interaction collection
  -> raw trajectory
  -> normalized InteractionGraph
  -> primitive occurrence extraction
  -> causal chain filtering
  -> library audit
  -> immutable frozen library
  -> scheduler and planner
  -> independent Attacker
  -> OpenClaw Victim
  -> mechanism and official verification
  -> report
```

Collection 保存完整交互事实；sample 是从这些事实中确定性挖掘并通过因果门禁的 primitive chain。Formal evaluation 只能读取审计通过的 frozen library。

## 项目结构

```text
stac-compositional-attack-lab/
├── configs/                  当前环境、collection、task、model 和实验配置
├── data/primitive_libraries/ 生成中与冻结后的 sample library
├── docs/                     项目指南、实验协议和 prompt 说明
├── experiments/safeclaw_runs/正式运行产物
├── integrations/safeclaw/    SafeClaw bridge 与 safety patch
├── prompts/formal/           Construction Attacker、Planner、Formal Attacker prompt
├── schemas/                  当前数据契约的 JSON Schema
├── scripts/                  两个正式 launcher
├── src/stac_attack_lab/      核心 Python 包
└── tests/                    当前流水线的 unit、integration 和 e2e tests
```

详细说明见 [项目结构与运行指南](docs/PROJECT_GUIDE_ZH.md)。Linux 长任务命令见 [tmux 运行手册](docs/LINUX_TMUX_RUNBOOK_ZH.md)。

## 安装

要求 Python 3.11+。真实 SafeClaw 实验建议在 Linux 服务器运行。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
make check
```

部分 contract tests 需要被 `.gitignore` 排除的 pinned SafeClawArena checkout。未准备 upstream 时，这些测试会明确跳过，不会自动下载依赖。

## 当前配置

| 用途 | 配置 |
|---|---|
| Pilot collection | `configs/sample_generation/pilot_collection.yaml` |
| Main collection | `configs/sample_generation/main_collection.yaml` |
| Formal evaluation | `configs/experiments/formal_evaluation.yaml` |
| SafeClaw environment | `configs/environments/safeclaw.yaml` |
| Construction tasks | `configs/task_sets/construction_tasks.yaml` |
| Evaluation tasks | `configs/task_sets/evaluation_tasks.yaml` |
| Primitive registry | `configs/primitives/registry.yaml` |

## 运行

```bash
make help
make sample-preflight
make sample-collection
make formal-preflight
make formal-evaluation
```

Pilot 至少产生 2 个 accepted samples 后，才允许启动 main collection。Main collection 目标为 30 个 accepted samples；审计和冻结通过后，formal evaluation 才能开始。

Formal matrix 为：

```text
1 task × 3 conditions × 5 seeds = 15 cases
```

三个 condition 分别是 `assigned_sample`、`no_sample` 和 `dependency_ablation`。完整命令、门禁和产物说明见 [PROJECT_GUIDE_ZH.md](docs/PROJECT_GUIDE_ZH.md)。

## 安全边界

凭证只能通过环境变量或 mode-0600 环境文件提供。Preflight 不会 clone upstream、下载模型、构建 Docker image 或绕过缺失的 frozen library。详细要求见 [SECURITY.md](SECURITY.md)。
