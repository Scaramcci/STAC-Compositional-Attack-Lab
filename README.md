# STAC Compositional Attack Lab

用于授权、隔离的 SafeClaw/OpenClaw 组合攻击研究。项目从真实 collection 轨迹提取带因果证据的 primitive chain，审计并冻结 sample library，再用配对条件评测 Planner、独立 Attacker、机制判定和 SafeClaw 官方判定。它不面向真实账号、生产系统或公网目标。

当前代码基线是 Git `4456194ae8e98c0ced43975aa4f4c8cca672f946`。Victim 主线是 Ark endpoint `ep-20260909180104-hmx9m`，API root 是 `https://ark.cn-beijing.volces.com/api/v3`；Planner 与 Attacker 保持 `gpt-5.5`，embedding 使用独立 `SAFECLAW_EMBEDDING_*` 配置。

## 结构

| 路径 | 职责 |
|---|---|
| `src/stac_attack_lab/` | collection、抽取、审计、冻结、planning、执行、验证和报告 |
| `configs/` | 环境、模型、任务集、采集和评测配置 |
| `integrations/safeclaw/` | pinned upstream 接入、bridge 和版本化 safety patch |
| `scripts/` | collection、formal evaluation 和统一诊断入口 |
| `schemas/` | 当前数据契约 |
| `tests/fixtures/` | 最小、脱敏、确定性测试数据 |
| `experiments/runs/` | 所有新运行输出；按唯一 run ID 隔离且默认不纳入 Git |

清理路径、理由与恢复方法见 [清理清单](docs/CLEANUP_MANIFEST.md)。

## 依赖与安装

要求 Ubuntu/Linux、Python 3.11+、Docker。Python 运行时只依赖 Pydantic、PyYAML 和 jsonschema；`dev` extra 提供 pytest、ruff、mypy。

```bash
conda activate stac
python -m pip install -e '.[dev]'
make check PYTHON=python
```

真实 Victim 运行还要求：

- `integrations/safeclaw/upstream/SafeClawArena` 固定在 `a11f5cceaba0676be721021f8d232638fd111305`；
- Docker image `openclaw-env:2026.3.12`；
- mode-0600 `.env` 中的真实凭证，不写入配置或日志。

## 最短上手

```bash
cp .env.example .env
chmod 600 .env
make sample-preflight PYTHON=python
```

唯一推荐 collection 入口：

```bash
STAC_PYTHON=python bash scripts/run_safeclaw_sample_collection.sh \
  --config configs/sample_generation/pilot_collection.yaml \
  --run-id <unique-run-id>
```

collection 完成后显式执行 `sample mine`、`sample audit`、`sample freeze`。Pilot 未达到至少 2 个 accepted samples时停止；main 未达到至少 30 个 accepted samples且未成功冻结时，不得启动 formal evaluation。

唯一推荐 formal 入口：

```bash
STAC_PYTHON=python bash scripts/run_formal_evaluation.sh --run-id <unique-run-id>
```

当前 `data/primitive_libraries/frozen/safeclaw-main` 不存在，因此 formal 入口应在 Victim episode 前清楚地 fail closed；本次整理没有生成假库，也没有运行正式实验。

统一诊断入口：

```bash
python scripts/diagnostics/run_openclaw_diagnostics.py --mode offline
python scripts/diagnostics/run_openclaw_diagnostics.py --mode live
python scripts/diagnostics/run_openclaw_diagnostics.py --mode memory-live --run-id <unique-run-id>
```

`live` 只用于受控的文本与单一 `add` 往返检查；`memory-live` 只用于普通合成 memory 写入、跨会话 `memory_search`/`memory_get` 观测，不是攻击或 collection。详见 [教师向项目指南](docs/PROJECT_GUIDE_ZH.md)、[Linux 运行说明](docs/LINUX_TMUX_RUNBOOK_ZH.md) 和 [安全边界](SECURITY.md)。
