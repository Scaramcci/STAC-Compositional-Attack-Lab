# STAC Compositional Attack Lab

用于授权、隔离的 SafeClaw/OpenClaw 组合攻击研究。项目从真实 collection 轨迹提取带因果证据的 primitive chain，审计并冻结 sample library，再用配对条件评测 Planner、独立 Attacker、机制判定和 SafeClaw 官方判定。它不面向真实账号、生产系统或公网目标。

当前审查 HEAD 始终以 `git rev-parse HEAD` 和 run provenance 为准；不要在多处复制易失效的 commit 值。复验默认入口为版本化 `revalidation prepare/offline`，默认 `execution_enabled=false`；不要从历史 run 复制配置或审核结论。Victim 主线是 Ark endpoint `ep-20260909180104-hmx9m`，API root 是 `https://ark.cn-beijing.volces.com/api/v3`；Planner 与 Attacker 使用 `gpt-5.6-sol`，embedding 使用独立 `SAFECLAW_EMBEDDING_*` 配置。

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

跨会话单条复验的安全入口（prepare/offline 均不访问 provider）：

```bash
STAC_PYTHON=python bash scripts/run_cross_session_revalidation.sh prepare
STAC_PYTHON=python bash scripts/run_cross_session_revalidation.sh offline \
  --run-root experiments/runs/<prepared-run>
```

已有 collection 的重新分析使用 `--collection`。只有包含每一步 action、bridge response 和 state 的 JSONL 才能使用 `--bridge-responses`；该模式会调用当前 driver mapping 重建 source events。字段统计或历史 collection 重挖不称为 bridge replay。当前 pinned runtime 尚不生产可验证的强消费证据，因此离线 readiness 不代表“只差一次 live 即可通过”。

真实 `live` 子命令要求另行授权、prepared config 显式启用以及 `--authorize-live`，并以同一 run 内的原子标记防重复启动；详见 [scripts/README.md](scripts/README.md)。

Primitive v3 保持为显式离线分析，不改变 legacy mine 默认语义：

```bash
python -m stac_attack_lab.cli flow profile-validate
python -m stac_attack_lab.cli flow reanalyze --input <graph-or-collection> \
  --output-root experiments/runs/<new-run>/analyses --terminal-outputs
```

输出包含独立 `analysis_manifest.json`、effect graph、依赖切片、四层准入和公共汇总。
详见 [Primitive v3 实现说明](docs/PRIMITIVE_V3_IMPLEMENTATION.md)。

正常交互采集阶段 A 提供独立、默认禁用的契约和离线 fixture 闭环：

```bash
python -m stac_attack_lab.cli benign validate
python -m stac_attack_lab.cli benign prepare
python -m stac_attack_lab.cli benign collect-fixture
```

`collect-fixture` 不访问模型服务；真实正常采集尚未授权或实现。详见
[阶段 A 交接](docs/BENIGN_COLLECTION_STAGE_A.md)。

`offline --collection` 是旧 collection 的重新分析；`offline --bridge-responses` 才是通过当前 driver mapping 重建 source events 的 bridge replay。后者要求完整 initialize/pre-state、action/response/post-state 和 finish 记录。`inputToolResultCallIds` 仍不可信；production relay 已能记录受控 request-boundary projection，但真实 provider 协议兼容性尚未复验，强派生规则默认禁用且仅限 synthetic experimental policy。因此 synthetic replay 成功不能解释为真实攻击、正式准入或 official outcome。

统一诊断入口：

```bash
python scripts/diagnostics/run_openclaw_diagnostics.py --mode offline
python scripts/diagnostics/run_openclaw_diagnostics.py --mode live
python scripts/diagnostics/run_openclaw_diagnostics.py --mode memory-live --run-id <unique-run-id>
```

`live` 只用于受控的文本与单一 `add` 往返检查；`memory-live` 只用于普通合成 memory 写入、跨会话 `memory_search`/`memory_get` 观测，不是攻击或 collection。详见 [项目结构说明](docs/PROJECT_STRUCTURE_ZH.md)、[Linux 运行说明](docs/LINUX_TMUX_RUNBOOK_ZH.md) 和 [安全边界](SECURITY.md)。
