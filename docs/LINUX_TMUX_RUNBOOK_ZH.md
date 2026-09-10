# Linux 运行说明

所有命令在仓库根目录执行。建议使用已有 `stac` conda 环境：

```bash
conda activate stac
python -m pip install -e '.[dev]'
cp .env.example .env
chmod 600 .env
make check PYTHON=python
```

## 环境变量

| 角色 | 变量 | 当前值或用途 |
|---|---|---|
| Victim | `SAFECLAW_MODEL` | `ep-20260909180104-hmx9m` |
| Victim | `SAFECLAW_BASE_URL` | `https://ark.cn-beijing.volces.com/api/v3`；这是 API root，不追加 `/v1` |
| Victim | `SAFECLAW_API_KEY` | 服务器现有 Ark 凭证 |
| Embedding | `SAFECLAW_EMBEDDING_MODEL` | 独立 embedding endpoint |
| Embedding | `SAFECLAW_EMBEDDING_BASE_URL` | 独立 API root |
| Embedding | `SAFECLAW_EMBEDDING_API_KEY` | 独立凭证 |
| Planner/Attacker | `OPENAI_BASE_URL`、`OPENAI_API_KEY` | 现有 `gpt-5.5` 配置 |
| Launcher | `STAC_PYTHON` | 可选；例如 conda 环境中的 `python` |
| Gateway | `SAFECLAW_GATEWAY_HOST_PORT` | 可选；缺省 `0`，让 Docker 原子分配宿主端口 |

不要打印 `.env`、把 key 放进命令行，或关闭 TLS 校验。

## 端口与生命周期

| 服务 | 网络命名空间 | bind/端口 | 宿主发布 | 启停与健康检查 |
|---|---|---|---|---|
| OpenClaw gateway | 每个 Victim 容器 | `127.0.0.1:18789` | `127.0.0.1:<Docker 原子分配>`；显式端口占用会报错 | pinned judge 启动，bridge 关闭；gateway health RPC |
| Ark embedding adapter | Victim 容器 | `127.0.0.1:18790` | 否 | safety patch 启动，随 Victim 删除；`GET /health` |
| provider relay | 每次运行独立 sibling 容器 | `0.0.0.0:18791`，只在该次 Docker network 可达 | 否 | bridge 启动/关闭；`GET /health` |
| 诊断 mock / 历史 gateway 默认 | 诊断 provider 容器 / 宿主 | `127.0.0.1:19090` | 当前主线不发布 | 统一诊断脚本启停；旧 upstream 默认仅作配置记录 |

不同容器可复用内部端口。Victim 收到的 provider 地址是 sibling relay DNS，不是容器 loopback；embedding 是 Victim 自身 loopback；宿主只访问动态发布的 gateway。browser 被禁用，canvas 不单独发布，管理端口不暴露。

容器和网络名包含 UUID。Docker 在 `run -p 127.0.0.1::18789` 时原子选端口，避免“先探测后启动”的竞争。若设置固定宿主端口且已占用，启动直接失败，不会杀占用进程。成功、失败、超时都只删除本次拥有的 Victim、relay 和 network，不执行全局 prune。

## 可重复诊断

先运行无外网的严格 mock：

```bash
python scripts/diagnostics/run_openclaw_diagnostics.py \
  --mode offline --run-id diagnostic-<unique-id>
```

它验证唯一 `add` 工具、分片参数、call ID、结果 `5`、一次执行、错误 tool result、真实底层 HTTP 计数、429 硬上限和脱敏 ledger。通过后才允许：

```bash
python scripts/diagnostics/run_openclaw_diagnostics.py \
  --mode live --run-id ark-live-<unique-id>
```

Live 模式先做无工具文本，再做唯一 `add` 往返；内部硬上限为 1+2 个真实请求，单次 90 秒，无 relay 自动重试。输出统一在 `experiments/runs/<run-id>/`，默认被 Git 忽略。不要把 mock 通过称为 Ark 通过。

## tmux collection

```bash
tmux new-session -s stac-pilot
conda activate stac
STAC_PYTHON=python bash scripts/run_safeclaw_sample_collection.sh \
  --config configs/sample_generation/pilot_collection.yaml \
  --run-id <unique-run-id>
```

`Ctrl-b d` 分离，`tmux attach -t stac-pilot` 恢复。日志：

```bash
tail -f experiments/runs/<run-id>/safeclaw-pilot/tmux-collection.log
```

collection 完成后按 [项目指南](PROJECT_GUIDE_ZH.md) 单独 mine、audit、freeze。不要在 audit 失败时继续 main/formal。

## tmux formal、停止与恢复

仅在 `data/primitive_libraries/frozen/safeclaw-main` 已由合格 main library 生成后：

```bash
tmux new-session -s stac-formal
conda activate stac
STAC_PYTHON=python bash scripts/run_formal_evaluation.sh --run-id <unique-run-id>
```

中断后以同一个 `--run-id` 重跑会使用 `--resume`；不要换 ID 冒充续跑。日志和 checkpoint 位于 `experiments/runs/<run-id>/`。查看：

```bash
tail -f experiments/runs/<run-id>/tmux-run.log
PYTHONPATH=src python -m stac_attack_lab.cli safeclaw audit-run \
  --run-root experiments/runs/<run-id>
```

优先在 tmux 中发送 `Ctrl-C`，让 launcher/bridge 执行 finally 清理。若进程已异常退出，只检查带本次 run UUID 的 `stac-*` 容器和网络；不要停止其他任务或运行 Docker prune。端口占用可用 `ss -ltnp` 定位，记录 owner 后处理，不自动 kill。
