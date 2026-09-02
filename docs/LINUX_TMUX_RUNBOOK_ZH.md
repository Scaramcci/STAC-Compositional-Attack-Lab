# Linux 服务器 tmux 运行手册

本文给出从 pilot collection 到 formal evaluation 的实际命令。所有命令都在项目根目录执行；请把 `/absolute/path/stac-compositional-attack-lab` 替换为服务器上的绝对路径。

## 1. 一次性准备

```bash
cd /absolute/path/stac-compositional-attack-lab
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
cp .env.example .env
chmod 600 .env
```

在 `.env` 中填写 `OPENAI_BASE_URL`、`OPENAI_API_KEY`、`SAFECLAW_MODEL` 和三个 `SAFECLAW_EMBEDDING_*` 变量。不要把凭证直接写进 tmux 命令或提交到 Git。

确认外部环境：

```bash
git -C integrations/safeclaw/upstream/SafeClawArena rev-parse HEAD
docker image inspect openclaw-env:2026.3.12 >/dev/null
make check
```

SafeClawArena 必须位于 `integrations/safeclaw/upstream/SafeClawArena`，commit 必须是 `a11f5cceaba0676be721021f8d232638fd111305`。

## 2. Pilot collection

创建 tmux 会话：

```bash
tmux new-session -s stac-pilot
```

在会话内运行：

```bash
cd /absolute/path/stac-compositional-attack-lab
bash scripts/run_safeclaw_sample_collection.sh \
  --config configs/sample_generation/pilot_collection.yaml
```

按 `Ctrl-b d` 退出但不停止任务。重新进入和查看状态：

```bash
tmux attach-session -t stac-pilot
tmux list-sessions
tail -f data/primitive_libraries/generated/safeclaw-pilot/tmux-collection.log
```

即使部分 trajectory 失败，collection 仍会保存已产生的记录。关键文件：

```text
data/primitive_libraries/generated/safeclaw-pilot/
├── tmux-collection.log
└── interactions/raw/safeclaw-construction-pilot/
    ├── collection_manifest.json
    ├── collection_failures.jsonl
    └── trajectories/<trajectory-id>/
        ├── raw_trajectory.json
        ├── source_events.jsonl
        └── checkpoints.jsonl
```

## 3. Pilot mining 与审计

Collection 结束后创建新会话：

```bash
tmux new-session -s stac-pilot-mine
```

在会话内运行：

```bash
cd /absolute/path/stac-compositional-attack-lab
export PYTHONPATH=src
set -o pipefail

.venv/bin/python -u -m stac_attack_lab.cli sample mine \
  --collection data/primitive_libraries/generated/safeclaw-pilot/interactions/raw/safeclaw-construction-pilot \
  2>&1 | tee -a data/primitive_libraries/generated/safeclaw-pilot/tmux-mine.log

.venv/bin/python -u -m stac_attack_lab.cli sample audit \
  --library data/primitive_libraries/generated/safeclaw-pilot/library \
  2>&1 | tee -a data/primitive_libraries/generated/safeclaw-pilot/tmux-audit.log
```

Pilot 的目标是至少 2 个 accepted samples。若审计输出 `accepted_sample_target_not_met`，保留整个 `safeclaw-pilot` 目录用于分析，不执行 freeze，也不要把它作为正式证据。

## 4. Pilot 失败时演示 evaluation gate

如果只是想确认 evaluation 会怎样失败，可以运行：

```bash
tmux new-session -s stac-evaluation-gate
```

会话内：

```bash
cd /absolute/path/stac-compositional-attack-lab
bash scripts/run_formal_evaluation.sh --run-id safeclaw-formal-gate-check
```

当前 formal 配置只接受 `data/primitive_libraries/frozen/safeclaw-main`。Pilot 或 main 未通过 audit/freeze 时，该命令应 fail closed；原因保存在：

```text
experiments/safeclaw_runs/safeclaw-formal-gate-check/tmux-run.log
```

不要复制失败的 library 来绕过门禁。

## 5. Main collection

只有 pilot 审计通过后才运行 main：

```bash
tmux new-session -s stac-main-collection
```

会话内：

```bash
cd /absolute/path/stac-compositional-attack-lab
bash scripts/run_safeclaw_sample_collection.sh \
  --config configs/sample_generation/main_collection.yaml
```

完成后在新的 tmux 会话中执行 mining、audit 和 freeze：

```bash
tmux new-session -s stac-main-freeze
```

```bash
cd /absolute/path/stac-compositional-attack-lab
export PYTHONPATH=src
set -o pipefail

.venv/bin/python -u -m stac_attack_lab.cli sample mine \
  --collection data/primitive_libraries/generated/safeclaw-main/interactions/raw/safeclaw-construction-main \
  2>&1 | tee -a data/primitive_libraries/generated/safeclaw-main/tmux-mine.log

.venv/bin/python -u -m stac_attack_lab.cli sample audit \
  --library data/primitive_libraries/generated/safeclaw-main/library \
  2>&1 | tee -a data/primitive_libraries/generated/safeclaw-main/tmux-audit.log

.venv/bin/python -u -m stac_attack_lab.cli sample freeze \
  --library data/primitive_libraries/generated/safeclaw-main/library \
  --version safeclaw-main \
  2>&1 | tee -a data/primitive_libraries/generated/safeclaw-main/tmux-freeze.log
```

Main 必须至少有 30 个 accepted samples，audit 通过后 freeze 才会成功。

## 6. Formal evaluation

```bash
tmux new-session -s stac-formal
```

会话内：

```bash
cd /absolute/path/stac-compositional-attack-lab
bash scripts/run_formal_evaluation.sh \
  --run-id safeclaw-formal-main
```

脚本依次执行 PSE smoke、environment preflight、15-case matched evaluation、run audit 和 report。中断后用相同 run id 再次执行即可按 case 恢复：

```bash
bash scripts/run_formal_evaluation.sh \
  --run-id safeclaw-formal-main
```

运行日志：

```bash
tail -f experiments/safeclaw_runs/safeclaw-formal-main/tmux-run.log
```

## 7. 查看攻击与模型对话

每个完成的 formal case 都有一份聚合记录：

```bash
find experiments/safeclaw_runs/safeclaw-formal-main/cases \
  -name complete_interaction_record.json -print
```

查看攻击动作、模型回答和官方结果：

```bash
jq '{
  planner: .planner_stage,
  attacker: .attacker_stage,
  attack: .attack_realization,
  victim_sessions: .victim_stage.sessions,
  victim_transcript: .victim_stage.session_transcript_raw,
  mechanism: .primitive_evaluation.mechanism_evaluation,
  official: .official_evaluation
}' experiments/safeclaw_runs/safeclaw-formal-main/cases/<case-id>/complete_interaction_record.json
```

逐次模型调用和逐动作请求/回应分别位于：

```text
experiments/safeclaw_runs/<run-id>/cases/<case-id>/model_calls.jsonl
experiments/safeclaw_runs/<run-id>/runner/<case-id>/attempts/<attempt-id>/formal_action_journal.jsonl
```

失败 case 会保留脱敏后的失败阶段、异常类型和消息：

```text
experiments/safeclaw_runs/<run-id>/cases/<case-id>/failure_events.jsonl
```

查看整个运行的完成情况：

```bash
jq '.' experiments/safeclaw_runs/safeclaw-formal-main/formal_progress.json
jq '.' experiments/safeclaw_runs/safeclaw-formal-main/formal_report.json
```

所有记录都会进行凭证脱敏。公开给导师前仍应运行 `safeclaw audit-run`，并避免上传 `.env`、外部 upstream checkout、Docker volume 或未经审计的原始凭证文件。
