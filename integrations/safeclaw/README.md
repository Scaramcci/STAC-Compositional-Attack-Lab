# SafeClawArena Integration

本集成只用于授权的 SafeClawArena benchmark、synthetic Sim-Google/workspace state 和无价值 effect。

## Pinned environment

- Upstream path：`integrations/safeclaw/upstream/SafeClawArena`
- Commit：`a11f5cceaba0676be721021f8d232638fd111305`
- Docker image：`openclaw-env:2026.3.12`
- Safety patch：`patches/a11f5cce-safety.patch`

Upstream checkout 被 `.gitignore` 排除，必须由操作者准备。Preflight 不会 clone、pull、build image 或修改 upstream。

## Components

| 文件 | 作用 |
|---|---|
| `construction_bridge.py` | Collection 阶段的 Construction Attacker -> OpenClaw Victim bridge |
| `formal_bridge.py` | Formal Attacker 逐 stage action -> OpenClaw Victim observation bridge |
| `patches/a11f5cce-safety.patch` | 在临时 upstream copy 上移除敏感 official result 字段并注入受控模型配置 |

Patch 只应用到 ephemeral copy，pinned upstream 本身保持不变。

## Collection path

`SafeClawConstructionInteractionAdapter` 驱动完整、stateful Victim。Construction Attacker 只接收 public task、component/capability inventory、公开 transcript/status 和剩余预算。Bridge 返回 response、tool call 和 public state delta，随后记录为 raw source event 和 checkpoint。

入口：

```bash
bash scripts/run_safeclaw_sample_collection.sh \
  --config configs/sample_generation/<authorized-version>.yaml
```

Launcher 只执行 preflight 和 collection；mining、audit、freeze 必须独立运行。

## Formal path

`scripts/run_formal_evaluation.sh` 当前默认使用：

- `configs/experiments/safeclaw_formal_v2.yaml`
- `configs/environments/safeclaw_openclaw_v2.yaml`
- run id `safeclaw-formal-v2-main`

执行顺序：

```text
official PSE smoke
  -> environment preflight
  -> resume-safe formal matrix
  -> recorder audit
  -> formal report
```

Sample conditions 会调用独立 Formal Attacker；`no_sample` 是 deterministic legal baseline。Materializer、bridge、runner 和 official evaluator 都不是 Attacker。

当前 matrix 是 1 task × 3 conditions × 5 seeds = 15 cases。真实 frozen library 尚不存在，因此 formal run 应在 Victim episode 之前 fail closed。

## Task materialization

只有带显式 `formal_experiment` overlay 的 task 才能 materialize。允许修改的 JSON pointer 必须预注册。包含 evaluation、success/safe condition、oracle、canary、auth、credential、token、password 或 secret 的 pointer 会被拒绝。

## Evidence and resume

每个 case 记录 assignment、plan、Attacker input/action、binding manifest、materialized task、Victim transcript/state、InteractionGraph、primitive extraction、mechanism verdict、official verdict 和 complete interaction record。

Formal execution 使用 whole-episode attempt。中断 attempt 被保留并标记 abandoned；恢复不会把不同 Victim container 的状态拼接起来。复用相同 run id 时，已完成 case 会跳过。

## Credentials

Chat 与 embedding endpoint/key 通过独立环境变量提供。临时 model config 使用 mode 0600，secret scanner 覆盖 endpoint 和 key 值。隐藏 chain-of-thought 不会被请求或记录。
