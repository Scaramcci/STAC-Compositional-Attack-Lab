# Scripts

| 命令 | 用途与退出语义 |
|---|---|
| `bash scripts/run_cross_session_revalidation.sh prepare` | 创建唯一、默认禁用真实执行的复验目录，写入新 provenance/configuration review；不访问 provider。成功 0。 |
| `bash scripts/run_cross_session_revalidation.sh offline --run-root PATH --collection COLLECTION` | collection reanalysis：读取已有 collection，重新 normalize/mine/audit/admission；不叫 bridge replay。 |
| `bash scripts/run_cross_session_revalidation.sh offline --run-root PATH --bridge-responses RESPONSES.jsonl` | true bridge replay：要求 initialize/pre-state、每个 action/response/post-state 和 finish，经 live 共用 driver mapper 生成新 source events 后再 mine/audit/admission。缺字段或坏行返回 blocked，不猜 action。 |
| `bash scripts/run_cross_session_revalidation.sh live --run-root PATH --authorize-live` | 仅在单独授权后运行已经显式启用的 prepared run；原子 `launch.marker` 防止同一 run 重复/并发启动，随后即使 collection partial/error 也尽可能执行离线 mine/audit/admission。执行或离线阶段失败均返回非 0。 |
| `bash scripts/run_safeclaw_sample_collection.sh` | canonical pilot/main collection（需单独授权）。 |
| `bash scripts/run_formal_evaluation.sh` | formal evaluation（需 frozen library 和单独授权）。 |

复验入口不复制历史 `experiments/runs`，不自动启用 live，不探测 provider，也不负责清理其他 run。prepare 会验证模板并写禁用配置、不可变 prepared snapshot、配置审核和 provenance；live 必须同时有仅改变 `execution_enabled` 的运行配置和 `--authorize-live`。launch reservation 在 collection 前原子创建，失败进程不能覆盖获胜进程的 live review/summary；可能已产生请求后的失败不会删除 marker。`max_tokens` 是 collection action 后累计的 Victim usage 检查，不是请求前硬 token 上限。

每次 offline 都写 `<RUN>/analyses/<mode-timestamp-id>/`，不覆盖旧分析。退出码：0 表示所需离线检查通过但 runtime review 仍可 pending；10 表示检查完成但门槛未满足；20 表示输入不足/blocked；30 表示配置或程序错误。live 的 2 表示执行和离线检查完成、等待 runtime review。查看 `<analysis>/offline_summary.json`、`offline_provenance.json` 和 `bridge_replay_diagnostics.json`；历史输入只读引用，不得把派生报告写回历史 run。

`inputToolResultCallIds` 仍没有可信生产者并始终只作诊断。当前 relay/bridge 路径可生成 request-boundary context projection；版本化的 exact UTF-8 verifier 仅在显式 synthetic/experimental policy 下复算强派生，正式默认禁用。fake HTTP/replay 成功只证明工程链路，不证明真实模型、攻击或 official outcome。默认禁用准备命令为：

```bash
STAC_PYTHON=.venv/bin/python bash scripts/run_cross_session_revalidation.sh prepare \
  --template configs/sample_generation/cross_session_revalidation.disabled.json \
  --run-id <new-unique-run-id>
```

该命令仅生成 `execution_enabled=false` 配置，不是 live 授权。任何单条真实兼容性复验仍需单独审核 policy、provider payload 形状、预算和最终配置后再授权。
