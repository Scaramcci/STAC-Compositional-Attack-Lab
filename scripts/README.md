# Scripts

| 命令 | 用途与退出语义 |
|---|---|
| `bash scripts/run_cross_session_revalidation.sh prepare` | 创建唯一、默认禁用真实执行的复验目录，写入新 provenance/configuration review；不访问 provider。成功 0。 |
| `bash scripts/run_cross_session_revalidation.sh offline --run-root PATH` | 只运行本地 mine/audit/admission，尽可能保留 partial/error 诊断；阶段失败返回非 0。 |
| `bash scripts/run_cross_session_revalidation.sh live --run-root PATH --authorize-live` | 仅在单独授权后运行已经显式启用的 prepared run；原子 `launch.marker` 防止同一 run 重复/并发启动，随后即使 collection partial/error 也尽可能执行离线 mine/audit/admission。执行或离线阶段失败均返回非 0。 |
| `bash scripts/run_safeclaw_sample_collection.sh` | canonical pilot/main collection（需单独授权）。 |
| `bash scripts/run_formal_evaluation.sh` | formal evaluation（需 frozen library 和单独授权）。 |

复验入口不复制历史 `experiments/runs`，不自动启用 live，不探测 provider，也不负责清理其他 run。prepare 只写禁用配置、配置审核和 provenance；live 必须同时有配置中的 `execution_enabled=true` 和命令行 `--authorize-live`。launch 防重只约束该 run 的本地产物，随机新 run ID 不能证明全局没有重复请求。`max_tokens` 是 collection action 后累计的 Victim usage 检查，不是请求前硬 token 上限。

离线查看：`jq . <RUN>/offline_summary.json` 与 `jq . <RUN>/offline-mining/library_audit.json`。历史输入回放必须使用新的 `<RUN>`，通过 `--collection` 和可选 `--bridge-responses` 只读引用旧输入；不得把派生报告写回历史 run。
