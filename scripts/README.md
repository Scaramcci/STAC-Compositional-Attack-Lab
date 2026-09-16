# Scripts

| 命令 | 用途与退出语义 |
|---|---|
| `bash scripts/run_cross_session_revalidation.sh prepare` | 创建唯一、默认禁用真实执行的复验目录，写入新 provenance/configuration review；不访问 provider。成功 0。 |
| `bash scripts/run_cross_session_revalidation.sh offline --run-root PATH` | 只运行本地 mine/audit/admission，尽可能保留 partial/error 诊断；阶段失败返回非 0。 |
| `bash scripts/run_safeclaw_sample_collection.sh` | canonical pilot/main collection（需单独授权）。 |
| `bash scripts/run_formal_evaluation.sh` | formal evaluation（需 frozen library 和单独授权）。 |

复验入口不复制历史 `experiments/runs`，不自动启用 live，不负责清理其他 run。prepare 生成的 launch 防重只约束该 run 的本地产物，随机新 run ID 不能证明全局没有重复请求。`max_tokens` 是 collection action 后累计的 Victim usage 检查，不是请求前硬 token 上限。
