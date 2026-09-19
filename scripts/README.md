# Scripts

| 命令 | 用途与退出语义 |
|---|---|
| `bash scripts/run_cross_session_revalidation.sh prepare` | 创建唯一、默认禁用真实执行的复验目录，写入新 provenance/configuration review；不访问 provider。成功 0。 |
| `bash scripts/run_cross_session_revalidation.sh offline --run-root PATH [--collection PATH]` | 对已有 collection 做重新 normalize/mine/audit/admission；每次写入新的 analysis ID。阶段失败返回非 0。 |
| `bash scripts/run_cross_session_revalidation.sh offline --run-root PATH --bridge-responses PATH` | 要求完整 action/response/state JSONL，经当前 live driver mapping 真正重建 source events，再 mine/audit/admission；不调用 provider。 |
| `bash scripts/run_cross_session_revalidation.sh live --run-root PATH --authorize-live` | 仅在单独授权后运行已经显式启用的 prepared run；原子 `launch.marker` 防止同一 run 重复/并发启动，随后即使 collection partial/error 也尽可能执行离线 mine/audit/admission。执行或离线阶段失败均返回非 0。 |
| `bash scripts/run_safeclaw_sample_collection.sh` | canonical pilot/main collection（需单独授权）。 |
| `bash scripts/run_formal_evaluation.sh` | formal evaluation（需 frozen library 和单独授权）。 |

复验入口不复制历史 `experiments/runs`，不自动启用 live，不探测 provider，也不负责清理其他 run。prepare 只写禁用配置、配置审核和 provenance；live 必须同时有配置中的 `execution_enabled=true` 和命令行 `--authorize-live`。launch 防重只约束该 run 的本地产物，随机新 run ID 不能证明全局没有重复请求。`max_tokens` 是 collection action 后累计的 Victim usage 检查，不是请求前硬 token 上限。

离线查看：`jq . <RUN>/offline_summary.json`，再按其中 `analysis_root` 查看 `offline_provenance.json`、`bridge_replay_diagnostics.json` 和 `offline-mining/library_audit.json`。`--collection` 是 collection reanalysis；`--bridge-responses` 是 driver replay，二者不是同义词。bridge JSONL 缺 action、response 或 state、存在坏行时明确失败，不按工具顺序猜测。输入路径必须位于仓库内；派生报告写入 prepared run 的新 analysis 目录，不回写历史 run。

状态语义：离线所有必需阶段通过返回 0；门槛未满足或输入/程序错误返回非 0。`runtime_review=pending` 与 `execution_authorization=absent` 不等于结构失败，也不会自动授权 live。`pilot_admitted` 是结构、运行时审核和授权全部满足后的保守聚合，本轮保持 false。
