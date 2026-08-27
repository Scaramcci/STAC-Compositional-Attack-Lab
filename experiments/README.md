# Experiment Outputs

| 路径 | 内容 |
|---|---|
| `runs/` | legacy online STAC evaluation |
| `safeclaw_runs/` | 当前 SafeClaw formal evaluation |

运行目录由 config hash 或显式 `run-id` 标识。正式结果必须从持久化的 manifest、results、events、verdicts、model-call journal 和 complete interaction record 重建，不能只依赖终端输出。

当前仓库包含历史 `evaluation_gpt_huihui_4090-02cb0b56baac` 摘要和证据。当前 formal-v2 的 `safeclaw_runs/` 仍为空，因为真实 sample library gate 尚未通过。

