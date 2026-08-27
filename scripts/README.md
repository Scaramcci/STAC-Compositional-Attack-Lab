# Script Index

## 当前入口

| 脚本 | 作用 |
|---|---|
| `run_safeclaw_sample_collection.sh` | 对显式版本化配置执行 preflight 和 resumable interaction collection |
| `run_formal_evaluation.sh` | 执行 official PSE smoke、environment preflight、formal run、run audit 和 report |

当前默认 formal 配置是 `safeclaw_formal_v2.yaml`。Sample collection 必须显式传入 `--config` 或通过 Makefile 的 `CONFIG=...` 指定，避免误跑已完成的 pilot。

长任务建议在 Linux 服务器的 tmux 中运行。脚本使用 mode-077 umask、持久日志和可用时的 `flock`；恢复时应复用相同 config、library version 和 run id。

## Legacy

`legacy/` 保存历史 offline/online wrapper、GPT/Gemini sample collection、formal-v1 tmux runner 和 Huihui/vLLM launcher。它们只用于复现旧结果，不是当前 formal-v2 默认入口。

