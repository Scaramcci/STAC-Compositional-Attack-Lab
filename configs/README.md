# Configuration

| 路径 | 用途 |
|---|---|
| `environments/safeclaw.yaml` | Pinned upstream、Docker、模型和 embedding preflight |
| `experiments/formal_evaluation.yaml` | Formal matrix、budget、library 和输出路径 |
| `models/formal_attacker.yaml` | Construction/Formal Attacker 模型 |
| `models/formal_planner.yaml` | 可选 LLM Planner 模型 |
| `primitives/registry.yaml` | Core primitive 与 semantic macro registry |
| `sample_generation/pilot_collection.yaml` | 2 tasks × 4 seeds 的 readiness gate |
| `sample_generation/main_collection.yaml` | 12 tasks × 10 seeds 的正式 collection |
| `task_sets/construction_tasks.yaml` | Construction split 与 template hash |
| `task_sets/evaluation_tasks.yaml` | Formal task、pair 和 bindable slot |

配置文件包含自身 schema/version 字段，因此文件名不再使用 `v1`、`v2` 后缀。已经产生输出的配置不得原地修改；新实验应使用新 `pipeline_id`、`library_version` 或 `run-id`。
