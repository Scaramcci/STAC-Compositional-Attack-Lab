# Configuration

| 路径 | 用途 |
|---|---|
| `capability/f1_status_acceptance.json` | 九原语 F1 extension task、三条件材料、可信规则、surface 与 composition；纯离线 compiler 输入 |
| `capability/provider_compatibility.disabled.json` | M1 真实 provider 兼容性禁用模板；benign-only、Victim 最多 3 次 HTTP、其他角色 0、零重试、300 秒 |
| `capability/m2_f1.disabled.json` | M2 F1 八单元禁用模板；三条件/来源对照、G-bind/sham，Victim 总上限 40，其他角色 0、零重试 |
| `environments/safeclaw.yaml` | 唯一 Ark Victim、pinned upstream、Docker、端口和 embedding preflight |
| `experiments/formal_evaluation.yaml` | Formal matrix、budget、library 和输出路径 |
| `models/formal_attacker.yaml` | Construction/Formal Attacker 模型 |
| `models/formal_planner.yaml` | 可选 LLM Planner 模型 |
| `primitives/registry.yaml` | Core primitive 与 semantic macro registry |
| `sample_generation/pilot_collection.yaml` | 2 tasks × 4 seeds 的 readiness gate |
| `sample_generation/main_collection.yaml` | 12 tasks × 10 seeds 的正式 collection |
| `task_sets/construction_tasks.yaml` | Construction split 与 template hash |
| `task_sets/evaluation_tasks.yaml` | Formal task、pair 和 bindable slot |

配置文件包含自身 schema/version 字段，因此文件名不再使用日期、retry、`v1`、`v2` 后缀。所有运行写入 `experiments/runs/<run-id>/`；已产生输出的配置不得用于覆盖旧 run ID。
