# Configuration Index

配置按用途保留在稳定路径中，避免破坏 provenance 和历史测试。文件名中的 `v1` 不一定表示无效：例如 `primitives/formal_v1.yaml` 仍是当前 formal-v2 使用的 registry。

## 当前 SafeClaw formal-v2

| 类型 | 当前配置 |
|---|---|
| Environment | `environments/safeclaw_openclaw_v2.yaml` |
| Formal experiment | `experiments/safeclaw_formal_v2.yaml` |
| Construction tasks | `task_sets/safeclaw_construction_v2.yaml` |
| Formal task set | `task_sets/safeclaw_compositional_v2.yaml` |
| Primitive registry | `primitives/formal_v1.yaml` |
| Main collection | `sample_generation/safeclaw_adversarial_v2.yaml` |
| Original pilot | `sample_generation/safeclaw_adversarial_v2_pilot.yaml` |
| Formal Attacker | `models/formal_attacker.yaml` |
| Optional LLM Planner | `models/formal_planner.yaml` |

`safeclaw_adversarial_v2_pilot_rerun.yaml` 和 `safeclaw_adversarial_v2_recovery_pilot.yaml` 是已经执行过的版本化恢复配置，不应覆盖输出或无条件重跑。

## Synthetic regression

- `sample_generation/formal_v1.yaml`
- `environments/workspace_canary.yaml`
- `models/fake.yaml`

这些配置用于确定性回归和本地 smoke，不构成真实 SafeClaw 研究结果。

## Legacy

以下配置为历史 STAC offline/online、Huihui evaluation 或 formal-v1 兼容路径：

- `experiments/mvp_*.yaml`
- `experiments/stac_sample_build_*.yaml`
- `experiments/evaluation_gpt_huihui_4090.yaml`
- `experiments/safeclaw_formal_v1.yaml`
- `environments/safeclaw_openclaw_v1.yaml`
- `sample_generation/safeclaw_adversarial_v1.yaml`
- `task_sets/*_v1.yaml`

新实验不得只因为 legacy 配置更容易运行，就用它替代当前 v2 gate。

