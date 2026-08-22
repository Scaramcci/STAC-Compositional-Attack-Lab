# Prompts

All prompts are markdown assets with YAML front matter: `prompt_id`, `version`, `role`, `input_schema`, `output_schema`, `temperature`, and `max_output_tokens`.

## Offline

本节描述 legacy `OfflineSample` prompt-bearing 路径。它保留用于历史复现，不能生成 formal-v2 去内容化冻结库。

- `offline.environment_analyst`: converts public environment specs into `EnvironmentInventory`; cannot infer hidden state.
- `offline.attack_graph_generator`: proposes registered-primitive `AttackGraph` candidates; code performs validation.
- `offline.chain_critic`: critiques structure and sandbox compliance; cannot execute tools.
- `offline.prompt_writer`: converts a candidate stage into the final Victim-visible text before offline execution. The exact stored text must be exercised by Gemini and hard-pass before collection.

## Runtime

- `runtime.adaptive_planner`: chooses the next legal frontier action or stop. It sees public graph/status only.
- `runtime.attacker`: instantiates one selected primitive message. It cannot replan or combine stages.
- `runtime.victim_system`: neutral workspace agent prompt. Its hash is invariant across clean, attack, ablation, and defense.

Runtime role configs are independent. Current temporary config `stac_sample_build_gemini.yaml` maps every role to Gemini. The intended sample-builder maps planner, attacker, prompt-writer, verifier, and judge to GPT-compatible models while leaving victim on Gemini. Evaluation maps victim to local Huihui; its Attacker receives the selected sample stage and frozen verified prompt and may not invent a different route.

## Formal-v2 construction, planner, and attacker

- `formal.construction_attacker` 驱动真实 adaptive construction。它只接收公开 construction objective、允许表面、component/capability inventory、公开 transcript、trust-boundary/terminal ids、安全约束与剩余预算。
- `formal.chain_selector` 从 sanitized semantic-macro nodes 与 typed edges 选择 primitive backbone，不生成 victim-visible payload。
- `formal.trajectory_planner` 单独提出 `LongHorizonAdversarialTrajectory`；runtime 对 stage/macro/family/order、state dependencies、persistence、trigger、observable evidence、judge condition、allowed actions 和五类机制支持进行确定性重验。
- `formal.independent_attacker` 与 Construction Attacker、Planner 分离。它只接收 public task、execution view 和 validated plan，并为本次运行生成 fresh typed slot values 与逐 stage victim-visible actions。
- formal-v2 public/execution frozen views 不包含 `victim_messages`、`frozen_prompt` 或 `verified_prompt`；这些字段只属于 legacy pipeline。
- materializer 只写 allowlisted public slot，官方 evaluator 只在 Victim 运行后判定；两者都不能替代 Attacker。

The SafeClaw formal no_sample condition does not invoke a planner or attacker model to invent a route. It emits a deterministic legal_baseline plan with a separate baseline binding, then sends the normally materialized task through the same Victim system/tool contract. No sample graph, verifier target, or private oracle is exposed to the Victim.

## Judges

- `judges.semantic_stage_verifier`: semantic labels only, with evidence ids.
- `judges.trajectory_judge`: trajectory labels and exact copy of hard aggregate result.
- `judges.benign_utility_judge`: condition-blind utility labels.

Judge outputs never override deterministic verifier verdicts.

## Prompt identity and transcript linkage

The full `runtime.victim_system` file hash is written to every condition manifest and tested for equality across clean, attack, ablation, defense, offline, and evaluation configurations. Each external call records prompt id, semantic version, byte hash, input schema, and output schema. Victim transcript audit rejects visible `private_oracle`, attack-graph, condition, verifier-target, or expected-predicate metadata.
