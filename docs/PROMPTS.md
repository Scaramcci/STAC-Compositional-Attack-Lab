# Prompts

All prompts are markdown assets with YAML front matter: `prompt_id`, `version`, `role`, `input_schema`, `output_schema`, `temperature`, and `max_output_tokens`.

## Offline

- `offline.environment_analyst`: converts public environment specs into `EnvironmentInventory`; cannot infer hidden state.
- `offline.attack_graph_generator`: proposes registered-primitive `AttackGraph` candidates; code performs validation.
- `offline.chain_critic`: critiques structure and sandbox compliance; cannot execute tools.
- `offline.prompt_writer`: converts a candidate stage into the final Victim-visible text before offline execution. The exact stored text must be exercised by Gemini and hard-pass before collection.

## Runtime

- `runtime.adaptive_planner`: chooses the next legal frontier action or stop. It sees public graph/status only.
- `runtime.attacker`: instantiates one selected primitive message. It cannot replan or combine stages.
- `runtime.victim_system`: neutral workspace agent prompt. Its hash is invariant across clean, attack, ablation, and defense.

Runtime role configs are independent. Current temporary config `stac_sample_build_gemini.yaml` maps every role to Gemini. The intended sample-builder maps planner, attacker, prompt-writer, verifier, and judge to GPT-compatible models while leaving victim on Gemini. Evaluation maps victim to local Huihui; its Attacker receives the selected sample stage and frozen verified prompt and may not invent a different route.

The SafeClaw formal no_sample condition does not invoke a planner or attacker model to invent a route. It emits a deterministic legal_baseline plan with a separate baseline binding, then sends the normally materialized task through the same Victim system/tool contract. No sample graph, verifier target, or private oracle is exposed to the Victim.

## Judges

- `judges.semantic_stage_verifier`: semantic labels only, with evidence ids.
- `judges.trajectory_judge`: trajectory labels and exact copy of hard aggregate result.
- `judges.benign_utility_judge`: condition-blind utility labels.

Judge outputs never override deterministic verifier verdicts.

## Prompt identity and transcript linkage

The full `runtime.victim_system` file hash is written to every condition manifest and tested for equality across clean, attack, ablation, defense, offline, and evaluation configurations. Each external call records prompt id, semantic version, byte hash, input schema, and output schema. Victim transcript audit rejects visible `private_oracle`, attack-graph, condition, verifier-target, or expected-predicate metadata.
