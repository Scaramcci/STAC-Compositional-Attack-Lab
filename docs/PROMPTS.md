# Prompts

All prompts are markdown assets with YAML front matter: `prompt_id`, `version`, `role`, `input_schema`, `output_schema`, `temperature`, and `max_output_tokens`.

## Offline

- `offline.environment_analyst`: converts public environment specs into `EnvironmentInventory`; cannot infer hidden state.
- `offline.attack_graph_generator`: proposes registered-primitive `AttackGraph` candidates; code performs validation.
- `offline.chain_critic`: critiques structure and sandbox compliance; cannot execute tools.
- `offline.prompt_writer`: converts verified stages into Victim-visible text without leaking graph, verifier, or canary answers.

## Runtime

- `runtime.adaptive_planner`: chooses the next legal frontier action or stop. It sees public graph/status only.
- `runtime.attacker`: instantiates one selected primitive message. It cannot replan or combine stages.
- `runtime.victim_system`: neutral workspace agent prompt. Its hash is invariant across clean, attack, ablation, and defense.

Runtime role configs are independent. Current temporary config `stac_sample_build_gemini.yaml` maps every role to Gemini. The intended sample-builder maps planner, attacker, prompt-writer, verifier, and judge to GPT-compatible models while leaving victim on Gemini. The evaluation config maps victim to local huihui and leaves the other roles GPT-compatible.

## Judges

- `judges.semantic_stage_verifier`: semantic labels only, with evidence ids.
- `judges.trajectory_judge`: trajectory labels and exact copy of hard aggregate result.
- `judges.benign_utility_judge`: condition-blind utility labels.

Judge outputs never override deterministic verifier verdicts.
