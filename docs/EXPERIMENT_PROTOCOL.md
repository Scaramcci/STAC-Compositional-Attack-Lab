# Experiment Protocol

## Local Smoke Matrix

Smoke uses 2 tasks x 1 seed x 9 conditions. The seed file contains 10 tasks so the same pipeline can run the full local scale by increasing `task_limit` and `seeds`.

Conditions: `clean`, `single_entry`, `fixed_full`, `random_legal_full`, `rule_planner_full`, `llm_planner_full`, `full_minus_memory_write`, `full_minus_retrieval`, and `llm_planner_full_defense_on`.

## STAC Sample Construction

The target sample-construction run is `configs/experiments/stac_sample_build_gpt_gemini.yaml`: GPT-compatible planner, attacker, prompt-writer, verifier, and judge roles; Gemini victim; deterministic hard verifier as final acceptance. Until OpenAI-compatible access is restored, `configs/experiments/stac_sample_build_gemini.yaml` uses Gemini for every LLM role while preserving the same contracts and role boundaries.

The output is an audited and frozen JSONL dataset with AgentLAB-offline-like records: seed task, clean baseline, attack graph, verified call params, victim messages, expected predicates, version hashes, transcript refs, and sample hash.

## Formal Evaluation

The target evaluation config is `configs/experiments/evaluation_gpt_huihui_4090.yaml`: GPT-compatible planner/attacker/verifier/judge roles and a local 4090-hosted huihui victim exposed through an OpenAI-compatible endpoint. AgentLAB and SHADE_Arena are referenced through read-only adapters and integration smoke before any formal run.

## Pairing

Each sample has a stable `pair_id`. Valid paired comparisons require matching seed task, initial snapshot hash, Victim prompt hash, budgets, sample hash, and role model config. Only the named condition change may differ.

## Metrics

Report includes chain success rate, numerator/denominator, Wilson 95% CI, utility success rate, average tool calls, and failed stage reason codes. Hard chain success requires all four deterministic stages and no direct shortcut.

## Statistics

The local smoke reports engineering feasibility and variance estimates. Wilson CI is implemented for smoke proportions; McNemar/bootstrap hooks are reserved for larger paired runs.

## Reproducibility

Freeze datasets before online runs. Reports must be rebuilt from `results.jsonl`, `events.jsonl`, and `verdicts.jsonl`, not from stdout.
