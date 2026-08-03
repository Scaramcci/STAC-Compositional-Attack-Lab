# STAC Compositional Attack Lab

Local, deterministic-first lab for building and evaluating safe STAC-style compositional attack chains against synthetic workspace canaries and read-only AgentLAB/SHADE_Arena integrations.

## Install

```bash
python -m pip install -e '.[dev]'
```

No API key is required for deterministic tests. The default smoke model is `fake-deterministic-v1`.

## Five-Minute Fake Smoke

```bash
make smoke-offline
make smoke-online
make smoke-report
```

Outputs are written to `data/generated/latest`, `data/frozen/mvp-v0.1`, and `experiments/runs/latest`.

## Commands

```bash
python -m stac_attack_lab.cli offline build --config configs/experiments/mvp_offline.yaml
python -m stac_attack_lab.cli dataset audit --dataset data/generated/latest
python -m stac_attack_lab.cli dataset freeze --dataset data/generated/latest --version mvp-v0.1
python -m stac_attack_lab.cli online run --config configs/experiments/mvp_online.yaml --dataset-version mvp-v0.1
python -m stac_attack_lab.cli report build --run-root experiments/runs/latest
python -m stac_attack_lab.cli integration smoke-shade
```

## Model Configs

- `configs/experiments/stac_sample_build_gemini.yaml`: temporary all-role Gemini sample construction while OpenAI-compatible access is unavailable.
- `configs/experiments/stac_sample_build_gpt_gemini.yaml`: intended STAC sample construction with GPT planner/attacker/prompt-writer/verifier/judge and Gemini victim.
- `configs/experiments/evaluation_gpt_huihui_4090.yaml`: intended formal evaluation with GPT planner/attacker/verifier/judge and local 4090-hosted huihui victim.

Real credentials are read only from environment variables: `GEMINI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_API_KEY`, optional `OPENAI_MODEL_LIST`, and for the server run `HUIHUI_BASE_URL`, optional `HUIHUI_API_KEY`, `HUIHUI_MODEL`.

## Minimal Result Example

The offline smoke freezes all 10 synthetic seeds as `mvp-v0.1`. The online smoke runs 2 tasks × 1 seed × 9 conditions. Expected fake-model behavior: `clean` has 0 canary successes, `fixed_full` succeeds, and `llm_planner_full_defense_on` is blocked by `MemoryIntegrityGuard`.

## Safety

All canaries are synthetic no-value IDs. The environment has no network, shell, host-file, credential, or real exfiltration capability.

## Current Limits

The local verifier remains deterministic and has final authority over attack success. LLM verifier and judge roles add labels only. AgentDojo and SHADE_Arena are exposed through integration smoke/adapters; formal external runs are separate from default tests.
