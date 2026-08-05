# STAC Compositional Attack Lab

A deterministic-first lab for constructing and evaluating safe, long-horizon STAC compositional attack chains against synthetic workspace canaries.

## Install and offline smoke

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
make lint
make typecheck
make test
make smoke-offline
make smoke-online
make smoke-report
```

The fake profile never needs credentials or network access. It builds 10 offline samples and runs the 2-task × 1-seed × 9-condition smoke matrix. Canaries are local, synthetic, and valueless.

## Experiment profiles

The profile field is validated together with every role assignment:

- `fake`: all roles use `fake-deterministic-v1`, with networking disabled.
- `gemini_development`: an explicitly non-formal all-Gemini development profile.
- `stac_offline`: Planner, Attacker, PromptWriter, Verifier, and Judge use `gpt-5.5` through the OpenAI-compatible endpoint; Victim uses Gemini.
- `formal_evaluation`: the same GPT-5.5 roles; only Victim changes to local `huihui-qwen3-14b-abliterated-v2`.

The deterministic verifier is authoritative in every profile. Semantic Verifier/Judge outputs are separate evidence labels and cannot change `chain_success`.

Copy `.env.example` to `.env` and replace placeholders locally. `OPENAI_MODEL_list` is the canonical existing spelling and takes precedence over `OPENAI_MODEL_LIST`. Startup fails closed unless `gpt-5.5` is present. Errors name missing variables or invalid configuration only; secrets are neither serialized nor hashed.

## Commands

```bash
python -m stac_attack_lab.cli offline build --config configs/experiments/mvp_offline.yaml
python -m stac_attack_lab.cli dataset audit --dataset data/generated/latest
python -m stac_attack_lab.cli dataset freeze --dataset data/generated/latest --version mvp-v0.1
python -m stac_attack_lab.cli online run --config configs/experiments/mvp_online.yaml
python -m stac_attack_lab.cli run resume --run-id <run-id>
python -m stac_attack_lab.cli transcript audit --run-root experiments/runs/latest
python -m stac_attack_lab.cli report build --run-root experiments/runs/latest
python -m stac_attack_lab.cli schemas build
```

Frozen versions are immutable: freezing identical content is idempotent; different content under an existing version is rejected.

## Verified sample collection

The real STAC builder treats seed tasks as a candidate-scenario pool, not as accepted samples. `stac_sample_build_gpt_gemini.yaml` cycles through 10 source tasks with independent candidate seeds, tries at most 120 candidates, and stops only after 30 candidates have passed the complete Gemini execution plus deterministic hard verification. Rejected candidates remain in `failures.jsonl`; they never enter `samples.jsonl`.

Each accepted row binds the candidate/source ids, executed tool parameters, frozen Victim-visible stage prompts, hard-pass evidence, graph/prompt hashes, and verification transcript. Dataset audit and freeze reject an incomplete collection. The main Huihui evaluation consumes `stac-verified-30-v0.1` and executes one sample-bound attack per accepted sample: 30 samples × 1 condition × 1 seed = 30 primary episodes. Clean, defense, and ablation matrices are follow-up analyses rather than part of the primary 30.

## Resume and provenance

Every online experiment writes:

- `progress.json`, atomically replaced after each individual attack case;
- `attack_progress.jsonl`, an append-only, fsynced status transition log;
- `conversations.jsonl`, typed complete observable role/model/tool events;
- `transcript_audit.json`, sequence, isolation, assignment, linkage, and redaction findings;
- per-attack events, artifacts, snapshots, verdicts, and reports.

`EXPERIMENT_PROGRESS.md` is the compact human ledger. Completed idempotency keys are skipped on resume. Quota/rate-limit failures checkpoint as `paused_quota` and exit without discarding completed attacks.

## Huihui on one RTX 4090

Discovery checks `HUIHUI_MODEL_PATH` first, then searches `../../../models` for a Hugging Face directory containing config, tokenizer, and weight files without loading weights:

```bash
python -m stac_attack_lab.cli models discover-huihui
python3 -m venv .venv-vllm
.venv-vllm/bin/python -m pip install --upgrade pip
.venv-vllm/bin/python -m pip install vllm 'bitsandbytes>=0.49.2'
scripts/launch_huihui_vllm.sh
```

The launcher uses `.venv-vllm/bin/vllm` by default and accepts a `VLLM_BIN` override. It defaults to runtime BitsAndBytes quantization because the discovered BF16 checkpoint is larger than 24 GB. Set `HUIHUI_QUANTIZATION=none` only when the weights fit; `HUIHUI_CPU_OFFLOAD_GB`, `HUIHUI_MAX_MODEL_LEN`, and `HUIHUI_GPU_MEMORY_UTILIZATION` tune the single-GPU deployment.

## Real-model integration

After credentials and quota are available, use `stac_sample_build_gpt_gemini.yaml` for formal sample construction, audit the completed generated directory, freeze it as `stac-verified-30-v0.1`, and use `evaluation_gpt_huihui_4090.yaml` for the 30-episode primary evaluation. A Gemini-only connectivity smoke is opt-in through `integration smoke-models`; OpenAI and Huihui calls additionally require their `STAC_SMOKE_*` flags.

## Safety and current limits

No local tool can access the public network, shell, host files, environment variables, real credentials, or real external services. The model clients are the only optional network boundary. AgentDojo and SHADE_Arena remain read-only adapter/contract smokes. The checked-in `mvp-v0.1` data is an engineering fixture, not a general empirical claim.
