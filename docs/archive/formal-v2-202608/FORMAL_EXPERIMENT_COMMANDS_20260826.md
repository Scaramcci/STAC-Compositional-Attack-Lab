# SafeClaw Formal Experiment Commands

This file records the executable command sequence for the v2 formal experiment.
Commands are not executed by this document.

## Current Gate Status

As of 2026-08-26, the recovery pilot is blocked:

- recovery trajectories: 8
- accepted samples: 0
- required accepted samples: 2
- Gate A: failed/blocked
- main collection: not started
- formal evaluation: not started

Do not start the main collection until Gate A is explicitly marked passed in
`FORMAL_EXPERIMENT_PROGRESS_20260824.md`. Do not lower the accepted-sample threshold.

The current checkout uses the pinned local `Qwen/Qwen3-Embedding-4B` service, not the old
`text-embedding-3-small` selector in earlier handoff text.

## Preconditions

Before starting Gate B, verify all of the following:

1. Gate A is explicitly passed in the progress ledger.
2. The Qwen model revision and embedding dimension remain unchanged:
   `5cf2132abc99cad020ac570b19d031efec650f2b`, dimension `2560`.
3. The private embedding service is reachable at `172.17.0.1:8001` and a real
   `/v1/embeddings` probe succeeds from both host and Docker paths.
4. The current checkout has the expected v2 configs and no conflicting collection tmux session.
5. The project `.env` and mode-0600 local embedding env file are present. Never enable shell tracing
   while loading them and never print their contents.

## Private Embedding Service

Start the service once before collection and keep it running through formal evaluation:

```bash
export STAC_ROOT=/home/kunyuan/snap/Zky_Agent_Attack/STAC-Compositional-Attack-Lab

tmux new-session -d -s stac-qwen3-embedding \
  "cd '$STAC_ROOT' && set +x && . /home/kunyuan/.config/stac-attack-lab/embedding.env && exec .venv-vllm/bin/vllm serve /home/kunyuan/models/Qwen3-Embedding-4B --served-model-name Qwen/Qwen3-Embedding-4B --runner pooling --max-model-len 8192 --dtype half --host 172.17.0.1 --port 8001 --api-key \"\\$SAFECLAW_EMBEDDING_API_KEY\""
```

The service must remain private. Do not bind it to a public interface.

## Gate B: Main Collection

Run only after the Gate A precondition passes:

```bash
tmux new-session -d -s stac-collection-v2-main \
  "cd '$STAC_ROOT' && set +x && set -a && . ./.env && . /home/kunyuan/.config/stac-attack-lab/embedding.env && set +a && export SAFECLAW_MODEL=gpt-5.5 SAFECLAW_EMBEDDING_MODEL=Qwen/Qwen3-Embedding-4B SAFECLAW_EMBEDDING_BASE_URL=http://172.17.0.1:8001/v1 && exec bash scripts/run_safeclaw_sample_collection.sh --config configs/sample_generation/safeclaw_adversarial_v2.yaml"
```

Monitor the session:

```bash
tmux capture-pane -pt stac-collection-v2-main -S -100
tail -f "$STAC_ROOT/data/primitive_libraries/generated/safeclaw-adversarial-v2/tmux-collection.log"
```

The expected matrix is 12 construction tasks x 10 seeds = 120 trajectories. The collection
launcher does not mine or freeze automatically.

## Gate B: Mine, Audit, Freeze

Run these only after the main collection exits successfully:

```bash
cd "$STAC_ROOT"
export PYTHONPATH="$STAC_ROOT/src"

MAIN_COLLECTION=data/primitive_libraries/generated/safeclaw-adversarial-v2/interactions/raw/safeclaw-adversarial-construction-v2
MAIN_LIBRARY=data/primitive_libraries/generated/safeclaw-adversarial-v2/library

.venv/bin/python -u -m stac_attack_lab.cli sample mine \
  --collection "$MAIN_COLLECTION"

.venv/bin/python -u -m stac_attack_lab.cli sample audit \
  --library "$MAIN_LIBRARY"

.venv/bin/python -u -m stac_attack_lab.cli sample freeze \
  --library "$MAIN_LIBRARY" \
  --version formal-v3-safeclaw-20260824
```

The audit must pass with at least 30 accepted real primitive samples. Freeze must create:

```text
data/primitive_libraries/frozen/formal-v3-safeclaw-20260824
```

If audit or freeze fails, stop. Do not fabricate samples, reuse the recovery library, or lower
the threshold.

## Gate C: Formal Evaluation

Start only after the main library audit and freeze both pass:

```bash
tmux new-session -d -s stac-formal-v2 \
  "cd '$STAC_ROOT' && set +x && set -a && . ./.env && . /home/kunyuan/.config/stac-attack-lab/embedding.env && set +a && export SAFECLAW_MODEL=gpt-5.5 SAFECLAW_EMBEDDING_MODEL=Qwen/Qwen3-Embedding-4B SAFECLAW_EMBEDDING_BASE_URL=http://172.17.0.1:8001/v1 && exec bash scripts/run_formal_evaluation.sh --run-id safeclaw-formal-v2-main --config configs/experiments/safeclaw_formal_v2.yaml --preflight configs/environments/safeclaw_openclaw_v2.yaml"
```

Monitor the evaluation:

```bash
tmux capture-pane -pt stac-formal-v2 -S -100
tail -f "$STAC_ROOT/experiments/safeclaw_runs/safeclaw-formal-v2-main/tmux-run.log"
```

The launcher performs the official smoke check, environment preflight, 15-case formal matrix,
run audit and report generation. To resume, confirm the old session has ended and reuse the same
run id, frozen library and unchanged configs.

## Safety Checks

- Never put API key values directly in this file or in a command line.
- Never source environment files under shell tracing.
- Keep the embedding service private.
- Do not start Gate B or Gate C while Gate A is blocked.
- Do not delete or overwrite the existing pilot or recovery output trees.
