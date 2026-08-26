# Formal Collection And Evaluation Handoff

Updated: 2026-08-24T16:37:01+02:00 (Europe/Berlin)

## 1. Current boundary

All implementation and deterministic acceptance gates before a real SafeClaw collection are
complete. No real collection, authenticated model call, frozen real library or formal result
has been produced.

The experiment remains restricted to the authorized isolated SafeClaw/OpenClaw benchmark,
synthetic services and no-value effects. It must not target real accounts, host files,
production services or public systems.

Evidence:

- progress ledger: `FORMAL_EXPERIMENT_PROGRESS_20260824.md`;
- schemas: regenerated;
- lint: 166 files passed;
- typecheck: 108 source files passed;
- tests: 138 passed;
- `git diff --check`: passed;
- pilot preflight: `passed=true`, `execution_started=false`; all deterministic checks pass
  with the selected embedding model below.

## 2. What remains before collection

There is no remaining code gate before the bounded pilot. The selected embedding model is
`text-embedding-3-small`; confirm that the configured endpoint serves it through `/v1/embeddings`.
Export both selectors:

```bash
export SAFECLAW_MODEL=gpt-5.5
export SAFECLAW_EMBEDDING_MODEL=text-embedding-3-small
```

The no-execution pilot preflight now passes. It verifies selector presence and configuration
completeness but does not make a real embedding request.

The provider URL/key variables are already loaded by the CLI from the project `.env`;
do not source, print or place them in tmux commands.

The required order is:

1. Run the 4-trajectory pilot.
2. Deterministically mine and audit it.
3. Review outcomes, raw transcript/state projections, resume behavior and failure reasons.
4. Start the 120-trajectory main campaign only if the pilot is acceptable.
5. Mine, audit and freeze the main library. The audit requires at least 30 accepted samples
   and does not weaken structural criteria to reach that number.

The pilot covers two task/topology families and two seeds. The main campaign covers 12
hash-pinned train tasks across four topology categories and ten seeds. Construction tasks
are disjoint from the formal task exclusions.

## 3. Versioned campaign

Files:

- `configs/sample_generation/safeclaw_adversarial_v2_pilot.yaml`
- `configs/sample_generation/safeclaw_adversarial_v2.yaml`
- `configs/task_sets/safeclaw_construction_v2.yaml`
- `scripts/run_safeclaw_sample_collection.sh`

Independent per-trajectory limits:

- 4 sessions;
- 8 victim turns;
- 12 attacker actions;
- 24 tool calls;
- 24,000 observable tokens;
- 300 normalized source events;
- 600 seconds per request;
- 1,800 seconds total wall time.

Missing victim token usage fails closed. Collection is resumable per task/seed cell and the
completed collection tree becomes immutable before deterministic mining. Both collection and
formal execution write the selected embedding model, endpoint and key to a temporary mode-0600
model config. The pinned OpenClaw 2026.3.12 schema uses `provider=openai` plus
`memorySearch.remote`; the key is covered by exact secret scans and is never retained.

## 4. Pilot tmux command

Run from an interactive shell:

```bash
export STAC_ROOT=/home/kunyuan/snap/Zky_Agent_Attack/STAC-Compositional-Attack-Lab
export SAFECLAW_MODEL=gpt-5.5
export SAFECLAW_EMBEDDING_MODEL=text-embedding-3-small
export SAFECLAW_EMBEDDING_MODEL
cd "$STAC_ROOT"

tmux new-session -d -s stac-collection-v2-pilot \
  "cd '$STAC_ROOT' && exec bash scripts/run_safeclaw_sample_collection.sh --config configs/sample_generation/safeclaw_adversarial_v2_pilot.yaml"
```

Monitor:

```bash
tmux capture-pane -pt stac-collection-v2-pilot -S -100
tmux attach-session -t stac-collection-v2-pilot
tail -f "$STAC_ROOT/data/primitive_libraries/generated/safeclaw-adversarial-v2-pilot/tmux-collection.log"
```

Detach with `Ctrl-b d`. To resume after interruption, first confirm the old session ended,
then rerun the exact `tmux new-session` command. Completed task/seed cells are validated and
skipped.

After the pilot collection exits successfully:

```bash
cd "$STAC_ROOT"
export PYTHONPATH="$STAC_ROOT/src"
PILOT_COLLECTION=data/primitive_libraries/generated/safeclaw-adversarial-v2-pilot/interactions/raw/safeclaw-adversarial-construction-v2-pilot
PILOT_LIBRARY=data/primitive_libraries/generated/safeclaw-adversarial-v2-pilot/library

.venv/bin/python -u -m stac_attack_lab.cli sample mine \
  --collection "$PILOT_COLLECTION"
.venv/bin/python -u -m stac_attack_lab.cli sample audit \
  --library "$PILOT_LIBRARY"
```

Do not start the main campaign if the pilot audit fails, fewer than two accepted samples are
mined, secrets appear in retained artifacts, or failures indicate an invalid task/model path.

## 5. Main collection tmux command

After pilot review:

```bash
export STAC_ROOT=/home/kunyuan/snap/Zky_Agent_Attack/STAC-Compositional-Attack-Lab
export SAFECLAW_MODEL=gpt-5.5
export SAFECLAW_EMBEDDING_MODEL=text-embedding-3-small
export SAFECLAW_EMBEDDING_MODEL
cd "$STAC_ROOT"

tmux new-session -d -s stac-collection-v2-main \
  "cd '$STAC_ROOT' && exec bash scripts/run_safeclaw_sample_collection.sh --config configs/sample_generation/safeclaw_adversarial_v2.yaml"
```

Monitor:

```bash
tmux capture-pane -pt stac-collection-v2-main -S -100
tmux attach-session -t stac-collection-v2-main
tail -f "$STAC_ROOT/data/primitive_libraries/generated/safeclaw-adversarial-v2/tmux-collection.log"
```

After collection exits successfully, run the model-free deterministic stages:

```bash
cd "$STAC_ROOT"
export PYTHONPATH="$STAC_ROOT/src"
MAIN_COLLECTION=data/primitive_libraries/generated/safeclaw-adversarial-v2/interactions/raw/safeclaw-adversarial-construction-v2
MAIN_LIBRARY=data/primitive_libraries/generated/safeclaw-adversarial-v2/library
FROZEN_VERSION=formal-v3-safeclaw-20260824

.venv/bin/python -u -m stac_attack_lab.cli sample mine \
  --collection "$MAIN_COLLECTION"
.venv/bin/python -u -m stac_attack_lab.cli sample audit \
  --library "$MAIN_LIBRARY"
.venv/bin/python -u -m stac_attack_lab.cli sample freeze \
  --library "$MAIN_LIBRARY" \
  --version "$FROZEN_VERSION"
```

`sample audit` returns nonzero if the accepted count is below 30 or any schema/hash/stage
check fails. `sample freeze` requires the exact current passing audit report and creates:

```text
data/primitive_libraries/frozen/formal-v3-safeclaw-20260824
```

The formal config already references this exact future path. Freeze must succeed before the
formal command is started.

## 6. What remains before formal evaluation

Files:

- `configs/environments/safeclaw_openclaw_v2.yaml`
- `configs/task_sets/safeclaw_compositional_v2.yaml`
- `configs/experiments/safeclaw_formal_v2.yaml`
- `scripts/run_formal_evaluation.sh`

Required before starting:

1. The main audit and freeze commands above pass.
2. `SAFECLAW_MODEL=gpt-5.5` remains exported.
3. `SAFECLAW_EMBEDDING_MODEL` remains set to an embedding model id verified against
   the configured provider endpoint. No id is currently selected, and the code does not
   guess or silently substitute one.
4. The formal preflight passes with the frozen library present.

The preregistered matrix is one PSE 2.1 formal task, three matched conditions and five seeds,
for 15 cases. The conditions are `assigned_sample`, `no_sample` and
`dependency_ablation`. Results support only coverage-limited PSE 2.1 claims; they do not
support broad cross-category generalization claims.

## 7. Formal evaluation tmux command

After selecting a provider-valid embedding model in the interactive shell:

```bash
export STAC_ROOT=/home/kunyuan/snap/Zky_Agent_Attack/STAC-Compositional-Attack-Lab
export SAFECLAW_MODEL=gpt-5.5
export SAFECLAW_EMBEDDING_MODEL=text-embedding-3-small
export SAFECLAW_EMBEDDING_MODEL
cd "$STAC_ROOT"

tmux new-session -d -s stac-formal-v2 \
  "cd '$STAC_ROOT' && exec bash scripts/run_formal_evaluation.sh --run-id safeclaw-formal-v2-main --config configs/experiments/safeclaw_formal_v2.yaml --preflight configs/environments/safeclaw_openclaw_v2.yaml"
```

The embedding selector should already be exported from the collection campaign. The command
fails before tmux starts if it is absent.

Monitor:

```bash
tmux capture-pane -pt stac-formal-v2 -S -100
tmux attach-session -t stac-formal-v2
tail -f "$STAC_ROOT/experiments/safeclaw_runs/safeclaw-formal-v2-main/tmux-run.log"
```

The launcher runs the official PSE smoke check, environment preflight, resume-safe formal
matrix, run audit and report generation. To resume, confirm the old tmux session ended and
rerun the exact command with the same run id and unchanged config/library.

Useful status checks:

```bash
tmux list-sessions
test -f "$STAC_ROOT/experiments/safeclaw_runs/safeclaw-formal-v2-main/progress.json" && \
  sed -n '1,240p' "$STAC_ROOT/experiments/safeclaw_runs/safeclaw-formal-v2-main/progress.json"
git -C "$STAC_ROOT" status --short --branch
```

## 8. Completion boundary

Collection is complete only after the real diverse library, retained negatives, mining
manifest and passing audit are frozen immutably. Formal evaluation is complete only after
all 15 matched cases pass schema, hash, transcript, secret, lineage, pair, mechanism and
official-result audits.

Synthetic fixtures, deterministic tests, the pilot alone, or a partially completed run are
not research results.
