# Formal Collection And Evaluation Handoff

Updated: 2026-08-26 (Europe/Berlin)

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

There is no remaining code gate before the bounded pilot, but the embedding endpoint capability
must be verified before any real collection. `SAFECLAW_EMBEDDING_MODEL` is currently set to
`text-embedding-3-small` for preflight. The deterministic preflight only checks that the selector
and endpoint/key variables are present; it does not call `/v1/embeddings`.

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
3. `SAFECLAW_EMBEDDING_MODEL` remains set to the embedding model ID verified by the Section 9 probe.
   The endpoint/model pair and any separate embedding variables must remain unchanged.
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


## 9. Embedding endpoint verification and fallback

The deterministic preflight checks only that the embedding selector, endpoint and key variables are
present. It does not call the provider. Before any real collection, prove the following contract:

- `POST <base-url>/v1/embeddings`;
- request JSON contains `model` and `input`;
- response contains a non-empty numeric `data[0].embedding` vector;
- the selected model is actually served by the endpoint, not merely listed by `/models`.

Run this one-request probe locally. It prints only a classification and vector dimension; do not
paste the key, endpoint, response body or full error response into chat:

```bash
cd /home/kunyuan/snap/Zky_Agent_Attack/STAC-Compositional-Attack-Lab
export SAFECLAW_EMBEDDING_MODEL=text-embedding-3-small
PYTHONPATH=src .venv/bin/python - <<'PY'
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from stac_attack_lab.env_loader import load_project_env
load_project_env(Path.cwd())
base = os.environ["OPENAI_BASE_URL"].rstrip("/")
if not base.endswith("/v1"):
    base += "/v1"
key = os.environ["OPENAI_API_KEY"]
request = Request(base + "/embeddings", data=json.dumps({
    "model": os.environ["SAFECLAW_EMBEDDING_MODEL"],
    "input": "stac embedding capability probe",
}).encode(), headers={
    "Authorization": f"Bearer {key}",
    "Content-Type": "application/json",
    "User-Agent": "stac-attack-lab-embedding-probe/1.0",
}, method="POST")
try:
    with urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode())
    rows = payload.get("data") if isinstance(payload, dict) else None
    vector = rows[0].get("embedding") if isinstance(rows, list) and rows else None
    if not isinstance(vector, list) or not vector:
        raise ValueError("invalid_response_shape")
    print(f"embedding_ok dimensions={len(vector)}")
except HTTPError as exc:
    print(f"embedding_failed http_status={exc.code}")
except URLError as exc:
    print(f"embedding_failed network_error={type(exc.reason).__name__}")
except (TimeoutError, ValueError, KeyError, TypeError, IndexError) as exc:
    print(f"embedding_failed error={type(exc).__name__}")
PY
```

Interpretation: `embedding_ok` is usable; `400` means model/request mismatch; `404` means no
embeddings route; `401` or `403` means credentials/permissions; `429` means quota/rate limiting;
network errors mean reachability problems. A Docker container cannot use a host loopback address
unless its network is explicitly configured for that case.

The local configured model inventory contains five IDs and none looks like an embedding model.
This is a warning, not proof; the authenticated probe is authoritative.

If the shared gateway lacks embeddings, use a provider that implements this OpenAI-compatible
contract, ask the gateway operator to expose one, or use a separate embedding service. The runtime
already supports separate endpoint variables; the versioned v2 configs must then use:

```yaml
embedding_base_url_env: SAFECLAW_EMBEDDING_BASE_URL
embedding_api_key_env: SAFECLAW_EMBEDDING_API_KEY
```

Set those variables locally, then regenerate config hashes/provenance and rerun every preflight.
OpenAI documents `text-embedding-3-small` and `text-embedding-3-large` ([embeddings guide](https://developers.openai.com/api/docs/guides/embeddings)); vLLM documents an
OpenAI-compatible `/v1/embeddings` server ([server docs](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/)). These are compatible API examples, not a claim that the
current gateway serves either model. Do not substitute `gpt-5.5`, a text-generation endpoint or a
fake embedding in the real experiment. The vector model, endpoint and configuration hash are
experiment provenance.
