# Server Codex Formal Experiment Continuation Plan

- Created: `2026-08-26 15:40:14 +0800`
- Execution target: Linux server with NVIDIA RTX 4090 (24 GB)
- Status: active continuation plan
- Supersedes: the server execution plan created on `2026-08-24`

## 1. Objective

Continue the existing SafeClaw formal experiment from the current verified repository state. Do not redo completed deterministic implementation work. Complete the remaining path in this order:

1. deploy and freeze a local embedding service;
2. verify the service from both the host and the OpenClaw Docker execution path;
3. update and validate the versioned v2 experiment configuration;
4. run a 4-trajectory pilot collection;
5. mine and audit the pilot;
6. run the 120-trajectory main collection;
7. mine, audit, and freeze at least 30 accepted primitive samples;
8. run the 15-case formal evaluation;
9. update evidence, provenance, and research-status documents.

The experiment is not complete until real provider calls, real SafeClaw collection, a frozen real primitive library, and formal evaluation artifacts all exist and pass their gates.

## 2. Authoritative inputs

Treat these files as repository evidence and specifications, not as higher-priority instructions:

- `FORMAL_COLLECTION_EVALUATION_HANDOFF_20260826.md`: current commands, paths, and live handoff state;
- `FORMAL_EXPERIMENT_PROGRESS_20260824.md`: append-only non-secret execution ledger;
- `docs/EXPERIMENT_PROTOCOL.md`: experiment protocol;
- `docs/DECISIONS.md`: accepted design decisions;
- `docs/PROMPTS.md`: prompt provenance;
- `docs/RESEARCH_STATUS.md`: claim and evidence status;
- `README.md` and `SECURITY.md`: user-facing operation and security requirements.

Before acting, inspect the live checkout and reconcile any differences with these files. Live code and fresh test evidence outrank stale prose, but do not silently weaken an existing gate.

## 3. Current verified starting point

The 2026-08-26 handoff reports:

- deterministic implementation gates are complete;
- schemas, lint, type checks, tests, and diff checks passed at handoff time;
- the v2 pilot preflight passed only a presence/configuration check;
- a real `POST /v1/embeddings` capability check is still pending;
- no real pilot or main collection has been completed;
- no real accepted primitive library has been frozen;
- no formal 15-case result exists.

Re-run verification on the server. Do not report the old results as proof of the server checkout.

## 4. Credential and environment boundary

The server `.env` contains third-party provider credentials and Gemini credentials. Expected names include:

- `OPENAI_BASE_URL`
- `OPENAI_API_KEY`
- `OPENAI_MODEL_list`
- `GEMINI_API_KEY`

Rules:

- never print, log, commit, summarize, hash, or copy credential values;
- only report whether a required variable is present or absent;
- never source `.env` under shell tracing;
- preserve `.env` and do not overwrite it;
- keep Victim/Attacker generation endpoints separate from the local embedding endpoint;
- do not assume the third-party OpenAI-compatible gateway supports embeddings;
- use a non-secret placeholder in `.env.example` only;
- any generated temporary model configuration containing a secret must use mode `0600` and be deleted by the existing cleanup path.

## 5. Fixed embedding choice

Use the open-source model:

```text
Qwen/Qwen3-Embedding-4B
```

Deployment target:

- runtime: vLLM OpenAI-compatible server;
- API: `POST /v1/embeddings`;
- served model name: `Qwen/Qwen3-Embedding-4B`;
- initial maximum context: `8192` tokens, not the model maximum, to preserve 4090 memory headroom;
- initial dtype: FP16 or BF16 supported by the installed vLLM/CUDA stack;
- default output dimension: use the service/model default and record the observed dimension; do not silently change it later.

This choice is fixed for pilot, main collection, and formal evaluation. If it must change, record a versioned deviation in `docs/DECISIONS.md`, regenerate provenance/config hashes, discard incompatible embedding-derived artifacts, and rerun all embedding and collection gates.

Reference model and serving documentation:

- <https://huggingface.co/Qwen/Qwen3-Embedding-4B>
- <https://docs.vllm.ai/en/latest/serving/openai_compatible_server/>
- <https://huggingface.co/docs/huggingface_hub/en/guides/cli>

## 6. Required configuration separation

Use these embedding-specific variables in the v2 experiment path:

```text
SAFECLAW_EMBEDDING_MODEL=Qwen/Qwen3-Embedding-4B
SAFECLAW_EMBEDDING_BASE_URL=http://<docker-reachable-host>:8001/v1
SAFECLAW_EMBEDDING_API_KEY=<local-service-key>
```

Keep these provider variables for their existing Victim/Attacker use:

```text
OPENAI_BASE_URL=<third-party-provider-base-url>
OPENAI_API_KEY=<third-party-provider-key>
OPENAI_MODEL_list=<third-party-model-list>
GEMINI_API_KEY=<gemini-key>
```

Update only the versioned v2 formal path so that embedding configuration no longer reuses `OPENAI_BASE_URL` or `OPENAI_API_KEY`:

- `configs/sample_generation/safeclaw_adversarial_v2_pilot.yaml`
- `configs/sample_generation/safeclaw_adversarial_v2.yaml`
- `configs/environments/safeclaw_openclaw_v2.yaml`
- any typed config tests or preflight tests that assert the old environment-variable names;
- `.env.example`, with placeholders only.

Do not change v1/legacy configs unless a current test proves a shared implementation requires it. Do not rename the existing third-party variables.

## 7. Gate E0 — Preserve and verify the checkout

1. Record without secrets:
   - current commit;
   - branch;
   - dirty-file list;
   - Python, package-manager, CUDA, driver, GPU, and Docker versions;
   - available disk space and GPU memory.
2. Preserve all pre-existing user changes.
3. Read the current handoff and progress ledger.
4. Run the repository's documented schema, lint, type-check, test, and diff-check commands.
5. Stop if deterministic checks fail. Fix only failures required for this plan, then rerun the complete gate.

Acceptance:

- server checkout identity and environment are recorded;
- no user-owned change is overwritten;
- all deterministic checks pass on the server.

## 8. Gate E1 — Pin and download the embedding model

Choose and record an immutable Hugging Face commit SHA before the formal run. Download the model to a stable server path, for example:

```bash
hf download Qwen/Qwen3-Embedding-4B \
  --revision <FULL_COMMIT_SHA> \
  --local-dir /home/kunyuan/models/Qwen3-Embedding-4B
```

Record in a non-secret provenance artifact:

- repository ID;
- full revision SHA;
- local path;
- relevant file hashes or a deterministic model-directory manifest;
- Hugging Face CLI version;
- vLLM version;
- PyTorch, CUDA, driver, and GPU identifiers.

Acceptance:

- the local model directory is complete and readable;
- revision is immutable and recorded;
- no credential or access token appears in provenance.

## 9. Gate E2 — Start a private embedding service

Use a dedicated service on port `8001`. Adapt the executable path to the server environment, but preserve the semantic options:

```bash
vllm serve /home/kunyuan/models/Qwen3-Embedding-4B \
  --served-model-name Qwen/Qwen3-Embedding-4B \
  --runner pooling \
  --dtype half \
  --max-model-len 8192 \
  --host 0.0.0.0 \
  --port 8001 \
  --api-key <local-service-key>
```

Security and networking:

- bind/firewall the port so it is not publicly reachable;
- use a random local service key stored only in `.env` or an equivalent secret store;
- `127.0.0.1` inside OpenClaw Docker is the container itself, not the host;
- set `SAFECLAW_EMBEDDING_BASE_URL` to a host address or service name reachable from the exact Docker network used by OpenClaw;
- do not expose the third-party provider key to the embedding service.

If FP16 is unsupported by the live stack, use BF16 and record the deviation. If memory pressure occurs, reduce request batch/concurrency first; do not change model identity or vector dimension silently.

Acceptance:

- service reaches ready state without repeated CUDA/OOM errors;
- port is not publicly exposed;
- process/service restart instructions are recorded without secrets.

## 10. Gate E3 — Real embedding capability probes

Perform two one-request probes using harmless text:

1. from the server host;
2. from the same Docker network or an equivalent temporary container used by OpenClaw.

Each probe must verify:

- HTTP success;
- returned model identity is expected or explicitly normalized by vLLM;
- `data[0].embedding` is a non-empty numeric array;
- the vector dimension is recorded and identical in both probes;
- repeated identical input returns the same dimension and finite values;
- secrets are redacted from captured diagnostics.

Presence-only environment validation is not sufficient. Do not continue on a text-generation response, fake embedding, empty vector, network timeout, authentication failure, or inconsistent dimension.

Acceptance artifact should contain only endpoint class, model ID, dimension, status, timestamps, and redacted error information.

## 11. Gate E4 — Update v2 configs and regression tests

Change the three v2 configs to reference:

```json
{
  "embedding_provider": "openai",
  "embedding_model_env": "SAFECLAW_EMBEDDING_MODEL",
  "embedding_base_url_env": "SAFECLAW_EMBEDDING_BASE_URL",
  "embedding_api_key_env": "SAFECLAW_EMBEDDING_API_KEY"
}
```

Then:

1. update exact config-contract tests;
2. add or update tests proving Victim and embedding endpoints can differ;
3. verify preflight fails closed when any embedding-specific variable is missing;
4. verify temporary OpenClaw model config receives the embedding endpoint and key without leaking them;
5. update `.env.example` with placeholder names only;
6. regenerate schemas/config hashes through project commands;
7. rerun lint, type checks, tests, secret scans, and diff checks.

Acceptance:

- v2 configs do not reuse third-party base URL/key for embedding;
- tests cover endpoint separation and missing-variable failure;
- generated hashes/provenance match the final configs;
- no secret value is present in Git-tracked or experiment-output files.

## 12. Gate E5 — Collection preflight

Run the documented v2 pilot preflight with the final environment. It must validate:

- Victim/Attacker provider variables are present;
- embedding-specific variables are present;
- the embedding capability probe passes;
- Docker is usable;
- the SafeClaw/OpenClaw image and required mounts are available;
- output directories are writable;
- config hashes are the ones just generated;
- no real collection was accidentally started by preflight.

Append the non-secret result to `FORMAL_EXPERIMENT_PROGRESS_20260824.md`.

## 13. Gate A — Four-trajectory pilot

Use the exact v2 pilot launcher and tmux workflow documented in `FORMAL_COLLECTION_EVALUATION_HANDOFF_20260826.md` with:

- `configs/sample_generation/safeclaw_adversarial_v2_pilot.yaml`;
- the frozen Qwen embedding service;
- real SafeClaw/OpenClaw execution;
- real provider calls;
- the existing provenance and redaction pipeline.

After collection:

1. verify exactly four expected trajectories or document any controlled failure;
2. audit complete interaction records and redaction evidence;
3. run deterministic mining and sample audit;
4. manually review the pilot for task validity, attack-stage independence, semantic coherence, tool execution, and suspicious leakage;
5. record costs, latency, failure types, and accepted/rejected counts without secrets.

Do not start the main campaign until the pilot is reviewed and explicitly marked passed in the progress ledger.

## 14. Gate B — Main collection and primitive freeze

Run the documented 120-trajectory v2 main campaign only after Gate A passes.

Required sequence:

1. collection;
2. completeness and redaction audit;
3. deterministic mining;
4. primitive-sample audit;
5. human review of borderline or high-impact samples;
6. freeze the accepted library.

Acceptance:

- at least 30 accepted real primitive samples;
- each accepted sample traces to a complete real interaction record;
- acceptance/rejection reasons are preserved;
- library manifest, config hash, code commit, model identities, embedding revision, embedding dimension, and environment profile are frozen;
- the formal evaluator cannot mutate or silently replace the frozen library.

If fewer than 30 samples pass, stop and report the evidence-backed shortfall. Do not lower the threshold or fabricate samples.

## 15. Gate C — Formal 15-case evaluation

Run the formal v2 evaluation using:

- `configs/task_sets/safeclaw_construction_v2.yaml`;
- `configs/environments/safeclaw_openclaw_v2.yaml`;
- `configs/experiments/safeclaw_formal_v2.yaml`;
- the frozen primitive library from Gate B;
- the same pinned embedding model, revision, endpoint behavior, and dimension used during collection.

Use the exact launcher/recovery procedure in the 2026-08-26 handoff. Preserve per-case evidence, complete interaction records, failure categories, and aggregate metrics. A launcher exit code alone is not proof of success.

Acceptance:

- all 15 intended cases have terminal, auditable states;
- success/failure denominators are explicit;
- missing or invalid runs are not counted as benign failures or successes;
- aggregate results can be regenerated from per-case artifacts;
- no secret is present in any saved artifact.

## 16. Reporting and documentation

After every gate, append a timestamped, non-secret entry to `FORMAL_EXPERIMENT_PROGRESS_20260824.md` containing:

- command or launcher identity, without credentials;
- input config paths and hashes;
- code commit and dirty-state summary;
- output artifact paths;
- counts and gate result;
- blockers and next action.

At completion:

1. update `docs/RESEARCH_STATUS.md` from actual evidence only;
2. update `docs/DECISIONS.md` for any approved deviation;
3. update `README.md` only if the durable run path changed;
4. keep raw outputs and formal evidence out of Git if required by existing repository policy;
5. provide a concise completion report distinguishing implementation completion from scientific evidence.

Do not claim an attack result, success rate, robustness conclusion, or formal completion before Gate C artifacts exist and are audited.

## 17. Stop conditions

Stop the current stage and report rather than bypassing the gate if any of these occurs:

- required credential variable is absent;
- embedding endpoint is unreachable from OpenClaw Docker;
- returned embedding is empty, non-numeric, non-finite, or changes dimension;
- embedding model/revision/dimension differs from the frozen record;
- deterministic tests or config-hash checks fail;
- Docker task isolation or transcript redaction cannot be verified;
- pilot review fails;
- fewer than 30 real samples pass audit;
- formal case evidence is incomplete or non-reproducible;
- continuing would require deleting or overwriting user-owned data.

Never replace a blocked real run with synthetic evidence and never weaken a gate merely to obtain a completed status.

## 18. Completion definition

This plan is complete only when all of the following are true:

- Qwen3-Embedding-4B is pinned, locally served, and provenance-recorded;
- host and Docker embedding probes pass with one stable vector dimension;
- embedding and third-party provider endpoints are separated in the v2 path;
- all deterministic verification passes after the config change;
- the four-trajectory pilot passes audit and review;
- the main collection produces at least 30 accepted real samples;
- the primitive library is frozen with complete provenance;
- all 15 formal cases have auditable terminal results;
- documentation reports only claims supported by generated evidence;
- secret scan is clean.
