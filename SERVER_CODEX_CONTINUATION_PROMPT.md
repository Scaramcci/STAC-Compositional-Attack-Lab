# Server Codex continuation prompt

You are continuing implementation of the repository currently checked out as
`STAC-Compositional-Attack-Lab`. Work directly in this repository and carry the
project to a production-quality, reproducible state. Do not stop after analysis,
planning, scaffolding, or configuration changes.

## First actions

1. Read the repository `AGENTS.md` files that apply to this directory, then read
   `PLAN.md`, `README.md`, `PROJECT_STRUCTURE.md`, `SECURITY.md`, and every file
   under `docs/` that defines the experiment protocol, prompts, or decisions.
2. Inspect `git status` before editing. Preserve all existing user changes and
   do not modify files outside this repository.
3. Audit the current implementation and tests against `PLAN.md`. Continue from
   the existing code instead of rebuilding the project from scratch.
4. Maintain an explicit task plan and implement the missing pieces end to end.

## Current execution restriction

The OpenAI-compatible API quota/access has not recovered. For this task, build
the complete implementation only. Do **not** run a real STAC sample-generation
experiment, a real evaluation, or any command that calls OpenAI, Gemini, or the
local Huihui model. Do not probe API availability and do not consume quota.

You may and should run deterministic/unit/contract tests using `FakeModelClient`,
plus linting, type checking, schema generation, and other tests that are proven
not to make model or public-network calls. Any integration test requiring a real
model must remain explicitly marked and skipped with a precise reason.

Current server state: model discovery resolves
`/home/kunyuan/models/huihui-qwen3-14b-abliterated-v2`. An ignored
`.venv-vllm` contains vLLM 0.26.0, PyTorch 2.11.0+cu130, and BitsAndBytes 0.50.0;
CUDA detection succeeds on the RTX 4090. The launcher defaults to that virtual
environment and runtime BitsAndBytes quantization. The Huihui weights/server and
the full experiment have intentionally not been started.

## Required model assignments

Implement and validate two distinct experiment profiles. Model assignment must
be explicit per role; do not silently substitute one role's client for another.

### STAC offline validation and sample construction

- Planner: GPT-5.5 through the OpenAI-compatible API.
- Attacker: GPT-5.5 through the OpenAI-compatible API.
- Verifier LLM: GPT-5.5 through the OpenAI-compatible API.
- PromptWriter and Judge: retain the GPT-5.5/OpenAI-compatible assignment where
  these roles participate in the pipeline.
- Victim: Gemini through the official Gemini API.
- The deterministic verifier remains authoritative. The GPT verifier and Judge
  may add semantic evidence and labels but must never override the hard verdict.

This phase must produce a frozen, AgentLAB-offline-like sample dataset containing
the attack graph, role outputs, prompt/model hashes, provenance, complete
transcript references, deterministic evidence, and verifier results.

### Formal evaluation

- Keep Planner, Attacker, PromptWriter, Verifier, and Judge assignments identical
  to the offline phase: GPT-5.5 through the OpenAI-compatible API.
- Change only Victim to the local
  `huihui-qwen3-14b-abliterated-v2` model.
- Search for the local model under `../../../models` rather than assuming one exact
  directory name. Validate a candidate using its model config/tokenizer and
  weight files. Support an explicit `HUIHUI_MODEL_PATH` override.
- Build the local serving/evaluation integration required by the repository,
  preferably through its existing OpenAI-compatible Huihui client and a vLLM
  launch/config script suitable for a single RTX 4090. Build and test discovery
  logic without loading weights or starting the server in this task.
- The Victim system prompt and tool contract must be byte-for-byte identical
  across clean, attack, ablation, defense, offline, and evaluation conditions.
  Enforce this using a recorded SHA-256 hash and automated tests.

## Environment variables and secrets

Use environment variables only. Never write values into source, configuration,
documentation, test snapshots, transcripts, logs, or error messages.

- `OPENAI_BASE_URL`
- `OPENAI_API_KEY`
- `OPENAI_MODEL_list` (the existing environment uses this spelling)
- Also accept `OPENAI_MODEL_LIST` as a compatibility alias, with the lowercase
  `list` spelling taking precedence when both are set.
- `GEMINI_API_KEY`
- `HUIHUI_MODEL_PATH`
- `HUIHUI_BASE_URL`
- `HUIHUI_API_KEY` when the local server requires one
- `HUIHUI_MODEL`

Add startup validation that reports only missing variable names or invalid model
configuration. Never print, serialize, hash, or partially reveal secret values.
Pin the configured GPT model name to GPT-5.5 for real offline/evaluation profiles;
fail closed if that requested model is absent from the configured model list.

## Durable progress and resume requirements

API quota exhaustion and transient failures are expected. The experiment runner
must be resumable without losing completed attacks or duplicating them.

1. Create `EXPERIMENT_PROGRESS.md` at the repository root if it does not exist.
   It is the human-readable experiment ledger. Include run id, profile, dataset
   version, config hash, start/update timestamps, total/completed/failed/pending
   counts, last completed attack id, current pause reason, and a compact table of
   per-attack status. Do not put secrets or full conversations in this Markdown.
2. Store machine-readable state under each run directory:
   - `progress.json`: current checkpoint, written atomically using temp-file plus
     rename.
   - `attack_progress.jsonl`: append-only transition log.
   - `conversations.jsonl`: append-only complete role-conversation log.
3. Persist a progress transition after **every individual attack case**, not only
   after a batch, condition, task, or full run. Flush and fsync before continuing.
4. Use a deterministic idempotency key derived from run/config/dataset/attack/
   condition/seed identifiers. On resume, skip completed keys and continue the
   first incomplete attack. Preserve every failed attempt instead of overwriting
   it.
5. Record statuses such as `pending`, `running`, `completed`, `failed_retryable`,
   `failed_terminal`, and `paused_quota`. A quota/rate-limit interruption must
   record the error category, finish the checkpoint, update
   `EXPERIMENT_PROGRESS.md`, and exit cleanly with a resumable state.
6. Implement real `run resume --run-id ...` behavior. The existing no-op resume
   behavior is not acceptable for real model runs.
7. Add recovery tests that terminate a fake run between attacks, resume it, and
   prove that completed attacks are neither lost nor executed twice.

## Complete conversation provenance

Conversation capture is a core experimental artifact, not optional debug output.
Record the full observable protocol for every attack, including:

- Planner input and the plan/decision sent to Attacker.
- Every Attacker instruction or message sent to Victim.
- Every Victim response, tool request, tool result made visible to Victim, and
  follow-up turn.
- PromptWriter outputs when used.
- GPT Verifier comments, evidence references, labels, abstentions, and errors.
- Judge inputs/outputs when used.
- Deterministic verifier inputs by reference, stage verdicts, aggregate hard
  verdict, artifact lineage references, event ids, and snapshot references.
- Retries, schema-validation failures, fallbacks, refusals, quota errors, and
  abstain behavior.

Define typed Pydantic contracts and JSON Schema for this data rather than storing
ad hoc dictionaries. A conversation event should include at least:

- schema version, run id, attack id/idempotency key, phase, condition, seed,
  monotonically increasing sequence number, timestamp, and attempt number;
- event type, sender role, recipient role, model provider/model id/config hash;
- prompt id/version/hash and input/output schema ids;
- complete request messages visible to that role, raw model response, parsed
  structured response, schema-validation result, token/latency metadata when
  available, error category, and references to related events/artifacts;
- a `redactions` field proving secret filtering occurred.

Write a request event before each external model call, then append its response
or error event immediately afterward. Use stable call ids so an interrupted call
can be distinguished from a completed response. Preserve raw response text for
research reproducibility, but pass it through explicit secret redaction first.
Do not record hidden chain-of-thought and do not ask models to provide it; record
only prompts, messages, structured outputs, concise rationale summaries, and
observable tool interactions.

Add transcript auditing that verifies sequence continuity, role isolation,
required stages, prompt hashes, model assignments, redaction, and correspondence
between conversation events, environment events, artifacts, snapshots, and hard
verdicts. Reports must link back to transcript event ids.

## Implementation and safety constraints

- Planner, Attacker, Victim, PromptWriter, Verifier, and Judge remain independent
  roles with separate prompts, input contracts, output schemas, clients, model
  configuration, and information permissions.
- The Victim must not receive the attack graph, condition name, verifier target,
  private oracle, or hidden experiment metadata.
- Preserve the local-only synthetic canary environment. No shell payloads, host
  command execution, real credentials, real exfiltration, or default public
  network access may be introduced.
- Model clients must not silently fall back to `FakeModelClient` in real profiles.
  Missing credentials, unavailable models, and schema failures must fail closed
  and produce resumable records.
- Avoid changing frozen datasets in place. Create a new immutable version with a
  manifest and content hashes.
- Keep configuration, CLI help, README, project structure documentation,
  security documentation, experiment protocol, prompt documentation, and ADRs in
  sync with the implementation.

## Required tests and handoff

Add deterministic tests for model-profile assignments, model-path discovery,
environment-name compatibility, victim prompt hash equality, conversation schema
round trips, secret redaction, per-attack checkpointing, crash recovery, quota
pause/resume, transcript auditing, and deterministic-verifier authority.

Run all offline-safe quality gates that cannot call real models. Before each
command, verify from code/configuration that it cannot make an external request.
Do not run real smoke experiments during this task.

At completion, report only:

- implemented components and important entry files;
- offline-safe commands actually run and their results;
- real-model commands intentionally not run;
- remaining integration prerequisites for OpenAI/Gemini and the local 4090;
- any deviation from `PLAN.md`, with the corresponding ADR.
