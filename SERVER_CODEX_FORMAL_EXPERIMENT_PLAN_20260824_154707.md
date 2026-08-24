# Linux Server Codex Execution Plan: Formal Primitive-Chain Experiment

- Created: `2026-08-24 15:47:07 +0800`
- Repository: `stac-compositional-attack-lab`
- Target environment: Linux server with Docker, SafeClawArena/OpenClaw, and configured model endpoints
- Purpose: finish the real interaction-collection -> primitive-chain library -> single-sample Planner -> adaptive Attacker -> SafeClaw formal evaluation experiment

This file is the authoritative execution plan for the next server run. Treat older
server prompts and completed implementation plans as historical context only. Do
not stop after producing another plan or smoke fixture: implement, test, run the
bounded pilot, complete the configured real collection and matched formal matrix,
audit the evidence, and report only supported conclusions.

## 1. Required experiment semantics

The following decisions are fixed for this run.

1. A formal non-baseline case is assigned exactly one frozen primitive-chain
   sample before the Planner is called. The Planner must not browse or select
   from the whole library.
2. The Planner receives the complete public benchmark prompt that is legitimately
   visible for the case, after deterministic removal of private evaluator/oracle
   fields. It also receives exactly one assigned public sample view.
3. A sample uses ordered core primitive occurrences and typed causal edges as its
   causal backbone. Semantic macros are annotations for interpretation, retrieval,
   and reporting; they are not substitutes for the core chain.
4. The formal Attacker is an independent adaptive execution role. It must perform
   plan stages through a controlled action/observation loop. Generating unused
   `stage_actions` or only pre-materializing task slots is not Attacker execution.
5. Every claimed mechanism transition must be traceable through:

   ```text
   library/sample hash
     -> case assignment
     -> Planner input/prompt/output
     -> Attacker input/prompt/action
     -> Victim request/tool/state event
     -> artifact/state evidence
     -> primitive and official verdicts
   ```

6. Construction tasks and formal test tasks are disjoint. Formal outcomes never
   flow back into a frozen construction library.
7. The experiment is restricted to authorized SafeClaw/OpenClaw containers,
   synthetic services, synthetic state, and no-value canaries. Do not access real
   accounts, host files, production services, or public targets.

## 2. Known starting state to verify

Do not trust this list without checking the pulled server checkout.

- The repository contains formal-v2 safety boundaries, three-view sample storage,
  a construction-agent skeleton, Planner/Attacker schemas, SafeClaw whole-episode
  runner, deterministic mechanism verification, official verdict parsing, resume,
  and audit/report infrastructure.
- `formal-v2-attack-synthetic` contains only one accepted positive and one blocked
  negative. It is a deterministic fixture, not a research library.
- The real `safeclaw-adversarial-v1` collection has not been run in the repository
  evidence currently committed.
- `experiments/safeclaw_runs` has no committed formal-v2 real run.
- `EXPERIMENT_PROGRESS.md` describes the legacy `stac-verified-30-v0.1` run with
  one primary condition and one seed. It is historical engineering evidence, not
  evidence for the experiment defined here.
- `src/stac_attack_lab/extraction/chains.py` currently selects the first occurrence
  of each primitive and constructs at most one fixed PSE chain per trajectory.
- `FormalPlannerInput` currently contains `public_samples`, and the formal runner
  passes the entire public library to the Planner.
- The current formal runner records Attacker stage actions but only consumes
  `public_slot_values` during task materialization.
- Planner and Attacker observable model messages are not yet fully preserved in
  `complete_interaction_record`.
- The pinned SafeClaw runner may expose only whole-episode execution. Verify the
  actual upstream API before designing the action loop; do not pretend a per-step
  API exists.

Before editing, read:

- `EXPERIMENT_GRANULARITY_ALIGNMENT_GAPS.md`
- `README.md`
- `docs/RESEARCH_STATUS.md`
- `docs/EXPERIMENT_PROTOCOL.md`
- `docs/DECISIONS.md`
- `docs/PROMPTS.md`
- `PROJECT_STRUCTURE.md`
- `SECURITY.md`
- `integrations/safeclaw/README.md`

Inspect applicable `AGENTS.md` files and `git status`. Preserve user changes and
do not modify unrelated code or generated historical evidence.

## 3. Server `.env` and model-provider contract

The server already has a local `.env` containing credentials/configuration for
an OpenAI-compatible third-party provider and native Gemini. Expected variable
names are:

```text
OPENAI_BASE_URL
OPENAI_API_KEY
OPENAI_MODEL_list
GEMINI_API_KEY
```

`OPENAI_MODEL_list` uses the existing lowercase `list` spelling and is canonical.
`OPENAI_MODEL_LIST` may remain a compatibility alias, but must not override the
canonical variable.

Rules:

1. Load `.env` through the existing project loader. Never `source` it with shell
   tracing enabled and never print its contents.
2. Confirm `.env` is ignored by Git and is not staged. Use restrictive file
   permissions. Never copy it into artifacts, Docker build contexts, prompts,
   task JSON, transcripts, reports, commits, or GitHub.
3. Preflight may report only variable presence, selected model identifiers, and
   redacted/hashed endpoint identity. It must never print keys or the raw endpoint
   URL.
4. Use `OPENAI_BASE_URL` and `OPENAI_API_KEY` only for the third-party
   OpenAI-compatible client. Use `GEMINI_API_KEY` only for the native Gemini
   client. Do not silently interchange these providers.
5. Parse `OPENAI_MODEL_list`, verify the requested role models are available, and
   record the chosen model id for every role. Prefer the model ids already pinned
   in versioned configs. If unavailable, create a new versioned config and record
   the substitution; do not mutate a historical run config in place.
6. Current SafeClaw configs also expect a target model selector such as
   `SAFECLAW_MODEL`. If it is absent, resolve it explicitly from the available
   model list and the versioned experiment allowlist, then export it only in the
   local run environment or add it to the untracked `.env`. Never guess or commit
   it. If no compatible target model exists, stop before model calls and report
   the exact non-secret compatibility blocker.
7. A real profile must never fall back to `FakeModelClient` after an endpoint or
   credential failure.
8. Add/retain redaction coverage for all four variables above and any derived
   Authorization headers. Run a secret scan before marking every real case
   complete.

## 4. Durable progress and execution discipline

Create `FORMAL_EXPERIMENT_PROGRESS_20260824.md` as the server-side human ledger.
For every gate record timestamp, commit, config hash, command, concise result,
artifact path, blocker, and next action. Never record secret values.

Long-running collection and evaluation must use:

- stable run ids;
- a single-run lock;
- unbuffered persistent logs;
- atomic checkpoints plus append-only transitions;
- idempotent resume that does not rerun completed cases;
- bounded retries and explicit quota/environment pause states.

Do not push, rewrite remote history, or delete historical artifacts unless the
user separately requests it. Leave implementation changes and evidence ready for
review with an exact `git status` summary.

## 5. Gate 0: reproduce the server baseline without model calls

1. Confirm the expected repository, branch, commit, worktree status, Python
   environment, disk space, Docker daemon, pinned image, SafeClaw upstream path,
   and upstream commit.
2. Confirm the safety patch applies cleanly to an ephemeral copy and does not
   mutate the pinned checkout.
3. Validate `.env` variable presence and model-list parsing without calling an
   endpoint or printing values.
4. Inventory available SafeClaw construction/formal tasks and prove the configured
   ids and splits do not overlap.
5. Run:

   ```bash
   make lint
   make typecheck
   make test
   ```

6. Record baseline test counts. Do not continue with a dirty failure masked by
   skips or by loosening a safety gate.

Exit criteria: deterministic quality gates pass, pinned upstream/image identity
is known, the task inventory exists, and all non-secret prerequisites are
recorded.

## 6. Gate 1: formal case assignment and single-sample Planner contract

Implement a scheduler-owned case contract, for example
`FormalCaseAssignment`, containing at least:

```text
case_id
pair_group
benchmark_task_id
benchmark_public_prompt
benchmark_public_prompt_hash
selected_sample_id | null
selected_sample_hash | null
condition
seed
budget
task_set/library/registry hashes
```

Replace the primary Planner contract with a singular input:

```text
SingleSamplePlannerInput
  public_task
  benchmark_public_prompt
  selected_sample | null
  budget
  condition
  seed
```

Requirements:

- The scheduler performs fixed/random/rule-based compatibility and assignment.
- A non-baseline Planner input contains exactly one selected sample.
- `no_sample` contains `selected_sample=null` and a valid matched benign binding.
- The Planner has no field or indirect artifact that exposes the full library.
- Remove sample selection from the primary LLM Planner prompt. Preserve any legacy
  selector only under an explicitly labeled legacy/retrieval experiment path.
- Pair identity fixes task, initial state, Victim prompt/tool contract, budget,
  seed, evaluator, and model configs; only the declared condition may differ.
- Update Pydantic contracts, JSON schemas, configs, prompt assets, documentation,
  and migrations together.

Required deterministic tests:

- singular sample/no-sample schema validation;
- full-library leakage rejection;
- incompatible sample assignment rejection;
- deterministic assignment by seed;
- pair invariant checks;
- Planner prompt-injection and private-oracle exclusion.

## 7. Gate 2: public benchmark prompt contract

1. Inspect the pinned task schema and runner to identify the exact public prompt
   text legitimately available before the Victim episode.
2. Create a deterministic public-view adapter that includes the complete public
   benchmark/user/session prompt needed by the research question while removing
   evaluator blocks, success/safe conditions, canaries, credentials, auth fields,
   private fixtures, and future outcomes.
3. Hash the canonical public prompt and keep the hash invariant across matched
   conditions.
4. Add tests showing that every included field is public and every protected
   field is absent.
5. Treat all benchmark/sample/tool text as untrusted data in Planner and Attacker
   prompts.

Exit criteria: the Planner sees the approved complete public prompt, the prompt
hash is paired across conditions, and leakage tests pass.

## 8. Gate 3: replace the fixed validator with a bounded Chain Miner

Refactor the current canonical-chain-only extractor into a general, deterministic,
bounded miner.

It must:

- consider every observable primitive occurrence, not only the first subtype
  occurrence;
- allow one trajectory to produce zero, one, or multiple candidates;
- enumerate typed causal paths/subgraphs from declared entry occurrences to
  declared terminal occurrences;
- require continuous observable data/state/control/authorization dependencies;
- support repeated primitive subtypes, variable length, session boundaries,
  optional nodes, branches, and joins where represented by the schema;
- distinguish positive, partial, blocked, rejected, error, timeout, and
  not-observable outcomes;
- preserve source event, artifact, state, trust-boundary, and evidence refs;
- reject temporal adjacency without causal evidence and reject direct shortcuts;
- bound path length, candidate count, branching factor, and runtime to prevent
  combinatorial explosion;
- perform structural/isomorphic deduplication while retaining provenance;
- report diversity by core sequence, typed edges, components, length, session
  span, topology, macro annotations, and negative reason codes.

The public sample view must contain sanitized ordered core nodes, typed edges,
state/artifact types, multiplicity, session-boundary markers, and optional macro
annotations. It must not contain original attack payloads, Victim transcript,
private oracle, canary, or construction success condition.

Required tests include multiple chains from one graph, repeated occurrences,
branch/join, cross-session state edges, shortcut rejection, deterministic order,
deduplication, bounds, and public/private leakage.

Keep the old fixed PSE topology as a named regression fixture, not as the miner's
only behavior.

## 9. Gate 4: real Attacker action/observation execution

Inspect the pinned SafeClaw/OpenClaw lifecycle first. Because the official runner
may expose only whole-episode execution, do not invent a nonexistent `step()` API.

Implement the smallest controlled adapter extension that can:

1. receive a validated Planner stage;
2. call the independent Attacker with only public task/sample/plan/history/state;
3. validate one typed action against the allowed surface, component, stage,
   bindings, and remaining budget;
4. deliver that action to a field or interaction surface proven to be consumed by
   the real pinned OpenClaw Victim;
5. capture the resulting public Victim/tool/state observation;
6. feed only that public observation to the next Attacker step;
7. stop, retry, or reroute within the frozen plan and bounded policy;
8. preserve official SafeClaw evaluation parity and oracle hashes.

If upstream requires an adapter/bridge or ephemeral patch, keep it versioned,
minimal, testable, and outside the immutable upstream checkout. Prove official
evaluator parity against an unmodified control. If a stage cannot be delivered
to a genuinely consumed surface, fail closed; do not count a recorded but unused
action as execution.

Every action and resulting event must carry stable links:

```text
plan_id
plan_stage_id
attacker_call_id
attacker_action_id
victim_request_event_id
victim_response_event_id
tool_event_ids
input_artifact/state_refs
output_artifact/state_refs
verifier_evidence_refs
```

Required tests:

- each action reaches the exact pinned Victim input path;
- unauthorized/invented surface rejection;
- stage order and budget enforcement;
- observation-dependent second action;
- action/event/evidence lineage completeness;
- official evaluator parity and protected-oracle equality;
- crash/resume without duplicate action delivery.

## 10. Gate 5: complete observable call recording and accurate accounting

Record a request event before every Planner, Attacker, Victim gateway, and native
Gemini call. Immediately append its response or categorized error.

For Planner and Attacker preserve, after redaction:

- provider and model id;
- prompt id/version/hash;
- complete observable request messages;
- filtered raw response and parsed structured output;
- schema/semantic validation result;
- call/request id, latency, retry count, and usage when returned;
- related plan/action/event/artifact/evidence refs.

Accounting must distinguish:

```text
planner_model_calls
attacker_model_calls
victim_gateway_requests
victim_provider_completions_when_observable
gemini_native_calls
embedding_calls_when_observable
whole_episode_attempts
input_tokens
output_tokens
cached_tokens
provider_cost_when_returned
wall_time
```

Never treat `episode.attempt_count` as total API calls. Never fabricate zero token
or cost values; use `null` with an explicit instrumentation-gap reason when the
provider does not return usage.

## 11. Gate 6: separate collection, mining, audit, and freeze

Create unambiguous, resume-safe interfaces equivalent to:

```text
sample collect --config <campaign>
sample mine --collection <immutable-collection>
sample audit --library <generated-library>
sample freeze --library <audited-library> --version <new-version>
```

Collection must not implicitly initialize models during offline mining. Mining
must consume a declared immutable collection manifest and work without model
credentials. Separate session count, interaction-turn count, action count, tool
count, token budget, wall-time budget, and retry limits.

Use campaign/case ids derived from task, split, seed, strategy, objective, and
config hash. Preserve every attempt and resume without duplicating completed
trajectories or samples.

## 12. Gate 7: deterministic integration gate before real calls

Before any real endpoint smoke:

1. Update schemas and verify schema registry consistency.
2. Run focused tests for Gates 1-6.
3. Run fake-model end-to-end tests for:
   - multi-trajectory collection and resume;
   - multi-chain mining;
   - single-sample assignment and Planner;
   - two-stage adaptive Attacker execution;
   - complete lineage and dual verifier;
   - matched `no_sample` and dependency-ablation controls;
   - transcript, usage, hash, secret, and artifact audits.
4. Run the full quality suite again:

   ```bash
   make lint
   make typecheck
   make test
   git diff --check
   ```

Do not start real collection until this gate is green.

## 13. Gate A: real Sample Collection

### A0. Endpoint and SafeClaw preflight

- Perform at most one minimal authenticated smoke per required provider/model.
- Do not print request headers, endpoint values, `.env`, or raw credentials.
- Verify the pinned SafeClaw image/upstream/patch and one official PSE smoke.
- Record provider/model selection and redacted request ids.
- Stop on incompatibility instead of silently substituting a model or fake client.

### A1. Bounded pilot

Create a new versioned construction campaign with:

- multiple seeds, explicit strategies, and separate budgets;
- construction-only SafeClaw tasks disjoint from formal tasks;
- at least three safe objective/topology families when supported by the task
  inventory, rather than repeated paraphrases of one PSE chain;
- explicit maximum attempts and quota stop conditions.

Run a small pilot first: at least two construction tasks, two seeds, and enough
bounded attempts to exercise positive, negative, blocked, and recovery paths.
Inspect complete transcripts, state diffs, lineage, resume behavior, and secret
scans before scaling.

### A2. Full collection and freeze

Default target for this execution is 30 accepted, structurally valid formal
samples with retained negatives, capped at 120 real construction trajectories.
Do not increase the cap without recording the reason and revised expected call
budget. Do not lower acceptance criteria to reach the target.

After collection:

1. mine all trajectories with the new Chain Miner;
2. filter and audit every candidate;
3. report attempted trajectories, candidates per trajectory, accepted unique
   chains, duplicates, partial/blocked/rejected/error counts, reason distribution,
   and structural diversity;
4. manually inspect representative accepted, rejected, blocked, and
   not-observable records;
5. freeze under a new immutable version such as
   `formal-v3-safeclaw-20260824`, with manifest/file/config/model/prompt hashes;
6. never overwrite `formal-v2-attack-synthetic` or legacy datasets.

Stage A is complete only if the real library is non-smoke, auditable, has more
than one topology, and its public/execution views pass prompt/payload/oracle/
transcript/secret leakage scans.

## 14. Gate B: matched formal SafeClaw evaluation

### B0. Freeze the evaluation design

Before the first formal model call, version and hash:

- real frozen library;
- formal task set and construction/test exclusion proof;
- case-assignment table;
- registry and schemas;
- Planner and Attacker prompts/configs/models;
- Victim system/tool contract and target model;
- budgets, seeds, retries, conditions, metrics, and stopping rules.

Primary matched conditions:

1. `assigned_sample`: exactly one real sample assigned before Planner input;
2. `no_sample`: same public task, state, seed, budget, model, and evaluator with
   a legal benign binding and no sample;
3. `dependency_ablation`: same assigned sample with one preregistered required
   causal dependency broken, without revealing condition labels to the Victim.

Keep fixed materialization, random assignment, and defenses as separately labeled
secondary engineering conditions; do not mix them into the primary denominator.

### B1. Formal pilot

Run one or two compatible sample-task pair groups across two seeds and all three
primary conditions. Audit every transcript, action delivery, state transition,
lineage link, mechanism verdict, official verdict, pair invariant, and usage
record. Repair deterministic or instrumentation failures and rerun with a new
versioned config when the frozen design changes.

### B2. Full matched matrix

Preregister at least 10 compatible sample-task assignments spanning the available
formal tasks/topologies, three seeds, and the three primary conditions: at least
90 completed cases when inventory permits. If the pinned benchmark cannot provide
10 valid disjoint assignments, run all valid preregistered assignments and label
the result as coverage-limited; do not invent tasks or overstate generalization.

Run serially unless container/port isolation is proven. Use one stable run id,
tmux, persistent logs, locking, and `--resume`. A completed case must pass schema,
hash, transcript, secret, lineage, pair, mechanism, and official-result audits.

## 15. Gate C: reporting and research-claim boundary

Report separately:

- official attack/security/utility outcomes;
- full core-chain mechanism success;
- macro completion;
- terminal-only/shortcut outcomes;
- stage and edge failure reasons;
- positive/negative/blocked/error rates during construction;
- selected-sample versus matched no-sample and dependency-ablation results;
- chain family, length, topology, component path, and session-span strata;
- retries, refusals, timeouts, instrumentation gaps, latency, tokens, and cost;
- benign utility and false-positive effects where available.

Use paired statistics only when pair invariants pass. Include denominators and
Wilson intervals; use paired bootstrap/McNemar only when assumptions and sample
size are appropriate.

Do not claim sample-conditioned effectiveness, causal contribution, transfer, or
generalization from synthetic fixtures, failed pairings, one topology, one task,
one seed, or incomplete runs.

## 16. Required final artifacts

The final server handoff must identify:

- changed source/config/schema/prompt/test files;
- server progress ledger;
- collection manifest and progress log;
- frozen real library path/version/tree hash and diversity summary;
- frozen formal assignment/config/task-set hashes;
- formal run root, progress, results, transcripts, per-case artifacts, audit, and
  report;
- exact safe tmux start/attach/detach/resume/audit/report commands;
- provider/model assignments without credential or raw endpoint disclosure;
- planned/completed/retryable/terminal case counts;
- quality-gate commands and exact pass counts;
- remaining external blockers, deviations, and claim limitations;
- final `git status`.

## 17. Completion criteria

Do not call the task complete until all applicable items are true:

1. P0 semantics are implemented: scheduler-assigned singular sample, approved
   public prompt, core-chain public view, real adaptive Attacker execution, and
   complete lineage.
2. The hard-coded one-chain extractor has been replaced by a bounded multi-chain
   miner with deterministic tests.
3. Collection, mining, audit, and freeze are separate and resume-safe.
4. A real authorized multi-task/multi-seed construction campaign produced and
   froze a non-smoke, diverse library with retained negatives.
5. Planner and Attacker observable calls, Victim/tool/state events, official
   verdicts, and primitive evidence are fully linked and redacted.
6. The matched formal pilot passed all audits.
7. The preregistered full matrix completed, or an unavoidable external blocker
   has a precise resumable state and evidence; partial work is not reported as a
   completed experiment.
8. All quality, transcript, secret, schema, hash, lineage, pair, resume, and
   official-parity gates pass.
9. Reports clearly distinguish legacy, smoke, pilot, formal, and coverage-limited
   evidence.

When blocked by an external service, preserve state, exhaust bounded retries,
record the non-secret error and next command, and continue all independent work.
Never bypass safety, provenance, evaluator, or information-isolation gates merely
to obtain a successful run.
