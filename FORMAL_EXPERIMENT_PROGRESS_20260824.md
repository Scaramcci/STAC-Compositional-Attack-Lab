# Formal Experiment Progress 2026-08-24

This ledger records only non-secret execution state for the formal primitive-chain experiment defined by `SERVER_CODEX_FORMAL_EXPERIMENT_PLAN_20260824_154707.md`.

## Gate 0 - Baseline and prerequisites

- Status: passed at `2026-08-24T10:11:47+02:00`
- Started: 2026-08-24 (Europe/Berlin)
- Repository: `/home/kunyuan/snap/Zky_Agent_Attack/STAC-Compositional-Attack-Lab`
- Branch/commit: `master` at `5265d8fb6861394df01fce1bf7cdce6bddb705af`
- Initial worktree: clean
- Python: project `.venv`, Python 3.12.3
- Disk: 138 GiB available (filesystem 92% used)
- Docker: client/server 29.6.1
- SafeClaw upstream: `a11f5cceaba0676be721021f8d232638fd111305`, clean `main`
- SafeClaw image: `openclaw-env:2026.3.12`, digest `sha256:8868e3c4bf0f74cafecef2fc8424a275a8a14e6ef0946f39a068f8cf97123337`
- Existing formal evidence: no completed real formal-v2 run; only entrypoint/preflight smoke logs under `experiments/safeclaw_runs/`
- Existing formal library: `formal-v2-attack-synthetic` contains synthetic fixture evidence and is not eligible as the real research library
- Commands completed: repository/branch/commit/status inspection; Python/disk/Docker/upstream/image inspection; required plan and context documents read
- Security correction: `.env` was ignored but mode `664`; it is now mode `600`. No variable values, key material, or endpoint were printed or hashed.
- Environment loader result: `OPENAI_BASE_URL`, `OPENAI_API_KEY`, canonical `OPENAI_MODEL_list`, and `GEMINI_API_KEY` are present. The uppercase compatibility alias is absent. Parsed OpenAI-compatible model ids are `gpt-5.5`, `gpt-5.4`, `gpt-5.4-mini`, `gpt-5.3-codex`, and `gpt-5.2`.
- SafeClaw selector preflight: no `SAFECLAW_MODEL` or `SAFECLAW_EMBEDDING_MODEL` is configured. Current versioned SafeClaw target allowlists have no intersection with the parsed OpenAI-compatible model list. No endpoint call was attempted. Before Gate A, a new versioned config must explicitly select an available allowlisted model and embedding policy; historical configs will not be mutated.
- Task inventory: construction tasks `pse-2.1-002` and `pse-2.1-003` (train) exist at the pinned upstream; formal task `pse-2.1-001` exists and is listed in `formal_excluded_task_ids`. Intersection is empty. The construction preflight passed its real-adapter, split, safety, paths, task hash, prompt, real-attacker, upstream, patch, Docker, image, disk, and resumability checks.
- Safety patch: hash `de701dc4c91530d0bc516e490fb83a6b3ec08a0e2b0a5e41b0361275a5d44cd5`; `git apply --check` and `git apply` passed in `/tmp/stac-safeclaw-patch-check-5265d8fb`; patched diff is limited to `scripts/judge.py` (26 insertions, 4 deletions). Pinned upstream remains clean.
- Config hashes: collection `22700a1a785c776d2147f3b60494c603a33305536d9aa8df48df6c02e5b97bd6`; historical formal `d9064e7e88a265cdebf437c254161033cde33fccbaaba7272d1a0c3a11eee457`; environment `498182245cb686f57b21e6cfde5ec2e86d3e125aa8b171664c7339f7cb0d0925`; construction task set `75fc9b4a98ffd9d20a7824c5fb3a6cf9f9cfddc75124641f97a64d9cffc68796`; formal task set `15a10b484a855062acfb1bf10436dbebdf783e57ff48d8e49515025de3131eb6`; registry `c39f1f607cea0205d53d7e69f2be8c3a48a696f718941e637b816f6af6c58f97`.
- Quality commands/results: `make lint` initially exposed 5 Ruff-format failures in the committed baseline; those exact files were mechanically formatted and the rerun passed (`155 files already formatted`, all checks passed). `make typecheck` passed with no issues in 102 source files. `make test` passed 100 tests in 1.39 seconds.
- Behavioral blockers: none for deterministic implementation. Real model calls remain gated on the explicit versioned target/embedding configuration above.
- Next: Gate 1 scheduler-owned singular sample assignment and Gate 2 deterministic complete public benchmark prompt adapter.


## Gate 1 - Scheduler-owned singular sample assignment

- Status: passed at `2026-08-24T11:12:33+02:00`
- Added a strict, hash-bound `FormalCaseAssignment` and `SingleSamplePlannerInput`. The scheduler resolves zero or exactly one sample before any Planner/model call; full-library fields are schema-forbidden.
- Fixed/random/no-sample pair assignment, compatibility, deterministic seed behavior, task/library/registry hashes, selected sample id/hash, and pair invariants are validated outside the Planner.
- Planner implementations now consume and revalidate only the assigned sample. The LLM Planner cannot change assignment and no longer receives the candidate library.
- Evidence: `tests/unit/test_formal_scheduler_public_prompt.py`, `tests/unit/test_formal_planner.py`.

## Gate 2 - Complete public benchmark prompt

- Status: passed at `2026-08-24T11:12:33+02:00`
- Added a deterministic `BenchmarkPublicPrompt` containing the public task title/description and every ordered session's public `session_id`, `user_instruction`, and `instruction_context`.
- Prompt hash is canonical and carried through assignment and Planner input. Task identity and hash consistency are validated.
- Protected evaluator, environment, taint, pre-session setup, canary, credential, and private-oracle fields are excluded and covered by tests.
- Planner/Attacker prompt contracts explicitly treat benchmark/sample/tool text as untrusted data.

## Gate 3 - Bounded causal Chain Miner

- Status: passed at `2026-08-24T11:12:33+02:00`
- Replaced the fixed first-occurrence topology validator with bounded deterministic enumeration over all observable primitive occurrences and typed data/state/control/authorization dependencies.
- Supports multiple candidates per graph, repeated subtypes, variable length, session boundaries, branch/join metadata, partial/blocked/rejected/error/timeout/not-observable outcomes, direct-shortcut rejection, deterministic bounds, and structural deduplication with duplicate provenance paths.
- Public samples expose sanitized ordered core nodes and typed edges as the causal backbone; macro nodes are annotations. Private occurrence ids, evidence refs, raw artifact labels containing reserved data-field terms, payloads, transcripts, oracle data, and canaries remain outside the public view.
- Manifest attempt accounting now distinguishes collection attempts from mined candidates: one completed interaction may produce several accepted chains.
- Deterministic regression fixture result: 2 collection attempts (1 completed, 1 blocked) produce 6 accepted causal candidates and 0 rejected candidates under the current filter policy.
- Verification: `.venv/bin/python -m pytest -q tests/unit/test_chain_construction_filtering.py tests/unit/test_primitive_chain_library.py tests/unit/test_formal_planner.py tests/unit/test_formal_scheduler_public_prompt.py` -> `25 passed in 0.45s`.
- Type verification: `.venv/bin/python -m mypy src/stac_attack_lab/extraction src/stac_attack_lab/datasets src/stac_attack_lab/planning` -> no issues in 21 source files.
- Tooling note: the managed `apply_patch` helper consistently fails before file access with `bwrap: loopback: Failed RTM_NEWADDR`. Reviewed unified diffs are being applied with `git apply`; no acceptance gate has been relaxed.
- Next: Gate 4 independent Attacker `prepare`/action/observation loop over the real pinned `TaskRunner.run_session` path, with official Evaluator parity and complete lineage.

## Gate 3 integration closure - Selected core-chain verification

- Status: passed at `2026-08-24T13:09:05+02:00`
- Replaced the remaining canonical verifier dependency with bounded deterministic assignment of observed occurrences to the selected sample's actual required core nodes. Required typed edges now come from `PlannerSampleView.core_edges`, including repeated-ref disambiguation by occurrence order and causal-edge score.
- Macro annotations are now attached only when every required macro occurrence and required typed edge is present on that specific mined path. A seven-node path without the restart occurrence is no longer mislabeled as a completed Recall macro.
- Sample capabilities and binding roles are derived from the core primitive specs plus macro annotations. Cross-session core structure explicitly adds the lifecycle capability and binding, so task materialization remains complete even when a semantic macro is absent.
- Regenerated the schema registry outputs, including `benchmark_public_prompt`, `formal_case_assignment`, and `single_sample_planner_input`.
- Focused verification: 30 Gate 3 miner/library/verifier/planner/scheduler tests passed; 31 affected source modules passed mypy.
- Full verification: `make lint` passed; `make typecheck` passed for 106 source files; `make test` passed 111 tests in 1.84 seconds; `git diff --check` passed.
- Next: close Gate 4 by joining the action journal to the normalized formal graph and primitive evidence, then prove resumable delivery and evaluator parity.

## Gate 4a - Action journal to verified primitive lineage

- Status: passed at `2026-08-24T13:32:26+02:00`
- Added explicit plan, stage, attacker call/action, and journal-reference fields to normalized interaction events.
- The SafeClaw formal normalizer now validates paired request/response journal records, emits non-primitive request/response control envelopes, and joins matching transcript, tool, lifecycle, and public state-delta events to the originating action. Tool observations returned by the real bridge remain representable when the raw transcript omits the corresponding event.
- Journal action intent does not create transform or terminal primitive evidence. Primitive extraction still depends on observed transcript/tool/lifecycle/state facts; action envelopes use a non-primitive component/operation.
- The formal verifier now checks that every observation request/response/tool id exists in the graph with matching lineage and that each selected required core occurrence is sourced from an event linked to the action for that exact plan stage.
- `full_chain_success` is fail-closed when formal action lineage is incomplete. The mechanism artifact and formal result record the linked action ids and deterministic reason codes.
- Regenerated JSON schemas after extending `InteractionEvent` and `FormalRunResult`.
- Verification: 10 focused verifier/adapter tests passed; affected verification, SafeClaw trajectory, and formal execution modules passed mypy; focused Ruff checks passed; `git diff --check` passed.
- Remaining Gate 4 work: implement safe partial-attempt restart/resume without reusing a fresh victim environment behind cached observations, then run bridge/evaluator parity acceptance.

## Gate 4b - Attempt-safe resume and Victim/Evaluator parity

- Status: passed at `2026-08-24T13:53:29+02:00`; Gate 4 is complete.
- Replaced invalid step-level resume across fresh victim containers with append-only whole-episode attempts. Every attempt has an isolated action journal; an incomplete attempt is retained and marked abandoned before a new bounded attempt starts.
- The execution attempt id is included in attacker and baseline call/action ids. A restarted attempt cannot reuse action ids or cached observations from the prior victim environment.
- Completed cases remain idempotent: atomic episode, sanitized-result and loop/trace artifacts are returned without starting another attempt. Attempt count now means whole-episode attempts and is no longer conflated with gateway/API calls.
- Experimental and matched-baseline paths share the same attempt ledger, bounded attempt budget, failure transitions, canonical attempt journal, and generic journal checkpoint for deterministic fake drivers.
- The real driver rejects any non-empty journal when starting a fresh environment. Completed actions may only be reused inside the still-live attempt; interrupted attempts are never spliced into a new container.
- Added an offline bridge-main contract test proving that a validated action reaches the pinned `TaskRunner.run_session` call, its tool observation returns through the step response, and finish feeds the same session results to `Evaluator`.
- Existing parity acceptance proves the safety patch leaves the protected evaluation object hash unchanged and produces the same official report projection as the pinned original evaluator.
- Crash/resume regression proves attempt-001 is retained/abandoned, attempt-002 uses a disjoint action-id set, and the configured maximum-attempt budget fails closed.
- Full verification: `make lint` passed for 162 files; `make typecheck` passed for 106 source files; `make test` passed 115 tests in 1.93 seconds; `git diff --check` passed.
- Next: Gate 5 complete observable Planner/Attacker/Victim call recording and accurate accounting.

## Gate 5a - Accurate role-separated accounting

- Status: passed at `2026-08-24T14:11:08+02:00`
- Added a strict `FormalExecutionAccounting` contract separating Planner model calls, Attacker model calls, Attacker decision calls, Victim gateway requests, observable Victim provider completions, native Gemini calls, observable embedding calls, whole-episode attempts, token classes, returned provider cost, wall time, and instrumentation gaps.
- Removed the incorrect `api_calls=episode.attempt_count` mapping. Formal `api_calls` is now the sum of known Planner model, Attacker model, and Victim gateway requests; whole-episode attempts remain a separate field.
- Deterministic injected Attackers no longer inflate model-call counts. `ModelFormalAttacker` is explicitly marked model-backed, while every adaptive decision is still counted separately.
- The interactive bridge's returned provider usage is aggregated when observable. Partial provider usage is labeled; absent completion/token/cost data remains `null` with deterministic gap reasons.
- Changed formal result token and cost fields to nullable and embedded the full accounting object in both `FormalRunResult` and `complete_interaction_record`.
- Added non-secret provider identities to model clients so native Gemini calls can be separated from OpenAI-compatible and local calls.
- Regenerated JSON schemas for the accounting/result changes.
- Verification: 18 focused accounting/verifier/action-loop/recorder tests passed; the formal e2e test proves `api_calls != whole_episode_attempts` and unknown aggregate token/cost are null; 27 affected modules passed mypy; focused Ruff and `git diff --check` passed.
- Remaining Gate 5 work: append redacted Planner/Attacker request/response/error events before and after every model call, populate complete observable messages and call metadata, and extend recorder audit coverage.

## Gate 5b - Observable model-call journal and recorder audit

- Status: passed at `2026-08-24T14:38:06+02:00`; Gate 5 is complete.
- Added an append-only, per-case `model_calls.jsonl` contract for Planner and Attacker request, response, error, and semantic-validation events. Requests are persisted before provider invocation and include provider/model identity, prompt id/version/hash, response schema, seed, timeout, complete observable messages, and lineage references.
- Responses record latency, observable retry count and provider request id, redacted raw output, parsed structured output, schema status, returned usage, and explicit instrumentation gaps. Provider clients now expose OpenAI-compatible `usage`/request ids and Gemini `usageMetadata`/response ids/retry count when returned.
- Exact API-key and target-endpoint values are redacted before journal writes and scanned again by the formal recorder. Model errors are categorized and sanitized; no credential or endpoint value is written to formal artifacts.
- Planner trajectory proposals and Attacker setup/stage actions now append semantic pass/fail events after deterministic contract validation. A wrong response type is recorded as a paired model-call error.
- Resume remains append-only: recorder initialization closes a pre-crash request without a terminal event as an interrupted error, and closes a response missing semantic validation with an explicit interrupted validation failure. Existing rows are never rewritten.
- `complete_interaction_record` now contains the observable Planner/Attacker messages, prompt metadata, model-call events, and explicit deterministic/no-model reasons. Every case also records a hashed `model_call_events` artifact.
- Formal accounting derives Planner/Attacker/Gemini call counts from actual request events. Returned model token usage is combined with Victim usage only when all components are observable; otherwise aggregate tokens/cost remain `null` with gap reasons.
- Recorder audit validates every model-call row and rejects duplicate requests, missing or duplicate response/error terminals, terminal/validation events without requests, missing semantic validation, and validation attached to an error.
- Focused verification: 21 recorder/planner/provider/formal-pipeline tests passed.
- Full verification: 117 tests passed; Ruff passed; mypy passed for 107 source files; `git diff --check` passed.
- Real collection/model-provider calls: not run.
- Next: Gate 6 separation of collection, deterministic mining, audit, and freeze commands with resume-safe immutable inputs/outputs.

## Gate 6 - Immutable collection, deterministic mining, audit, and freeze stages

- Status: passed at `2026-08-24T14:57:36+02:00`.
- Added explicit `sample collect`, `sample mine --collection`, `sample audit --library`, and audit-gated `sample freeze --library --version` stages. Mining consumes only an already completed collection and never initializes collection adapters, Attacker models, Victim drivers, or provider clients.
- A strict collection-stage manifest snapshots the non-secret generation config and binds the registry, collection manifest, every raw trajectory/source-event/checkpoint file, and the full collection tree by content hash.
- Completed collection resume validates the immutable stage and returns before constructing collection components. Config drift, extra/missing files, trajectory identity/count drift, path escape, and source-reference or content tampering fail closed.
- A strict mining-stage manifest binds the collection tree hash, registry/config hashes, outcome counts, candidate/accepted/negative counts, library tree hash, every normalized/extraction/library output, and the full output tree hash.
- Mining is idempotent when the stage manifest and all outputs validate. The compatibility `build_sample_library` wrapper is now restricted to authorized JSONL fixtures; real SafeClaw configs must use the separated commands.
- `sample audit` writes a deterministic `library_audit.json` tied to the current mining manifest and library tree. `sample freeze` refuses a missing, failing, or stale audit report before invoking the existing atomic immutable freeze.
- CLI collection/library inputs are resolved inside the project root, preventing the new stages from reading or writing through a path escape.
- Registered and generated JSON schemas for collection-stage, mining-stage, and audit-report contracts.
- Focused verification: 20 sample-stage/normalization/adaptive/formal-pipeline tests passed before schema registration; dedicated tests prove no collection-component initialization after completion, idempotent mine, collection tamper rejection, audit-gated freeze, stale-audit rejection, and CLI routing/path scope.
- Full verification: 121 tests passed; Ruff passed; mypy passed for 107 source files; `git diff --check` passed.

## Gate 6b - Matched dependency ablation

- Status: passed at `2026-08-24T15:23:54+02:00`; the remaining P0 semantic gap is closed.
- Added a strict, hash-bound dependency intervention to the formal plan. Selection is deterministic,
  prefers required cross-session state edges, is tied to the scheduler-assigned sample and trajectory
  hash, and identifies exactly one public materialization slot.
- The ablation case retains the treatment task, seed, budget, pair id, sample, Planner trajectory and
  Attacker realization, then replaces only the preregistered target slot with its
  `baseline.task_set` value. Equal treatment/replacement values and non-sample-derived slots fail
  closed.
- Plan, intervention, materialization manifest and complete-interaction artifacts record stable
  lineage and value hashes without recording secret values. The formal result now contains a typed
  target-edge evaluation distinguishing absent, still-present and not-observable outcomes.
- The deterministic three-condition e2e matrix proves `sample_rule_based`, `no_sample` and
  `dependency_ablation` share the matched pair invariants; the ablation changes one slot and the
  targeted state dependency is evaluated as absent in the synthetic fixture.
- Full verification: 123 tests passed; Ruff passed for 163 files; mypy passed for 107 source files;
  schemas regenerated; `git diff --check` passed.
- Real collection/model-provider calls: not run.
- Next: create and validate versioned v2 collection, environment, task-set and formal-evaluation
  configs, then run the final deterministic Gate 7 acceptance without authenticated calls.


## Gate 6c - Multi-seed collection matrix

- Status: passed at `2026-08-24T15:33:43+02:00`.
- Extended sample-generation and interaction-collection contracts with a backward-compatible
  `seeds` matrix. Historical v1 configs using one `seed` still validate; a new campaign must
  choose exactly one representation.
- Collection now expands the Cartesian product of configured source tasks and seeds. Every
  trajectory id and raw trajectory records its own seed, and resume independently skips each
  already completed task/seed cell.
- Empty seed sets, duplicate seeds and simultaneous `seed` plus `seeds` declarations fail closed.
- Regression coverage proves a two-seed fixture produces two distinct trajectories and an
  idempotent rerun skips both without duplication.
- Full verification: 127 tests passed; Ruff passed for 163 files; mypy passed for 107 source
  files; schemas regenerated; `git diff --check` passed.
- Real collection/model-provider calls: not run.
- Next: separate collection session, turn, action, tool, token and total wall-time budgets before
  creating the v2 campaign config.

## Gate 6d - Independent collection budgets and preregistered campaign caps

- Status: passed at `2026-08-24T16:07:20+02:00`.
- Separated session, victim-turn, attacker-action, tool-call, observable-token, event,
  per-request timeout and total wall-time limits. Lifecycle/control actions no longer consume
  a victim turn or session, while every executed attacker action consumes the action budget.
- Every observation exposes only the remaining public budget counters. Collection provenance
  records the final counts and a canonical budget hash; missing token usage on a victim
  delivery fails closed instead of silently treating usage as zero.
- The SafeClaw construction bridge projects provider usage to non-secret token counts and
  discards raw provider response metadata. The subprocess driver caps each request by the
  remaining campaign wall time.
- Added explicit maximum trajectory and accepted-sample targets. The 120-cell campaign matrix
  cannot exceed its preregistered cap, and audit/freeze fail closed when the mined library has
  fewer than the configured target (30 main, 2 pilot).
- Focused verification: 22 budget, stage and v2-config tests passed; focused Ruff and mypy
  passed. Real collection/model-provider calls: not run.


## Gate 7 - Versioned v2 configs, launchers and final deterministic acceptance

- Status: passed at `2026-08-24T16:37:01+02:00` for all deterministic gates.
  The operator embedding selector was supplied and validated by Gate 7d below.
- Added a four-topology construction task set with 12 hash-pinned train tasks, disjoint from
  all formal exclusions. The main matrix is 12 tasks x 10 seeds = 120 trajectories with a
  target of 30 accepted samples; the pilot is 2 tasks x 2 seeds = 4 trajectories with a
  target of 2.
- Added v2 collection, pilot, environment, coverage-limited formal task-set and formal
  experiment configs. The preregistered formal matrix is one PSE 2.1 task x three matched
  conditions (`assigned_sample`, `no_sample`, `dependency_ablation`) x five seeds = 15
  cases. Claims must remain coverage-limited until compatible disjoint formal tasks are added.
- The formal config references only the intended future frozen real library
  `formal-v3-safeclaw-20260824`; that path intentionally does not exist before main
  collection, mining, audit and freeze.
- Added `scripts/run_safeclaw_sample_collection.sh` with deterministic preflight, a
  per-library lock, stable logging, exact resume paths and no automatic mining/freezing.
- An earlier presence-only pilot/main preflight passed before the embedding runtime path was
  audited. That result is superseded by Gate 7b. The pre-selection pilot preflight failed only because `SAFECLAW_EMBEDDING_MODEL` was unset;
  Gate 7d records the passing rerun.
- Config SHA256 values:
  - main collection: `cdc5283bedd5d0ee78d0f677799faa53c45fa5e837a5617dc27e33a80778f13f`
  - pilot collection: `7f40c3b7005f8bcdb7217106b649f73b20b2cc5887f5114a4967edd885809004`
  - construction task set: `310849f5c91131b36956294b324b8d627e442e3d5a155c91b79500acbce2ec1d`
  - environment: `16eafbfa3338d60a28f6c7215cf0b76086d52f614e4d5b30c254e4045f142d69`
  - formal task set: `3b1f5f9c01c08c3d5833a4d95d17c242e30a6ba1f965e1310df3024fac1d7b6b`
  - formal experiment: `477abe3756fd74dc280c1960144eec86beb685c7b8bf94166915787128797fe1`
  - collection launcher: `41b5124b54281993ed72e1247bd6ce6e7a5b4a54ed7c0fe733072171563c4724`
- Final verification after Gate 7b: schemas regenerated; Ruff passed for 166 files; mypy
  passed for 108 source files; all 138 tests passed in 2.48 seconds;
  `git diff --check` passed.
- Remaining before real pilot: run the pilot collection with the validated selectors, inspect
  its logs and audit the resulting pilot library. Remaining before formal evaluation: the main
  library must pass the 30-sample audit and freeze gate.


## Gate 7b - Runtime-bound embedding configuration

- Status: implementation passed at `2026-08-24T16:37:01+02:00`; operator model selection was
  pending until Gate 7d.
- Audit found that the prior environment policy checked `SAFECLAW_EMBEDDING_MODEL` presence
  but did not pass it to SafeClaw. Added one shared model-config builder used by collection,
  whole-episode formal execution and interactive formal execution.
- The v2 configs now bind embedding provider, model env, base-URL env and API-key env.
  Missing or partial configuration fails before a Victim container starts. Formal config
  and environment config target contracts must match exactly.
- The temporary mode-0600 model config carries chat and embedding settings. The pinned safety
  patch writes embedding settings to `agents.defaults.memorySearch` and never records the
  embedding key. Formal redaction and secret scans cover both chat and embedding endpoints
  and keys.
- Current OpenClaw documentation permits a newer `openai-compatible` provider id, but the
  pinned 2026.3.12 image rejects it. An isolated image `openclaw config validate` proved
  that this version accepts `provider=openai` with `remote.baseUrl` and `remote.apiKey`;
  the v2 contract is pinned to that validated schema.
- The safety patch remains applicable to commit
  `a11f5cceaba0676be721021f8d232638fd111305` using explicit
  `git apply --unidiff-zero`. Patch SHA256:
  `a576f672e5c3f016cee56d78916fd514438b581edf38402f087949d9a9eacb0b`.
- Focused verification: 26 embedding/preflight/collection/formal tests passed, including
  execution of the patched `_apply_model_config`, runner payload projection, key redaction
  and missing-key failure. Full verification: 138 tests, Ruff 166 files, mypy 108 source
  files, regenerated schemas and `git diff --check` all passed.
- Previous no-execution pilot preflight result: failed only
  `sample_collection_model_environment_missing` with
  `missing_variable_names=SAFECLAW_EMBEDDING_MODEL`; this was cleared by Gate 7d.


## Gate 7c - Operator entrypoint documentation closure

- Status: passed at `2026-08-24T16:37:01+02:00`.
- Replaced README's obsolete v1 real-collection commands with the v2 pilot launcher,
  target/embedding selector checks and the canonical handoff link.
- The handoff explicitly exports the checked embedding selector before each tmux launch, so
  the tmux server and child launcher receive it even when it was initially a shell-local
  variable.
- The legacy `scripts/run_sample_collection.sh` and historical v1 config are explicitly
  excluded from the v2 formal workflow.


## Gate 7d - Embedding selector supplied and pilot preflight rerun

- Status: passed at `2026-08-25` with `SAFECLAW_EMBEDDING_MODEL=text-embedding-3-small`.
- The selector was supplied by the operator and paired with `SAFECLAW_MODEL=gpt-5.5` for the
  no-execution pilot preflight. No API key or endpoint value was written to this progress file.
- Pilot preflight result: `passed=true`, `execution_started=false`. All checks passed,
  including embedding configuration, model environment, allowlisted victim model, pinned
  upstream commit, safety patch, Docker image, disk capacity and resumable output state.
- The embedding endpoint/model capability is provider-dependent; the preflight verifies the
  configured selector is present and complete but does not make a real embedding request.
- Next operator action: run the pilot collection tmux command in the handoff, review its output,
  then run the main 30-sample collection. Formal evaluation remains gated on main-library audit
  and freeze.





## Gate 7e - Endpoint capability verification pending

- Status: diagnostic pending at `2026-08-25`. The local configured model inventory contains five
  model IDs and zero IDs that look like embedding models. This is a warning, not proof of failure.
- No network embedding request was made by the diagnostic; API keys and endpoint values remain
  excluded from the progress file.
- The required proof is one authenticated `POST /v1/embeddings` request that returns a non-empty
  numeric vector for `text-embedding-3-small`.
- If the shared gateway fails this probe, the existing runtime can use a separate embedding
  base URL and API-key environment variable; the versioned v2 configs must then be updated and
  their hashes/provenance regenerated before collection.