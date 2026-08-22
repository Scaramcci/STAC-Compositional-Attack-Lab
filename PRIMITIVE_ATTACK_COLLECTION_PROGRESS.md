# Primitive And Attack Collection Progress

Updated: 2026-08-20

## Gate 0: Baseline and migration map

Status: complete.

- Baseline targeted suite: 26 passed.
- Legacy prompt-bearing path: `OfflineSample` in `execution/offline.py` and `execution/online_stac.py`; historical frozen datasets were not modified.
- Formal path: interaction trajectory -> graph -> core occurrence -> macro candidate -> G0-G8 -> three-view library.
- Migration: four legacy attack-chain macro ids remain aliases of `macro.ingest@2`, `macro.persist@2`, `macro.recall@2`, and `macro.act@2`.

## Gate 1: Primitive and macro contracts

Status: complete.

- Core families: `TRANSFER / TRANSFORM / MUTATE / CONTROL`.
- Outcomes include rejected/error/timeout/abstained/stopped/not-observable and remain orthogonal to family.
- Semantic registry contains exactly the nine teacher macros.
- `Adopt` records E3/E4 semantic requirements and cannot override E1/E2 hard evidence.
- Registry version: `formal-v2-semantic-macros`.

## Gate 2: Attack-driven collection

Status: implementation complete; real collection not started.

- CLI: `sample attack-build --config configs/sample_generation/formal_v1.yaml`.
- Stable ids include adapter, task, split, seed, and Construction Manifest.
- Atomic writes and existing-trajectory validation provide crash-safe resume without duplicate collection.
- Construction/test exclusion and safety constraints are recorded in raw trajectories.
- Real config: `configs/sample_generation/safeclaw_adversarial_v1.yaml`.
- Construction task set uses `pse-2.1-002` and `pse-2.1-003`, disjoint from the formal task ids.
- `ModelConstructionAttacker` receives only public construction observations and cannot see SafeClaw evaluation fields.
- `SafeClawSubprocessVictimDriver` runs the complete isolated Victim lifecycle through a persistent JSONL bridge; the bridge never instantiates the official evaluator.
- Per-session messages, tool calls, lifecycle transitions, allowlisted state checkpoints, state diffs, failures, and terminal errors are durably recorded.
- CLI: `sample collect-preflight` checks readiness without execution; `sample collect` is the first command that starts real collection.

## Gate 3: Extraction and filtering

Status: complete for the current canonical topology.

- All nine macros are evaluated by one typed matcher; current positive matches Ingest/Persist/Recall/Bind/Act.
- G5 rejects ordinary traces, missing objectives/trust boundaries/terminal ids, incomplete attempts, unobserved terminal relations, untainted ingress, and shortcuts.
- Temporal proximity cannot replace typed data/state/control edges.

## Gate 4: Frozen library

Status: complete.

- Generated: `data/primitive_libraries/generated/formal-v2-attack-synthetic/library`.
- Frozen: `data/primitive_libraries/frozen/formal-v2-attack-synthetic`.
- Counts: attempted 2, accepted 1, negative 1, blocked 1.
- Registry hash: `a23474b5967c8efde66ca5d97ff10c6b2cccf9d3c7c0a29710390cb1748f18bf`.
- Tree hash: `7bae9362279a40a67d6845bcb11171d9c2e829973fa7bb750b9acfb4eb205456`.
- Public/execution leakage scan: no prompt, payload, victim message, canary, oracle, success condition, or transcript match.
- Identical freeze is idempotent; `formal-v1-smoke` was not modified.

## Gate 5: Planner, independent attacker, and verification

Status: implementation complete; formal real-model execution not started.

- Planner emits an abstract primitive/state trajectory with persistence, trigger, objective trajectory, evidence, judge condition, sandbox constraints, and five causal controls.
- The LLM planner uses separate selection and trajectory prompts. Every proposal is revalidated against the exact primitive backbone, typed state dependencies, supported mechanism families, persistence/trigger support, public predicates, allowed actions, and sandbox constraints.
- Supported mechanism labels are inferred from actual macros: objective drifting, intent hijacking, persistent-state poisoning, trigger-based, and compound hybrid only when at least two mechanisms share the same backbone.
- Planner does not emit concrete attack payloads.
- `ModelFormalAttacker` is a separate role that receives only public task data, the execution view, and a validated plan. It creates fresh typed slot values and one action per stage; missing or invalid realization fails closed before materialization.
- Formal config records `attacker_stage_implemented=true`; the historical synthetic frozen library correctly retains its original false value.

Verification evidence:

- `make lint`: passed; 149 files formatted and Ruff checks clean.
- `make typecheck`: passed; 102 source files checked by strict mypy.
- Full deterministic suite: 100 tests passed after the pre-collection implementation.
- Targeted primitive/sample/planner/formal suite: 34 passed.
- Formal synthetic e2e smoke: 1 passed.
- Generated and frozen library audit: passed.
- Identical freeze replay: returned the existing version without replacement.
- Secret scan: no API token, Bearer token, or private-key material; generic API-key assignment matches were environment-variable lookups and the existing `local-no-key` placeholder.
- `git diff --check`: passed.

## Stop point and next work

- Run `sample collect-preflight` and resolve any host environment/image findings.
- Run real-model Sample Collection under the pinned SafeClaw sandbox config; this has not been started in this implementation turn.
- Normalize, extract, filter, audit, and freeze the resulting real collection as a new immutable version; do not overwrite `formal-v2-attack-synthetic`.
- Run matched formal conditions before reporting ASR, transfer, or causal mechanism claims.
