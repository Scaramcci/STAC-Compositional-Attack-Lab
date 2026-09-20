# Benign collection stage A

Stage A adds a separate normal-interaction collection path. It does not rename adversarial
collection, run a model, build the final FlowPattern library, or authorize evaluation.

## Contracts and entry points

- `interactions/benign.py`: strict `BenignScenario`, source mapping and sanitization change models,
  hash-bound `neutralize_source_task()`, public policy observation/action, scripted cooperative
  policy and deterministic scenario adapter.
- `execution/benign_collection.py`: `BenignCollectionConfig`, disabled preparation, source-mode
  manifest, synthetic fixture collection, v3 reanalysis and per-trace planning-reference assessment.
- `configs/benign_scenarios/scenarios_v1.json`: reviewed synthetic read-only, multi-source and
  legitimate-memory scenarios. These are engineering fixtures, not official SafeClaw tasks.
- `configs/benign_collection/synthetic_stage_a.disabled.json`: default-disabled, zero-network
  configuration.
- `prompts/benign/cooperative_policy.md`: legitimate goal, authorized operations and bounded stop
  policy without a security objective or private evaluator.

The benign schema rejects adversarial-only fields such as `public_attack_goal`. A SafeClaw-derived
scenario must bind the source task hash and list each removed, replaced or retained field. The
neutralizer applies only reviewed field paths and fails on source-hash mismatch or unreviewed
replacement. Independent synthetic scenarios cannot claim an upstream task identity.

## Offline commands

```bash
python -m stac_attack_lab.cli benign validate
python -m stac_attack_lab.cli benign prepare
python -m stac_attack_lab.cli benign collect-fixture
```

`validate` and `prepare` do no collection or network work. `collect-fixture` is explicitly limited
to `source_mode=synthetic_fixture` and rejects enabled execution. It uses the common collector and
normalizer, then invokes the existing v3 reanalysis path. A real SafeClaw-derived collection runner
is deliberately not part of Stage A and remains separately authorized future work.

The source-mode manifest records config, scenario set, sanitization mapping, prompt, profile,
registry, collection and trajectory hashes. It states that no security evaluator, attack objective
or real model request was used. The v3 `AnalysisManifest.parameters.origin_modes` preserves
`benign_interaction`; legacy sealed collections remain `legacy_adversarial`.

`benign_trace_assessments.json` separates:

- `observation_valid`;
- `planning_reference_eligible`;
- verified and unknown dependency counts;
- optional cross-session capability;
- security outcome, always `not_evaluated` in this stage.

A single-session graph may be planning-reference eligible when its observations and effects are
valid. It does not need cross-session evidence. A scenario claiming cross-session capability still
needs verified `read_from`; the current synthetic memory fixture therefore remains capability
`unknown` while its weaker observation is retained.

## Current offline artifact

The current run is under
`experiments/runs/benign-stage-a/benign-offline-20260920T123601-332075Z/`. It contains three raw
normal trajectories, the source-mode manifest, normalized graphs, v3 effect graphs, slices,
admission results and resealed analysis manifest. All three traces are observation-valid and
planning-reference eligible. This is software evidence only and reports no security outcome.

Run the focused checks with:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q \
  tests/unit/test_benign_collection.py tests/unit/test_flow_v3.py \
  tests/unit/test_flow_v3_phase2.py tests/unit/test_provider_evidence.py
make schemas PYTHON=python
make check PYTHON=python
```
