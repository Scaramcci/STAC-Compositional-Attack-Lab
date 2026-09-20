# Primitive v3 implementation and offline workflow

Primitive v3 is an explicit parallel analysis representation for the fixed observation profile
`stac.observable-flow@3.0.0`. It does not replace legacy mining, authorize a run, or establish that
`TRANSFER / DERIVE / UPDATE` are a universally minimal basis.

## Implemented contracts and interfaces

- `flow/models.py`, `flow/analysis.py`: observations, domains, artifact occurrences, ports,
  resource versions, effects/groups, claims, evidence, slices, joins, four admission profiles,
  macros, intervention records, reports and `AnalysisManifest`.
- `configs/flow/observation_profile_v3.json`, `configs/flow/registry_v3.json`: independently hashed
  profile and registry. Projector/verifier/macro versions are recorded in each analysis.
- `interactions/flow_v3.py`: legacy normalized facts to neutral observations and stable many-to-many
  effects. Legacy inferred verdicts are never imported.
- `verification/flow_v3.py`, `interactions/provider_flow_adapter.py`: pure relation verifier and
  strict provider-evidence adapter. Existing policy, identity, request, selector, bundle and
  projection validation is reused.
- `extraction/flow_slice.py`: explicit-sink bounded slices with fan-in/fan-out, external
  preconditions, observed/template joins (`ALL`, `ANY`, `K_OF_N`), groups and separate
  graph-reference/replay-consistency states.
- `verification/flow_admission.py`: descriptive, verified-dependency, cross-session-propagation and
  intervention-comparison profiles. Lower-layer success cannot satisfy a stronger profile.
- `extraction/flow_macros.py`: concrete `PersistRecall` and multi-source `Bind` bindings. Other
  legacy macros remain unsupported in v3.
- `execution/flow_reanalysis.py`, `cli.py`: immutable collection validation, explicit projection,
  verification, slicing, admission, report and manifest output. Every invocation creates a new
  directory; `analysis_key` is stable for identical inputs and versions.

Schemas are generated from these models. Legacy planner/formal remains the default. Formal config
accepts only `analysis_representation=legacy_chain_v2`; the planner rejects a v3 graph rather than
flattening it to a legacy chain.

## Commands

```bash
python -m stac_attack_lab.cli flow profile-validate
python -m stac_attack_lab.cli flow reanalyze \
  --input <interaction_graph.json-or-sealed-collection> \
  --output-root <new-analysis-parent> --terminal-outputs
python -m stac_attack_lab.cli flow analysis-validate --analysis <analysis-dir>
python -m stac_attack_lab.cli flow inspect --analysis <analysis-dir>
python -m stac_attack_lab.cli flow slice --graph <effect-graph.json> \
  --sink-port <port-id> --output <new-slice.json>
```

`--terminal-outputs` explicitly selects effect output ports that are not claim sources, falling
back to all output ports. `--sink-port` names exact ports. Reanalysis uses an observed `ALL` join
over claims entering each selected sink; this is an analysis requirement, not proof that alternate
branches exist. Exit 10 means a requested profile was not met or a slice was truncated; input,
configuration and program errors return 2.

## Evidence and state semantics

Execution status, dependency verdict, intervention result, runtime review, authorization and
official outcome remain independent. Available input is not data dependency. Exact equality is a
narrow configured value relation, not unique source or causal necessity. Resource read-from
requires resource, workspace, version, range and commit evidence; nearest-writer inference is not
used. Paths are display projections, not a tree constraint. `replay_consistency=not_evaluated`
unless an actual replay checker runs.

Reports contain aggregate public facts and limitations, not private evidence locators. Internal
graphs use mode 0600. SHA-256 detects changes relative to a manifest but does not authenticate the
producer or resist coordinated rewriting of all trusted inputs.

## Current offline artifacts

- Synthetic workflow: `experiments/runs/primitive-v3-phase2-offline-20260920/deliverables/synthetic-positive/v3-20260920T090903-099005Z-9c5e8d5958/`.
- Unknown strong-profile case: `experiments/runs/primitive-v3-phase2-offline-20260920/deliverables/negative-unknown/v3-20260920T090904-190684Z-9c5e8d5958/`.
- Read-only historical collection: `experiments/runs/primitive-v3-phase2-offline-20260920/deliverables/historical-readonly/v3-20260920T090905-289092Z-cd4126c838/`.

The synthetic report passes descriptive and verified-dependency profiles but leaves cross-session
and intervention unknown. The historical report passes descriptive only. All have runtime review
unknown, authorization absent and official outcome not evaluated.

## Tests and remaining boundary

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q \
  tests/unit/test_flow_v3.py tests/unit/test_flow_v3_phase2.py \
  tests/unit/test_provider_evidence.py
make schemas PYTHON=python
make check PYTHON=python
```

Still unsupported: seven macro matchers, v3 library freeze, v3 planner/formal execution, real
interventions and official evaluation. Real provider message compatibility, network isolation,
cleanup and ledger closure remain pending. The tracked
`configs/sample_generation/provider_compatibility_revalidation.disabled.json` template is disabled,
uses one request per role, zero retries and a 300-second wall clock; preparing or enabling it does
not authorize live requests.
