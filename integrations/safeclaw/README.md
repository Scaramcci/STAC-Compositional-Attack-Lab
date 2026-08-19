# SafeClawArena Formal Integration

This adapter is restricted to the authorized SafeClawArena benchmark and its
synthetic Sim-Google/workspace state. It never targets real websites, accounts,
credentials, production services, or third-party infrastructure.

The supported upstream identity is commit
`a11f5cceaba0676be721021f8d232638fd111305` with image
`openclaw-env:2026.3.12`. The formal runner uses upstream `scripts/judge.py` as a
whole-episode subprocess. It does not import judge internals or pretend that
SafeClaw exposes a per-tool `step()` API. The separate `safeclaw pse-smoke`
command loads the pinned official `Evaluator` only to exercise its PSE scoring
function without starting a Docker episode.

`patches/a11f5cce-safety.patch` removes credential suffixes and raw auth profile
content from official result serialization. The runner applies it only to an
ephemeral copy of the pinned checkout. The upstream checkout itself is never
modified.

Preflight is read-only and fails closed on a missing checkout, commit mismatch,
missing critical file, missing patch, unavailable Docker daemon, missing Docker
image, missing model variable, missing required embedding endpoint, or
insufficient disk. It does not clone, build, download, change permissions, or
broaden access automatically.

Only task templates paired with an explicit `formal_experiment` block or
task-set overlay can be materialized. Bindable JSON pointers are allow-listed in
that metadata. Pointers containing evaluation, success/safe condition, oracle,
canary, auth, credential, token, password, or secret fields are rejected.
Official tasks without that external metadata remain the `safeclaw_conformance`
track and cannot be materialized.

Each formal case stores `materialized_task.json` and
`complete_interaction_record.json` under `cases/<case-id>/`. The complete record
links the deterministic planner input/output, selected primitive chain and
binding, exact materialized victim task, sanitized SafeClaw sessions and raw
transcript, attempt logs, normalized interaction graph, primitive extraction,
mechanism verdicts, and official verdict. API credentials are redacted and
hidden chain-of-thought is never requested or recorded.

## Long-running execution with tmux

The tmux-oriented runner performs preflight, starts or resumes the formal run,
audits the recorded artifacts, and rebuilds the report. Output is unbuffered and
also written to `experiments/safeclaw_runs/<run-id>/tmux-run.log`. Reusing the
same run id resumes completed cases instead of duplicating them.

```bash
tmux new-session -d -s safeclaw-formal \
  "cd /path/to/stac-compositional-attack-lab && bash scripts/run_formal_evaluation.sh"
tmux attach -t safeclaw-formal
```

Detach with `Ctrl-b d`. If the process exits, inspect the persistent log and
rerun the same `tmux new-session` command to resume. The launcher respects the
configured execution and task-set gates and does not override them.

The current formal path consumes model API only inside the OpenClaw victim
episode. Deterministic planners, task materialization, primitive extraction,
mechanism verification, and the official SafeClaw checks do not call an LLM.
Each current task has two sessions, so the 12-case matrix issues at least 24
OpenClaw gateway requests before malformed-call or whole-episode retries. A
gateway request can trigger multiple provider completions during tool-use loops.
Current `tokens`, `cost`, and `api_calls` result fields are not provider billing
telemetry: tokens/cost remain zero and api_calls currently counts episode
attempts. Use provider-side usage logs for billing until usage extraction is
implemented.
