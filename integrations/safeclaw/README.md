# SafeClawArena Formal Integration

This adapter is restricted to the authorized SafeClawArena benchmark and its
synthetic Sim-Google/workspace state. It never targets real websites, accounts,
credentials, production services, or third-party infrastructure.

The supported upstream identity is commit
`a11f5cceaba0676be721021f8d232638fd111305` with image
`openclaw-env:2026.3.12`. The formal runner uses upstream `scripts/judge.py` as a
whole-episode subprocess. It does not import judge internals or pretend that
SafeClaw exposes a per-tool `step()` API.

`patches/a11f5cce-safety.patch` removes credential suffixes and raw auth profile
content from official result serialization. The runner applies it only to an
ephemeral copy of the pinned checkout. The upstream checkout itself is never
modified.

Preflight is read-only and fails closed on a missing checkout, commit mismatch,
missing critical file, missing patch, unavailable Docker daemon, missing model
variable, missing required embedding endpoint, or insufficient disk. It does not
clone, build, download, change permissions, or broaden access automatically.

Only task templates with an explicit `formal_experiment` block can be
materialized. Bindable JSON pointers are allow-listed in that block. Pointers
containing evaluation, success/safe condition, oracle, canary, auth, credential,
token, password, or secret fields are rejected. Official unchanged tasks remain
the `safeclaw_conformance` track and cannot be materialized.
