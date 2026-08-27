# Security

## Threat Model

This project studies synthetic cross-component propagation inside `WorkspaceCanaryEnv`. The target behavior is a local no-value `emit_canary` state change.

## Boundaries

- Default network is disabled.
- Tools are allowlisted and implemented in memory.
- No shell, subprocess payload, arbitrary file path, host environment access, real credentials, or external service action exists in the local environment.
- Canary IDs are generated synthetic values, not secrets.
- SafeClaw baseline values require an explicit baseline.task_set slot allowlist. Sample and baseline materialization share the protected official evaluation block; only pre-registered sample-derived slots may differ.
- Logs store hashes and artifact refs; raw prompts/responses belong in controlled trace files.

## Responsible Use

Use the lab for defensive measurement of propagation, persistence, verifier design, and mitigation effects. Do not adapt it for real credential access, real exfiltration, malware, destructive file operations, or public targets.

## Secret Handling

`.env.example` contains fake values only. Real model keys, when integration work is added, must be read from environment variables and must never be written to configs, prompts, docs, events, traces, or reports.

## Model And Integration Limits

The full local fake model is deterministic and does not represent broad model behavior. Gemini, OpenAI-compatible, and huihui clients read credentials/endpoints only from environment variables. AgentDojo/SHADE_Arena integration is read-only discovery plus contract smoke until a dedicated integration runner is explicitly enabled.

## Incident Response

If a real secret or unsafe payload is accidentally written into this project, stop running experiments, remove the artifact, rotate the exposed credential if applicable, document the incident in `docs/DECISIONS.md`, and regenerate affected datasets.

## Transcript and checkpoint controls

All observable messages are filtered against configured secret values before serialization or hashing. Every conversation event records that the filter ran. Transcript audit flags sequence gaps, role/model mismatches, missing request events, absent redaction proof, and Victim-visible experiment metadata. The archived execution ledger at `docs/archive/formal-v2-202608/FORMAL_EXPERIMENT_PROGRESS_20260824.md` contains status only, never full messages.

A real-profile configuration error fails before execution and reports variable names or a generic model-configuration category. Provider errors are categorized without response headers, endpoint query strings, key fragments, or secret fingerprints.

Frozen dataset versions cannot be overwritten with different content. The local-model discovery command reads model metadata and filenames only; it does not load weights or start a network service.
