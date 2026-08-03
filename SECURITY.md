# Security

## Threat Model

This project studies synthetic cross-component propagation inside `WorkspaceCanaryEnv`. The target behavior is a local no-value `emit_canary` state change.

## Boundaries

- Default network is disabled.
- Tools are allowlisted and implemented in memory.
- No shell, subprocess payload, arbitrary file path, host environment access, real credentials, or external service action exists in the local environment.
- Canary IDs are generated synthetic values, not secrets.
- Logs store hashes and artifact refs; raw prompts/responses belong in controlled trace files.

## Responsible Use

Use the lab for defensive measurement of propagation, persistence, verifier design, and mitigation effects. Do not adapt it for real credential access, real exfiltration, malware, destructive file operations, or public targets.

## Secret Handling

`.env.example` contains fake values only. Real model keys, when integration work is added, must be read from environment variables and must never be written to configs, prompts, docs, events, traces, or reports.

## Model And Integration Limits

The full local fake model is deterministic and does not represent broad model behavior. Gemini, OpenAI-compatible, and huihui clients read credentials/endpoints only from environment variables. AgentDojo/SHADE_Arena integration is read-only discovery plus contract smoke until a dedicated integration runner is explicitly enabled.

## Incident Response

If a real secret or unsafe payload is accidentally written into this project, stop running experiments, remove the artifact, rotate the exposed credential if applicable, document the incident in `docs/DECISIONS.md`, and regenerate affected datasets.
