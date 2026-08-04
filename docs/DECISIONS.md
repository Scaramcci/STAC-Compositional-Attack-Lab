# Decisions

## ADR-001: Use a restricted YAML parser instead of PyYAML

Problem: The environment has Pydantic available but not PyYAML, and the core should not require network dependency installation.

Options: add PyYAML dependency, use JSON configs, or implement a small YAML subset parser.

Decision: Implement a restricted parser for the simple mapping/list/scalar configs and prompt front matter.

Reason: It keeps `pip install -e '.[dev]'` light and supports the planned config files.

Impact: YAML features such as anchors and complex multiline scalars are intentionally unsupported.

## ADR-002: Fake LLM planner delegates legality to deterministic planner

Problem: No real model key is available, but the online STAC interface must be testable.

Options: stop at integration skip, mock raw text outputs only, or implement a fake structured planner behind the same interface.

Decision: Use `FakeModelClient` and deterministic planner behavior for fake STAC smoke.

Reason: This exercises schema validation, role separation, event logging, verifier precedence, ablations, defense, and reporting without external services.

Impact: Real model adaptive behavior is an integration extension and is explicitly skipped when unavailable.

## ADR-003: Wilson CI for smoke proportions

Problem: PLAN asks for bootstrap and McNemar statistics, but smoke scale is tiny and deterministic.

Options: implement full paired bootstrap now or provide deterministic smoke-safe intervals with hooks.

Decision: Implement Wilson CI in report and keep dependency-free McNemar/bootstrap extension points for larger runs.

Reason: It is reproducible, dependency-free, and sufficient for smoke acceptance.

Impact: Full statistical claims require extending `reporting/statistics.py` before paper-scale runs.

## ADR-004: JSON contracts allow enum strings on reload

Problem: Append-only JSONL events and prompt examples encode enums as strings, while strict enum instances break normal JSON reload.

Options: keep strict enum instances only, add per-field validators, or allow standard Pydantic enum coercion while keeping unknown-field rejection.

Decision: Keep `extra=forbid` on contracts and allow JSON enum strings to parse back into enum values.

Reason: JSON Schema, event logs, frozen samples, and prompt examples must round-trip from plain JSON.

Impact: Config shape still rejects unknown fields; scalar coercion is not used as a security boundary.

## ADR-005: Rename project to STAC Compositional Attack Lab

Problem: The original implementation used a mini project name, but the target work is now a complete STAC-style sample construction and evaluation codebase.

Decision: Rename the distribution, CLI, package namespace, and top-level directory to `stac-compositional-attack-lab`, `stac-attack-lab`, and `stac_attack_lab`. Keep the old console-script alias for compatibility.

Impact: Existing commands using `python -m mini_attack_lab.cli` must switch to `python -m stac_attack_lab.cli`. The compatibility console script is available after reinstall.

## ADR-006: Gemini-first temporary role mapping

Problem: OpenAI-compatible access is temporarily unavailable, but sample construction code should continue to evolve without consuming OpenAI quota.

Decision: Add `stac_sample_build_gemini.yaml` where planner, attacker, victim, prompt-writer, verifier, and judge are all Gemini. Keep `stac_sample_build_gpt_gemini.yaml` as the intended restored-quota config.

Impact: Current local tests do not require model calls. Real STAC sample construction can be launched later by choosing the appropriate config and environment keys.

## ADR-007: 4090 huihui victim is an OpenAI-compatible local provider

Problem: Formal evaluation will run on a separate 4090 server with a local huihui model as victim.

Decision: Implement `huihui_local` as an OpenAI-compatible client reading `HUIHUI_BASE_URL`, optional `HUIHUI_API_KEY`, and model config. The evaluation config switches only the victim role to this provider.

Impact: No local experiment is blocked by missing 4090 resources. Server-side validation requires the endpoint and model to be available.

## ADR-008: SHADE_Arena is referenced read-only from the parent research tree

Problem: SHADE_Arena exists under `papers/projects/AgentLAB/code/official/SHADE_Arena/`, outside the project directory.

Decision: Add a read-only adapter smoke that checks expected SHADE_Arena files and reports discovered task/tool modules. Do not edit SHADE_Arena or vendor it into this project.

Impact: Integration readiness is visible, but formal SHADE_Arena execution remains an explicit integration step.

## ADR-009: Fail-closed named model profiles

Problem: Role model names were independently configurable and the intended GPT/Gemini and GPT/Huihui experiments could silently drift.

Decision: Add validated `stac_offline` and `formal_evaluation` profiles. Every non-Victim role is pinned to `gpt-5.5`; only Victim differs. `OPENAI_MODEL_list` takes precedence over its uppercase compatibility alias, and startup rejects a list without GPT-5.5.

Impact: Older GPT-4.1 configs no longer load as formal profiles. The all-Gemini mapping remains clearly labeled `gemini_development` and is not a formal substitute.

## ADR-010: Per-attack checkpoint and typed observable transcripts

Problem: Resume was a no-op and hash-only LLM traces could not reconstruct interrupted experiments.

Decision: Store atomic `progress.json`, append-only `attack_progress.jsonl`, and typed, redacted `conversations.jsonl`. Use a deterministic run/config/dataset/attack/condition/seed idempotency key and checkpoint every case. Audit sequence, roles, prompt/model assignment, redaction, and call linkage.

Impact: Quota interruptions become `paused_quota` and resume skips completed keys. Research artifacts are larger because observable messages and raw responses are retained after explicit secret filtering.

## ADR-011: Immutable frozen versions and discovered local weights

Problem: Dataset freeze replaced existing versions, and the Huihui path was an assumed server detail.

Decision: Reject content changes under an existing frozen version while treating identical freezes as idempotent. Discover Huihui under `../../../models` or `HUIHUI_MODEL_PATH` by checking config, tokenizer, and weights before vLLM launch. Keep vLLM in an ignored `.venv-vllm` environment and default the 24 GB launcher to BitsAndBytes runtime quantization, with explicit binary, quantization, and CPU-offload overrides.

Impact: Dataset corrections require a new version. Local evaluation has a deterministic preflight and does not load weights during discovery tests. The 28 GB BF16 checkpoint is not assumed to fit unquantized on the RTX 4090.
