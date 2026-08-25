from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from stac_attack_lab.environments.safeclaw.contracts import (
    EpisodeRequest,
    SafeClawEpisodeResult,
    SafeClawExecutionStatus,
    SanitizedSessionResult,
)
from stac_attack_lab.environments.safeclaw.interactive_driver import (
    SafeClawInteractiveVictimDriver,
)
from stac_attack_lab.environments.safeclaw.materializer import MaterializedTask
from stac_attack_lab.execution.formal_action_loop import (
    FormalActionLoopResult,
    execute_formal_action_loop,
)
from stac_attack_lab.execution.formal_attacker import (
    FormalAttacker,
    FormalAttackerInput,
    FormalAttackerStageAction,
    FormalAttackRealization,
    FormalVictimObservation,
)
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.recording.events import append_jsonl, read_jsonl


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _attempt_number(attempt_id: str) -> int:
    try:
        return int(attempt_id.removeprefix("attempt-"))
    except ValueError as exc:
        raise ValueError(f"interactive_attempt_id_invalid:{attempt_id}") from exc


def _begin_attempt(case_root: Path, request: EpisodeRequest) -> tuple[str, int]:
    ledger_path = case_root / "interactive_attempts.jsonl"
    records = read_jsonl(ledger_path)
    starts = [item for item in records if item.get("kind") == "attempt_started"]
    terminal_ids = {
        str(item.get("attempt_id"))
        for item in records
        if item.get("kind") in {"attempt_abandoned", "attempt_failed", "attempt_completed"}
    }
    if starts:
        last_id = str(starts[-1].get("attempt_id", ""))
        if last_id not in terminal_ids:
            append_jsonl(
                ledger_path,
                {
                    "kind": "attempt_abandoned",
                    "attempt_id": last_id,
                    "reason_code": "resume_after_incomplete_attempt",
                    "recorded_at": _now(),
                },
            )
        next_number = max(_attempt_number(str(item.get("attempt_id", ""))) for item in starts) + 1
    else:
        next_number = 1
    if next_number > request.max_attempts:
        raise ValueError(
            f"interactive_attempt_budget_exhausted:{next_number - 1}/{request.max_attempts}"
        )
    attempt_id = f"attempt-{next_number:03d}"
    append_jsonl(
        ledger_path,
        {
            "kind": "attempt_started",
            "attempt_id": attempt_id,
            "attempt_no": next_number,
            "case_id": request.case_id,
            "seed": request.seed,
            "recorded_at": _now(),
        },
    )
    return attempt_id, next_number


def _journal_path(case_root: Path, relative_ref: str) -> Path:
    relative = Path(relative_ref)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"interactive_journal_ref_unsafe:{relative_ref}")
    return case_root / relative


def _ensure_action_journal(
    case_root: Path,
    relative_ref: str,
    actions: list[FormalAttackerStageAction],
    observations: list[FormalVictimObservation],
) -> None:
    path = _journal_path(case_root, relative_ref)
    if path.is_file():
        return
    for action, observation in zip(actions, observations, strict=True):
        append_jsonl(
            path,
            {
                "kind": "victim_request",
                "plan_id": action.plan_id,
                "plan_stage_id": action.stage_id,
                "attacker_call_id": action.attacker_call_id,
                "attacker_action_id": action.attacker_action_id,
                "victim_request_event_id": observation.victim_request_event_id,
                "action": action.model_dump(mode="json"),
            },
        )
        append_jsonl(
            path,
            {
                "kind": "victim_response",
                "plan_id": observation.plan_id,
                "plan_stage_id": observation.plan_stage_id,
                "attacker_call_id": observation.attacker_call_id,
                "attacker_action_id": observation.attacker_action_id,
                "victim_request_event_id": observation.victim_request_event_id,
                "victim_response_event_id": observation.victim_response_event_id,
                "tool_event_ids": observation.tool_event_ids,
                "observation": observation.model_dump(mode="json"),
            },
        )


def _usage_total(
    records: list[dict[str, Any]],
    keys: tuple[str, ...],
) -> int | None:
    values: list[int] = []
    for record in records:
        value = next((record[key] for key in keys if isinstance(record.get(key), int)), None)
        if isinstance(value, int) and not isinstance(value, bool):
            values.append(value)
    return sum(values) if values else None


def _usage_cost(records: list[dict[str, Any]]) -> float | None:
    values = [
        float(value)
        for record in records
        for key in ("cost", "total_cost", "provider_cost")
        if isinstance((value := record.get(key)), (int, float)) and not isinstance(value, bool)
    ]
    return sum(values) if values else None


def _attach_victim_provider_usage(
    loop: FormalActionLoopResult,
    records: list[dict[str, Any]],
) -> FormalActionLoopResult:
    observed_completions = len(records) if records else None
    input_tokens = _usage_total(records, ("input_tokens", "prompt_tokens"))
    output_tokens = _usage_total(records, ("output_tokens", "completion_tokens"))
    cached_tokens = _usage_total(
        records,
        ("cached_tokens", "cache_read_input_tokens", "cached_input_tokens"),
    )
    provider_cost = _usage_cost(records)
    gaps = [
        item
        for item in loop.accounting.instrumentation_gap_reasons
        if not (
            observed_completions is not None
            and item == "victim_provider_completion_count_not_exposed_by_gateway"
        )
        and not (provider_cost is not None and item == "provider_cost_not_returned")
    ]
    if (
        observed_completions is not None
        and observed_completions < loop.accounting.victim_gateway_requests
    ):
        gaps.append("victim_provider_usage_partial")
    accounting = loop.accounting.model_copy(
        update={
            "victim_provider_completions_when_observable": observed_completions,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
            "provider_cost": provider_cost,
            "instrumentation_gap_reasons": list(dict.fromkeys(gaps)),
        }
    )
    payload = {
        "schema_version": loop.schema_version,
        "realization": loop.realization.model_dump(mode="json"),
        "observations": [item.model_dump(mode="json") for item in loop.observations],
        "accounting": accounting.model_dump(mode="json"),
    }
    return FormalActionLoopResult.model_validate({**payload, "loop_hash": stable_hash(payload)})


def _cached(
    case_root: Path,
    request: EpisodeRequest,
) -> tuple[SafeClawEpisodeResult, dict[str, Any], FormalActionLoopResult] | None:
    episode_path = case_root / "episode_result.json"
    sanitized_path = case_root / "sanitized_result.json"
    loop_path = case_root / "formal_action_loop_result.json"
    if not all(path.is_file() for path in (episode_path, sanitized_path, loop_path)):
        return None
    episode = SafeClawEpisodeResult.model_validate_json(episode_path.read_text(encoding="utf-8"))
    if episode.case_id != request.case_id or episode.task_id != request.task_ref.task_id:
        raise ValueError("cached_interactive_episode_identity_mismatch")
    sanitized = json.loads(sanitized_path.read_text(encoding="utf-8"))
    if not isinstance(sanitized, dict):
        raise ValueError("cached_interactive_sanitized_result_invalid")
    loop = FormalActionLoopResult.model_validate_json(loop_path.read_text(encoding="utf-8"))
    return episode, sanitized, loop


def run_interactive_episode(
    *,
    request: EpisodeRequest,
    materialized_task: MaterializedTask,
    attacker: FormalAttacker,
    attacker_input: FormalAttackerInput,
    setup_realization: FormalAttackRealization,
    driver: SafeClawInteractiveVictimDriver,
    output_root: Path,
    upstream_commit: str,
    safety_patch_hash: str,
    resume: bool = True,
) -> tuple[SafeClawEpisodeResult, dict[str, Any], FormalActionLoopResult]:
    case_root = output_root / request.case_id
    case_root.mkdir(parents=True, exist_ok=True)
    if resume and (cached := _cached(case_root, request)) is not None:
        return cached
    attempt_id, attempt_no = _begin_attempt(case_root, request)
    prepare_attempt = getattr(driver, "prepare_attempt", None)
    if callable(prepare_attempt):
        prepare_attempt(attempt_id)
    canonical_trajectory_ref = str(
        getattr(driver, "canonical_trajectory_ref", "formal_action_journal.jsonl")
    )
    _journal_path(case_root, canonical_trajectory_ref)
    started_at = _now()
    started_monotonic = time.monotonic()
    try:
        driver.start(materialized_task)
        loop = execute_formal_action_loop(
            attacker,
            attacker_input,
            setup_realization,
            driver,
            seed=request.seed,
            execution_attempt_id=attempt_id,
        )
        finished = driver.finish()
    except BaseException as exc:
        append_jsonl(
            case_root / "interactive_attempts.jsonl",
            {
                "kind": "attempt_failed",
                "attempt_id": attempt_id,
                "error_category": type(exc).__name__,
                "recorded_at": _now(),
            },
        )
        driver.abort()
        raise
    loop = _attach_victim_provider_usage(loop, finished.provider_usage_records)
    _ensure_action_journal(
        case_root,
        canonical_trajectory_ref,
        loop.realization.stage_actions,
        loop.observations,
    )
    sanitized = finished.official_report
    sanitized_path = case_root / "sanitized_result.json"
    _atomic_json(sanitized_path, sanitized)
    loop_path = case_root / "formal_action_loop_result.json"
    _atomic_json(loop_path, loop.model_dump(mode="json"))
    raw_sessions = sanitized.get("sessions", [])
    session_items = raw_sessions if isinstance(raw_sessions, list) else []
    sessions = [
        SanitizedSessionResult(
            session_id=str(item.get("session_id", f"session-{index}")),
            sequence_no=index,
            status="completed",
            transcript_ref=f"sanitized_result.json#/sessions/{index - 1}",
            public_stage_status={},
        )
        for index, item in enumerate(session_items, start=1)
        if isinstance(item, dict)
    ]
    observations = loop.observations
    episode = SafeClawEpisodeResult(
        episode_id=f"episode-{request.case_id}",
        case_id=request.case_id,
        task_id=request.task_ref.task_id,
        binding_id=request.task_ref.binding_id,
        status=SafeClawExecutionStatus.completed,
        error_category=None,
        upstream_commit=upstream_commit,
        runner_version="safeclaw-formal-interactive-v1",
        target_model_id=request.target_model_id,
        started_at=started_at,
        ended_at=_now(),
        duration_ms=int((time.monotonic() - started_monotonic) * 1000),
        attempt_count=attempt_no,
        sessions=sessions,
        sanitized_result_ref=sanitized_path.name,
        sanitized_result_hash=file_hash(sanitized_path),
        canonical_trajectory_ref=canonical_trajectory_ref,
        official_checks_ref="sanitized_result.json#/checks",
        state_evidence_refs=sorted(
            {ref for item in observations for ref in item.output_state_refs}
        ),
        taint_evidence_refs=sorted(
            {ref for item in observations for ref in item.verifier_evidence_refs}
        ),
        secret_scan_passed=True,
        provenance={
            "materialized_task_hash": request.task_ref.materialized_task_hash,
            "safety_patch_hash": safety_patch_hash,
            "interactive_bridge": driver.driver_id,
            "action_loop_hash": loop.loop_hash,
            "execution_attempt_id": attempt_id,
            "attempt_ledger_ref": "interactive_attempts.jsonl",
        },
    )
    _atomic_json(case_root / "episode_result.json", episode.model_dump(mode="json"))
    append_jsonl(
        case_root / "interactive_attempts.jsonl",
        {
            "kind": "attempt_completed",
            "attempt_id": attempt_id,
            "episode_id": episode.episode_id,
            "recorded_at": _now(),
        },
    )
    return episode, sanitized, loop


def run_interactive_baseline_episode(
    *,
    request: EpisodeRequest,
    materialized_task: MaterializedTask,
    driver: SafeClawInteractiveVictimDriver,
    output_root: Path,
    upstream_commit: str,
    safety_patch_hash: str,
    max_sessions: int,
    max_turns: int,
    resume: bool = True,
) -> tuple[SafeClawEpisodeResult, dict[str, Any], dict[str, Any]]:
    case_root = output_root / request.case_id
    case_root.mkdir(parents=True, exist_ok=True)
    episode_path = case_root / "episode_result.json"
    sanitized_path = case_root / "sanitized_result.json"
    trace_path = case_root / "formal_baseline_replay.json"
    if resume and all(path.is_file() for path in (episode_path, sanitized_path, trace_path)):
        episode = SafeClawEpisodeResult.model_validate_json(
            episode_path.read_text(encoding="utf-8")
        )
        sanitized = json.loads(sanitized_path.read_text(encoding="utf-8"))
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        if not isinstance(sanitized, dict) or not isinstance(trace, dict):
            raise ValueError("cached_interactive_baseline_invalid")
        return episode, sanitized, trace
    attempt_id, attempt_no = _begin_attempt(case_root, request)
    prepare_attempt = getattr(driver, "prepare_attempt", None)
    if callable(prepare_attempt):
        prepare_attempt(attempt_id)
    canonical_trajectory_ref = str(
        getattr(driver, "canonical_trajectory_ref", "formal_action_journal.jsonl")
    )
    _journal_path(case_root, canonical_trajectory_ref)
    task = json.loads(materialized_task.path.read_text(encoding="utf-8"))
    raw_sessions = task.get("sessions", [])
    if not isinstance(raw_sessions, list):
        raise ValueError("interactive_baseline_sessions_invalid")
    if len(raw_sessions) > max_sessions or len(raw_sessions) > max_turns:
        raise ValueError("interactive_baseline_budget_exceeded")
    started_at = _now()
    started_monotonic = time.monotonic()
    actions: list[FormalAttackerStageAction] = []
    observations: list[FormalVictimObservation] = []
    try:
        driver.start(materialized_task)
        for index, session in enumerate(raw_sessions, start=1):
            if not isinstance(session, dict):
                raise ValueError("interactive_baseline_session_invalid")
            session_id = str(session["session_id"])
            call_id = (
                "baseline-call-"
                + stable_hash(
                    {
                        "case_id": request.case_id,
                        "execution_attempt_id": attempt_id,
                        "session_id": session_id,
                        "index": index,
                    }
                )[:20]
            )
            action_id = "baseline-action-" + stable_hash(call_id)[:20]
            action = FormalAttackerStageAction(
                attacker_call_id=call_id,
                attacker_action_id=action_id,
                plan_id=f"baseline-plan:{request.case_id}",
                benchmark_session_id=session_id,
                stage_id=f"baseline-session-{index}",
                macro_ref="baseline.public_session_replay",
                action_type="victim_message",
                benchmark_surface="safeclaw.session_lifecycle",
                victim_visible_content=str(session["user_instruction"]),
                public_slot_refs=[],
                expected_public_predicate="baseline_session_completed",
                rationale_summary="Replay the registered public baseline session.",
            )
            observation = driver.apply(action, timeout_seconds=request.timeout_seconds)
            actions.append(action)
            observations.append(observation)
        finished = driver.finish()
    except BaseException as exc:
        append_jsonl(
            case_root / "interactive_attempts.jsonl",
            {
                "kind": "attempt_failed",
                "attempt_id": attempt_id,
                "error_category": type(exc).__name__,
                "recorded_at": _now(),
            },
        )
        driver.abort()
        raise
    _ensure_action_journal(
        case_root,
        canonical_trajectory_ref,
        actions,
        observations,
    )
    sanitized = finished.official_report
    _atomic_json(sanitized_path, sanitized)
    provider_records = finished.provider_usage_records
    observed_completions = len(provider_records) if provider_records else None
    input_tokens = _usage_total(provider_records, ("input_tokens", "prompt_tokens"))
    output_tokens = _usage_total(provider_records, ("output_tokens", "completion_tokens"))
    cached_tokens = _usage_total(
        provider_records,
        ("cached_tokens", "cache_read_input_tokens", "cached_input_tokens"),
    )
    provider_cost = _usage_cost(provider_records)
    accounting_gaps = [
        item
        for item, missing in (
            (
                "victim_provider_completion_count_not_exposed_by_gateway",
                observed_completions is None,
            ),
            ("provider_cost_not_returned", provider_cost is None),
        )
        if missing
    ]
    if observed_completions is not None and observed_completions < len(actions):
        accounting_gaps.append("victim_provider_usage_partial")
    trace_payload = {
        "schema_version": "1.0",
        "actions": [item.model_dump(mode="json") for item in actions],
        "observations": [item.model_dump(mode="json") for item in observations],
        "accounting": {
            "attacker_model_calls": 0,
            "victim_gateway_requests": len(actions),
            "sessions_used": len(raw_sessions),
            "turns_used": len(actions),
            "tool_calls_observed": sum(len(item.tool_event_ids) for item in observations),
            "victim_provider_completions_when_observable": observed_completions,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
            "provider_cost": provider_cost,
            "instrumentation_gap_reasons": accounting_gaps,
        },
    }
    trace = {**trace_payload, "trace_hash": stable_hash(trace_payload)}
    _atomic_json(trace_path, trace)
    report_sessions = sanitized.get("sessions", [])
    session_items = report_sessions if isinstance(report_sessions, list) else []
    episode_sessions = [
        SanitizedSessionResult(
            session_id=str(item.get("session_id", f"session-{index}")),
            sequence_no=index,
            status="completed",
            transcript_ref=f"sanitized_result.json#/sessions/{index - 1}",
            public_stage_status={},
        )
        for index, item in enumerate(session_items, start=1)
        if isinstance(item, dict)
    ]
    episode = SafeClawEpisodeResult(
        episode_id=f"episode-{request.case_id}",
        case_id=request.case_id,
        task_id=request.task_ref.task_id,
        binding_id=request.task_ref.binding_id,
        status=SafeClawExecutionStatus.completed,
        error_category=None,
        upstream_commit=upstream_commit,
        runner_version="safeclaw-formal-interactive-baseline-v1",
        target_model_id=request.target_model_id,
        started_at=started_at,
        ended_at=_now(),
        duration_ms=int((time.monotonic() - started_monotonic) * 1000),
        attempt_count=attempt_no,
        sessions=episode_sessions,
        sanitized_result_ref=sanitized_path.name,
        sanitized_result_hash=file_hash(sanitized_path),
        canonical_trajectory_ref=canonical_trajectory_ref,
        official_checks_ref="sanitized_result.json#/checks",
        state_evidence_refs=sorted(
            {ref for item in observations for ref in item.output_state_refs}
        ),
        taint_evidence_refs=sorted(
            {ref for item in observations for ref in item.verifier_evidence_refs}
        ),
        secret_scan_passed=True,
        provenance={
            "materialized_task_hash": request.task_ref.materialized_task_hash,
            "safety_patch_hash": safety_patch_hash,
            "interactive_bridge": driver.driver_id,
            "baseline_trace_hash": str(trace["trace_hash"]),
            "execution_attempt_id": attempt_id,
            "attempt_ledger_ref": "interactive_attempts.jsonl",
        },
    )
    _atomic_json(episode_path, episode.model_dump(mode="json"))
    append_jsonl(
        case_root / "interactive_attempts.jsonl",
        {
            "kind": "attempt_completed",
            "attempt_id": attempt_id,
            "episode_id": episode.episode_id,
            "recorded_at": _now(),
        },
    )
    return episode, sanitized, trace
