from __future__ import annotations

import json
from collections import deque
from typing import Any

from pydantic import NonNegativeInt

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.environments.safeclaw.contracts import (
    SafeClawEpisodeResult,
    SafeClawTaskDescriptor,
)
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.models import InteractionGraph, RawInteractionTrajectory
from stac_attack_lab.interactions.normalizer import NormalizationAudit, normalize_source_events


class SafeClawTrajectoryAudit(StrictModel):
    task_id: str
    session_count: NonNegativeInt
    source_event_count: NonNegativeInt
    tool_call_count: NonNegativeInt
    tool_result_count: NonNegativeInt
    unpaired_tool_event_count: NonNegativeInt
    lifecycle_event_count: NonNegativeInt
    instrumentation_gaps: list[str]
    normalization: NormalizationAudit


def _text_content(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(part for item in value if (part := _text_content(item)))
    if isinstance(value, dict):
        if value.get("type") in {"text", "input_text", "output_text"}:
            return str(value.get("text", ""))
        return _text_content(value.get("content", value.get("text", "")))
    return "" if value is None else str(value)


def _component_for_tool(tool_name: str) -> str:
    lowered = tool_name.lower()
    if "memory" in lowered:
        return "persistent_memory"
    if any(token in lowered for token in ("gmail", "drive", "document", "search", "read")):
        return "untrusted_source"
    return "effect_tool"


def _event_type_for_tool(tool_name: str, *, result: bool) -> str:
    lowered = tool_name.lower()
    if result:
        return "tool_result"
    if "memory" in lowered and any(token in lowered for token in ("write", "save", "append")):
        return "state_write"
    if "memory" in lowered and any(token in lowered for token in ("read", "search", "get")):
        return "state_read"
    return "tool_call"


def _parse_transcript(
    raw: str, session_records: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], int, int]:
    events: list[dict[str, Any]] = []
    pending: deque[tuple[str, str, str]] = deque()
    sequence = 0
    session_ids = [str(item.get("session_id", "")) for item in session_records]
    instructions = {
        str(item.get("session_id", "")): str(item.get("user_instruction", ""))
        for item in session_records
    }
    current_session = session_ids[0] if session_ids else "session-unknown"
    call_count = 0
    result_count = 0
    for line_number, line in enumerate(raw.splitlines(), start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict) or record.get("type") != "message":
            continue
        message = record.get("message", {})
        if not isinstance(message, dict):
            continue
        role = str(message.get("role", "unknown"))
        content = message.get("content", [])
        message_text = _text_content(content)
        if role == "user":
            for session_id, instruction in instructions.items():
                if instruction and (instruction in message_text or message_text in instruction):
                    current_session = session_id
                    break
        items = content if isinstance(content, list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("type", ""))
            if kind in {"toolCall", "tool_call"}:
                call_count += 1
                sequence += 1
                call_id = str(
                    item.get("id") or item.get("toolCallId") or f"derived-call-{call_count}"
                )
                tool_name = str(
                    item.get("name") or item.get("tool", {}).get("name") or "unknown_tool"
                )
                arguments = item.get(
                    "arguments", item.get("input", item.get("tool", {}).get("input", {}))
                )
                pending.append((call_id, tool_name, f"safeclaw-call-{call_count}"))
                events.append(
                    {
                        "event_id": f"safeclaw-call-{call_count}",
                        "session_id": current_session,
                        "sequence_no": sequence,
                        "actor_role": "agent",
                        "event_type": _event_type_for_tool(tool_name, result=False),
                        "component_role": _component_for_tool(tool_name),
                        "operation": tool_name,
                        "status": "passed",
                        "public_payload": {"arguments_hash": stable_hash(arguments)},
                        "source_event_ref": f"session_transcript_raw:line-{line_number}",
                        "evidence_ref_ids": [f"tool_call_id:{call_id}"],
                    }
                )
            elif kind in {"toolResult", "tool_result"}:
                result_count += 1
                sequence += 1
                call_id = str(item.get("toolCallId") or item.get("tool_call_id") or "")
                paired = next(
                    (
                        (cid, name, event_id)
                        for cid, name, event_id in pending
                        if not call_id or cid == call_id
                    ),
                    None,
                )
                if paired is not None:
                    pending.remove(paired)
                    call_id, tool_name, request_event_id = paired
                else:
                    tool_name = str(item.get("name") or "unknown_tool")
                text = _text_content(item.get("content", item.get("text", "")))
                artifact_id = f"safeclaw-tool-result-{result_count}"
                events.append(
                    {
                        "event_id": f"safeclaw-result-{result_count}",
                        "session_id": current_session,
                        "sequence_no": sequence,
                        "actor_role": "tool",
                        "event_type": "tool_result",
                        "component_role": _component_for_tool(tool_name),
                        "operation": tool_name,
                        "status": "passed",
                        "request_event_id": (request_event_id if paired else None),
                        "output_artifacts": [
                            {
                                "artifact_id": artifact_id,
                                "artifact_type": "tool_result",
                                "content_hash": stable_hash(text),
                                "parent_artifact_ids": [],
                                "taint_labels": ["safeclaw_observable"],
                                "trust_label": "benchmark_tool_result",
                                "source_ref_ids": [f"tool_call_id:{call_id}"],
                            }
                        ],
                        "public_payload": {"content_hash": stable_hash(text)},
                        "source_event_ref": f"session_transcript_raw:line-{line_number}",
                        "evidence_ref_ids": [f"tool_call_id:{call_id}"],
                    }
                )
        text = _text_content(content)
        if text and role in {"user", "assistant"}:
            sequence += 1
            events.append(
                {
                    "event_id": f"safeclaw-message-{sequence}",
                    "session_id": current_session,
                    "sequence_no": sequence,
                    "actor_role": "user" if role == "user" else "agent",
                    "event_type": "message",
                    "component_role": "agent_context",
                    "operation": f"{role}_message",
                    "status": "passed",
                    "public_payload": {"content_hash": stable_hash(text)},
                    "source_event_ref": f"session_transcript_raw:line-{line_number}",
                }
            )
    return events, call_count, result_count


def normalize_safeclaw_episode(
    episode: SafeClawEpisodeResult,
    descriptor: SafeClawTaskDescriptor,
    sanitized_result: dict[str, Any],
) -> tuple[InteractionGraph, SafeClawTrajectoryAudit]:
    session_ids = [session.session_id for session in episode.sessions]
    raw_session_records = sanitized_result.get("sessions", [])
    session_records = (
        [item for item in raw_session_records if isinstance(item, dict)]
        if isinstance(raw_session_records, list)
        else []
    )
    if not session_records:
        session_records = [
            {"session_id": session_id, "user_instruction": ""} for session_id in session_ids
        ]
    source_events, call_count, result_count = _parse_transcript(
        str(sanitized_result.get("session_transcript_raw", "")), session_records
    )
    ordered_events: list[dict[str, Any]] = []
    seen_sessions: set[str] = set()
    lifecycle_count = 0
    for event in source_events:
        session_id = str(event["session_id"])
        if session_id in session_ids[1:] and session_id not in seen_sessions:
            lifecycle_count += 1
            ordered_events.append(
                {
                    "event_id": f"safeclaw-lifecycle-{lifecycle_count}",
                    "session_id": session_id,
                    "sequence_no": 0,
                    "actor_role": "runner",
                    "event_type": "lifecycle",
                    "component_role": "session_lifecycle",
                    "operation": "new_session",
                    "status": "passed",
                    "lifecycle_id": f"safeclaw-session-boundary-{lifecycle_count}",
                    "public_payload": {"session_id": session_id},
                    "source_event_ref": (
                        f"sanitized_result.json#/sessions/{session_ids.index(session_id)}"
                    ),
                }
            )
        seen_sessions.add(session_id)
        ordered_events.append(event)
    for session_id in session_ids[1:]:
        if session_id not in seen_sessions:
            lifecycle_count += 1
            ordered_events.append(
                {
                    "event_id": f"safeclaw-lifecycle-{lifecycle_count}",
                    "session_id": session_id,
                    "sequence_no": 0,
                    "actor_role": "runner",
                    "event_type": "lifecycle",
                    "component_role": "session_lifecycle",
                    "operation": "new_session",
                    "status": "passed",
                    "lifecycle_id": f"safeclaw-session-boundary-{lifecycle_count}",
                    "public_payload": {"session_id": session_id},
                    "source_event_ref": (
                        f"sanitized_result.json#/sessions/{session_ids.index(session_id)}"
                    ),
                }
            )
    for sequence_no, event in enumerate(ordered_events, start=1):
        event["sequence_no"] = sequence_no
    source_events = ordered_events
    sequence = len(source_events) + 1
    source_events.append(
        {
            "event_id": "safeclaw-official-verdict",
            "session_id": "evaluator",
            "sequence_no": sequence,
            "actor_role": "evaluator",
            "event_type": "evaluator",
            "component_role": "sandbox_external_state",
            "operation": "official_safeclaw_evaluation",
            "status": "passed",
            "public_payload": {
                "attack_succeeded": sanitized_result.get("attack_succeeded"),
                "score": sanitized_result.get("score"),
            },
            "source_event_ref": "sanitized_result.json#/checks",
            "evidence_ref_ids": ["sanitized_result.json#/checks"],
        }
    )
    trajectory = RawInteractionTrajectory(
        trajectory_id=f"safeclaw-trajectory-{episode.case_id}",
        source_adapter_id="safeclaw_formal",
        source_adapter_version="1.0.0",
        source_environment_family="SafeClawArena",
        source_environment_version=episode.upstream_commit,
        source_task_id=descriptor.task_id,
        source_split="test",
        episode_id=episode.episode_id,
        session_ids=session_ids,
        event_refs=[],
        checkpoint_refs=[],
        model_hashes={"target_model": stable_hash(episode.target_model_id)},
        config_hash=episode.provenance.get("materialized_task_hash", "unknown"),
        collection_seed=0,
        collection_status=("complete" if episode.status.value == "completed" else "partial"),
        provenance={
            "sanitized_result_hash": episode.sanitized_result_hash or "unavailable",
            "authorization_scope": "SafeClawArena",
        },
    )
    graph, normalization = normalize_source_events(
        trajectory,
        source_events,
        audit_ref=f"{episode.case_id}/trajectory_audit.json",
    )
    gaps: list[str] = []
    if call_count != result_count:
        gaps.append("unpaired_tool_events")
    if not sanitized_result.get("session_transcript_raw"):
        gaps.append("raw_transcript_missing")
    if not sanitized_result.get("setup_state"):
        gaps.append("state_checkpoint_missing")
    audit = SafeClawTrajectoryAudit(
        task_id=descriptor.task_id,
        session_count=len(session_ids),
        source_event_count=len(source_events),
        tool_call_count=call_count,
        tool_result_count=result_count,
        unpaired_tool_event_count=abs(call_count - result_count),
        lifecycle_event_count=lifecycle_count,
        instrumentation_gaps=gaps,
        normalization=normalization,
    )
    return graph, audit
