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


def _formal_action_lineages(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    requests: dict[str, tuple[int, dict[str, Any]]] = {}
    responses: dict[str, tuple[int, dict[str, Any]]] = {}
    for line_number, record in enumerate(records, start=1):
        kind = record.get("kind")
        if kind not in {"victim_request", "victim_response"}:
            continue
        action_id = str(record.get("attacker_action_id", ""))
        if not action_id:
            raise ValueError(f"formal_action_journal_missing_action_id:line-{line_number}")
        target = requests if kind == "victim_request" else responses
        if action_id in target:
            raise ValueError(f"formal_action_journal_duplicate_{kind}:{action_id}")
        target[action_id] = (line_number, record)
    if set(requests) != set(responses):
        incomplete = sorted(set(requests) ^ set(responses))
        raise ValueError("formal_action_journal_incomplete:" + ",".join(incomplete))

    lineages: list[dict[str, Any]] = []
    for action_id, (request_line, request) in sorted(requests.items(), key=lambda item: item[1][0]):
        response_line, response = responses[action_id]
        action = request.get("action")
        observation = response.get("observation")
        if not isinstance(action, dict) or not isinstance(observation, dict):
            raise ValueError(f"formal_action_journal_payload_invalid:{action_id}")
        identity = {
            "plan_id": str(request.get("plan_id", "")),
            "plan_stage_id": str(request.get("plan_stage_id", "")),
            "attacker_call_id": str(request.get("attacker_call_id", "")),
            "attacker_action_id": action_id,
            "victim_request_event_id": str(request.get("victim_request_event_id", "")),
            "victim_response_event_id": str(response.get("victim_response_event_id", "")),
        }
        if not all(identity.values()):
            raise ValueError(f"formal_action_journal_lineage_incomplete:{action_id}")
        compared = {
            "plan_id": observation.get("plan_id"),
            "plan_stage_id": observation.get("plan_stage_id"),
            "attacker_call_id": observation.get("attacker_call_id"),
            "attacker_action_id": observation.get("attacker_action_id"),
            "victim_request_event_id": observation.get("victim_request_event_id"),
            "victim_response_event_id": observation.get("victim_response_event_id"),
        }
        if compared != identity:
            raise ValueError(f"formal_action_journal_lineage_mismatch:{action_id}")
        lineages.append(
            {
                **identity,
                "request_line": request_line,
                "response_line": response_line,
                "request_ref": f"formal_action_journal.jsonl#L{request_line}",
                "response_ref": f"formal_action_journal.jsonl#L{response_line}",
                "action": action,
                "observation": observation,
            }
        )
    return lineages


def _lineage_event_fields(lineage: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": lineage["plan_id"],
        "plan_stage_id": lineage["plan_stage_id"],
        "attacker_call_id": lineage["attacker_call_id"],
        "attacker_action_id": lineage["attacker_action_id"],
        "action_journal_ref": lineage["response_ref"],
        "evidence_ref_ids": [
            lineage["request_ref"],
            lineage["response_ref"],
            f"attacker_action:{lineage['attacker_action_id']}",
            f"plan_stage:{lineage['plan_stage_id']}",
        ],
    }


def _matches_action_message(lineage: dict[str, Any], message_text: str) -> bool:
    action = lineage["action"]
    content = str(action.get("victim_visible_content") or "").strip()
    observed = message_text.strip()
    return bool(content and observed and (content in observed or observed in content))


def _state_component(key: str) -> str:
    if key.startswith("memory_"):
        return "persistent_memory"
    if key.startswith("new_workspace_file"):
        return "workspace_file"
    if key.startswith("simulated_external_call"):
        return "sandbox_external_state"
    return "safeclaw_public_state"


def _action_envelope_events(
    lineage: dict[str, Any],
    associated_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    fields = _lineage_event_fields(lineage)
    action = lineage["action"]
    observation = lineage["observation"]
    session_id = str(
        observation.get("benchmark_session_id")
        or action.get("benchmark_session_id")
        or "session-unknown"
    )
    request_id = lineage["victim_request_event_id"]
    response_id = lineage["victim_response_event_id"]
    request_artifact = f"formal-action-input-{stable_hash(request_id)[:16]}"
    response_artifact = f"formal-victim-output-{stable_hash(response_id)[:16]}"
    request = {
        "event_id": request_id,
        "session_id": session_id,
        "actor_role": "attacker",
        "event_type": "message",
        "component_role": "formal_action_envelope",
        "operation": "formal_victim_request",
        "status": "passed",
        "output_artifacts": [
            {
                "artifact_id": request_artifact,
                "artifact_type": "victim_request",
                "content_hash": stable_hash(action.get("victim_visible_content")),
                "parent_artifact_ids": [],
                "taint_labels": ["formal_action", "public"],
                "trust_label": "attacker_supplied",
                "source_ref_ids": [lineage["request_ref"]],
            }
        ],
        "public_payload": {"action_type": action.get("action_type")},
        "source_event_ref": lineage["request_ref"],
        **fields,
    }
    output: list[dict[str, Any]] = [request]
    if action.get("action_type") == "session_transition":
        output.append(
            {
                "event_id": "formal-lifecycle-" + stable_hash(request_id)[:20],
                "session_id": session_id,
                "actor_role": "runner",
                "event_type": "lifecycle",
                "component_role": "session_lifecycle",
                "operation": "restart_session",
                "status": "passed",
                "lifecycle_id": "formal-session-boundary-" + stable_hash(request_id)[:16],
                "request_event_id": request_id,
                "public_payload": {"session_id": session_id},
                "source_event_ref": lineage["response_ref"],
                **fields,
            }
        )
    for event in associated_events:
        event.setdefault("input_artifact_ids", []).append(request_artifact)
        dependencies = event.setdefault("dependencies", [])
        dependencies.append(
            {
                "source_event_id": request_id,
                "edge_type": "control",
                "source_fact": "validated_action_dispatched",
                "target_precondition": "victim_event_observed",
                "evidence_ref_ids": [lineage["request_ref"], event["source_event_ref"]],
            }
        )
        output.append(event)
    emitted_ids = {str(item["event_id"]) for item in output}
    raw_tool_ids = observation.get("tool_event_ids", [])
    tool_ids = raw_tool_ids if isinstance(raw_tool_ids, list) else []
    raw_tool_calls = observation.get("public_tool_calls", [])
    tool_calls = raw_tool_calls if isinstance(raw_tool_calls, list) else []
    for index, tool_id_value in enumerate(tool_ids):
        tool_id = str(tool_id_value)
        if tool_id in emitted_ids:
            continue
        raw_tool = tool_calls[index] if index < len(tool_calls) else {}
        tool = raw_tool if isinstance(raw_tool, dict) else {"name": str(raw_tool)}
        tool_name = str(tool.get("name") or tool.get("tool_name") or "unknown_tool")
        output.append(
            {
                "event_id": tool_id,
                "session_id": session_id,
                "actor_role": "agent",
                "event_type": _event_type_for_tool(tool_name, result=False),
                "component_role": _component_for_tool(tool_name),
                "operation": tool_name,
                "status": "passed",
                "input_artifact_ids": [request_artifact],
                "request_event_id": request_id,
                "public_payload": {"tool_call_hash": stable_hash(tool)},
                "source_event_ref": lineage["response_ref"],
                **fields,
            }
        )
        emitted_ids.add(tool_id)
    state_delta = observation.get("public_state_delta", {})
    if isinstance(state_delta, dict):
        for key, delta in sorted(state_delta.items()):
            if not isinstance(delta, dict):
                continue
            state_event_id = "formal-state-" + stable_hash({"request": request_id, "key": key})[:20]
            state_ref = f"public_state:{key}"
            output.append(
                {
                    "event_id": state_event_id,
                    "session_id": session_id,
                    "actor_role": "runner",
                    "event_type": "state_write",
                    "component_role": _state_component(str(key)),
                    "operation": f"public_state_change:{key}",
                    "status": "passed",
                    "write_state_refs": [state_ref],
                    "pre_state_ref": f"{state_ref}:{stable_hash(delta.get('before'))[:16]}",
                    "post_state_ref": f"{state_ref}:{stable_hash(delta.get('after'))[:16]}",
                    "request_event_id": request_id,
                    "public_payload": {"state_key": key},
                    "source_event_ref": lineage["response_ref"],
                    **fields,
                }
            )
    terminal_sources = [item["event_id"] for item in output[1:]]
    response_dependencies = [
        {
            "source_event_id": source_id,
            "edge_type": "control",
            "source_fact": "victim_step_observed",
            "target_precondition": "victim_response_recorded",
            "evidence_ref_ids": [lineage["response_ref"]],
        }
        for source_id in terminal_sources
    ]
    output.append(
        {
            "event_id": response_id,
            "session_id": session_id,
            "actor_role": "victim",
            "event_type": "message",
            "component_role": "formal_action_envelope",
            "operation": "formal_victim_response",
            "status": "passed",
            "request_event_id": request_id,
            "input_artifact_ids": [request_artifact],
            "output_artifacts": [
                {
                    "artifact_id": response_artifact,
                    "artifact_type": "victim_response",
                    "content_hash": stable_hash(observation.get("public_response_text")),
                    "parent_artifact_ids": [request_artifact],
                    "taint_labels": ["victim_observation", "public"],
                    "trust_label": "victim_generated",
                    "source_ref_ids": [lineage["response_ref"]],
                }
            ],
            "dependencies": response_dependencies,
            "public_payload": {"status": observation.get("status")},
            "source_event_ref": lineage["response_ref"],
            **fields,
        }
    )
    return output


def _parse_transcript(
    raw: str,
    session_records: list[dict[str, Any]],
    action_lineages: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int, int]:
    events: list[dict[str, Any]] = []
    action_events: list[list[dict[str, Any]]] = [[] for _ in action_lineages]
    matched_lineages: set[int] = set()
    active_lineage: int | None = None
    tool_offsets: dict[int, int] = {}

    def append_event(event: dict[str, Any]) -> None:
        if active_lineage is None:
            events.append(event)
            return
        lineage = action_lineages[active_lineage]
        fields = _lineage_event_fields(lineage)
        evidence = [
            *event.get("evidence_ref_ids", []),
            *fields.pop("evidence_ref_ids"),
        ]
        event.update(fields)
        event["evidence_ref_ids"] = list(dict.fromkeys(str(item) for item in evidence))
        action_events[active_lineage].append(event)

    def next_matching_lineage(message_text: str) -> int | None:
        for index, lineage in enumerate(action_lineages):
            if index in matched_lineages:
                continue
            action = lineage["action"]
            if action.get("action_type") not in {"victim_message", "tool_surface"}:
                continue
            if _matches_action_message(lineage, message_text):
                return index
        return None

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
            active_lineage = next_matching_lineage(message_text)
            if active_lineage is not None:
                matched_lineages.add(active_lineage)
                observation = action_lineages[active_lineage]["observation"]
                current_session = str(observation.get("benchmark_session_id") or current_session)
            for session_id, instruction in instructions.items():
                if (
                    active_lineage is None
                    and instruction
                    and (instruction in message_text or message_text in instruction)
                ):
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
                event_id = f"safeclaw-call-{call_count}"
                if active_lineage is not None:
                    offset = tool_offsets.get(active_lineage, 0)
                    tool_ids = action_lineages[active_lineage]["observation"].get(
                        "tool_event_ids", []
                    )
                    if isinstance(tool_ids, list) and offset < len(tool_ids):
                        event_id = str(tool_ids[offset])
                    tool_offsets[active_lineage] = offset + 1
                pending.append((call_id, tool_name, event_id))
                append_event(
                    {
                        "event_id": event_id,
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
                append_event(
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
            append_event(
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
    if not action_lineages:
        return events, call_count, result_count
    ordered: list[dict[str, Any]] = []
    for index, lineage in enumerate(action_lineages):
        ordered.extend(_action_envelope_events(lineage, action_events[index]))
    ordered.extend(events)
    return ordered, call_count, result_count


def normalize_safeclaw_episode(
    episode: SafeClawEpisodeResult,
    descriptor: SafeClawTaskDescriptor,
    sanitized_result: dict[str, Any],
    *,
    action_journal_records: list[dict[str, Any]] | None = None,
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
    journal_records = action_journal_records or []
    action_lineages = _formal_action_lineages(journal_records)
    source_events, call_count, result_count = _parse_transcript(
        str(sanitized_result.get("session_transcript_raw", "")),
        session_records,
        action_lineages,
    )
    ordered_events: list[dict[str, Any]] = []
    seen_sessions: set[str] = set()
    lifecycle_count = 0
    for event in source_events:
        session_id = str(event["session_id"])
        if event.get("event_type") == "lifecycle":
            lifecycle_count += 1
        elif session_id in session_ids[1:] and session_id not in seen_sessions:
            lifecycle_count += 1
            ordered_events.append(
                {
                    "event_id": f"safeclaw-lifecycle-{lifecycle_count}",
                    "session_id": session_id,
                    "sequence_no": 0,
                    "actor_role": "runner",
                    "event_type": "lifecycle",
                    "component_role": "session_lifecycle",
                    "operation": "restart_session",
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
                    "operation": "restart_session",
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
    if (episode.canonical_trajectory_ref or "").endswith(
        "formal_action_journal.jsonl"
    ) and not journal_records:
        gaps.append("formal_action_journal_missing")
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
