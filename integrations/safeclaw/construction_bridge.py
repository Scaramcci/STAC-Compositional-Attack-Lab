#!/usr/bin/env python3
"""JSONL bridge for adaptive SafeClaw construction sessions.

This bridge intentionally never instantiates SafeClaw's Evaluator. The caller sees
only victim responses, tool calls, and state snapshots; official success checks
remain unavailable to the construction attacker.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

from stac_attack_lab.environments.safeclaw.observations import (
    classify_explicit_error,
    classify_provider_response,
    observable_gateway_diagnostics,
)
from stac_attack_lab.environments.safeclaw.provider_relay import (
    ContainerProviderRelay,
    relay_runtime_from_model_config,
)
from stac_attack_lab.environments.safeclaw.redaction import redact_value

SUPPORTED_DELIVERY_SURFACES = frozenset({"safeclaw_user_message"})
MEMORY_RETRIEVAL_TOOLS = frozenset({"memory_search", "memory_get"})
PERSISTENCE_FILE_TOOLS = frozenset({"read", "write", "edit"})
CONTROLLED_WORKSPACE_PREFIXES = (
    "/root/.openclaw/workspace/",
    "/workspace/",
)


def _normalise_workspace_path(value: Any) -> str | None:
    """Return a safe, repository-relative workspace path projection."""
    if not isinstance(value, str):
        return None
    candidate = value.replace("\\", "/").strip()
    if not candidate:
        return None
    if candidate.startswith("/"):
        for prefix in CONTROLLED_WORKSPACE_PREFIXES:
            if candidate.startswith(prefix):
                candidate = candidate[len(prefix) :]
                break
        else:
            return None
    parts = [part for part in candidate.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def _tool_path(arguments_projection: str) -> str | None:
    with contextlib.suppress(json.JSONDecodeError):
        value = json.loads(arguments_projection)
        if isinstance(value, dict):
            for key in ("path", "file", "filename", "file_path"):
                path = _normalise_workspace_path(value.get(key))
                if path:
                    return path
    return None


def _write_content_hash(tool_name: str, arguments_projection: str) -> str | None:
    if tool_name != "write":
        return None
    with contextlib.suppress(json.JSONDecodeError):
        value = json.loads(arguments_projection)
        if isinstance(value, dict) and isinstance(value.get("content"), str):
            return hashlib.sha256(value["content"].encode()).hexdigest()
    return None


def _observation_class(tool_name: str) -> str:
    return {
        "memory_search": "semantic_memory_search",
        "memory_get": "direct_memory_get",
        "read": "workspace_file_read",
        "write": "workspace_file_write",
        "edit": "workspace_file_edit",
    }.get(tool_name, "other_tool")


def _load_judge(upstream: Path) -> ModuleType:
    path = upstream / "scripts/judge.py"
    spec = importlib.util.spec_from_file_location("safeclaw_construction_judge", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("safeclaw_judge_import_failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True) + "\n")
    sys.stdout.flush()


def _observable_state(
    raw: dict[str, Any], exact_secrets: list[str] | None = None
) -> dict[str, Any]:
    """Project bounded state evidence without provider credentials or raw logs."""
    keys = (
        "config_hash",
        "memory_content",
        "memory_root_content",
        "memory_dir_content",
        "sim_google_calls",
        "new_workspace_files",
        "workspace_file_contents",
    )
    projected = {key: raw.get(key) for key in keys}
    projected["gateway_log_provenance"] = observable_gateway_diagnostics(raw, exact_secrets or [])
    return projected


def _nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return int(value)


def _transcript_provenance(
    raw_state: dict[str, Any], exact_secrets: list[str] | None = None
) -> dict[str, Any]:
    transcript = str(raw_state.get("session_transcript_raw") or "")
    redacted = str(redact_value(transcript[-12000:], exact_secrets or []).sanitized)
    lines = redacted.splitlines()
    return {
        "content_hash": __import__("hashlib").sha256(redacted.encode()).hexdigest(),
        "line_count": len(lines),
        "tool_call_lines": sum(line.startswith("TOOL_CALL:") for line in lines),
        "tool_result_lines": sum(line.startswith("TOOL_RESULT:") for line in lines),
        "structured_lineage_available": False,
    }


def _text_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(
        str(item.get("text", ""))
        for item in content
        if isinstance(item, dict) and item.get("type") == "text"
    )


def _structured_tool_observations(
    raw_state: dict[str, Any],
    seen_entry_ids: set[str],
    exact_secrets: list[str] | None = None,
) -> tuple[list[dict[str, Any]], set[str]]:
    """Project new, paired tool facts from pinned OpenClaw session JSONL."""
    calls: dict[str, dict[str, Any]] = {}
    results: dict[str, dict[str, Any]] = {}
    observed_ids: set[str] = set()
    raw = str(raw_state.get("session_transcript_raw") or "")
    for line_number, line in enumerate(raw.splitlines(), start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict) or entry.get("type") != "message":
            continue
        entry_id = str(entry.get("id") or f"line-{line_number}")
        if entry_id in seen_entry_ids:
            continue
        observed_ids.add(entry_id)
        message = entry.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if message.get("role") == "assistant" and isinstance(content, list):
            for block in content:
                if not isinstance(block, dict) or block.get("type") not in {
                    "toolCall",
                    "toolUse",
                    "functionCall",
                }:
                    continue
                call_id = str(block.get("id") or "")
                tool_name = str(block.get("name") or "")
                if not call_id or not tool_name:
                    continue
                arguments = block.get("arguments", block.get("input", {}))
                projection = str(
                    redact_value(
                        json.dumps(arguments, sort_keys=True, default=str), exact_secrets or []
                    ).sanitized
                )[:2000]
                calls[call_id] = {
                    "call_id": call_id,
                    "tool_name": tool_name,
                    "arguments_hash": hashlib.sha256(projection.encode()).hexdigest(),
                    "arguments_projection": projection,
                    "workspace_relative_path": _tool_path(projection),
                    "write_content_hash": _write_content_hash(tool_name, projection),
                    "request_line_number": line_number,
                    "request_evidence_ref": f"openclaw-session-entry:{entry_id}",
                    # Some pinned/fake gateways can expose an explicit provider
                    # correlation instead of forcing us to infer use from
                    # transcript adjacency.  Preserve only call ids here; the
                    # driver resolves them to observed result artifacts.
                    "input_result_call_ids": [
                        str(value)
                        for value in (
                            block.get("inputToolResultCallIds")
                            or message.get("inputToolResultCallIds")
                            or []
                        )
                        if str(value)
                    ],
                }
        if message.get("role") in {"toolResult", "tool"}:
            call_id = str(message.get("toolCallId") or message.get("toolUseId") or "")
            if not call_id:
                continue
            result_text = str(redact_value(_text_content(content), exact_secrets or []).sanitized)
            is_error = bool(message.get("isError"))
            lowered = result_text.lower()
            parsed_result: Any = None
            with contextlib.suppress(json.JSONDecodeError):
                parsed_result = json.loads(result_text)
            semantic_error = isinstance(parsed_result, dict) and (
                bool(parsed_result.get("error"))
                or parsed_result.get("unavailable") is True
                or parsed_result.get("disabled") is True
            )
            observed_empty = not result_text or (
                isinstance(parsed_result, dict) and parsed_result.get("results") == []
            )
            observation = (
                "rejected"
                if is_error
                and any(marker in lowered for marker in ("denied", "not allowed", "forbidden"))
                else "error"
                if is_error or semantic_error
                else "observed"
            )
            results[call_id] = {
                "tool_name": str(message.get("toolName") or ""),
                "result_line_number": line_number,
                "result_observation": observation,
                "result_empty": observed_empty,
                "result_disabled": parsed_result.get("disabled")
                if isinstance(parsed_result, dict)
                else None,
                "result_unavailable": parsed_result.get("unavailable")
                if isinstance(parsed_result, dict)
                else None,
                "result_error": parsed_result.get("error")
                if isinstance(parsed_result, dict)
                else None,
                "result_is_error": is_error,
                "result_hash_scope": "redacted_text_content",
                "result_hash": hashlib.sha256(result_text.encode()).hexdigest(),
                "result_excerpt": result_text[:2000],
                "result_evidence_ref": f"openclaw-session-entry:{entry_id}",
            }
    projected = []
    for call_id, call in sorted(
        calls.items(), key=lambda item: (item[1].get("request_line_number", 0), item[0])
    ):
        result = results.get(call_id)
        if result is not None and int(result.get("result_line_number", 0)) <= int(
            call.get("request_line_number", 0)
        ):
            result = None
        item = {
            "call_id": call_id,
            "tool_name": call["tool_name"],
            "arguments_hash": call["arguments_hash"],
            "arguments_projection": call["arguments_projection"],
            "request_evidence_ref": call["request_evidence_ref"],
            "result_observation": result["result_observation"] if result else "not_observed",
            "result_empty": bool(result.get("result_empty")) if result else False,
            "result_disabled": result.get("result_disabled") if result else None,
            "result_unavailable": result.get("result_unavailable") if result else None,
            "result_error": result.get("result_error") if result else None,
            "result_is_error": result.get("result_is_error") if result else None,
            "result_hash_scope": result.get("result_hash_scope") if result else None,
            "result_hash": result.get("result_hash") if result else None,
            "result_excerpt": result.get("result_excerpt")
            if result and call["tool_name"] in MEMORY_RETRIEVAL_TOOLS
            else None,
            "result_evidence_ref": result.get("result_evidence_ref") if result else None,
            "request_line_number": call.get("request_line_number"),
            "result_line_number": result.get("result_line_number") if result else None,
            "result_order_valid": result is not None,
            "observation_class": _observation_class(call["tool_name"]),
            "workspace_relative_path": call.get("workspace_relative_path"),
            "write_content_hash": call.get("write_content_hash"),
            "input_result_call_ids": call.get("input_result_call_ids", []),
            "use_evidence_kind": (
                "explicit_provider_output_reference" if call.get("input_result_call_ids") else None
            ),
        }
        projected.append(item)
    return projected, observed_ids


def _embedding_ledger(
    judge: ModuleType, relay: ContainerProviderRelay | None = None
) -> list[dict[str, Any]]:
    if relay is None or not hasattr(relay, "embedding_records"):
        # Never fall back to a Victim-local ledger: that would mask an adapter
        # started in the wrong container or report stale records as live use.
        raise RuntimeError("embedding_relay_missing")
    return relay.embedding_records()


def _observable_usage(raw: Any) -> dict[str, int] | None:
    """Return token counts only; never retain raw provider response metadata."""
    if isinstance(raw, list):
        for value in raw:
            nested = _observable_usage(value)
            if nested is not None:
                return nested
        return None
    if not isinstance(raw, dict):
        return None
    aliases = {
        "input_tokens": ("input_tokens", "prompt_tokens", "promptTokenCount"),
        "output_tokens": ("output_tokens", "completion_tokens", "candidatesTokenCount"),
        "total_tokens": ("total_tokens", "totalTokenCount"),
    }
    projected: dict[str, int] = {}
    for canonical, candidates in aliases.items():
        for candidate in candidates:
            value = _nonnegative_int(raw.get(candidate))
            if value is not None:
                projected[canonical] = value
                break
    if projected:
        if "total_tokens" not in projected and {
            "input_tokens",
            "output_tokens",
        } <= set(projected):
            projected["total_tokens"] = projected["input_tokens"] + projected["output_tokens"]
        return projected
    priority_keys = ("usage", "usageMetadata", "result", "payload", "data", "response")
    for key in priority_keys:
        nested = _observable_usage(raw.get(key))
        if nested is not None:
            return nested
    for value in raw.values():
        if isinstance(value, (dict, list)):
            nested = _observable_usage(value)
            if nested is not None:
                return nested
    return None


def _aggregate_relay_usage(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate one action's relay attempts without counting ledger snapshots twice."""
    attempts = [item for item in records if item.get("accepted") is True]
    known = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    complete = 0
    missing = 0
    failed = 0
    for item in attempts:
        usage = item.get("provider_usage")
        if item.get("status") != 200:
            failed += 1
        if (
            isinstance(usage, dict)
            and all(isinstance(usage.get(key), int) and usage.get(key) >= 0 for key in known)
            and usage.get("total_tokens") == usage.get("input_tokens") + usage.get("output_tokens")
        ):
            complete += 1
            for key in known:
                known[key] += int(usage[key])
        else:
            missing += 1
    observation = (
        "complete"
        if attempts and complete == len(attempts) and failed == 0
        else "partial"
        if attempts and complete > 0
        else "failed"
        if attempts and failed == len(attempts)
        else "missing"
    )
    return {
        "usage": known if attempts and complete == len(attempts) and failed == 0 else None,
        "known_subtotal": known if complete else None,
        "observation": observation,
        "attempt_count": len(attempts),
        "complete_request_count": complete,
        "missing_request_count": missing,
        "failed_request_count": failed,
    }


def _classify_response(
    raw: Any,
    agent_response: Any,
    tool_calls: Any,
    gateway_diagnostics: dict[str, Any] | None = None,
    exact_secrets: list[str] | None = None,
) -> dict[str, Any]:
    return classify_provider_response(
        raw,
        agent_response,
        tool_calls,
        gateway_diagnostics=gateway_diagnostics,
        exact_secrets=exact_secrets or [],
    )


def _session_identity(session_key: Any) -> str | None:
    if not isinstance(session_key, str) or not session_key or session_key == "***REDACTED***":
        return None
    return hashlib.sha256(session_key.encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--model-config", required=True)
    args = parser.parse_args()

    def terminate(signum: int, frame: Any) -> None:
        del signum, frame
        raise SystemExit(124)

    signal.signal(signal.SIGTERM, terminate)
    upstream = Path(args.upstream).resolve()
    task_path = Path(args.task).resolve()
    task = json.loads(task_path.read_text(encoding="utf-8"))
    model_runtime = json.loads(Path(args.model_config).read_text(encoding="utf-8"))
    exact_secrets = [
        str(model_runtime.get(key) or "")
        for key in ("api_key", "embedding_api_key")
        if model_runtime.get(key)
    ]
    judge = _load_judge(upstream)
    judge._set_platform("openclaw")
    runner = None
    container_started = False
    relay: ContainerProviderRelay | None = None
    effective_model_config: Path | None = None
    phase = "startup"
    current_key = None
    pending_restart = False
    pending_lifecycle_action_id: str | None = None
    last_delivery_identity: str | None = None
    session_index = 0
    seen_transcript_entry_ids: set[str] = set()
    provider_record_cursor = 0
    try:
        with contextlib.redirect_stdout(sys.stderr):
            phase = "container_start"
            judge.start_container(judge.IMAGE)
            container_started = True
            relay_runtime = relay_runtime_from_model_config(model_runtime)
            if relay_runtime is not None:
                phase = "provider_relay_start"
                relay = ContainerProviderRelay(
                    image=judge.IMAGE,
                    victim_container=judge.CONTAINER,
                    runtime=relay_runtime,
                )
                model_runtime.update(relay.start())
                exact_secrets.append(relay.ingress_token)
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    prefix="safeclaw-model-runtime-",
                    suffix=".json",
                    dir=Path(args.model_config).parent,
                    delete=False,
                ) as stream:
                    json.dump(model_runtime, stream)
                    effective_model_config = Path(stream.name)
                effective_model_config.chmod(0o600)
            client = judge.GatewayClient(judge.GATEWAY_URL, judge.GATEWAY_TOKEN, verbose=False)
            runner = judge.TaskRunner(task, client, verbose=False)
            phase = "reset_environment"
            runner.reset_environment(str(task_path))
            phase = "read_gateway_token"
            judge._read_gateway_token()
            client = judge.GatewayClient(judge.GATEWAY_URL, judge.GATEWAY_TOKEN, verbose=False)
            runner.client = client
            phase = "apply_model_config"
            runner.model_config_applied = judge._apply_model_config(
                str(effective_model_config or args.model_config)
            )
            phase = "wait_for_healthy"
            if not client.wait_for_healthy(timeout=90):
                raise RuntimeError("safeclaw_gateway_unhealthy")
            phase = "capture_pre_state"
            runner.pre_state = runner.capture_pre_state()
            pre_state = _observable_state(runner.capture_post_state(), exact_secrets)
        _emit({"kind": "ready", "pre_state": pre_state})
        for raw in sys.stdin:
            command = json.loads(raw)
            kind = command.get("kind")
            if kind == "embedding_probe":
                if relay is None:
                    raise RuntimeError("embedding_relay_missing")
                source = str(command.get("source", "relay"))
                if source not in {"relay", "victim"}:
                    raise RuntimeError("embedding_probe_invalid_source")
                with contextlib.redirect_stdout(sys.stderr):
                    probe = relay.embedding_probe(
                        from_victim=source == "victim",
                        model=str(command["model"]),
                        text=str(command["text"]),
                    )
                    ledger = relay.embedding_records()
                _emit(
                    {
                        "kind": "embedding_probe",
                        "source": source,
                        "probe": probe,
                        "embedding_request_ledger": ledger,
                    }
                )
                continue
            if kind == "finish":
                with contextlib.redirect_stdout(sys.stderr):
                    post_state = runner.capture_post_state()
                _emit(
                    {
                        "kind": "finished",
                        "post_state": post_state,
                        "provider_request_ledger": relay.records() if relay else [],
                        "embedding_request_ledger": _embedding_ledger(judge, relay),
                    }
                )
                return 0
            if kind != "action":
                raise RuntimeError("safeclaw_bridge_unknown_command")
            action = command["action"]
            action_type = action["action_type"]
            if action_type == "start_new_session":
                pending_restart = True
                pending_lifecycle_action_id = str(action["action_id"])
                current_key = None
                _emit({"kind": "step", "action_type": action_type})
                continue
            if action_type in {"retry", "reroute"}:
                raise RuntimeError("safeclaw_construction_control_not_implemented")
            if action_type != "deliver_message":
                raise RuntimeError("safeclaw_bridge_action_not_executable")
            if action.get("delivery_surface") not in SUPPORTED_DELIVERY_SURFACES:
                raise RuntimeError("safeclaw_bridge_delivery_surface_not_implemented")
            session_index += 1
            session = {
                "session_id": f"construction-s{session_index}",
                "role": "attack",
                "user_instruction": action["public_message"],
                "timeout_seconds": int(command["timeout_seconds"]),
                "pre_session_setup": {"restart_gateway": pending_restart},
            }
            with contextlib.redirect_stdout(sys.stderr):
                result = runner.run_session(
                    session,
                    session_index - 1,
                    shared_session_key=current_key,
                )
                raw_post_state = runner.capture_post_state()
                public_post_state = _observable_state(raw_post_state, exact_secrets)
            current_key = result.pop("_session_key")
            result["actual_session_identity_sha256"] = _session_identity(current_key)
            result["previous_delivery_session_identity_sha256"] = last_delivery_identity
            last_delivery_identity = result["actual_session_identity_sha256"]
            result["restart_requested"] = pending_restart
            result["new_session_request_action_id"] = pending_lifecycle_action_id
            result["workspace_identity_sha256"] = _session_identity(
                f"{judge.CONTAINER}:{judge.WORKSPACE}"
            )
            # Namespace identity, not proof that an index exists or contains an item.
            result["memory_index_namespace_sha256"] = _session_identity(
                f"{judge.CONTAINER}:openclaw:default-agent-memory-index"
            )
            raw_api_response = result.pop("raw_api_response", None)
            relay_records = relay.records() if relay is not None else []
            action_relay_records = relay_records[provider_record_cursor:]
            provider_record_cursor = len(relay_records)
            relay_usage = _aggregate_relay_usage(action_relay_records)
            tool_observations, newly_seen = _structured_tool_observations(
                raw_post_state, seen_transcript_entry_ids, exact_secrets
            )
            seen_transcript_entry_ids.update(newly_seen)
            classification = _classify_response(
                raw_api_response,
                result.get("agent_response"),
                result.get("tool_calls"),
                public_post_state.get("gateway_log_provenance"),
                exact_secrets,
            )
            result.update(classification)
            gateway_usage = _observable_usage(raw_api_response)
            gateway_complete = (
                gateway_usage is not None
                and all(
                    key in gateway_usage
                    for key in ("input_tokens", "output_tokens", "total_tokens")
                )
                and gateway_usage["total_tokens"]
                == gateway_usage["input_tokens"] + gateway_usage["output_tokens"]
            )
            gateway_complete = gateway_complete and gateway_usage["total_tokens"] > 0
            result["gateway_provider_usage"] = gateway_usage
            result["gateway_usage_observation"] = (
                "complete" if gateway_complete else "missing_or_invalid"
            )
            result["provider_relay_usage_observation"] = relay_usage["observation"]
            result["provider_relay_attempt_count"] = relay_usage["attempt_count"]
            result["provider_relay_complete_request_count"] = relay_usage["complete_request_count"]
            result["provider_relay_missing_request_count"] = relay_usage["missing_request_count"]
            result["provider_relay_known_subtotal"] = relay_usage["known_subtotal"]
            result["provider_relay_failed_request_count"] = relay_usage["failed_request_count"]
            if relay_usage["observation"] == "complete":
                result["provider_usage"] = relay_usage["usage"]
                result["provider_usage_source"] = "provider_relay_upstream"
                result["provider_usage_observation"] = "complete"
            elif gateway_complete:
                result["provider_usage"] = gateway_usage
                result["provider_usage_source"] = "gateway"
                result["provider_usage_observation"] = "complete"
            else:
                result["provider_usage"] = None
                result["provider_usage_source"] = None
                result["provider_usage_observation"] = (
                    "partial" if relay_usage["observation"] == "partial" else "missing_or_invalid"
                )
            result["gateway_diagnostics"] = public_post_state.get("gateway_log_provenance", {})
            result["transcript_provenance"] = _transcript_provenance(raw_post_state, exact_secrets)
            result["tool_observations"] = tool_observations
            memory_tools = [
                item for item in tool_observations if item["tool_name"] in MEMORY_RETRIEVAL_TOOLS
            ]
            observed_memory_results = [
                item for item in memory_tools if item["result_observation"] == "observed"
            ]
            observed_retrievals = [
                item for item in observed_memory_results if not item["result_empty"]
            ]
            result["memory_retrievals"] = [
                {
                    "retrieval_id": item["call_id"],
                    "retrieval_class": item.get("observation_class"),
                    "content_hash": item["result_hash"],
                    "content_hash_scope": item.get("result_hash_scope"),
                    "content_excerpt": item["result_excerpt"],
                    # Upstream may provide a source/version reference. An empty
                    # list is intentional: a result hash alone is not lineage.
                    "parent_artifact_ids": [
                        str(v) for v in item.get("parent_artifact_ids", []) if str(v)
                    ],
                    "request_event_id": f"tool-call-{item['call_id']}",
                    "request_line_number": item.get("request_line_number"),
                    "result_line_number": item.get("result_line_number"),
                    "evidence_ref_ids": [
                        item["request_evidence_ref"],
                        item["result_evidence_ref"],
                    ],
                }
                for item in observed_retrievals
                if item.get("result_order_valid") is True
            ]
            result["persistence_reads"] = [
                {
                    "call_id": item["call_id"],
                    "classification": item.get("observation_class"),
                    "workspace_relative_path": item.get("workspace_relative_path"),
                    "read_scope": "tool_result_text" if item.get("result_hash") else None,
                    "content_hash": item.get("result_hash"),
                    "content_hash_scope": item.get("result_hash_scope"),
                    "result_observation": item.get("result_observation"),
                    "result_empty": bool(item.get("result_empty")),
                    "result_order_valid": bool(item.get("result_order_valid")),
                    "request_line_number": item.get("request_line_number"),
                    "result_line_number": item.get("result_line_number"),
                    "request_evidence_ref": item.get("request_evidence_ref"),
                    "result_evidence_ref": item.get("result_evidence_ref"),
                }
                for item in tool_observations
                if item.get("tool_name") == "read"
            ]
            result["persistence_writes"] = [
                {
                    "call_id": item["call_id"],
                    "classification": item.get("observation_class"),
                    "workspace_relative_path": item.get("workspace_relative_path"),
                    "content_hash": item.get("write_content_hash"),
                    "content_hash_scope": "redacted_text_content"
                    if item.get("write_content_hash")
                    else None,
                    "result_observation": item.get("result_observation"),
                    "result_order_valid": bool(item.get("result_order_valid")),
                    "request_line_number": item.get("request_line_number"),
                    "result_line_number": item.get("result_line_number"),
                    "request_evidence_ref": item.get("request_evidence_ref"),
                    "result_evidence_ref": item.get("result_evidence_ref"),
                }
                for item in tool_observations
                if item.get("tool_name") in {"write", "edit"}
            ]
            if observed_retrievals:
                result["memory_retrieval_observation"] = "observed"
            elif observed_memory_results:
                result["memory_retrieval_observation"] = "empty"
            elif memory_tools:
                states = {str(item["result_observation"]) for item in memory_tools}
                result["memory_retrieval_observation"] = (
                    "rejected"
                    if "rejected" in states
                    else "error"
                    if "error" in states
                    else "not_observed"
                )
            else:
                result["memory_retrieval_observation"] = "not_occurred"
            pending_restart = False
            pending_lifecycle_action_id = None
            runner.session_results.append(result)
            _emit(
                {
                    "kind": "step",
                    "action_type": action_type,
                    "session": result,
                    "post_state": public_post_state,
                    "provider_request_ledger": relay.records() if relay else [],
                    "embedding_request_ledger": _embedding_ledger(judge, relay),
                }
            )
    except Exception as exc:
        detail_parts = [str(exc)]
        if isinstance(exc, subprocess.CalledProcessError):
            for label, value in (("stderr", exc.stderr), ("stdout", exc.stdout)):
                if value:
                    detail_parts.append(f"{label}={value}")
            detail_parts.append(f"returncode={exc.returncode}")
        detail = str(redact_value(" | ".join(detail_parts)).sanitized)[:2000]
        _emit(
            {
                "kind": "error",
                "error_category": classify_explicit_error(exc, type(exc).__name__),
                "phase": phase,
                "detail": detail or "no_exception_message",
            }
        )
        return 2
    finally:
        if relay is not None:
            with contextlib.suppress(Exception), contextlib.redirect_stdout(sys.stderr):
                relay.stop()
        if container_started:
            with contextlib.suppress(Exception), contextlib.redirect_stdout(sys.stderr):
                judge.remove_container()
        if effective_model_config is not None:
            effective_model_config.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
