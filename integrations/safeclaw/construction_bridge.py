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
                    "request_evidence_ref": f"openclaw-session-entry:{entry_id}",
                }
        if message.get("role") in {"toolResult", "tool"}:
            call_id = str(message.get("toolCallId") or message.get("toolUseId") or "")
            if not call_id:
                continue
            result_text = str(redact_value(_text_content(content), exact_secrets or []).sanitized)
            is_error = bool(message.get("isError"))
            lowered = result_text.lower()
            parsed_result: Any = None
            try:
                parsed_result = json.loads(result_text)
            except json.JSONDecodeError:
                pass
            semantic_error = isinstance(parsed_result, dict) and (
                bool(parsed_result.get("error"))
                or parsed_result.get("unavailable") is True
                or parsed_result.get("disabled") is True
            )
            observed_empty = (
                str(message.get("toolName") or "") == "memory_search"
                and isinstance(parsed_result, dict)
                and parsed_result.get("results") == []
                and not semantic_error
            )
            observation = (
                "rejected"
                if is_error
                and any(marker in lowered for marker in ("denied", "not allowed", "forbidden"))
                else "error"
                if is_error or semantic_error
                else "not_occurred"
                if observed_empty
                else "observed"
            )
            results[call_id] = {
                "tool_name": str(message.get("toolName") or ""),
                "result_observation": observation,
                "result_hash": hashlib.sha256(result_text.encode()).hexdigest(),
                "result_excerpt": result_text[:2000],
                "result_evidence_ref": f"openclaw-session-entry:{entry_id}",
            }
    projected = []
    for call_id, call in calls.items():
        result = results.get(call_id)
        projected.append(
            {
                **call,
                "result_observation": (result["result_observation"] if result else "not_observed"),
                "result_hash": result.get("result_hash") if result else None,
                "result_excerpt": (
                    result.get("result_excerpt")
                    if result and call["tool_name"] in MEMORY_RETRIEVAL_TOOLS
                    else None
                ),
                "result_evidence_ref": (result.get("result_evidence_ref") if result else None),
            }
        )
    return projected, observed_ids


def _embedding_ledger(judge: ModuleType) -> list[dict[str, Any]]:
    raw = judge.dexec_output("cat /tmp/stac-embedding-ledger.jsonl 2>/dev/null")
    records: list[dict[str, Any]] = []
    for line in str(raw or "").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--model-config", required=True)
    args = parser.parse_args()
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
    session_index = 0
    seen_transcript_entry_ids: set[str] = set()
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
            if kind == "finish":
                with contextlib.redirect_stdout(sys.stderr):
                    post_state = runner.capture_post_state()
                _emit(
                    {
                        "kind": "finished",
                        "post_state": post_state,
                        "provider_request_ledger": relay.records() if relay else [],
                        "embedding_request_ledger": _embedding_ledger(judge),
                    }
                )
                return 0
            if kind != "action":
                raise RuntimeError("safeclaw_bridge_unknown_command")
            action = command["action"]
            action_type = action["action_type"]
            if action_type == "start_new_session":
                pending_restart = True
                current_key = None
                _emit({"kind": "step", "action_type": action_type})
                continue
            if action_type in {"retry", "reroute"}:
                _emit({"kind": "step", "action_type": action_type})
                continue
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
            raw_api_response = result.pop("raw_api_response", None)
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
            usage = _observable_usage(raw_api_response)
            if usage is not None and any(value > 0 for value in usage.values()):
                result["provider_usage"] = usage
                result["provider_usage_observation"] = "reported_nonzero"
            else:
                result["provider_usage"] = None
                result["provider_usage_observation"] = "gateway_zero_or_missing_unverified"
            result["gateway_diagnostics"] = public_post_state.get("gateway_log_provenance", {})
            result["transcript_provenance"] = _transcript_provenance(raw_post_state, exact_secrets)
            result["tool_observations"] = tool_observations
            memory_tools = [
                item for item in tool_observations if item["tool_name"] in MEMORY_RETRIEVAL_TOOLS
            ]
            observed_retrievals = [
                item for item in memory_tools if item["result_observation"] == "observed"
            ]
            result["memory_retrievals"] = [
                {
                    "retrieval_id": item["call_id"],
                    "content_hash": item["result_hash"],
                    "content_excerpt": item["result_excerpt"],
                    "parent_artifact_ids": [],
                    "request_event_id": f"tool-call-{item['call_id']}",
                    "evidence_ref_ids": [
                        item["request_evidence_ref"],
                        item["result_evidence_ref"],
                    ],
                }
                for item in observed_retrievals
            ]
            if observed_retrievals:
                result["memory_retrieval_observation"] = "observed"
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
            runner.session_results.append(result)
            _emit(
                {
                    "kind": "step",
                    "action_type": action_type,
                    "session": result,
                    "post_state": public_post_state,
                    "provider_request_ledger": relay.records() if relay else [],
                    "embedding_request_ledger": _embedding_ledger(judge),
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
