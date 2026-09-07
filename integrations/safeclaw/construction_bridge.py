#!/usr/bin/env python3
"""JSONL bridge for adaptive SafeClaw construction sessions.

This bridge intentionally never instantiates SafeClaw's Evaluator. The caller sees
only victim responses, tool calls, and state snapshots; official success checks
remain unavailable to the construction attacker.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from stac_attack_lab.environments.safeclaw.redaction import redact_value


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


def _observable_state(raw: dict[str, Any]) -> dict[str, Any]:
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
    gateway_log = str(raw.get("gateway_log") or "")
    if gateway_log:
        redacted_log = str(redact_value(gateway_log[-4000:]).sanitized)
        projected["gateway_log_provenance"] = {
            "content_hash": __import__("hashlib").sha256(redacted_log.encode()).hexdigest(),
            "line_count": len(redacted_log.splitlines()),
            "retrieval_marker_observed": any(
                marker in redacted_log.lower()
                for marker in ("memory search result", "memory_search_result", "memoryretrieval")
            ),
        }
    else:
        projected["gateway_log_provenance"] = {
            "content_hash": None,
            "line_count": 0,
            "retrieval_marker_observed": False,
        }
    return projected


def _nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return int(value)


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--model-config", required=True)
    args = parser.parse_args()
    upstream = Path(args.upstream).resolve()
    task_path = Path(args.task).resolve()
    task = json.loads(task_path.read_text(encoding="utf-8"))
    judge = _load_judge(upstream)
    judge._set_platform("openclaw")
    runner = None
    phase = "startup"
    current_key = None
    pending_restart = False
    session_index = 0
    try:
        with contextlib.redirect_stdout(sys.stderr):
            phase = "container_start"
            judge.start_container(judge.IMAGE)
            client = judge.GatewayClient(judge.GATEWAY_URL, judge.GATEWAY_TOKEN, verbose=False)
            runner = judge.TaskRunner(task, client, verbose=False)
            phase = "reset_environment"
            runner.reset_environment(str(task_path))
            phase = "read_gateway_token"
            judge._read_gateway_token()
            client = judge.GatewayClient(judge.GATEWAY_URL, judge.GATEWAY_TOKEN, verbose=False)
            runner.client = client
            phase = "apply_model_config"
            runner.model_config_applied = judge._apply_model_config(args.model_config)
            phase = "wait_for_healthy"
            if not client.wait_for_healthy(timeout=90):
                raise RuntimeError("safeclaw_gateway_unhealthy")
            phase = "capture_pre_state"
            runner.pre_state = runner.capture_pre_state()
            pre_state = _observable_state(runner.capture_post_state())
        _emit({"kind": "ready", "pre_state": pre_state})
        for raw in sys.stdin:
            command = json.loads(raw)
            kind = command.get("kind")
            if kind == "finish":
                with contextlib.redirect_stdout(sys.stderr):
                    post_state = runner.capture_post_state()
                _emit({"kind": "finished", "post_state": post_state})
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
                public_post_state = _observable_state(runner.capture_post_state())
            current_key = result.pop("_session_key")
            raw_api_response = result.pop("raw_api_response", None)
            result["provider_usage"] = _observable_usage(raw_api_response)
            transcript = str(public_post_state.get("session_transcript_raw") or "")
            redacted_transcript = str(redact_value(transcript[-4000:]).sanitized)
            result["transcript_provenance"] = {
                "content_hash": __import__("hashlib")
                .sha256(redacted_transcript.encode())
                .hexdigest(),
                "line_count": len(redacted_transcript.splitlines()),
                "tool_call_lines": sum(
                    line.startswith("TOOL_CALL:") for line in redacted_transcript.splitlines()
                ),
                "tool_result_lines": sum(
                    line.startswith("TOOL_RESULT:") for line in redacted_transcript.splitlines()
                ),
                "structured_lineage_available": False,
            }
            # The pinned upstream exposes assistant tool calls but no tool-result
            # stream. Preserve an explicit unknown status; never infer recall
            # from memory files or a memory-search request alone.
            result["memory_retrievals"] = []
            result["memory_retrieval_observation"] = "unknown"
            pending_restart = False
            runner.session_results.append(result)
            _emit(
                {
                    "kind": "step",
                    "action_type": action_type,
                    "session": result,
                    "post_state": public_post_state,
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
                "error_category": type(exc).__name__,
                "phase": phase,
                "detail": detail or "no_exception_message",
            }
        )
        return 2
    finally:
        if runner is not None:
            with contextlib.suppress(Exception), contextlib.redirect_stdout(sys.stderr):
                judge.remove_container()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
