#!/usr/bin/env python3
"""Controlled JSONL bridge for formal SafeClaw action/observation execution."""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


def _load_judge(upstream: Path) -> ModuleType:
    path = upstream / "scripts/judge.py"
    spec = importlib.util.spec_from_file_location("safeclaw_formal_judge", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("safeclaw_judge_import_failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True) + "\n")
    sys.stdout.flush()


def _public_state(raw: dict[str, Any]) -> dict[str, Any]:
    memory = str(raw.get("memory_content", ""))
    workspace = raw.get("new_workspace_files", [])
    sim_calls = str(raw.get("sim_google_calls", ""))
    return {
        "memory_present": bool(memory),
        "memory_size": len(memory),
        "new_workspace_file_count": len(workspace) if isinstance(workspace, list) else 0,
        "simulated_external_call_count": len(
            [line for line in sim_calls.splitlines() if line.strip()]
        ),
    }


def _merge_session_result(
    by_session: dict[str, dict[str, Any]],
    result: dict[str, Any],
) -> None:
    session_id = str(result["session_id"])
    existing = by_session.get(session_id)
    if existing is None:
        by_session[session_id] = result
        return
    existing["user_instruction"] += "\n---\n" + str(result.get("user_instruction", ""))
    existing["agent_response"] += "\n---\n" + str(result.get("agent_response", ""))
    existing["tool_calls"].extend(result.get("tool_calls", []))
    existing["duration_seconds"] = round(
        float(existing.get("duration_seconds", 0)) + float(result.get("duration_seconds", 0)),
        1,
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
    sessions = {str(item["session_id"]): item for item in task["sessions"]}
    judge = _load_judge(upstream)
    judge._set_platform("openclaw")
    runner = None
    current_session_id: str | None = None
    session_keys: dict[str, str] = {}
    initialized_sessions: set[str] = set()
    session_results: dict[str, dict[str, Any]] = {}
    try:
        with contextlib.redirect_stdout(sys.stderr):
            judge.start_container(judge.IMAGE)
            client = judge.GatewayClient(judge.GATEWAY_URL, judge.GATEWAY_TOKEN, verbose=False)
            runner = judge.TaskRunner(task, client, verbose=False)
            runner.reset_environment(str(task_path))
            judge._read_gateway_token()
            client = judge.GatewayClient(judge.GATEWAY_URL, judge.GATEWAY_TOKEN, verbose=False)
            runner.client = client
            applied = judge._apply_model_config(args.model_config)
            runner.model_config_applied = {
                "model": applied.get("model"),
                "base_url_source": "environment",
            }
            if not client.wait_for_healthy(timeout=90):
                raise RuntimeError("safeclaw_gateway_not_healthy")
            pre_state = runner.capture_pre_state()
            runner.pre_state = pre_state
        _emit({"kind": "ready", "public_pre_state": _public_state(pre_state)})
        for raw in sys.stdin:
            command = json.loads(raw)
            kind = command.get("kind")
            if kind == "finish":
                with contextlib.redirect_stdout(sys.stderr):
                    post_state = runner.capture_post_state()
                    ordered_results = [
                        session_results[session_id]
                        for session_id in sessions
                        if session_id in session_results
                    ]
                    evaluator = judge.Evaluator(
                        task,
                        ordered_results,
                        pre_state,
                        post_state,
                        verbose=False,
                    )
                    report = evaluator.generate_report()
                    report["model_config_override"] = runner.model_config_applied
                _emit(
                    {
                        "kind": "finished",
                        "official_report": report,
                        "public_post_state": _public_state(post_state),
                    }
                )
                return 0
            if kind != "action":
                raise RuntimeError("safeclaw_formal_bridge_unknown_command")
            action = command["action"]
            session_id = str(action["benchmark_session_id"])
            if session_id not in sessions:
                raise RuntimeError("safeclaw_formal_bridge_unknown_session")
            action_type = str(action["action_type"])
            before = _public_state(runner.capture_post_state())
            if action_type == "session_transition":
                current_session_id = session_id
                initialized_sessions.discard(session_id)
                _emit(
                    {
                        "kind": "step",
                        "action_type": action_type,
                        "benchmark_session_id": session_id,
                        "agent_response": "",
                        "tool_calls": [],
                        "provider_usage": None,
                        "public_state_before": before,
                        "public_state_after": before,
                    }
                )
                continue
            if action_type not in {"victim_message", "tool_surface"}:
                raise RuntimeError("safeclaw_formal_bridge_action_not_executable")
            template = sessions[session_id]
            first_in_session = session_id not in initialized_sessions
            session = {
                "session_id": session_id,
                "role": template.get("role", "attack"),
                "agent_id": template.get("agent_id", "main"),
                "user_instruction": action["victim_visible_content"],
                "timeout_seconds": min(
                    int(command["timeout_seconds"]),
                    int(template.get("timeout_seconds", command["timeout_seconds"])),
                ),
                "pre_session_setup": template.get("pre_session_setup", {})
                if first_in_session
                else {},
                "follow_up_messages": [],
            }
            shared_key = None
            if current_session_id == session_id:
                shared_key = session_keys.get(session_id)
            with contextlib.redirect_stdout(sys.stderr):
                result = runner.run_session(
                    session,
                    len(initialized_sessions),
                    shared_session_key=shared_key,
                )
                after_raw = runner.capture_post_state()
            current_session_id = session_id
            initialized_sessions.add(session_id)
            session_keys[session_id] = result.pop("_session_key")
            raw_api_response = result.pop("raw_api_response", {})
            provider_usage = (
                raw_api_response.get("usage") if isinstance(raw_api_response, dict) else None
            )
            _merge_session_result(session_results, result)
            _emit(
                {
                    "kind": "step",
                    "action_type": action_type,
                    "benchmark_session_id": session_id,
                    "agent_response": result.get("agent_response", ""),
                    "tool_calls": result.get("tool_calls", []),
                    "provider_usage": provider_usage,
                    "public_state_before": before,
                    "public_state_after": _public_state(after_raw),
                }
            )
    except Exception as exc:
        _emit({"kind": "error", "error_category": type(exc).__name__})
        return 2
    finally:
        if runner is not None:
            with contextlib.suppress(Exception), contextlib.redirect_stdout(sys.stderr):
                judge.remove_container()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
