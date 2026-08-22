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
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


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
    """Project state evidence without provider credentials or raw gateway logs."""
    keys = (
        "config_hash",
        "memory_content",
        "memory_root_content",
        "memory_dir_content",
        "sim_google_calls",
        "new_workspace_files",
        "workspace_file_contents",
    )
    return {key: raw.get(key) for key in keys}


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
    current_key = None
    pending_restart = False
    session_index = 0
    try:
        with contextlib.redirect_stdout(sys.stderr):
            judge.start_container(judge.IMAGE)
            client = judge.GatewayClient(judge.GATEWAY_URL, judge.GATEWAY_TOKEN, verbose=False)
            runner = judge.TaskRunner(task, client, verbose=False)
            runner.reset_environment(str(task_path))
            judge._read_gateway_token()
            client = judge.GatewayClient(judge.GATEWAY_URL, judge.GATEWAY_TOKEN, verbose=False)
            runner.client = client
            runner.model_config_applied = judge._apply_model_config(args.model_config)
            if not client.wait_for_healthy(timeout=90):
                raise RuntimeError("safeclaw_gateway_unhealthy")
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
            pending_restart = False
            result.pop("raw_api_response", None)
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
        _emit({"kind": "error", "error_category": type(exc).__name__})
        return 2
    finally:
        if runner is not None:
            with contextlib.suppress(Exception), contextlib.redirect_stdout(sys.stderr):
                judge.remove_container()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
