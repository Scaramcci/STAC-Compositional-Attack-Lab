#!/usr/bin/env python3
"""Exercise F5 through the production OpenClaw bridge with a local fake provider."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from run_local_fake_runtime import _docker, _owned_resources, _response

from stac_attack_lab.capability.evidence import verify_episode_evidence
from stac_attack_lab.capability.f5_repeats import prepare_f5_repeats, report_f5_repeats
from stac_attack_lab.capability.m3_f5 import (
    BACKUP,
    LEDGER,
    NOTE,
    PRIMARY,
    F5Task,
    assess_f5_acceptance,
    f5_comparison_gate,
    prepare_m3_f5,
    run_f5_with_driver,
    verify_f5_evidence,
)
from stac_attack_lab.diagnostics.openclaw_mock import MockProviderServer, MockResponse
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.base import CollectionBudget
from stac_attack_lab.interactions.safeclaw_collection import (
    SafeClawConstructionTask,
    SafeClawSubprocessVictimDriver,
)


def _tool(call_id: str, name: str, arguments: dict[str, str]) -> dict[str, Any]:
    return {
        "finish_reason": "tool_calls",
        "message": {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(arguments)},
                }
            ],
        },
    }


def _choices(scenario: str) -> list[dict[str, Any]]:
    report = json.dumps({"decision": "hold", "source": LEDGER}) + "\n"
    choices = [
        _tool(f"{scenario}-initial", "read", {"path": LEDGER}),
        _tool(f"{scenario}-supplier", "read", {"path": NOTE}),
        _tool(f"{scenario}-primary", "write", {"path": PRIMARY, "content": report}),
        _tool(f"{scenario}-recheck", "read", {"path": LEDGER}),
        _tool(f"{scenario}-backup", "write", {"path": BACKUP, "content": report}),
    ]
    if scenario == "ambiguous_commit":
        choices.append(_tool(f"{scenario}-overwrite", "write", {"path": BACKUP, "content": report}))
    if scenario == "missing_pre_with_post":
        choices = choices[:3] + choices[4:]
    if scenario != "no_post_read":
        choices.append(_tool(f"{scenario}-post", "read", {"path": LEDGER}))
    choices.append(
        {"finish_reason": "stop", "message": {"role": "assistant", "content": "Report complete."}}
    )
    return choices


def _responder(choices: list[dict[str, Any]]) -> Any:
    def respond(payload: dict[str, Any] | None, index: int) -> MockResponse:
        if index >= len(choices):
            return MockResponse.json({"error": {"message": "fake responses exhausted"}}, status=500)
        if index and not any(
            isinstance(item, dict) and item.get("role") == "tool"
            for item in (payload or {}).get("messages", [])
        ):
            return MockResponse.json({"error": {"message": "tool result missing"}}, status=409)
        streamed = bool((payload or {}).get("stream"))
        response = _response(choices[index], index + 1, stream=streamed)
        if not streamed:
            return response
        terminator = b"data: [DONE]\n\n"
        if not response.body.endswith(terminator):
            raise ValueError("fake_sse_terminator_missing")
        usage = {
            "choices": [],
            "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
        }
        body = (
            response.body[: -len(terminator)]
            + b"data: "
            + json.dumps(usage, separators=(",", ":")).encode("utf-8")
            + b"\n\n"
            + terminator
        )
        return MockResponse(body=body, content_type="text/event-stream")

    return respond


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--repeat-plan", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError("f5_fake_output_exists")
    gateway = _docker(
        "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"
    )
    baseline = _owned_resources()
    output.mkdir(parents=True, mode=0o700)
    if args.repeat_plan:
        plan_root = output / "repeat-plan"
        prepare_f5_repeats(root, root / "configs/capability/m3b_f5_repeat.disabled.json", plan_root)
        prepared = plan_root / "r01"
    else:
        prepared = output / "prepared-synthetic"
        prepare_m3_f5(root, root / "configs/capability/m3b_f5_v1_2.disabled.json", prepared)
    item = json.loads((prepared / "manifest.json").read_text())["units"][0]
    task = F5Task.model_validate_json((prepared / item["task_ref"]).read_text())
    materialized = prepared / item["materialized_ref"]
    runtime_task = SafeClawConstructionTask(
        source_task_id=task.task_id,
        source_split="synthetic",
        template_path=str(materialized.relative_to(root)),
        template_hash=file_hash(materialized),
        public_summary="Synthetic F5 recovery task.",
        public_component_inventory={"workspace_resource": [LEDGER, BACKUP, PRIMARY]},
        public_capabilities=["read", "write"],
        allowed_delivery_surfaces=["safeclaw_user_message"],
    )
    summary: dict[str, Any] = {
        "provider_kind": "local_fake_http",
        "real_model_requests": 0,
        "gateway_sha256": stable_hash(gateway),
        "baseline_owned_resources": baseline,
        "cases": {},
    }
    try:
        for scenario in ("complete", "ambiguous_commit", "no_post_read", "missing_pre_with_post"):
            choices = _choices(scenario)
            batch_id = f"f5-local-fake-{scenario}"
            with MockProviderServer(
                [],
                max_requests=len(choices),
                bind_host="0.0.0.0",
                advertised_host=gateway,
                responder=_responder(choices),
            ) as provider:
                driver = SafeClawSubprocessVictimDriver(
                    project_root=root,
                    upstream_root=root / "integrations/safeclaw/upstream/SafeClawArena",
                    safety_patch=root / "integrations/safeclaw/patches/a11f5cce-safety.patch",
                    bridge_path=root / "integrations/safeclaw/construction_bridge.py",
                    target_model_id="stac-local-fake",
                    target_base_url=provider.url,
                    target_api_key_env="STAC_F5_LOCAL_FAKE_KEY",
                    embedding=None,
                    model_hash=stable_hash("stac-local-fake"),
                    provider_request_budget=len(choices),
                    provider_timeout_seconds=10,
                    provider_max_output_tokens=4096,
                    provider_allowed_tools=["read", "write"],
                    embedding_request_budget=0,
                    environment={"STAC_F5_LOCAL_FAKE_KEY": "synthetic-local-only"},
                    batch_id=batch_id,
                )
                case_dir = (
                    prepared / "results/benign"
                    if args.repeat_plan and scenario == "complete"
                    else output / "cases" / scenario
                )
                result = run_f5_with_driver(
                    task,
                    driver,
                    runtime_task,
                    case_dir,
                    batch_id=batch_id,
                    budget=CollectionBudget(
                        max_sessions=1,
                        max_turns=1,
                        max_actions=1,
                        max_tool_calls=8,
                        max_tokens=60000,
                        max_wall_time_seconds=600,
                        max_events=200,
                        timeout_seconds=90,
                    ),
                )
                fake_requests = provider.state.request_count
            verify_episode_evidence(case_dir)
            original = result["evidence"]
            recomputed = verify_f5_evidence(
                _read_jsonl(case_dir / "runtime_events.jsonl"),
                _read_jsonl(case_dir / "provider_boundary_evidence.jsonl"),
                json.loads((case_dir / "checkpoints/initial.json").read_text()),
                json.loads((case_dir / "checkpoints/final.json").read_text()),
            )
            if original != recomputed:
                raise AssertionError(f"{scenario}: verifier replay differs")
            expected = {
                "complete": ("observed", True, "observed"),
                "ambiguous_commit": ("unknown", False, "unknown"),
                "no_post_read": ("observed", True, "unknown"),
                "missing_pre_with_post": ("observed", True, "observed"),
            }[scenario]
            actual = (
                original["recover"],
                original["backup_committed"],
                original["constraint_recheck"],
            )
            acceptance = assess_f5_acceptance(
                original,
                execution_status=result["execution_status"],
                cleanup_status=result["runtime_review"]["cleanup_status"],
                tool_trace_complete=result["runtime_review"]["tool_trace_complete"],
            )
            gate = f5_comparison_gate(acceptance)
            summary["cases"][scenario] = {
                "execution_status": result["execution_status"],
                "cleanup_status": result["runtime_review"]["cleanup_status"],
                "fake_requests": fake_requests,
                "observed_tool_calls": result["runtime_review"]["observed_tool_calls"],
                "actual": actual,
                "expected": expected,
                "aggregate": acceptance["aggregate"],
                "comparison_gate": gate,
                "acceptance": (
                    result["execution_status"] == "completed"
                    and result["runtime_review"]["cleanup_status"] == "completed"
                    and fake_requests == len(choices)
                    and actual == expected
                    and gate["admitted"] == (scenario == "complete")
                ),
            }
    finally:
        summary["final_owned_resources"] = _owned_resources()
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if summary["baseline_owned_resources"] != summary["final_owned_resources"]:
        raise AssertionError("owned Docker resources changed")
    if not all(case["acceptance"] for case in summary["cases"].values()):
        raise AssertionError("F5 local fake acceptance failed")
    if args.repeat_plan:
        report_f5_repeats(root, plan_root, output / "repeat_report.json")
        repeat = json.loads((output / "repeat_report.json").read_text())
        if (repeat["denominator"], repeat["completed"], repeat["not_started"]) != (9, 1, 8):
            raise AssertionError("F5 repeat fake report denominator mismatch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
