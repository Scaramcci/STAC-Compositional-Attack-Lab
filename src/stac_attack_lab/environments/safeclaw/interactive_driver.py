from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from pydantic import Field

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.environments.safeclaw.materializer import MaterializedTask
from stac_attack_lab.environments.safeclaw.model_config import (
    SafeClawEmbeddingRuntime,
    build_safeclaw_model_config,
)
from stac_attack_lab.environments.safeclaw.redaction import redact_value, scan_for_secrets
from stac_attack_lab.execution.formal_attacker import (
    FormalAttackerStageAction,
    FormalVictimObservation,
)
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.recording.events import append_jsonl, read_jsonl


class SafeClawInteractiveFinish(StrictModel):
    official_report: dict[str, Any]
    public_post_state: dict[str, Any]
    provider_usage_records: list[dict[str, Any]] = Field(default_factory=list)


class SafeClawInteractiveVictimDriver:
    """Executes validated actions through pinned TaskRunner.run_session calls."""

    driver_id = "safeclaw_formal_interactive_v1"

    def __init__(
        self,
        *,
        upstream_root: Path,
        safety_patch: Path,
        bridge_path: Path,
        case_root: Path,
        target_model_id: str,
        target_base_url: str,
        target_api_key_env: str,
        embedding: SafeClawEmbeddingRuntime | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.upstream_root = upstream_root
        self.safety_patch = safety_patch
        self.bridge_path = bridge_path
        self.case_root = case_root
        self.target_model_id = target_model_id
        self.target_base_url = target_base_url
        self.target_api_key_env = target_api_key_env
        self.embedding = embedding
        self.environment = environment if environment is not None else os.environ
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._process: subprocess.Popen[str] | None = None
        self._exact_secrets: list[str] = []
        self._provider_usage_records: list[dict[str, Any]] = []
        self.attempt_id = "attempt-001"
        self.journal_path = case_root / "formal_action_journal.jsonl"

    def prepare_attempt(self, attempt_id: str) -> None:
        if self._process is not None:
            raise RuntimeError("safeclaw_formal_attempt_already_started")
        if not attempt_id.startswith("attempt-") or not attempt_id[8:].isdigit():
            raise ValueError(f"safeclaw_formal_attempt_id_invalid:{attempt_id}")
        self.attempt_id = attempt_id
        self.journal_path = self.case_root / "attempts" / attempt_id / "formal_action_journal.jsonl"

    @property
    def canonical_trajectory_ref(self) -> str:
        return str(self.journal_path.relative_to(self.case_root))

    def _read_bridge(self) -> dict[str, Any]:
        if self._process is None or self._process.stdout is None:
            raise RuntimeError("safeclaw_formal_bridge_not_started")
        raw = self._process.stdout.readline()
        if not raw:
            raise RuntimeError("safeclaw_formal_bridge_closed")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise RuntimeError("safeclaw_formal_bridge_invalid_response")
        if value.get("kind") == "error":
            raise RuntimeError(str(value.get("error_category", "bridge_error")))
        sanitized = redact_value(value, self._exact_secrets).sanitized
        if not isinstance(sanitized, dict):
            raise RuntimeError("safeclaw_formal_bridge_sanitization_failed")
        return cast(dict[str, Any], sanitized)

    def _send_bridge(self, value: dict[str, Any]) -> dict[str, Any]:
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("safeclaw_formal_bridge_not_started")
        self._process.stdin.write(json.dumps(value, sort_keys=True) + "\n")
        self._process.stdin.flush()
        return self._read_bridge()

    def _existing_observation(self, action_id: str) -> FormalVictimObservation | None:
        records = read_jsonl(self.journal_path)
        request_count = sum(
            item.get("kind") == "victim_request" and item.get("attacker_action_id") == action_id
            for item in records
        )
        responses = [
            item
            for item in records
            if item.get("kind") == "victim_response" and item.get("attacker_action_id") == action_id
        ]
        if request_count and not responses:
            raise ValueError(f"interactive_resume_inflight_action:{action_id}")
        if len(responses) > 1 or request_count > 1:
            raise ValueError(f"interactive_duplicate_action_journal:{action_id}")
        if responses:
            return FormalVictimObservation.model_validate(responses[0]["observation"])
        return None

    def start(self, materialized_task: MaterializedTask) -> dict[str, Any]:
        if self._process is not None:
            raise RuntimeError("safeclaw_formal_driver_already_started")
        model_config_payload, self._exact_secrets = build_safeclaw_model_config(
            target_model_id=self.target_model_id,
            target_base_url=self.target_base_url,
            target_api_key_env=self.target_api_key_env,
            environment=self.environment,
            embedding=self.embedding,
        )
        self.case_root.mkdir(parents=True, exist_ok=True)
        records = read_jsonl(self.journal_path)
        if records:
            raise ValueError(f"interactive_attempt_journal_not_empty:{self.attempt_id}")
        self._temporary = tempfile.TemporaryDirectory(prefix="safeclaw-formal-interactive-")
        temporary_root = Path(self._temporary.name)
        patched_upstream = temporary_root / "SafeClawArena"
        shutil.copytree(self.upstream_root, patched_upstream)
        check = subprocess.run(
            ["git", "apply", "--unidiff-zero", "--check", str(self.safety_patch)],
            cwd=patched_upstream,
            text=True,
            capture_output=True,
            check=False,
        )
        if check.returncode != 0:
            raise ValueError("safeclaw_formal_patch_check_failed")
        applied = subprocess.run(
            ["git", "apply", "--unidiff-zero", str(self.safety_patch)],
            cwd=patched_upstream,
            text=True,
            capture_output=True,
            check=False,
        )
        if applied.returncode != 0:
            raise ValueError("safeclaw_formal_patch_apply_failed")
        task_path = temporary_root / "materialized-task.json"
        shutil.copy2(materialized_task.path, task_path)
        model_config = temporary_root / "model-config.json"
        model_config.write_text(
            json.dumps(model_config_payload, sort_keys=True),
            encoding="utf-8",
        )
        os.chmod(model_config, 0o600)
        self._process = subprocess.Popen(
            [
                sys.executable,
                str(self.bridge_path),
                "--upstream",
                str(patched_upstream),
                "--task",
                str(task_path),
                "--model-config",
                str(model_config),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        ready = self._read_bridge()
        if ready.get("kind") != "ready":
            raise RuntimeError("safeclaw_formal_bridge_not_ready")
        return cast(dict[str, Any], ready.get("public_pre_state", {}))

    def apply(
        self,
        action: FormalAttackerStageAction,
        *,
        timeout_seconds: int,
    ) -> FormalVictimObservation:
        action_id = action.attacker_action_id
        if action_id is None:
            raise ValueError("formal_action_missing_canonical_id")
        existing = self._existing_observation(action_id)
        if existing is not None:
            return existing
        request_event_id = (
            "victim-request-"
            + stable_hash({"action_id": action_id, "stage_id": action.stage_id})[:20]
        )
        response_event_id = "victim-response-" + stable_hash(request_event_id)[:20]
        append_jsonl(
            self.journal_path,
            {
                "kind": "victim_request",
                "plan_id": action.plan_id,
                "plan_stage_id": action.stage_id,
                "attacker_call_id": action.attacker_call_id,
                "attacker_action_id": action_id,
                "victim_request_event_id": request_event_id,
                "action": action.model_dump(mode="json"),
            },
        )
        response = self._send_bridge(
            {
                "kind": "action",
                "action": action.model_dump(mode="json"),
                "timeout_seconds": timeout_seconds,
            }
        )
        if response.get("kind") != "step":
            raise RuntimeError("safeclaw_formal_bridge_invalid_step")
        tool_calls = response.get("tool_calls", [])
        if not isinstance(tool_calls, list):
            raise RuntimeError("safeclaw_formal_bridge_invalid_tool_calls")
        tool_event_ids = [
            "victim-tool-" + stable_hash({"request": request_event_id, "index": index})[:20]
            for index, _ in enumerate(tool_calls)
        ]
        before = cast(dict[str, Any], response.get("public_state_before", {}))
        after = cast(dict[str, Any], response.get("public_state_after", {}))
        changed_state = {
            key: {"before": before.get(key), "after": after.get(key)}
            for key in sorted(set(before) | set(after))
            if before.get(key) != after.get(key)
        }
        output_state_refs = [
            f"public_state:{key}:{stable_hash(value)[:16]}" for key, value in changed_state.items()
        ] or [f"public_state:unchanged:{stable_hash(after)[:16]}"]
        observation_payload = {
            "schema_version": "1.0",
            "observation_id": "observation-" + stable_hash(response_event_id)[:20],
            "plan_id": action.plan_id,
            "plan_stage_id": action.stage_id,
            "attacker_call_id": action.attacker_call_id,
            "attacker_action_id": action_id,
            "victim_request_event_id": request_event_id,
            "victim_response_event_id": response_event_id,
            "tool_event_ids": tool_event_ids,
            "input_artifact_refs": [f"public_slot:{item}" for item in action.public_slot_refs],
            "input_state_refs": [f"plan_stage:{action.stage_id}:input"],
            "output_artifact_refs": [
                f"victim_response:{response_event_id}",
                *[f"tool_event:{item}" for item in tool_event_ids],
            ],
            "output_state_refs": output_state_refs,
            "verifier_evidence_refs": [f"safeclaw_bridge:{response_event_id}"],
            "benchmark_session_id": action.benchmark_session_id,
            "public_response_text": str(response.get("agent_response", "")),
            "public_tool_calls": tool_calls,
            "public_state_delta": changed_state,
            "status": "completed",
        }
        observation = FormalVictimObservation.model_validate(
            {
                **observation_payload,
                "observation_hash": stable_hash(observation_payload),
            }
        )
        usage = response.get("provider_usage")
        if isinstance(usage, dict):
            self._provider_usage_records.append(cast(dict[str, Any], usage))
        response_record = {
            "kind": "victim_response",
            "plan_id": action.plan_id,
            "plan_stage_id": action.stage_id,
            "attacker_call_id": action.attacker_call_id,
            "attacker_action_id": action_id,
            "victim_request_event_id": request_event_id,
            "victim_response_event_id": response_event_id,
            "tool_event_ids": tool_event_ids,
            "observation": observation.model_dump(mode="json"),
            "provider_usage": usage if isinstance(usage, dict) else None,
        }
        if scan_for_secrets(response_record, self._exact_secrets):
            raise ValueError("safeclaw_formal_action_record_secret_gate_failed")
        append_jsonl(self.journal_path, response_record)
        return observation

    def finish(self) -> SafeClawInteractiveFinish:
        try:
            response = self._send_bridge({"kind": "finish"})
            if response.get("kind") != "finished":
                raise RuntimeError("safeclaw_formal_bridge_invalid_finish")
            report = response.get("official_report")
            post_state = response.get("public_post_state")
            if not isinstance(report, dict) or not isinstance(post_state, dict):
                raise RuntimeError("safeclaw_formal_bridge_finish_shape_invalid")
            if scan_for_secrets(report, self._exact_secrets):
                raise ValueError("safeclaw_formal_official_report_secret_gate_failed")
            if self._process is not None:
                self._process.wait(timeout=30)
            return SafeClawInteractiveFinish(
                official_report=cast(dict[str, Any], report),
                public_post_state=cast(dict[str, Any], post_state),
                provider_usage_records=self._provider_usage_records,
            )
        finally:
            self._cleanup()

    def abort(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        self._cleanup()

    def _cleanup(self) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
        self._process = None
        self._temporary = None
