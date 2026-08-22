from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import IO, Any, Literal, Protocol, cast

from pydantic import Field, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.base import (
    CollectedInteraction,
    CollectionBudget,
    SourceInteractionTask,
)
from stac_attack_lab.interactions.construction import (
    ConstructionAttacker,
    ConstructionAttackerAction,
    ConstructionObservation,
)
from stac_attack_lab.interactions.models import (
    ConstructionManifest,
    InteractionGraph,
    RawInteractionTrajectory,
)
from stac_attack_lab.interactions.normalizer import normalize_source_events


class SafeClawConstructionTask(StrictModel):
    source_task_id: str
    source_split: Literal["train", "dev", "synthetic"]
    template_path: str
    template_hash: str
    public_summary: str
    public_component_inventory: dict[str, list[str]]
    public_capabilities: list[str]
    allowed_delivery_surfaces: list[str]
    legal_retry_ids: list[str] = Field(default_factory=list)
    legal_reroute_ids: list[str] = Field(default_factory=list)


class SafeClawConstructionTaskSet(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    task_set_id: str
    upstream_commit: str
    environment_version: str
    formal_excluded_task_ids: list[str]
    tasks: list[SafeClawConstructionTask]

    @model_validator(mode="after")
    def validate_split(self) -> SafeClawConstructionTaskSet:
        ids = [task.source_task_id for task in self.tasks]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate_construction_task_id")
        overlap = set(ids) & set(self.formal_excluded_task_ids)
        if overlap:
            raise ValueError("construction_formal_task_overlap:" + ",".join(sorted(overlap)))
        return self


class ConstructionVictimStep(StrictModel):
    session_id: str
    source_events: list[dict[str, Any]]
    checkpoints: list[dict[str, Any]] = Field(default_factory=list)
    public_transcript_events: list[dict[str, str]] = Field(default_factory=list)
    public_stage_status: dict[str, str] = Field(default_factory=dict)
    status: Literal["complete", "partial", "blocked", "error"] = "complete"
    failure_category: str | None = None


class ConstructionVictimResult(StrictModel):
    episode_id: str
    source_events: list[dict[str, Any]] = Field(default_factory=list)
    checkpoints: list[dict[str, Any]] = Field(default_factory=list)
    model_hashes: dict[str, str]
    config_hash: str
    status: Literal["complete", "partial", "blocked", "error"]
    failure_category: str | None = None
    provenance: dict[str, str]


class ConstructionVictimDriver(Protocol):
    driver_id: str

    def start(
        self,
        task: SafeClawConstructionTask,
        *,
        seed: int,
        budget: CollectionBudget,
    ) -> ConstructionObservation: ...

    def apply(self, action: ConstructionAttackerAction) -> ConstructionVictimStep: ...

    def finish(self) -> ConstructionVictimResult: ...

    def abort(self) -> None: ...


class SafeClawConstructionInteractionAdapter:
    """Adaptive collection over a complete, stateful SafeClaw-style victim driver."""

    adapter_id = "safeclaw_adaptive_construction"
    adapter_version = "1.0.0"

    def __init__(
        self,
        *,
        project_root: Path,
        task_set_path: Path,
        driver: ConstructionVictimDriver,
    ) -> None:
        self.project_root = project_root
        self.task_set_path = task_set_path
        self.task_set = SafeClawConstructionTaskSet.model_validate_json(
            task_set_path.read_text(encoding="utf-8")
        )
        self.driver = driver
        self.environment_version = self.task_set.environment_version
        self._tasks = {task.source_task_id: task for task in self.task_set.tasks}
        for task in self.task_set.tasks:
            template = project_root / task.template_path
            if not template.is_file() or file_hash(template) != task.template_hash:
                raise ValueError(f"construction_template_hash_mismatch:{task.source_task_id}")

    def inventory(self) -> list[SourceInteractionTask]:
        return [
            SourceInteractionTask(
                source_task_id=task.source_task_id,
                source_split=task.source_split,
                public_summary=task.public_summary,
                environment_family="safeclaw_openclaw",
                metadata={
                    "task_set_id": self.task_set.task_set_id,
                    "upstream_commit": self.task_set.upstream_commit,
                },
            )
            for task in self.task_set.tasks
        ]

    def collect(
        self, task: SourceInteractionTask, *, seed: int, budget: CollectionBudget
    ) -> CollectedInteraction:
        del task, seed, budget
        raise ValueError("safeclaw_construction_requires_explicit_attacker")

    def collect_adversarial(
        self,
        task: SourceInteractionTask,
        manifest: ConstructionManifest,
        attacker: ConstructionAttacker,
        *,
        seed: int,
        budget: CollectionBudget,
    ) -> CollectedInteraction:
        configured = self._tasks[task.source_task_id]
        if not set(manifest.allowed_delivery_surfaces) <= set(
            configured.allowed_delivery_surfaces
        ):
            raise ValueError("construction_manifest_surface_not_supported")
        observation = self.driver.start(configured, seed=seed, budget=budget)
        all_events: list[dict[str, Any]] = []
        all_checkpoints: list[dict[str, Any]] = []
        session_ids: list[str] = []
        last_status: Literal["complete", "partial", "blocked", "error"] = "partial"
        last_failure: str | None = None
        try:
            for _ in range(budget.max_sessions):
                if observation.remaining_events <= 0:
                    last_failure = "construction_event_budget_exhausted"
                    break
                action = attacker.next_action(task, manifest, observation, seed=seed)
                if action.action_type == "stop":
                    break
                step = self.driver.apply(action)
                session_ids.append(step.session_id)
                all_events.extend(step.source_events)
                all_checkpoints.extend(step.checkpoints)
                last_status = step.status
                last_failure = step.failure_category
                if len(all_events) > budget.max_events:
                    raise ValueError("construction_event_budget_exceeded")
                observation = observation.model_copy(
                    update={
                        "session_index": observation.session_index + 1,
                        "public_transcript": [
                            *observation.public_transcript,
                            *step.public_transcript_events,
                        ],
                        "public_stage_status": step.public_stage_status,
                        "remaining_sessions": max(observation.remaining_sessions - 1, 0),
                        "remaining_events": budget.max_events - len(all_events),
                    }
                )
                if step.status in {"blocked", "error"}:
                    break
            result = self.driver.finish()
        except Exception:
            self.driver.abort()
            raise
        all_events.extend(result.source_events)
        all_checkpoints.extend(result.checkpoints)
        if len(all_events) > budget.max_events:
            raise ValueError("construction_final_event_budget_exceeded")
        final_status = result.status if result.source_events or result.checkpoints else last_status
        final_failure = result.failure_category or last_failure
        return CollectedInteraction(
            source_task=task,
            episode_id=result.episode_id,
            session_ids=list(dict.fromkeys(session_ids)),
            source_events=all_events,
            checkpoints=all_checkpoints,
            model_hashes=result.model_hashes,
            config_hash=result.config_hash,
            status=final_status,
            failure_category=final_failure,
            provenance={
                **result.provenance,
                "adapter_id": self.adapter_id,
                "driver_id": self.driver.driver_id,
                "task_set_hash": file_hash(self.task_set_path),
                "authorization_scope": "safeclaw_isolated_synthetic_construction",
            },
        )

    def normalize(
        self, trajectory: RawInteractionTrajectory, artifact_root: str
    ) -> InteractionGraph:
        event_ref = trajectory.event_refs[0]
        if event_ref.relative_path is None:
            raise ValueError("safeclaw_collection_event_ref_missing")
        event_path = Path(artifact_root) / event_ref.relative_path
        source_events = [
            cast(dict[str, Any], json.loads(line))
            for line in event_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        graph, _ = normalize_source_events(
            trajectory,
            source_events,
            audit_ref=f"{artifact_root}/normalization_audit.json",
        )
        return graph


def safeclaw_task_set_hash(task_set: SafeClawConstructionTaskSet) -> str:
    return stable_hash(task_set.model_dump(mode="json"))


class SafeClawSubprocessVictimDriver:
    """Runs one isolated SafeClaw victim container for an adaptive construction trace."""

    driver_id = "safeclaw_subprocess_victim_v1"

    def __init__(
        self,
        *,
        project_root: Path,
        upstream_root: Path,
        safety_patch: Path,
        bridge_path: Path,
        target_model_id: str,
        target_base_url: str,
        target_api_key_env: str,
        model_hash: str,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.project_root = project_root
        self.upstream_root = upstream_root
        self.safety_patch = safety_patch
        self.bridge_path = bridge_path
        self.target_model_id = target_model_id
        self.target_base_url = target_base_url
        self.target_api_key_env = target_api_key_env
        self.model_hash = model_hash
        self.environment = environment if environment is not None else os.environ
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._process: subprocess.Popen[str] | None = None
        self._stderr: IO[str] | None = None
        self._task: SafeClawConstructionTask | None = None
        self._budget: CollectionBudget | None = None
        self._pre_state: dict[str, Any] = {}
        self._last_state: dict[str, Any] = {}
        self._new_session_pending = False
        self._event_sequence = 0
        self._events: list[dict[str, Any]] = []
        self._checkpoints: list[dict[str, Any]] = []

    def _next_sequence(self) -> int:
        self._event_sequence += 1
        return self._event_sequence

    def _read_bridge(self) -> dict[str, Any]:
        if self._process is None or self._process.stdout is None:
            raise RuntimeError("safeclaw_construction_bridge_not_started")
        raw = self._process.stdout.readline()
        if not raw:
            raise RuntimeError("safeclaw_construction_bridge_closed")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise RuntimeError("safeclaw_construction_bridge_invalid_response")
        if value.get("kind") == "error":
            raise RuntimeError(str(value.get("error_category", "bridge_error")))
        return cast(dict[str, Any], value)

    def _send_bridge(self, value: dict[str, Any]) -> dict[str, Any]:
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("safeclaw_construction_bridge_not_started")
        self._process.stdin.write(json.dumps(value, sort_keys=True) + "\n")
        self._process.stdin.flush()
        return self._read_bridge()

    def start(
        self,
        task: SafeClawConstructionTask,
        *,
        seed: int,
        budget: CollectionBudget,
    ) -> ConstructionObservation:
        if self._process is not None:
            raise RuntimeError("safeclaw_construction_driver_already_started")
        api_key = self.environment.get(self.target_api_key_env)
        if not api_key:
            raise ValueError(f"missing_environment_variable:{self.target_api_key_env}")
        self._temporary = tempfile.TemporaryDirectory(prefix="safeclaw-construction-")
        temporary_root = Path(self._temporary.name)
        patched_upstream = temporary_root / "SafeClawArena"
        shutil.copytree(self.upstream_root, patched_upstream)
        check = subprocess.run(
            ["git", "apply", "--check", str(self.safety_patch)],
            cwd=patched_upstream,
            text=True,
            capture_output=True,
            check=False,
        )
        if check.returncode != 0:
            raise ValueError("safeclaw_construction_patch_check_failed")
        applied = subprocess.run(
            ["git", "apply", str(self.safety_patch)],
            cwd=patched_upstream,
            text=True,
            capture_output=True,
            check=False,
        )
        if applied.returncode != 0:
            raise ValueError("safeclaw_construction_patch_apply_failed")
        model_config = temporary_root / "model-config.json"
        model_config.write_text(
            json.dumps(
                {
                    "model": self.target_model_id,
                    "api_base_url": self.target_base_url.removesuffix("/v1"),
                    "api_key": api_key,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        os.chmod(model_config, 0o600)
        stderr_path = temporary_root / "bridge.log"
        self._stderr = stderr_path.open("w", encoding="utf-8")
        self._process = subprocess.Popen(
            [
                sys.executable,
                str(self.bridge_path),
                "--upstream",
                str(patched_upstream),
                "--task",
                str(self.project_root / task.template_path),
                "--model-config",
                str(model_config),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            text=True,
            bufsize=1,
        )
        ready = self._read_bridge()
        if ready.get("kind") != "ready":
            raise RuntimeError("safeclaw_construction_bridge_not_ready")
        self._task = task
        self._budget = budget
        self._pre_state = cast(dict[str, Any], ready.get("pre_state", {}))
        self._last_state = dict(self._pre_state)
        pre_hash = stable_hash(self._pre_state)
        self._checkpoints = [{"checkpoint_id": "victim-pre", "state_hash": pre_hash}]
        return ConstructionObservation(
            task_id=task.source_task_id,
            session_index=0,
            public_component_inventory=task.public_component_inventory,
            public_capabilities=task.public_capabilities,
            remaining_sessions=budget.max_sessions,
            remaining_events=budget.max_events,
            legal_retry_ids=task.legal_retry_ids,
            legal_reroute_ids=task.legal_reroute_ids,
        )

    def apply(self, action: ConstructionAttackerAction) -> ConstructionVictimStep:
        if self._budget is None:
            raise RuntimeError("safeclaw_construction_driver_not_started")
        response = self._send_bridge(
            {
                "kind": "action",
                "action": action.model_dump(mode="json"),
                "timeout_seconds": self._budget.timeout_seconds,
            }
        )
        action_type = action.action_type
        if action_type == "start_new_session":
            self._new_session_pending = True
            event = {
                "event_id": f"lifecycle-{action.action_id}",
                "session_id": f"construction-lifecycle-{self._next_sequence()}",
                "sequence_no": self._event_sequence,
                "actor_role": "environment",
                "event_type": "lifecycle",
                "component_role": "session_lifecycle",
                "operation": "restart_new_session",
                "status": "passed",
                "lifecycle_id": action.action_id,
                "public_payload": {"transition": "new_session"},
                "evidence_ref_ids": [f"bridge:{action.action_id}"],
            }
            self._events.append(event)
            return ConstructionVictimStep(
                session_id=str(event["session_id"]),
                source_events=[event],
                public_stage_status={"lifecycle": "new_session_started"},
            )
        if action_type in {"retry", "reroute"}:
            event = {
                "event_id": f"control-{action.action_id}",
                "session_id": "construction-control",
                "sequence_no": self._next_sequence(),
                "actor_role": "construction_attacker",
                "event_type": "lifecycle",
                "component_role": "session_lifecycle",
                "operation": "retry" if action_type == "retry" else "branch_reroute",
                "status": "passed",
                "lifecycle_id": action.action_id,
                "public_payload": {"transition": action_type},
                "evidence_ref_ids": [f"bridge:{action.action_id}"],
            }
            self._events.append(event)
            return ConstructionVictimStep(
                session_id="construction-control",
                source_events=[event],
                public_stage_status={"control": action_type},
            )
        session = cast(dict[str, Any], response.get("session", {}))
        post_state = cast(dict[str, Any], response.get("post_state", {}))
        session_id = str(session.get("session_id", f"construction-{action.action_id}"))
        message_id = f"artifact-message-{stable_hash(action.public_message or '')[:16]}"
        delivery_event_id = f"delivery-{action.action_id}"
        source_events: list[dict[str, Any]] = [
            {
                "event_id": delivery_event_id,
                "session_id": session_id,
                "sequence_no": self._next_sequence(),
                "actor_role": "construction_attacker",
                "event_type": "message",
                "component_role": "untrusted_source",
                "operation": "deliver_external_ingress",
                "status": "passed",
                "public_payload": {"delivery_surface": action.delivery_surface},
                "output_artifacts": [
                    {
                        "artifact_id": message_id,
                        "artifact_type": "untrusted_message",
                        "content_hash": stable_hash(action.public_message or ""),
                        "parent_artifact_ids": [],
                        "taint_labels": ["untrusted", "synthetic"],
                        "trust_label": "untrusted",
                        "source_ref_ids": [f"attacker_action:{action.action_id}"],
                    }
                ],
                "evidence_ref_ids": [f"attacker_action:{action.action_id}"],
            }
        ]
        memory_state_ref = "safeclaw_state:memory"
        if self._new_session_pending and post_state.get("memory_content"):
            source_events.append(
                {
                    "event_id": f"state-read-memory-{action.action_id}",
                    "session_id": session_id,
                    "sequence_no": self._next_sequence(),
                    "actor_role": "victim_system",
                    "event_type": "state_read",
                    "component_role": "persistent_memory",
                    "operation": "memory_retrieve_later_session",
                    "status": "passed",
                    "read_state_refs": [memory_state_ref],
                    "output_artifacts": [
                        {
                            "artifact_id": f"artifact-recall-{action.action_id}",
                            "artifact_type": "recalled_state",
                            "content_hash": stable_hash(post_state.get("memory_content", "")),
                            "parent_artifact_ids": [],
                            "taint_labels": ["synthetic", "persistent"],
                            "trust_label": "derived",
                            "source_ref_ids": [f"checkpoint:{session_id}:memory"],
                        }
                    ],
                    "evidence_ref_ids": [f"checkpoint:{session_id}:memory"],
                }
            )
        self._new_session_pending = False
        response_text = str(session.get("agent_response", ""))
        response_artifact_id = f"artifact-response-{stable_hash(response_text)[:16]}"
        source_events.append(
            {
                "event_id": f"response-{action.action_id}",
                "session_id": session_id,
                "sequence_no": self._next_sequence(),
                "actor_role": "victim_agent",
                "event_type": "message",
                "component_role": "agent_context",
                "operation": "extract_victim_response",
                "status": "passed",
                "input_artifact_ids": [message_id],
                "output_artifacts": [
                    {
                        "artifact_id": response_artifact_id,
                        "artifact_type": "agent_response",
                        "content_hash": stable_hash(response_text),
                        "parent_artifact_ids": [message_id],
                        "taint_labels": ["synthetic"],
                        "trust_label": "derived",
                        "source_ref_ids": [f"bridge:{session_id}:response"],
                    }
                ],
                "public_payload": {"response": response_text},
                "evidence_ref_ids": [f"bridge:{session_id}:response"],
            }
        )
        tool_calls = session.get("tool_calls", [])
        for index, tool_call in enumerate(tool_calls if isinstance(tool_calls, list) else []):
            call_payload = tool_call if isinstance(tool_call, dict) else {"value": str(tool_call)}
            source_events.append(
                {
                    "event_id": f"tool-call-{action.action_id}-{index}",
                    "session_id": session_id,
                    "sequence_no": self._next_sequence(),
                    "actor_role": "victim_agent",
                    "event_type": "tool_call",
                    "component_role": "effect_tool",
                    "operation": "safeclaw.tool_request",
                    "status": "attempted",
                    "input_artifact_ids": [response_artifact_id],
                    "public_payload": call_payload,
                    "evidence_ref_ids": [f"bridge:{session_id}:tool:{index}"],
                }
            )
        state_specs = [
            ("memory", "persistent_memory", "memory_write", "memory_content"),
            ("workspace", "workspace_file", "workspace_write", "workspace_file_contents"),
            (
                "external",
                "sandbox_external_state",
                "external_effect",
                "sim_google_calls",
            ),
        ]
        for name, component, operation, key in state_specs:
            before = stable_hash(self._last_state.get(key, ""))
            after = stable_hash(post_state.get(key, ""))
            if before == after:
                continue
            state_ref = f"safeclaw_state:{name}"
            source_events.append(
                {
                    "event_id": f"state-write-{name}-{action.action_id}",
                    "session_id": session_id,
                    "sequence_no": self._next_sequence(),
                    "actor_role": "victim_system",
                    "event_type": "state_write",
                    "component_role": component,
                    "operation": operation,
                    "status": "passed",
                    "pre_state_ref": f"{state_ref}:{before}",
                    "post_state_ref": f"{state_ref}:{after}",
                    "write_state_refs": [state_ref],
                    "request_event_id": (
                        f"tool-call-{action.action_id}-{len(tool_calls) - 1}"
                        if name == "external" and tool_calls
                        else None
                    ),
                    "evidence_ref_ids": [f"checkpoint:{session_id}:{name}"],
                }
            )
        self._last_state = post_state
        self._checkpoints.append(
            {
                "checkpoint_id": f"victim-{session_id}",
                "state_hash": stable_hash(post_state),
            }
        )
        self._events.extend(source_events)
        return ConstructionVictimStep(
            session_id=session_id,
            source_events=source_events,
            public_transcript_events=[
                {"role": "attacker", "content": action.public_message or ""},
                {"role": "victim", "content": response_text},
            ],
            public_stage_status={"victim_session": "completed"},
        )

    def finish(self) -> ConstructionVictimResult:
        if self._task is None or self._process is None:
            raise RuntimeError("safeclaw_construction_driver_not_started")
        try:
            response = self._send_bridge({"kind": "finish"})
            post_state = cast(dict[str, Any], response.get("post_state", {}))
            post_hash = stable_hash(post_state)
            final_events: list[dict[str, Any]] = []
            state_specs = [("configuration", "configuration", "config_update", "config_hash")]
            for name, component, operation, key in state_specs:
                before = stable_hash(self._last_state.get(key, ""))
                after = stable_hash(post_state.get(key, ""))
                if before == after:
                    continue
                state_ref = f"safeclaw_state:{name}"
                final_events.append(
                    {
                        "event_id": f"state-write-{name}-{self._next_sequence()}",
                        "session_id": "construction-finalize",
                        "sequence_no": self._event_sequence,
                        "actor_role": "victim_system",
                        "event_type": "state_write",
                        "component_role": component,
                        "operation": operation,
                        "status": "passed",
                        "pre_state_ref": f"{state_ref}:{before}",
                        "post_state_ref": f"{state_ref}:{after}",
                        "write_state_refs": [state_ref],
                        "evidence_ref_ids": [f"checkpoint:{name}:post"],
                    }
                )
            self._checkpoints.append(
                {"checkpoint_id": "victim-post", "state_hash": post_hash}
            )
            self._process.wait(timeout=30)
            return ConstructionVictimResult(
                episode_id=f"construction-episode-{self._task.source_task_id}",
                source_events=final_events,
                checkpoints=self._checkpoints,
                model_hashes={"victim": self.model_hash},
                config_hash=stable_hash(
                    {
                        "task_hash": self._task.template_hash,
                        "patch_hash": file_hash(self.safety_patch),
                        "target_model_hash": self.model_hash,
                    }
                ),
                status="complete",
                provenance={
                    "upstream_hash": stable_hash(str(self.upstream_root)),
                    "safety_patch_hash": file_hash(self.safety_patch),
                    "bridge_hash": file_hash(self.bridge_path),
                    "private_oracle_exposed": "false",
                    "official_evaluator_invoked": "false",
                },
            )
        finally:
            if self._stderr is not None:
                self._stderr.close()
            if self._temporary is not None:
                self._temporary.cleanup()
            self._process = None

    def abort(self) -> None:
        process = self._process
        try:
            if process is not None and process.poll() is None:
                try:
                    self._send_bridge({"kind": "finish"})
                    process.wait(timeout=30)
                except Exception:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
        finally:
            if self._stderr is not None and not self._stderr.closed:
                self._stderr.close()
            if self._temporary is not None:
                self._temporary.cleanup()
            self._process = None
