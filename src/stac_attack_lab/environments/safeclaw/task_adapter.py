from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, cast

from stac_attack_lab.environments.safeclaw.contracts import (
    SafeClawBindingSlot,
    SafeClawPublicTaskView,
    SafeClawTaskDescriptor,
    SafeClawTrack,
)
from stac_attack_lab.hashing import file_hash, stable_hash

PINNED_SAFECLAW_COMMIT = "a11f5cceaba0676be721021f8d232638fd111305"
FORBIDDEN_BINDING_TOKENS = (
    "evaluation",
    "success_condition",
    "safe_condition",
    "oracle",
    "canary",
    "auth_profiles",
    "credential",
    "api_key",
    "token",
    "password",
    "secret",
)


def _default_capabilities(task: dict[str, Any]) -> list[str]:
    metadata = task["metadata"]
    dimension = str(metadata["dimension"]).upper()
    sessions = task.get("sessions", [])
    environment = task.get("environment", {})
    capabilities = {"effectful_sandbox_action"}
    if environment.get("sim_google_data") or environment.get("workspace_files"):
        capabilities.add("read_untrusted_source")
    if dimension == "PSE":
        capabilities.update({"persistent_state_write", "persistent_state_read"})
    if len(sessions) > 1 or any(session.get("pre_session_setup") for session in sessions):
        capabilities.add("lifecycle_boundary")
    return sorted(capabilities)


def _default_component_roles() -> dict[str, list[str]]:
    return {
        "untrusted_source": ["safeclaw_fixture"],
        "agent_context": ["openclaw_main_session"],
        "persistent_memory": ["openclaw_workspace_memory"],
        "workspace_file": ["openclaw_workspace"],
        "configuration": ["openclaw_config"],
        "session_lifecycle": ["safeclaw_session_runner"],
        "effect_tool": ["safeclaw_simulated_tool"],
        "sandbox_external_state": ["safeclaw_simulated_state"],
    }


def _parse_bindable_slots(formal: dict[str, Any]) -> tuple[list[SafeClawBindingSlot], list[str]]:
    slots: list[SafeClawBindingSlot] = []
    errors: list[str] = []
    for raw in formal.get("bindable_slots", []):
        pointer = str(raw.get("json_pointer", ""))
        if not pointer.startswith("/"):
            errors.append("binding_pointer_must_be_absolute")
            continue
        lowered = pointer.lower()
        if any(token in lowered for token in FORBIDDEN_BINDING_TOKENS):
            errors.append(f"forbidden_binding_pointer:{pointer}")
            continue
        slots.append(
            SafeClawBindingSlot(
                slot_id=str(raw["slot_id"]),
                json_pointer=pointer,
                value_type=cast(
                    Literal["string", "integer", "boolean", "string_list", "object"],
                    str(raw.get("value_type", "string")),
                ),
                public=bool(raw.get("public", True)),
                allowed_sources=[str(item) for item in raw.get("allowed_sources", [])],
                description=str(raw.get("description", "Authorized bindable field.")),
            )
        )
    return slots, errors


def parse_safeclaw_task(
    path: Path,
    *,
    upstream_root: Path,
    upstream_commit: str = PINNED_SAFECLAW_COMMIT,
) -> SafeClawTaskDescriptor:
    task = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(task, dict):
        raise ValueError("safeclaw_task_root_must_be_mapping")
    metadata = task.get("metadata", {})
    evaluation = task.get("evaluation", {})
    sessions = task.get("sessions", [])
    if not isinstance(metadata, dict) or not isinstance(evaluation, dict) or not sessions:
        raise ValueError("safeclaw_task_missing_metadata_evaluation_or_sessions")
    formal = task.get("formal_experiment")
    formal_mapping = formal if isinstance(formal, dict) else {}
    track = SafeClawTrack.compositional if formal_mapping else SafeClawTrack.conformance
    slots, slot_errors = _parse_bindable_slots(formal_mapping)
    capabilities = [
        str(item) for item in formal_mapping.get("public_capabilities", _default_capabilities(task))
    ]
    component_roles = formal_mapping.get("component_roles", _default_component_roles())
    if not isinstance(component_roles, dict):
        raise ValueError("safeclaw_component_roles_must_be_mapping")
    task_id = str(metadata["task_id"])
    source_hash = file_hash(path)
    public_view = SafeClawPublicTaskView(
        task_id=task_id,
        track=track,
        dimension=str(metadata["dimension"]),
        category=str(metadata["category"]),
        public_goal=str(
            formal_mapping.get(
                "public_goal",
                metadata.get("description", metadata.get("title", "Authorized benchmark task.")),
            )
        ),
        public_capabilities=sorted(set(capabilities)),
        component_roles={
            str(role): [str(item) for item in values] for role, values in component_roles.items()
        },
        session_count=len(sessions),
        lifecycle_boundaries=[
            str(session.get("session_id", f"session-{index + 2}"))
            for index, session in enumerate(sessions[1:])
        ],
        bindable_slots=slots,
        allowed_actions=[
            str(item)
            for item in formal_mapping.get("allowed_actions", ["safeclaw_official_task_actions"])
        ],
        materialization_template_id=(
            str(formal_mapping["materialization_template_id"])
            if formal_mapping.get("materialization_template_id")
            else None
        ),
        task_source_hash=source_hash,
    )
    supported = not slot_errors and (
        track == SafeClawTrack.conformance
        or bool(formal_mapping.get("materialization_template_id"))
    )
    unsupported_reason = None
    if slot_errors:
        unsupported_reason = ",".join(slot_errors)
    elif track == SafeClawTrack.compositional and not formal_mapping.get(
        "materialization_template_id"
    ):
        unsupported_reason = "compositional_task_missing_template_id"
    relative_path = str(path.resolve().relative_to(upstream_root.resolve()))
    return SafeClawTaskDescriptor(
        task_id=task_id,
        track=track,
        dimension=str(metadata["dimension"]),
        category=str(metadata["category"]),
        title=str(metadata["title"]),
        source_relative_path=relative_path,
        source_hash=source_hash,
        upstream_commit=upstream_commit,
        public_view=public_view,
        private_oracle_ref=f"{relative_path}#/evaluation",
        official_success_condition_hash=stable_hash(evaluation.get("success_condition")),
        official_safe_condition_hash=stable_hash(evaluation.get("safe_condition")),
        materialization_template_id=(
            str(formal_mapping["materialization_template_id"])
            if formal_mapping.get("materialization_template_id")
            else None
        ),
        supported=supported,
        unsupported_reason=unsupported_reason,
    )


def inventory_safeclaw_tasks(
    upstream_root: Path,
    task_paths: list[str],
    *,
    upstream_commit: str = PINNED_SAFECLAW_COMMIT,
) -> list[SafeClawTaskDescriptor]:
    descriptors = [
        parse_safeclaw_task(
            upstream_root / relative_path,
            upstream_root=upstream_root,
            upstream_commit=upstream_commit,
        )
        for relative_path in task_paths
    ]
    task_ids = [descriptor.task_id for descriptor in descriptors]
    if len(task_ids) != len(set(task_ids)):
        raise ValueError("duplicate_safeclaw_task_id")
    return descriptors
