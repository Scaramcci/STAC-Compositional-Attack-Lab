from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stac_attack_lab.datasets.primitive_chain import ExecutionBindingView
from stac_attack_lab.environments.safeclaw.contracts import (
    MaterializedTaskReference,
    SafeClawTaskDescriptor,
    SafeClawTrack,
)
from stac_attack_lab.environments.safeclaw.redaction import scan_for_secrets
from stac_attack_lab.environments.safeclaw.task_adapter import FORBIDDEN_BINDING_TOKENS
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.planning.formal_base import FormalEvaluationPlan


@dataclass(frozen=True)
class MaterializedTask:
    path: Path
    reference: MaterializedTaskReference


def _pointer_parts(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ValueError("json_pointer_must_be_absolute")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _set_existing_pointer(document: Any, pointer: str, value: Any) -> None:
    parts = _pointer_parts(pointer)
    if not parts:
        raise ValueError("cannot_replace_task_root")
    current = document
    for part in parts[:-1]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise ValueError(f"bindable_pointer_parent_missing:{pointer}")
    final = parts[-1]
    if isinstance(current, dict) and final in current:
        current[final] = value
    elif isinstance(current, list) and final.isdigit() and int(final) < len(current):
        current[int(final)] = value
    else:
        raise ValueError(f"bindable_pointer_target_missing:{pointer}")


def _value_matches_type(value: Any, value_type: str) -> bool:
    if value_type == "string":
        return isinstance(value, str)
    if value_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if value_type == "boolean":
        return isinstance(value, bool)
    if value_type == "string_list":
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if value_type == "object":
        return isinstance(value, dict)
    return False


def materialize_safeclaw_task(
    template_path: Path,
    descriptor: SafeClawTaskDescriptor,
    plan: FormalEvaluationPlan,
    execution_view: ExecutionBindingView,
    slot_values: dict[str, Any],
    temporary_root: Path,
) -> MaterializedTask:
    if descriptor.track != SafeClawTrack.compositional:
        raise ValueError("official_conformance_task_cannot_be_materialized")
    if not descriptor.supported or descriptor.materialization_template_id is None:
        raise ValueError("unsupported_safeclaw_compositional_template")
    if plan.task_template_id != descriptor.materialization_template_id:
        raise ValueError("formal_plan_template_id_mismatch")
    if plan.binding is None or not plan.binding.binding_valid:
        raise ValueError("formal_plan_requires_valid_binding")
    if plan.selected_sample_id != execution_view.sample_id:
        raise ValueError("execution_view_sample_mismatch")
    if file_hash(template_path) != descriptor.source_hash:
        raise ValueError("safeclaw_template_hash_mismatch")
    task = json.loads(template_path.read_text(encoding="utf-8"))
    materialized = copy.deepcopy(task)
    protected_before = stable_hash(task.get("evaluation"))
    slots = {slot.slot_id: slot for slot in descriptor.public_view.bindable_slots}
    changed_pointers: list[str] = []
    for assignment in plan.binding.assignments:
        slot = slots.get(assignment.benchmark_slot_id)
        if slot is None or not slot.public:
            raise ValueError(f"binding_uses_unknown_or_private_slot:{assignment.benchmark_slot_id}")
        lowered = slot.json_pointer.lower()
        if any(token in lowered for token in FORBIDDEN_BINDING_TOKENS):
            raise ValueError(f"binding_attempts_protected_path:{slot.json_pointer}")
        if assignment.sample_slot_id not in slot_values:
            raise ValueError(f"missing_materialization_value:{assignment.sample_slot_id}")
        value = slot_values[assignment.sample_slot_id]
        if not _value_matches_type(value, slot.value_type):
            raise ValueError(f"materialization_value_type_mismatch:{slot.slot_id}")
        if scan_for_secrets(value):
            raise ValueError(f"materialization_value_contains_secret_pattern:{slot.slot_id}")
        _set_existing_pointer(materialized, slot.json_pointer, value)
        changed_pointers.append(slot.json_pointer)
    if not changed_pointers:
        raise ValueError("formal_plan_did_not_materialize_any_slot")
    if stable_hash(materialized.get("evaluation")) != protected_before:
        raise ValueError("materialization_changed_official_evaluation")
    materialized_hash = stable_hash(materialized)
    if materialized_hash == stable_hash(task):
        raise ValueError("formal_plan_did_not_change_task")
    temporary_root.mkdir(parents=True, exist_ok=True)
    os.chmod(temporary_root, 0o700)
    task_path = temporary_root / f"{descriptor.task_id}-{plan.plan_id}.json"
    task_path.write_text(json.dumps(materialized, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(task_path, 0o600)
    binding_manifest_path = temporary_root / f"{plan.plan_id}-binding.json"
    binding_manifest = {
        "plan_id": plan.plan_id,
        "binding_id": plan.binding.binding_id,
        "task_id": descriptor.task_id,
        "template_hash": descriptor.source_hash,
        "materialized_task_hash": materialized_hash,
        "changed_pointers": changed_pointers,
        "official_evaluation_hash": protected_before,
    }
    binding_manifest_path.write_text(
        json.dumps(binding_manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    os.chmod(binding_manifest_path, 0o600)
    reference = MaterializedTaskReference(
        task_id=descriptor.task_id,
        template_id=descriptor.materialization_template_id,
        binding_id=plan.binding.binding_id,
        materialized_task_hash=materialized_hash,
        sanitized_projection_ref=binding_manifest_path.name,
        binding_manifest_ref=binding_manifest_path.name,
    )
    return MaterializedTask(path=task_path, reference=reference)
