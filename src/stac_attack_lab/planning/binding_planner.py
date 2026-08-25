from __future__ import annotations

from stac_attack_lab.datasets.primitive_chain import PlannerSampleView
from stac_attack_lab.environments.safeclaw.contracts import (
    BaselineBinding,
    BenchmarkBinding,
    BindingAssignment,
    SafeClawPublicTaskView,
)
from stac_attack_lab.hashing import stable_hash


def build_benchmark_binding(
    sample: PlannerSampleView,
    task: SafeClawPublicTaskView,
) -> BenchmarkBinding:
    task_slots = {slot.slot_id: slot for slot in task.bindable_slots if slot.public}
    assignments: list[BindingAssignment] = []
    reason_codes: list[str] = []
    for slot in sample.binding_slots:
        components = task.component_roles.get(slot.required_component_role, [])
        benchmark_slot = task_slots.get(slot.slot_id)
        if not components:
            reason_codes.append(f"missing_component_role:{slot.required_component_role}")
            continue
        if benchmark_slot is None:
            reason_codes.append(f"missing_bindable_slot:{slot.slot_id}")
            continue
        if "sample.execution_view" not in benchmark_slot.allowed_sources:
            reason_codes.append(f"sample_source_not_allowed:{slot.slot_id}")
            continue
        if slot.required_capability and slot.required_capability not in task.public_capabilities:
            reason_codes.append(f"missing_slot_capability:{slot.required_capability}")
            continue
        assignments.append(
            BindingAssignment(
                sample_slot_id=slot.slot_id,
                benchmark_slot_id=benchmark_slot.slot_id,
                public_value_ref=f"public_component:{components[0]}",
                component_role=slot.required_component_role,
                capability=slot.required_capability or "role_binding",
            )
        )
    node_component_mapping: dict[str, str] = {}
    node_session_mapping: dict[str, str] = {}
    assignment_by_slot = {item.sample_slot_id: item for item in assignments}
    macro_component_mapping: dict[str, str] = {}
    for index, macro_node in enumerate(sample.macro_nodes, start=1):
        mapped = next(
            (
                assignment_by_slot[slot].public_value_ref
                for slot in macro_node.binding_slots
                if slot in assignment_by_slot
            ),
            None,
        )
        if mapped is None:
            reason_codes.append(f"node_has_no_component_binding:{macro_node.node_id}")
        else:
            node_component_mapping[macro_node.node_id] = mapped
            macro_component_mapping[macro_node.macro_primitive_ref] = mapped
        node_session_mapping[macro_node.node_id] = "session-1" if index <= 2 else "session-2"
    session_ordinal = 1
    for core_node in sorted(sample.core_nodes, key=lambda item: item.position):
        if core_node.session_boundary_before:
            session_ordinal += 1
        node_session_mapping[core_node.node_id] = f"session-{session_ordinal}"
        mapped = next(
            (
                macro_component_mapping[macro_ref]
                for macro_ref in core_node.macro_annotations
                if macro_ref in macro_component_mapping
            ),
            None,
        )
        if mapped is None:
            mapped = next(iter(macro_component_mapping.values()), None)
        if mapped is None:
            reason_codes.append(f"core_node_has_no_component_binding:{core_node.node_id}")
        else:
            node_component_mapping[core_node.node_id] = mapped
    binding_id = (
        "binding-"
        + stable_hash(
            {
                "sample_id": sample.sample_id,
                "task_id": task.task_id,
                "assignments": [item.model_dump(mode="json") for item in assignments],
            }
        )[:20]
    )
    payload = {
        "schema_version": "2.0",
        "binding_id": binding_id,
        "materialization_template_id": task.materialization_template_id,
        "sample_id": sample.sample_id,
        "chain_id": stable_hash([node.macro_primitive_ref for node in sample.macro_nodes]),
        "task_id": task.task_id,
        "task_source_hash": task.task_source_hash,
        "assignments": [item.model_dump(mode="json") for item in assignments],
        "node_component_mapping": node_component_mapping,
        "node_session_mapping": node_session_mapping,
        "edge_artifact_mapping": {
            edge.edge_id: f"public_artifact:{edge.edge_id}" for edge in sample.macro_edges
        },
        "allowed_actions": task.allowed_actions,
        "binding_valid": not reason_codes,
        "validation_reason_codes": reason_codes or ["binding_valid"],
    }
    return BenchmarkBinding.model_validate({**payload, "binding_hash": stable_hash(payload)})


def build_baseline_binding(task: SafeClawPublicTaskView) -> BaselineBinding:
    assignments: list[BindingAssignment] = []
    reason_codes: list[str] = []
    for slot in task.bindable_slots:
        if not slot.public:
            continue
        if "baseline.task_set" not in slot.allowed_sources:
            reason_codes.append(f"baseline_source_not_allowed:{slot.slot_id}")
            continue
        assignments.append(
            BindingAssignment(
                sample_slot_id=slot.slot_id,
                benchmark_slot_id=slot.slot_id,
                public_value_ref=f"baseline_task_set:{slot.slot_id}",
                component_role="baseline_materialization",
                capability="legal_baseline_value",
            )
        )
    if not assignments:
        reason_codes.append("no_public_baseline_slots")
    template_id = task.materialization_template_id or task.task_id
    binding_id = (
        "baseline-binding-"
        + stable_hash(
            {
                "task_id": task.task_id,
                "template_id": template_id,
                "assignments": [item.model_dump(mode="json") for item in assignments],
            }
        )[:20]
    )
    payload = {
        "schema_version": "2.0",
        "binding_id": binding_id,
        "materialization_source": "legal_baseline",
        "task_id": task.task_id,
        "materialization_template_id": template_id,
        "task_source_hash": task.task_source_hash,
        "assignments": [item.model_dump(mode="json") for item in assignments],
        "allowed_actions": task.allowed_actions,
        "binding_valid": not reason_codes,
        "validation_reason_codes": reason_codes or ["baseline_binding_valid"],
    }
    return BaselineBinding.model_validate({**payload, "binding_hash": stable_hash(payload)})
