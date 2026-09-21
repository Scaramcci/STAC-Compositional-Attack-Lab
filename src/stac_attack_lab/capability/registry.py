from __future__ import annotations

from stac_attack_lab.capability.models import PrimitiveKind, PrimitiveSpec


def primitive_registry() -> list[PrimitiveSpec]:
    rows = {
        PrimitiveKind.INGEST: (
            "external_content",
            "available_context",
            ["content_delivery"],
            "read a trusted invoice",
            "file exists but was never delivered",
        ),
        PrimitiveKind.ADOPT: (
            "available_content",
            "task_interpretation",
            ["behavioral_semantic_use"],
            "apply an explicit trusted policy",
            "repeat text without relying on it",
        ),
        PrimitiveKind.PERSIST: (
            "current_state",
            "durable_state_version",
            ["victim_write", "committed_state_delta"],
            "save a correct preference",
            "harness preloads a file",
        ),
        PrimitiveKind.RECALL: (
            "durable_state_version",
            "available_context",
            ["state_read", "resource_version_link"],
            "read a saved summary",
            "same text appears without a read",
        ),
        PrimitiveKind.SELECT: (
            "goal_and_capabilities",
            "selected_route",
            ["tool_selection"],
            "select the authorized project tool",
            "tool name appears in prose",
        ),
        PrimitiveKind.BIND: (
            "selected_route_and_values",
            "bound_request",
            ["complete_arguments"],
            "bind the trusted project ID",
            "incomplete request arguments",
        ),
        PrimitiveKind.ACT: (
            "bound_request",
            "business_effect",
            ["committed_receipt", "state_delta"],
            "update the authorized record",
            "tool request is rejected",
        ),
        PrimitiveKind.RECORD: (
            "decision_or_effect",
            "consumable_artifact",
            ["victim_record_write", "artifact_version"],
            "write an accurate report",
            "private evaluator log",
        ),
        PrimitiveKind.RECOVER: (
            "failure_or_block",
            "changed_route",
            ["trigger_event", "changed_followup"],
            "use a legal fallback after outage",
            "repeat the same failed request",
        ),
    }
    return [
        PrimitiveSpec(
            primitive=primitive,
            input_type=values[0],
            output_type=values[1],
            preconditions=[f"{values[0]}_available"],
            minimum_observations=values[2],
            neutral_example=values[3],
            counterexample=values[4],
        )
        for primitive, values in rows.items()
    ]


def validate_registry() -> list[PrimitiveSpec]:
    registry = primitive_registry()
    if {item.primitive for item in registry} != set(PrimitiveKind):
        raise ValueError("capability_registry_not_exactly_nine_primitives")
    return registry
