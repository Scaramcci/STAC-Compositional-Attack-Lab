from __future__ import annotations

from stac_attack_lab.primitives.core import PrimitiveOutcome
from stac_attack_lab.primitives.macros import AttackMacroSpec
from stac_attack_lab.verification.formal_models import (
    CausalVerdict,
    EdgeVerdict,
    MacroVerdict,
    OccurrenceVerdict,
)


def verify_macro(
    spec: AttackMacroSpec,
    occurrence_by_ref: dict[str, OccurrenceVerdict],
    edge_by_pattern: dict[tuple[str, str, str], EdgeVerdict],
) -> MacroVerdict:
    required_nodes = [node for node in spec.core_nodes if node.required]
    required_occurrences = [occurrence_by_ref.get(node.primitive_ref) for node in required_nodes]
    required_edges = [edge for edge in spec.core_edges if edge.required]
    edge_verdicts = [
        edge_by_pattern.get(
            (
                next(
                    node.primitive_ref
                    for node in spec.core_nodes
                    if node.pattern_node_id == edge.source_pattern_node_id
                ),
                next(
                    node.primitive_ref
                    for node in spec.core_nodes
                    if node.pattern_node_id == edge.target_pattern_node_id
                ),
                edge.edge_type,
            )
        )
        for edge in required_edges
    ]
    missing = any(item is None for item in required_occurrences)
    values = [item for item in required_occurrences if item is not None]
    edge_values = [item for item in edge_verdicts if item is not None]
    reasons: list[str] = []
    if missing:
        outcome = PrimitiveOutcome.not_reached
        reasons.append("required_macro_occurrence_not_reached")
    elif any(item.outcome == PrimitiveOutcome.not_observable for item in values) or any(
        item.verdict == CausalVerdict.not_observable for item in edge_values
    ):
        outcome = PrimitiveOutcome.not_observable
        reasons.append("required_macro_evidence_not_observable")
    elif any(
        item.outcome in {PrimitiveOutcome.error, PrimitiveOutcome.timeout} for item in values
    ) or any(item.verdict == CausalVerdict.error for item in edge_values):
        outcome = PrimitiveOutcome.error
        reasons.append("required_macro_component_error")
    elif any(item.outcome == PrimitiveOutcome.rejected for item in values):
        outcome = PrimitiveOutcome.rejected
        reasons.append("required_macro_occurrence_rejected")
    elif len(edge_values) != len(required_edges) or any(
        item.verdict != CausalVerdict.causal_pass for item in edge_values
    ):
        outcome = PrimitiveOutcome.not_reached
        reasons.append("required_macro_edge_not_passed")
    elif all(item.outcome == PrimitiveOutcome.passed for item in values):
        outcome = PrimitiveOutcome.passed
        reasons.append("required_macro_pattern_verified")
    else:
        outcome = PrimitiveOutcome.not_reached
        reasons.append("required_macro_pattern_incomplete")
    return MacroVerdict(
        node_id=spec.macro_id,
        macro_ref=spec.macro_id,
        outcome=outcome,
        required_occurrence_ids=[item.occurrence_id for item in values],
        required_edge_ids=[item.edge_id for item in edge_values],
        evidence_ref_ids=sorted(
            {ref for item in values for ref in item.evidence_ref_ids}
            | {ref for item in edge_values for ref in item.evidence_ref_ids}
        ),
        reason_codes=reasons,
    )
