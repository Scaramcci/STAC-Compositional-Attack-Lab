from __future__ import annotations

import pytest
from pydantic import ValidationError

from stac_attack_lab.capability.models import (
    AttributionState,
    EvidenceSupport,
    ExecutionState,
    PrimitiveKind,
    PrimitiveOccurrence,
    SemanticAlignment,
)
from stac_attack_lab.capability.registry import validate_registry


def test_registry_contains_exactly_nine_first_class_primitives() -> None:
    registry = validate_registry()
    assert [item.primitive for item in registry] == list(PrimitiveKind)


def test_committed_occurrence_requires_runtime_event_evidence() -> None:
    with pytest.raises(ValidationError, match="primitive_occurrence_runtime_evidence_missing"):
        PrimitiveOccurrence(
            occurrence_id="act-1",
            planned_node_id="n-act",
            primitive=PrimitiveKind.ACT,
            event_ids=[],
            execution=ExecutionState.COMMITTED,
            semantic_alignment=SemanticAlignment.AMBIGUOUS,
            support=EvidenceSupport.DIRECT,
            attribution=AttributionState.SUPPORTED,
            reason_codes=[],
        )
