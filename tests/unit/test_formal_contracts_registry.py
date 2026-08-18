from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from stac_attack_lab.contracts import OfflineSample
from stac_attack_lab.environments.safeclaw.contracts import (
    SafeClawBindingSlot,
    SafeClawPublicTaskView,
    SafeClawTrack,
)
from stac_attack_lab.interactions.models import PrimitiveOccurrence
from stac_attack_lab.primitives.core import (
    CorePrimitiveFamily,
    EvidenceGrade,
    PrimitiveOutcome,
)
from stac_attack_lab.primitives.formal_registry import load_formal_registry
from stac_attack_lab.schema_registry import FORMAL_SCHEMA_MODELS, validate_schema_registry

ROOT = Path(__file__).resolve().parents[2]


def test_formal_registry_is_frozen_and_legacy_aliases_resolve() -> None:
    path = ROOT / "configs/primitives/formal_v1.yaml"
    first = load_formal_registry(path)
    second = load_formal_registry(path)

    assert len(first.core_primitives) == 20
    assert len(first.attack_macros) == 4
    assert first.registry_hash == second.registry_hash
    assert first.resolve_macro("memory_write").macro_id == "macro.persistent_state_write@1"
    assert first.resolve_macro("canary_tool_trigger@1").macro_id == (
        "macro.tainted_effectful_action@1"
    )


def test_formal_schema_registry_is_disjoint_and_serializable() -> None:
    validate_schema_registry()
    assert len(FORMAL_SCHEMA_MODELS) == 17
    for model in FORMAL_SCHEMA_MODELS.values():
        schema = model.model_json_schema()
        assert schema["type"] == "object"
        json.dumps(schema)


def test_legacy_frozen_sample_contract_remains_unchanged() -> None:
    line = (ROOT / "data/frozen/mvp-v0.1/samples.jsonl").read_text(encoding="utf-8").splitlines()[0]
    sample = OfflineSample.model_validate_json(line)
    assert sample.model_dump_json()
    assert sample.dataset_version == "generated"


def test_public_safeclaw_view_forbids_private_oracle_fields() -> None:
    payload = {
        "task_id": "safeclaw-template-1",
        "track": SafeClawTrack.compositional,
        "dimension": "PSE",
        "category": "2.1",
        "public_goal": "Complete an authorized synthetic workspace task.",
        "public_capabilities": ["persistent_state_write"],
        "component_roles": {"persistent_memory": ["workspace_memory"]},
        "session_count": 2,
        "lifecycle_boundaries": ["new_session"],
        "bindable_slots": [
            SafeClawBindingSlot(
                slot_id="fixture_text",
                json_pointer="/environment/fixture/text",
                value_type="string",
                public=True,
                allowed_sources=["sample.execution_view"],
                description="Authorized synthetic fixture text.",
            ).model_dump(mode="json")
        ],
        "allowed_actions": ["workspace_memory.write"],
        "task_source_hash": "a" * 64,
        "private_oracle": "must-not-parse",
    }
    with pytest.raises(ValidationError):
        SafeClawPublicTaskView.model_validate(payload)


def test_semantic_evidence_cannot_create_a_hard_primitive_pass() -> None:
    with pytest.raises(ValidationError, match="hard_pass_requires_e1_or_e2"):
        PrimitiveOccurrence(
            occurrence_id="occ-1",
            graph_id="graph-1",
            primitive_ref="core.transform.extract@1",
            family=CorePrimitiveFamily.transform,
            subtype="extract",
            outcome=PrimitiveOutcome.passed,
            source_component_roles=["agent_context"],
            target_component_roles=["agent_context"],
            input_artifact_ids=["artifact-in"],
            output_artifact_ids=["artifact-out"],
            pre_state_refs=[],
            post_state_refs=[],
            source_event_ids=["event-1"],
            evidence_grades=[EvidenceGrade.semantic],
            evidence_ref_ids=["semantic-label-1"],
            confidence=0.9,
            hard_fact=True,
            reason_codes=[],
        )
