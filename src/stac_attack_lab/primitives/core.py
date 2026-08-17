from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from stac_attack_lab.contracts import StrictModel


class CorePrimitiveFamily(StrEnum):
    transfer = "TRANSFER"
    transform = "TRANSFORM"
    mutate = "MUTATE"
    control = "CONTROL"


class PrimitiveOutcome(StrEnum):
    not_reached = "not_reached"
    attempted = "attempted"
    passed = "passed"
    rejected = "rejected"
    error = "error"
    timeout = "timeout"
    abstained = "abstained"
    not_observable = "not_observable"


class EvidenceGrade(StrEnum):
    direct = "E1"
    deterministic_derived = "E2"
    interventional = "E3"
    semantic = "E4"


class EvidencePolicy(StrictModel):
    hard_pass_grades: list[EvidenceGrade] = Field(
        default_factory=lambda: [EvidenceGrade.direct, EvidenceGrade.deterministic_derived]
    )
    causal_claim_grades: list[EvidenceGrade] = Field(
        default_factory=lambda: [EvidenceGrade.interventional]
    )
    semantic_can_override_hard_fact: Literal[False] = False


class CorePrimitiveSpec(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    primitive_id: str
    version: str
    family: CorePrimitiveFamily
    subtype: str
    public_summary: str
    source_roles: list[str]
    target_roles: list[str]
    required_capabilities: list[str]
    required_observations: list[str]
    observable_state_differences: list[str]
    allowed_outcomes: list[PrimitiveOutcome]
    minimum_hard_evidence: list[EvidenceGrade]
    safety_scope: Literal["authorized_benchmark_sandbox"] = "authorized_benchmark_sandbox"

    @model_validator(mode="after")
    def validate_identity_and_evidence(self) -> CorePrimitiveSpec:
        expected_prefix = f"core.{self.family.value.lower()}."
        if not self.primitive_id.startswith(expected_prefix):
            raise ValueError("core_primitive_id_family_mismatch")
        if (
            not self.subtype
            or self.primitive_id != f"{expected_prefix}{self.subtype}@{self.version}"
        ):
            raise ValueError("core_primitive_id_version_mismatch")
        if PrimitiveOutcome.passed not in self.allowed_outcomes:
            raise ValueError("core_primitive_pass_outcome_required")
        if any(
            grade not in {EvidenceGrade.direct, EvidenceGrade.deterministic_derived}
            for grade in self.minimum_hard_evidence
        ):
            raise ValueError("semantic_evidence_cannot_support_hard_pass")
        return self


CORE_SUBTYPES: dict[CorePrimitiveFamily, tuple[str, ...]] = {
    CorePrimitiveFamily.transfer: (
        "external_ingress",
        "request",
        "response",
        "retrieve",
        "publish",
    ),
    CorePrimitiveFamily.transform: (
        "extract",
        "summarize",
        "parameterize",
        "merge",
        "sanitize",
    ),
    CorePrimitiveFamily.mutate: (
        "memory_write",
        "workspace_write",
        "config_update",
        "external_effect",
    ),
    CorePrimitiveFamily.control: (
        "branch",
        "reject",
        "retry",
        "wait",
        "restart",
        "stop",
    ),
}


def make_core_spec(family: CorePrimitiveFamily, subtype: str) -> CorePrimitiveSpec:
    if subtype not in CORE_SUBTYPES[family]:
        raise ValueError(f"unknown_core_subtype:{family.value}:{subtype}")
    observations = {
        CorePrimitiveFamily.transfer: ["artifact_delivery", "target_visibility", "lineage"],
        CorePrimitiveFamily.transform: ["input_artifacts", "output_artifacts", "derivation"],
        CorePrimitiveFamily.mutate: ["pre_state", "post_state", "persistence_scope"],
        CorePrimitiveFamily.control: ["lifecycle_or_policy_event", "enabled_transitions"],
    }[family]
    return CorePrimitiveSpec(
        primitive_id=f"core.{family.value.lower()}.{subtype}@1",
        version="1",
        family=family,
        subtype=subtype,
        public_summary=f"Observable {family.value.lower()} transition: {subtype}.",
        source_roles=["component"],
        target_roles=["component"],
        required_capabilities=[],
        required_observations=observations,
        observable_state_differences=observations,
        allowed_outcomes=list(PrimitiveOutcome),
        minimum_hard_evidence=[EvidenceGrade.direct, EvidenceGrade.deterministic_derived],
    )


def default_core_specs() -> list[CorePrimitiveSpec]:
    return [
        make_core_spec(family, subtype)
        for family, subtypes in CORE_SUBTYPES.items()
        for subtype in subtypes
    ]
