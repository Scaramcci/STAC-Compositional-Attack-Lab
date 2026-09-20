from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, NonNegativeInt, PositiveInt, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import stable_hash


class PrimitiveKind(StrEnum):
    transfer = "TRANSFER"
    derive = "DERIVE"
    update = "UPDATE"


class ExecutionStatus(StrEnum):
    observed = "observed"
    committed = "committed"
    attempted = "attempted"
    failed = "failed"
    unknown = "unknown"
    not_applicable = "not_applicable"


class ClaimVerdict(StrEnum):
    verified = "verified"
    refuted = "refuted"
    unknown = "unknown"
    unsupported = "unsupported"


class InterventionResult(StrEnum):
    not_evaluated = "not_evaluated"
    observed_change = "observed_change"
    observed_no_change = "observed_no_change"
    unknown = "unknown"


class OfficialOutcome(StrEnum):
    not_evaluated = "not_evaluated"
    passed = "passed"
    failed = "failed"
    unknown = "unknown"


class DependencyRelation(StrEnum):
    correlates_with = "correlates_with"
    delivered_to = "delivered_to"
    available_input = "available_input"
    data_dep = "data_dep"
    control_dep = "control_dep"
    read_from = "read_from"
    happens_before = "happens_before"


class EvidenceMethod(StrEnum):
    direct_observation = "direct_observation_v1"
    request_response_correlation = "request_response_correlation_v1"
    explicit_partial_order = "explicit_partial_order_v1"
    resource_commit = "resource_commit_v1"
    provider_request_context = "provider_request_context_recomputed_v1"
    exact_projection = "exact_utf8_projection_recomputed_v1"
    trusted_control = "trusted_control_instrumentation_v1"
    hypothesis = "hypothesis_only_v1"


class ObservationProfile(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    profile_id: str
    profile_version: str
    observation_boundary: str
    object_granularity: list[str]
    visible_event_types: list[str]
    hidden_components: list[str]
    resource_semantics: str
    projection_rule_version: str
    max_events: PositiveInt = 10000

    @model_validator(mode="after")
    def validate_profile(self) -> ObservationProfile:
        required = {
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "observation_boundary": self.observation_boundary,
            "resource_semantics": self.resource_semantics,
            "projection_rule_version": self.projection_rule_version,
        }
        missing = [name for name, value in required.items() if not value.strip()]
        if missing:
            raise ValueError("observation_profile_fields_missing:" + ",".join(missing))
        for name, values in (
            ("object_granularity", self.object_granularity),
            ("visible_event_types", self.visible_event_types),
            ("hidden_components", self.hidden_components),
        ):
            if not values or any(not value.strip() for value in values):
                raise ValueError(f"observation_profile_{name}_invalid")
            if len(values) != len(set(values)):
                raise ValueError(f"observation_profile_{name}_duplicate")
        return self


class EvidenceRef(StrictModel):
    evidence_id: str
    producer: str
    locator: str
    content_hash: str | None = None
    hash_scope: str
    privacy_scope: Literal["public", "private", "synthetic_private"]
    method: EvidenceMethod
    method_version: str
    sealed_input_id: str

    @model_validator(mode="after")
    def validate_identity(self) -> EvidenceRef:
        for name in ("evidence_id", "producer", "locator", "hash_scope", "sealed_input_id"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"evidence_{name}_missing")
        if self.content_hash is not None and (
            len(self.content_hash) != 64
            or any(char not in "0123456789abcdef" for char in self.content_hash)
        ):
            raise ValueError("evidence_content_hash_invalid")
        return self


class DomainRef(StrictModel):
    domain_id: str
    instance_id: str
    role: str
    actual_session_id: str | None = None
    workspace_scope: str | None = None
    tenant_scope: str | None = None
    identity_evidence_ids: list[str]

    @model_validator(mode="after")
    def validate_domain(self) -> DomainRef:
        if not self.domain_id or not self.instance_id or not self.role:
            raise ValueError("domain_identity_missing")
        if not self.identity_evidence_ids:
            raise ValueError("domain_identity_evidence_missing")
        return self


class Artifact(StrictModel):
    artifact_id: str
    source_instance_id: str
    artifact_type: str
    content_hash: str
    encoding: str
    hash_scope: str
    immutable_value_ref: str | None = None
    source_locator: str
    evidence_ids: list[str]

    @model_validator(mode="after")
    def validate_artifact(self) -> Artifact:
        if not self.artifact_id or not self.source_instance_id or not self.source_locator:
            raise ValueError("artifact_source_identity_missing")
        if len(self.content_hash) != 64 or any(
            char not in "0123456789abcdef" for char in self.content_hash
        ):
            raise ValueError("artifact_content_hash_invalid")
        return self


class PortRef(StrictModel):
    port_id: str
    owner_kind: Literal["effect", "invocation", "resource_version", "domain"]
    owner_id: str
    direction: Literal["input", "output", "state", "endpoint"]
    field_path: str
    data_type: str
    value_scope: Literal["whole", "field", "range", "handle", "summary", "wrapped", "partial"]
    artifact_id: str | None = None
    domain_id: str | None = None
    resource_version_id: str | None = None


class ResourceVersion(StrictModel):
    resource_version_id: str
    resource_id: str
    workspace_scope: str
    version_id: str
    predecessor_version_id: str | None = None
    state: Literal["present", "tombstone", "external_root", "unknown"]
    content_hash: str | None = None
    content_scope: Literal["whole", "partial", "wrapped", "summary", "unknown"] = "unknown"
    commit_evidence_ids: list[str]
    source_event_ids: list[str]

    @model_validator(mode="after")
    def validate_commit(self) -> ResourceVersion:
        if not self.resource_id or not self.workspace_scope or not self.version_id:
            raise ValueError("resource_version_identity_missing")
        if self.state not in {"unknown", "external_root"} and not self.commit_evidence_ids:
            raise ValueError("resource_version_commit_evidence_missing")
        return self


class Effect(StrictModel):
    effect_id: str
    primitive: PrimitiveKind
    domain_ids: list[str]
    input_port_ids: list[str]
    output_port_ids: list[str]
    resource_version_ids: list[str]
    source_event_ids: list[str]
    invocation_id: str | None = None
    transaction_id: str | None = None
    group_id: str | None = None
    execution_status: ExecutionStatus
    evidence_ids: list[str]
    claim_ids: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)


class EffectGroup(StrictModel):
    group_id: str
    operation_instance_id: str
    effect_ids: list[str]
    transaction_id: str | None = None
    atomicity: Literal["atomic", "non_atomic", "unknown"] = "unknown"
    ordered_pairs: list[tuple[str, str]] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class DependencyClaim(StrictModel):
    claim_id: str
    relation: DependencyRelation
    source_port_id: str
    target_port_id: str
    evidence_ids: list[str]
    verifier_id: str
    rule_version: str
    dependency_verdict: ClaimVerdict = ClaimVerdict.unknown
    intervention_result: InterventionResult = InterventionResult.not_evaluated
    reason_code: str = "not_verified"
    hypothesis: bool = False

    @model_validator(mode="after")
    def reject_unproved_intervention(self) -> DependencyClaim:
        if self.intervention_result != InterventionResult.not_evaluated and not self.evidence_ids:
            raise ValueError("intervention_result_requires_evidence")
        if self.dependency_verdict == ClaimVerdict.verified and not self.evidence_ids:
            raise ValueError("verified_claim_requires_evidence")
        return self


class UnresolvedFlow(StrictModel):
    unresolved_id: str
    reason_code: str
    source_event_ids: list[str]
    related_ids: list[str] = Field(default_factory=list)


class EffectGraph(StrictModel):
    schema_version: Literal["3.0"] = "3.0"
    graph_id: str
    profile_id: str
    profile_version: str
    source_graph_id: str
    source_graph_hash: str
    domains: list[DomainRef]
    artifacts: list[Artifact]
    ports: list[PortRef]
    resource_versions: list[ResourceVersion]
    effects: list[Effect]
    effect_groups: list[EffectGroup]
    claims: list[DependencyClaim]
    unresolved: list[UnresolvedFlow]
    official_outcome: OfficialOutcome = OfficialOutcome.not_evaluated
    graph_hash: str

    @model_validator(mode="after")
    def validate_graph(self) -> EffectGraph:
        collections = {
            "domain": [item.domain_id for item in self.domains],
            "artifact": [item.artifact_id for item in self.artifacts],
            "port": [item.port_id for item in self.ports],
            "resource_version": [item.resource_version_id for item in self.resource_versions],
            "effect": [item.effect_id for item in self.effects],
            "effect_group": [item.group_id for item in self.effect_groups],
            "claim": [item.claim_id for item in self.claims],
        }
        for kind, identifiers in collections.items():
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"duplicate_v3_{kind}_id")
        domains, artifacts, ports = (
            set(collections["domain"]),
            set(collections["artifact"]),
            set(collections["port"]),
        )
        resources, effects = set(collections["resource_version"]), set(collections["effect"])
        for port in self.ports:
            if port.artifact_id is not None and port.artifact_id not in artifacts:
                raise ValueError(f"port_unknown_artifact:{port.port_id}")
            if port.domain_id is not None and port.domain_id not in domains:
                raise ValueError(f"port_unknown_domain:{port.port_id}")
            if port.resource_version_id is not None and port.resource_version_id not in resources:
                raise ValueError(f"port_unknown_resource_version:{port.port_id}")
        for effect in self.effects:
            if not set(effect.domain_ids) <= domains:
                raise ValueError(f"effect_unknown_domain:{effect.effect_id}")
            if not set(effect.input_port_ids + effect.output_port_ids) <= ports:
                raise ValueError(f"effect_unknown_port:{effect.effect_id}")
            if not set(effect.resource_version_ids) <= resources:
                raise ValueError(f"effect_unknown_resource_version:{effect.effect_id}")
        for group in self.effect_groups:
            if not set(group.effect_ids) <= effects:
                raise ValueError(f"effect_group_unknown_effect:{group.group_id}")
            if any(
                left not in effects or right not in effects for left, right in group.ordered_pairs
            ):
                raise ValueError(f"effect_group_order_unknown_effect:{group.group_id}")
        for claim in self.claims:
            if claim.source_port_id not in ports or claim.target_port_id not in ports:
                raise ValueError(f"claim_unknown_port:{claim.claim_id}")
        expected = self.model_dump(mode="json", exclude={"graph_hash"})
        if self.graph_hash != stable_hash(expected):
            raise ValueError("effect_graph_hash_mismatch")
        return self


class FlowObservation(StrictModel):
    """Neutral, adapter-produced facts; primitive names are intentionally absent."""

    schema_version: Literal["3.0"] = "3.0"
    observation_id: str
    event_type: str
    source_event_ids: list[str]
    domain: DomainRef
    execution_status: ExecutionStatus
    evidence_ids: list[str]
    sequence_no: NonNegativeInt | None = None
    invocation_id: str | None = None
    operation_instance_id: str | None = None
    transaction_id: str | None = None
    correlation_id: str | None = None
    explicit_predecessor_ids: list[str] = Field(default_factory=list)
    input_artifact_ids: list[str] = Field(default_factory=list)
    output_artifact_ids: list[str] = Field(default_factory=list)
    endpoint_domain: DomainRef | None = None
    field_paths: dict[str, str] = Field(default_factory=dict)
    resource_id: str | None = None
    resource_scope: str | None = None
    before_version_id: str | None = None
    after_version_id: str | None = None
    read_version_id: str | None = None
    resource_state: Literal["present", "tombstone", "external_root", "unknown"] | None = None
    read_scope: Literal["whole", "partial", "wrapped", "summary", "unknown"] | None = None
    commit_evidence_ids: list[str] = Field(default_factory=list)
    control_source_observation_ids: list[str] = Field(default_factory=list)
    actual_session_before: str | None = None
    actual_session_after: str | None = None
    restart_requested: bool = False
    opaque: bool = False


def effect_graph_hash(payload: dict[str, Any]) -> str:
    return stable_hash({key: value for key, value in payload.items() if key != "graph_hash"})
