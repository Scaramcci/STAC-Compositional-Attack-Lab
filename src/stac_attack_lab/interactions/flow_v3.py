from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any, Literal

from stac_attack_lab.flow.models import (
    Artifact,
    DependencyClaim,
    DependencyRelation,
    DomainRef,
    Effect,
    EffectGraph,
    EffectGroup,
    EvidenceMethod,
    EvidenceRef,
    ExecutionStatus,
    FlowObservation,
    ObservationProfile,
    PortRef,
    PrimitiveKind,
    ResourceVersion,
    UnresolvedFlow,
    effect_graph_hash,
)
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.models import InteractionGraph
from stac_attack_lab.primitives.core import PrimitiveOutcome


def _identifier(prefix: str, value: object) -> str:
    return f"{prefix}-{stable_hash(value)[:20]}"


def _execution_status(value: PrimitiveOutcome) -> ExecutionStatus:
    return {
        PrimitiveOutcome.passed: ExecutionStatus.observed,
        PrimitiveOutcome.rejected: ExecutionStatus.failed,
        PrimitiveOutcome.error: ExecutionStatus.failed,
        PrimitiveOutcome.timeout: ExecutionStatus.failed,
        PrimitiveOutcome.not_observable: ExecutionStatus.unknown,
        PrimitiveOutcome.attempted: ExecutionStatus.attempted,
    }.get(value, ExecutionStatus.unknown)


def _read_scope(value: object) -> Literal["whole", "partial", "wrapped", "summary", "unknown"]:
    return {
        "whole": "whole",
        "partial": "partial",
        "wrapped": "wrapped",
        "summary": "summary",
    }.get(str(value), "unknown")  # type: ignore[return-value]


def observations_from_interaction_graph(
    graph: InteractionGraph,
) -> tuple[list[FlowObservation], list[Artifact], list[EvidenceRef]]:
    """Adapt legacy normalized facts without inheriting legacy edge verdicts."""

    artifacts: list[Artifact] = []
    evidence: dict[str, EvidenceRef] = {}
    events = {event.event_id: event for event in graph.events}
    for item in graph.artifacts:
        producer = events.get(item.producer_event_id or "")
        source_instance = (
            str(producer.public_payload.get("actual_session_identity_sha256"))
            if producer and producer.public_payload.get("actual_session_identity_sha256")
            else f"legacy-event:{item.producer_event_id or 'external'}"
        )
        artifacts.append(
            Artifact(
                artifact_id=f"v3:{item.artifact_id}",
                source_instance_id=source_instance,
                artifact_type=item.artifact_type,
                content_hash=(
                    item.content_hash
                    if len(item.content_hash) == 64
                    else stable_hash({"legacy_declared_content_identity": item.content_hash})
                ),
                encoding="legacy-declared",
                hash_scope=(
                    "legacy_interaction_artifact_projection"
                    if len(item.content_hash) == 64
                    else "hash_of_legacy_declared_content_identity"
                ),
                source_locator=item.source_ref_ids[0] if item.source_ref_ids else item.artifact_id,
                evidence_ids=[],
            )
        )

    observations: list[FlowObservation] = []
    for event in graph.events:
        direct_evidence_id = _identifier(
            "evidence",
            {"graph": graph.graph_id, "event": event.event_id, "source": event.source_event_ref},
        )
        evidence[direct_evidence_id] = EvidenceRef(
            evidence_id=direct_evidence_id,
            producer="legacy_interaction_graph_adapter",
            locator=event.source_event_ref,
            hash_scope="source_event_reference",
            privacy_scope="public",
            method=EvidenceMethod.direct_observation,
            method_version="1.0",
            sealed_input_id=graph.source_trajectory_hash,
        )
        actual_session = event.public_payload.get("actual_session_identity_sha256")
        workspace = event.public_payload.get("workspace_identity_sha256")
        domain = DomainRef(
            domain_id=_identifier(
                "domain",
                {
                    "trajectory": graph.trajectory_id,
                    "role": event.actor_role,
                    "actual_session": actual_session,
                    "legacy_session": event.session_id,
                    "workspace": workspace,
                },
            ),
            instance_id=str(
                actual_session or f"legacy-session:{event.session_id}:{event.actor_role}"
            ),
            role=event.actor_role,
            actual_session_id=str(actual_session) if actual_session else None,
            workspace_scope=str(workspace) if workspace else None,
            tenant_scope=None,
            identity_evidence_ids=[direct_evidence_id],
        )
        endpoint_role = event.public_payload.get("recipient_role")
        endpoint = None
        if isinstance(endpoint_role, str) and endpoint_role:
            endpoint = DomainRef(
                domain_id=_identifier(
                    "domain",
                    {
                        "trajectory": graph.trajectory_id,
                        "role": endpoint_role,
                        "session": actual_session or event.session_id,
                        "workspace": workspace,
                    },
                ),
                instance_id=f"{actual_session or event.session_id}:{endpoint_role}",
                role=endpoint_role,
                actual_session_id=str(actual_session) if actual_session else None,
                workspace_scope=str(workspace) if workspace else None,
                tenant_scope=None,
                identity_evidence_ids=[direct_evidence_id],
            )
        payload = event.public_payload
        resource_id = payload.get("resource_id") or (
            event.write_state_refs[0]
            if event.write_state_refs
            else event.read_state_refs[0]
            if event.read_state_refs
            else None
        )
        observation_type = event.event_type.value
        if observation_type == "message" and event.component_role == "model_response":
            observation_type = "model_response"
        observations.append(
            FlowObservation(
                observation_id=f"legacy:{event.event_id}",
                event_type=observation_type,
                source_event_ids=[event.event_id],
                domain=domain,
                execution_status=_execution_status(event.status),
                evidence_ids=[direct_evidence_id],
                sequence_no=event.sequence_no,
                invocation_id=str(
                    payload.get("provider_request_id") or event.request_event_id or ""
                )
                or None,
                operation_instance_id=str(
                    payload.get("operation_instance_id") or event.request_event_id or event.event_id
                ),
                transaction_id=str(payload.get("transaction_id") or "") or None,
                correlation_id=event.request_event_id,
                input_artifact_ids=[f"v3:{item}" for item in event.input_artifact_ids],
                output_artifact_ids=[f"v3:{item}" for item in event.output_artifact_ids],
                endpoint_domain=endpoint,
                resource_id=str(resource_id) if resource_id else None,
                resource_scope=str(workspace) if workspace else None,
                before_version_id=str(payload.get("pre_version_id") or event.pre_state_ref or "")
                or None,
                after_version_id=str(payload.get("post_version_id") or event.post_state_ref or "")
                or None,
                read_version_id=str(payload.get("read_version_id") or "") or None,
                resource_state=(
                    "tombstone"
                    if payload.get("tombstone") is True
                    else "present"
                    if event.post_state_ref
                    else None
                ),
                read_scope=_read_scope(payload.get("read_scope")),
                commit_evidence_ids=[direct_evidence_id]
                if payload.get("commit_observed") is True
                else [],
                actual_session_before=str(
                    payload.get("previous_actual_session_identity_sha256") or ""
                )
                or None,
                actual_session_after=str(payload.get("actual_session_identity_sha256") or "")
                or None,
                restart_requested=bool(payload.get("restart_requested", False)),
                opaque=bool(payload.get("opaque", False)),
            )
        )
    return observations, artifacts, sorted(evidence.values(), key=lambda item: item.evidence_id)


def _deduplicate_observations(
    observations: Iterable[FlowObservation],
) -> tuple[list[FlowObservation], list[UnresolvedFlow]]:
    by_fingerprint: dict[str, FlowObservation] = {}
    by_id: dict[str, FlowObservation] = {}
    unresolved: list[UnresolvedFlow] = []
    for observation in observations:
        previous = by_id.get(observation.observation_id)
        if previous is not None and previous != observation:
            unresolved.append(
                UnresolvedFlow(
                    unresolved_id=_identifier(
                        "unresolved", [observation.observation_id, "conflict"]
                    ),
                    reason_code="conflicting_duplicate_observation_id",
                    source_event_ids=sorted(
                        set(previous.source_event_ids + observation.source_event_ids)
                    ),
                )
            )
            continue
        by_id[observation.observation_id] = observation
        fingerprint = stable_hash(
            observation.model_dump(
                mode="json", exclude={"observation_id", "evidence_ids", "sequence_no"}
            )
        )
        if fingerprint in by_fingerprint:
            old = by_fingerprint[fingerprint]
            by_fingerprint[fingerprint] = old.model_copy(
                update={
                    "evidence_ids": sorted(set(old.evidence_ids + observation.evidence_ids)),
                    "source_event_ids": sorted(
                        set(old.source_event_ids + observation.source_event_ids)
                    ),
                }
            )
        else:
            by_fingerprint[fingerprint] = observation
    return sorted(by_fingerprint.values(), key=lambda item: item.observation_id), unresolved


def project_effect_graph(
    *,
    source_graph_id: str,
    source_graph_hash: str,
    observations: list[FlowObservation],
    artifacts: list[Artifact],
    evidence: list[EvidenceRef],
    profile: ObservationProfile,
    external_claims: list[DependencyClaim] | None = None,
) -> EffectGraph:
    if len(observations) > profile.max_events:
        raise ValueError("v3_profile_event_limit_exceeded")
    observations, unresolved = _deduplicate_observations(observations)
    evidence_ids = {item.evidence_id for item in evidence}
    artifact_ids = {item.artifact_id for item in artifacts}
    for observation in observations:
        if observation.event_type not in profile.visible_event_types:
            unresolved.append(
                UnresolvedFlow(
                    unresolved_id=_identifier("unresolved", [observation.observation_id, "hidden"]),
                    reason_code="event_type_outside_observation_profile",
                    source_event_ids=observation.source_event_ids,
                )
            )
        if not set(observation.evidence_ids + observation.commit_evidence_ids) <= evidence_ids:
            unresolved.append(
                UnresolvedFlow(
                    unresolved_id=_identifier(
                        "unresolved", [observation.observation_id, "evidence"]
                    ),
                    reason_code="observation_evidence_reference_missing",
                    source_event_ids=observation.source_event_ids,
                )
            )

    domains: dict[str, DomainRef] = {}
    for observation in observations:
        domains[observation.domain.domain_id] = observation.domain
        if observation.endpoint_domain:
            domains[observation.endpoint_domain.domain_id] = observation.endpoint_domain
    ports: dict[str, PortRef] = {}
    resources: dict[str, ResourceVersion] = {}
    effects: dict[str, Effect] = {}
    claims: dict[str, DependencyClaim] = {item.claim_id: item for item in (external_claims or [])}
    observations_by_operation: dict[str, list[FlowObservation]] = defaultdict(list)
    for observation in observations:
        observations_by_operation[
            observation.operation_instance_id or observation.observation_id
        ].append(observation)

    # Establish all explicit committed versions before projecting reads. This
    # keeps read-from resolution invariant under harmless log reordering.
    for observation in observations:
        if (
            observation.event_type == "state_write"
            and observation.execution_status
            not in {ExecutionStatus.failed, ExecutionStatus.unknown}
            and observation.resource_id
            and observation.resource_scope
            and observation.after_version_id
            and observation.commit_evidence_ids
            and observation.before_version_id != observation.after_version_id
        ):
            version_id = _identifier(
                "resource-version",
                [
                    observation.resource_scope,
                    observation.resource_id,
                    observation.after_version_id,
                    observation.operation_instance_id,
                ],
            )
            resources[version_id] = ResourceVersion(
                resource_version_id=version_id,
                resource_id=observation.resource_id,
                workspace_scope=observation.resource_scope,
                version_id=observation.after_version_id,
                predecessor_version_id=observation.before_version_id,
                state=observation.resource_state or "present",
                content_scope="unknown",
                commit_evidence_ids=observation.commit_evidence_ids,
                source_event_ids=observation.source_event_ids,
            )

    def port(
        *,
        owner_kind: str,
        owner_id: str,
        direction: str,
        field_path: str,
        data_type: str,
        value_scope: str = "whole",
        artifact_id: str | None = None,
        domain_id: str | None = None,
        resource_version_id: str | None = None,
    ) -> str:
        port_id = _identifier(
            "port",
            [
                owner_kind,
                owner_id,
                direction,
                field_path,
                artifact_id,
                domain_id,
                resource_version_id,
            ],
        )
        ports.setdefault(
            port_id,
            PortRef(
                port_id=port_id,
                owner_kind=owner_kind,  # type: ignore[arg-type]
                owner_id=owner_id,
                direction=direction,  # type: ignore[arg-type]
                field_path=field_path,
                data_type=data_type,
                value_scope=value_scope,  # type: ignore[arg-type]
                artifact_id=artifact_id,
                domain_id=domain_id,
                resource_version_id=resource_version_id,
            ),
        )
        return port_id

    def emit_effect(
        observation: FlowObservation,
        primitive: PrimitiveKind,
        tag: str,
        *,
        input_ports: list[str],
        output_ports: list[str],
        resource_versions: list[str] | None = None,
        status: ExecutionStatus | None = None,
        reasons: list[str] | None = None,
    ) -> Effect:
        operation_id = observation.operation_instance_id or observation.observation_id
        related = observations_by_operation[operation_id]
        effect_id = _identifier(
            "effect",
            {
                "source_graph": source_graph_id,
                "operation": operation_id,
                "primitive": primitive.value,
                "tag": tag,
                "resource_versions": sorted(resource_versions or []),
            },
        )
        value = Effect(
            effect_id=effect_id,
            primitive=primitive,
            domain_ids=sorted(
                {item.domain.domain_id for item in related}
                | (
                    {observation.endpoint_domain.domain_id}
                    if observation.endpoint_domain is not None
                    else set()
                )
            ),
            input_port_ids=sorted(set(input_ports)),
            output_port_ids=sorted(set(output_ports)),
            resource_version_ids=sorted(set(resource_versions or [])),
            source_event_ids=sorted(
                {event_id for item in related for event_id in item.source_event_ids}
            ),
            invocation_id=observation.invocation_id,
            transaction_id=observation.transaction_id,
            group_id=_identifier("group", observation.transaction_id or operation_id),
            execution_status=status or observation.execution_status,
            evidence_ids=sorted(
                {
                    evidence_id
                    for related_item in related
                    for evidence_id in related_item.evidence_ids
                }
            ),
            reason_codes=reasons or [],
        )
        effects.setdefault(effect_id, value)
        return effects[effect_id]

    observation_ports: dict[str, dict[str, list[str]]] = {}
    for observation in observations:
        if observation.event_type not in profile.visible_event_types:
            continue
        in_ports = [
            port(
                owner_kind="invocation",
                owner_id=(
                    observation.invocation_id
                    or observation.operation_instance_id
                    or observation.observation_id
                ),
                direction="input",
                field_path=observation.field_paths.get(item, f"/artifacts/{index}"),
                data_type="artifact",
                artifact_id=item,
            )
            for index, item in enumerate(observation.input_artifact_ids)
            if item in artifact_ids
        ]
        out_ports = [
            port(
                owner_kind="invocation",
                owner_id=(
                    observation.invocation_id
                    or observation.operation_instance_id
                    or observation.observation_id
                ),
                direction="output",
                field_path=observation.field_paths.get(item, f"/outputs/{index}"),
                data_type="artifact",
                artifact_id=item,
            )
            for index, item in enumerate(observation.output_artifact_ids)
            if item in artifact_ids
        ]
        observation_ports[observation.observation_id] = {"input": in_ports, "output": out_ports}
        if observation.opaque:
            unresolved.append(
                UnresolvedFlow(
                    unresolved_id=_identifier("unresolved", [observation.observation_id, "opaque"]),
                    reason_code="opaque_internal_processing",
                    source_event_ids=observation.source_event_ids,
                )
            )
        if observation.event_type in {"model_response", "tool_call"}:
            derive = emit_effect(
                observation,
                PrimitiveKind.derive,
                "invocation_output",
                input_ports=in_ports,
                output_ports=out_ports,
                reasons=["input_contribution_unverified"] if in_ports else [],
            )
            for source in in_ports:
                for target in out_ports:
                    claim_id = _identifier("claim", [derive.effect_id, source, target, "data_dep"])
                    claims.setdefault(
                        claim_id,
                        DependencyClaim(
                            claim_id=claim_id,
                            relation=DependencyRelation.data_dep,
                            source_port_id=source,
                            target_port_id=target,
                            evidence_ids=[],
                            verifier_id="stac.flow.verifier",
                            rule_version="3.0.0",
                            reason_code="field_dependency_not_observed",
                            hypothesis=True,
                        ),
                    )
        if observation.event_type in {"message", "tool_call", "tool_result", "state_read"}:
            target_domain = observation.endpoint_domain or observation.domain
            endpoint_port = port(
                owner_kind="domain",
                owner_id=target_domain.domain_id,
                direction="endpoint",
                field_path="/inbox",
                data_type="delivered_artifact",
                domain_id=target_domain.domain_id,
            )
            transfer_inputs = out_ports or in_ports
            transfer = emit_effect(
                observation,
                PrimitiveKind.transfer,
                observation.event_type,
                input_ports=transfer_inputs,
                output_ports=[endpoint_port],
                status=(
                    ExecutionStatus.unknown
                    if observation.execution_status == ExecutionStatus.attempted
                    else observation.execution_status
                ),
                reasons=(
                    ["attempt_does_not_prove_delivery"]
                    if observation.execution_status == ExecutionStatus.attempted
                    else []
                ),
            )
            for source in transfer_inputs:
                claim_id = _identifier("claim", [transfer.effect_id, source, endpoint_port])
                claims.setdefault(
                    claim_id,
                    DependencyClaim(
                        claim_id=claim_id,
                        relation=DependencyRelation.delivered_to,
                        source_port_id=source,
                        target_port_id=endpoint_port,
                        evidence_ids=(
                            []
                            if observation.execution_status == ExecutionStatus.attempted
                            else observation.evidence_ids
                        ),
                        verifier_id="stac.flow.verifier",
                        rule_version="3.0.0",
                        reason_code="awaiting_independent_verification",
                    ),
                )
        if observation.event_type == "state_write":
            if observation.execution_status in {ExecutionStatus.failed, ExecutionStatus.unknown}:
                unresolved.append(
                    UnresolvedFlow(
                        unresolved_id=_identifier(
                            "unresolved", [observation.observation_id, "write"]
                        ),
                        reason_code="resource_write_not_committed",
                        source_event_ids=observation.source_event_ids,
                    )
                )
            elif not (
                observation.resource_id
                and observation.resource_scope
                and observation.after_version_id
                and observation.commit_evidence_ids
            ):
                unresolved.append(
                    UnresolvedFlow(
                        unresolved_id=_identifier(
                            "unresolved", [observation.observation_id, "commit"]
                        ),
                        reason_code="resource_commit_evidence_incomplete",
                        source_event_ids=observation.source_event_ids,
                    )
                )
            elif observation.before_version_id == observation.after_version_id:
                unresolved.append(
                    UnresolvedFlow(
                        unresolved_id=_identifier(
                            "unresolved", [observation.observation_id, "noop"]
                        ),
                        reason_code="resource_write_no_effect_observed",
                        source_event_ids=observation.source_event_ids,
                    )
                )
            else:
                version_id = _identifier(
                    "resource-version",
                    [
                        observation.resource_scope,
                        observation.resource_id,
                        observation.after_version_id,
                        observation.operation_instance_id,
                    ],
                )
                resources[version_id] = ResourceVersion(
                    resource_version_id=version_id,
                    resource_id=observation.resource_id,
                    workspace_scope=observation.resource_scope,
                    version_id=observation.after_version_id,
                    predecessor_version_id=observation.before_version_id,
                    state=observation.resource_state or "present",
                    content_scope="unknown",
                    commit_evidence_ids=observation.commit_evidence_ids,
                    source_event_ids=observation.source_event_ids,
                )
                state_port = port(
                    owner_kind="resource_version",
                    owner_id=version_id,
                    direction="state",
                    field_path="/state",
                    data_type="resource_version",
                    resource_version_id=version_id,
                )
                emit_effect(
                    observation,
                    PrimitiveKind.update,
                    "resource_commit",
                    input_ports=in_ports,
                    output_ports=[state_port],
                    resource_versions=[version_id],
                    status=ExecutionStatus.committed,
                )
        if observation.event_type == "state_read":
            if not (
                observation.resource_id
                and observation.resource_scope
                and observation.read_version_id
            ):
                unresolved.append(
                    UnresolvedFlow(
                        unresolved_id=_identifier(
                            "unresolved", [observation.observation_id, "read"]
                        ),
                        reason_code="resource_read_version_unknown",
                        source_event_ids=observation.source_event_ids,
                    )
                )
            else:
                candidates = [
                    item
                    for item in resources.values()
                    if item.resource_id == observation.resource_id
                    and item.workspace_scope == observation.resource_scope
                    and item.version_id == observation.read_version_id
                ]
                if len(candidates) != 1:
                    unresolved.append(
                        UnresolvedFlow(
                            unresolved_id=_identifier(
                                "unresolved", [observation.observation_id, "read-from"]
                            ),
                            reason_code=(
                                "resource_read_version_not_observed"
                                if not candidates
                                else "resource_read_version_ambiguous"
                            ),
                            source_event_ids=observation.source_event_ids,
                        )
                    )
                else:
                    version = candidates[0]
                    state_port = port(
                        owner_kind="resource_version",
                        owner_id=version.resource_version_id,
                        direction="state",
                        field_path="/state",
                        data_type="resource_version",
                        value_scope=observation.read_scope or "unknown",
                        resource_version_id=version.resource_version_id,
                    )
                    for target in out_ports:
                        claim_id = _identifier("claim", [state_port, target, "read_from"])
                        claims[claim_id] = DependencyClaim(
                            claim_id=claim_id,
                            relation=DependencyRelation.read_from,
                            source_port_id=state_port,
                            target_port_id=target,
                            evidence_ids=observation.evidence_ids + version.commit_evidence_ids,
                            verifier_id="stac.flow.verifier",
                            rule_version="3.0.0",
                            reason_code="awaiting_independent_verification",
                        )
        if observation.event_type == "lifecycle":
            if (
                observation.actual_session_before
                and observation.actual_session_after
                and observation.actual_session_before != observation.actual_session_after
                and observation.commit_evidence_ids
            ):
                session_version = _identifier(
                    "resource-version",
                    [
                        "session",
                        observation.actual_session_after,
                        observation.operation_instance_id,
                    ],
                )
                resources[session_version] = ResourceVersion(
                    resource_version_id=session_version,
                    resource_id="session",
                    workspace_scope=observation.domain.workspace_scope or "unknown-workspace",
                    version_id=observation.actual_session_after,
                    predecessor_version_id=observation.actual_session_before,
                    state="present",
                    commit_evidence_ids=observation.commit_evidence_ids,
                    source_event_ids=observation.source_event_ids,
                )
                state_port = port(
                    owner_kind="resource_version",
                    owner_id=session_version,
                    direction="state",
                    field_path="/actual_session",
                    data_type="session_identity",
                    resource_version_id=session_version,
                )
                emit_effect(
                    observation,
                    PrimitiveKind.update,
                    "session_transition",
                    input_ports=[],
                    output_ports=[state_port],
                    resource_versions=[session_version],
                    status=ExecutionStatus.committed,
                )
            elif observation.restart_requested:
                unresolved.append(
                    UnresolvedFlow(
                        unresolved_id=_identifier(
                            "unresolved", [observation.observation_id, "restart"]
                        ),
                        reason_code="restart_requested_without_observed_session_transition",
                        source_event_ids=observation.source_event_ids,
                    )
                )

    by_correlation: dict[str, list[FlowObservation]] = defaultdict(list)
    by_observation_id = {item.observation_id: item for item in observations}
    for observation in observations:
        if observation.correlation_id:
            by_correlation[observation.correlation_id].append(observation)
        for predecessor_id in observation.explicit_predecessor_ids:
            predecessor_ports = observation_ports.get(predecessor_id, {})
            current_ports = observation_ports.get(observation.observation_id, {})
            if (
                predecessor_id not in by_observation_id
                or not predecessor_ports
                or not current_ports
            ):
                unresolved.append(
                    UnresolvedFlow(
                        unresolved_id=_identifier(
                            "unresolved", [observation.observation_id, predecessor_id, "order"]
                        ),
                        reason_code="explicit_predecessor_missing",
                        source_event_ids=observation.source_event_ids,
                    )
                )
                continue
            source = (predecessor_ports.get("output") or predecessor_ports.get("input") or [])[0]
            target = (current_ports.get("input") or current_ports.get("output") or [])[0]
            claim_id = _identifier("claim", [source, target, "happens_before"])
            claims[claim_id] = DependencyClaim(
                claim_id=claim_id,
                relation=DependencyRelation.happens_before,
                source_port_id=source,
                target_port_id=target,
                evidence_ids=observation.evidence_ids,
                verifier_id="stac.flow.verifier",
                rule_version="3.0.0",
                reason_code="awaiting_independent_verification",
            )
        for control_source_id in observation.control_source_observation_ids:
            source_ports = observation_ports.get(control_source_id, {})
            current_ports = observation_ports.get(observation.observation_id, {})
            source_options = source_ports.get("output") or source_ports.get("input") or []
            target_options = current_ports.get("input") or current_ports.get("output") or []
            if (
                control_source_id not in by_observation_id
                or not source_options
                or not target_options
            ):
                unresolved.append(
                    UnresolvedFlow(
                        unresolved_id=_identifier(
                            "unresolved",
                            [observation.observation_id, control_source_id, "control"],
                        ),
                        reason_code="control_dependency_endpoint_missing",
                        source_event_ids=observation.source_event_ids,
                    )
                )
                continue
            claim_id = _identifier("claim", [source_options[0], target_options[0], "control_dep"])
            claims[claim_id] = DependencyClaim(
                claim_id=claim_id,
                relation=DependencyRelation.control_dep,
                source_port_id=source_options[0],
                target_port_id=target_options[0],
                evidence_ids=observation.evidence_ids,
                verifier_id="stac.flow.verifier",
                rule_version="3.0.0",
                reason_code="awaiting_independent_verification",
            )
    for correlation_id, items in by_correlation.items():
        if len(items) != 2:
            unresolved.append(
                UnresolvedFlow(
                    unresolved_id=_identifier("unresolved", [correlation_id, "correlation"]),
                    reason_code="correlation_endpoint_ambiguous",
                    source_event_ids=sorted(
                        {event for item in items for event in item.source_event_ids}
                    ),
                )
            )
            continue
        left, right = sorted(items, key=lambda item: item.observation_id)
        left_ports = observation_ports.get(left.observation_id, {})
        right_ports = observation_ports.get(right.observation_id, {})
        source_options = left_ports.get("output") or left_ports.get("input") or []
        target_options = right_ports.get("input") or right_ports.get("output") or []
        if source_options and target_options:
            claim_id = _identifier("claim", [correlation_id, "correlates_with"])
            claims[claim_id] = DependencyClaim(
                claim_id=claim_id,
                relation=DependencyRelation.correlates_with,
                source_port_id=source_options[0],
                target_port_id=target_options[0],
                evidence_ids=sorted(set(left.evidence_ids + right.evidence_ids)),
                verifier_id="stac.flow.verifier",
                rule_version="3.0.0",
                reason_code="awaiting_independent_verification",
            )

    groups: list[EffectGroup] = []
    grouped_effects: dict[str, list[Effect]] = defaultdict(list)
    for effect in effects.values():
        if effect.group_id:
            grouped_effects[effect.group_id].append(effect)
    for group_id, members in grouped_effects.items():
        operation_ids = {
            item.operation_instance_id or item.observation_id
            for item in observations
            if set(item.source_event_ids)
            & {event for member in members for event in member.source_event_ids}
        }
        groups.append(
            EffectGroup(
                group_id=group_id,
                operation_instance_id=sorted(operation_ids)[0] if operation_ids else group_id,
                effect_ids=sorted(item.effect_id for item in members),
                transaction_id=next(
                    (item.transaction_id for item in members if item.transaction_id), None
                ),
                atomicity=(
                    "atomic"
                    if any(item.transaction_id for item in members) and len(members) > 1
                    else "unknown"
                ),
                ordered_pairs=[],
                evidence_ids=sorted({eid for item in members for eid in item.evidence_ids}),
            )
        )

    payload: dict[str, Any] = {
        "schema_version": "3.0",
        "graph_id": _identifier(
            "flow-graph", [source_graph_hash, profile.profile_id, profile.profile_version]
        ),
        "profile_id": profile.profile_id,
        "profile_version": profile.profile_version,
        "source_graph_id": source_graph_id,
        "source_graph_hash": source_graph_hash,
        "domains": [
            item.model_dump(mode="json")
            for item in sorted(domains.values(), key=lambda x: x.domain_id)
        ],
        "artifacts": [
            item.model_dump(mode="json") for item in sorted(artifacts, key=lambda x: x.artifact_id)
        ],
        "ports": [
            item.model_dump(mode="json") for item in sorted(ports.values(), key=lambda x: x.port_id)
        ],
        "resource_versions": [
            item.model_dump(mode="json")
            for item in sorted(resources.values(), key=lambda x: x.resource_version_id)
        ],
        "effects": [
            item.model_dump(mode="json")
            for item in sorted(effects.values(), key=lambda x: x.effect_id)
        ],
        "effect_groups": [
            item.model_dump(mode="json") for item in sorted(groups, key=lambda x: x.group_id)
        ],
        "claims": [
            item.model_dump(mode="json")
            for item in sorted(claims.values(), key=lambda x: x.claim_id)
        ],
        "unresolved": [
            item.model_dump(mode="json")
            for item in sorted(unresolved, key=lambda x: x.unresolved_id)
        ],
        "official_outcome": "not_evaluated",
    }
    payload["graph_hash"] = effect_graph_hash(payload)
    return EffectGraph.model_validate(payload)
