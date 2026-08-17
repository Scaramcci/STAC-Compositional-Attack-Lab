from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field, NonNegativeInt

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.models import (
    DependencyType,
    InteractionArtifact,
    InteractionEdge,
    InteractionEvent,
    InteractionEventType,
    InteractionGraph,
    JoinSemantics,
    RawInteractionTrajectory,
    UnresolvedInteractionLink,
)
from stac_attack_lab.primitives.core import PrimitiveOutcome


class NormalizationAudit(StrictModel):
    schema_version: str = "2.0"
    trajectory_id: str
    source_event_count: NonNegativeInt
    normalized_event_count: NonNegativeInt
    artifact_count: NonNegativeInt
    edge_count: NonNegativeInt
    unresolved_count: NonNegativeInt
    reason_counts: dict[str, NonNegativeInt] = Field(default_factory=dict)
    passed: bool


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"jsonl_row_not_object:{path}:{line_number}")
        rows.append(value)
    return rows


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _source_events(
    trajectory: RawInteractionTrajectory, collection_root: Path
) -> list[dict[str, Any]]:
    event_refs = [ref for ref in trajectory.event_refs if ref.kind == "source_events"]
    if len(event_refs) != 1 or event_refs[0].relative_path is None:
        raise ValueError("trajectory_requires_one_source_events_ref")
    path = collection_root / event_refs[0].relative_path
    if file_hash(path) != event_refs[0].content_hash:
        raise ValueError("source_events_hash_mismatch")
    return _read_jsonl(path)


def _artifact_from_raw(raw: dict[str, Any], producer_event_id: str) -> InteractionArtifact:
    return InteractionArtifact(
        artifact_id=str(raw["artifact_id"]),
        artifact_type=str(raw.get("artifact_type", "observable_payload")),
        content_hash=str(raw["content_hash"]),
        producer_event_id=producer_event_id,
        parent_artifact_ids=[str(item) for item in raw.get("parent_artifact_ids", [])],
        taint_labels=[str(item) for item in raw.get("taint_labels", [])],
        trust_label=str(raw.get("trust_label", "unknown")),
        source_ref_ids=[str(item) for item in raw.get("source_ref_ids", [])],
    )


def normalize_source_events(
    trajectory: RawInteractionTrajectory,
    source_events: list[dict[str, Any]],
    *,
    audit_ref: str,
) -> tuple[InteractionGraph, NormalizationAudit]:
    events: list[InteractionEvent] = []
    artifacts: list[InteractionArtifact] = []
    edges: list[InteractionEdge] = []
    unresolved: list[UnresolvedInteractionLink] = []
    artifact_producers: dict[str, str] = {}
    event_ids: set[str] = set()

    ordered = sorted(
        source_events,
        key=lambda item: (int(item.get("sequence_no", 0)), str(item.get("event_id", ""))),
    )
    for raw in ordered:
        event_id = str(raw["event_id"])
        if event_id in event_ids:
            raise ValueError(f"duplicate_source_event_id:{event_id}")
        event_ids.add(event_id)
        output_ids: list[str] = []
        for raw_artifact in raw.get("output_artifacts", []):
            artifact = _artifact_from_raw(raw_artifact, event_id)
            if artifact.artifact_id in artifact_producers:
                raise ValueError(f"duplicate_source_artifact_id:{artifact.artifact_id}")
            artifact_producers[artifact.artifact_id] = event_id
            artifacts.append(artifact)
            output_ids.append(artifact.artifact_id)
        events.append(
            InteractionEvent(
                event_id=event_id,
                trajectory_id=trajectory.trajectory_id,
                episode_id=trajectory.episode_id,
                session_id=str(raw["session_id"]),
                sequence_no=int(raw["sequence_no"]),
                logical_time=int(raw.get("logical_time", raw["sequence_no"])),
                actor_role=str(raw["actor_role"]),
                event_type=InteractionEventType(str(raw["event_type"])),
                component_role=str(raw["component_role"]),
                operation=str(raw["operation"]),
                status=PrimitiveOutcome(str(raw.get("status", "passed"))),
                input_artifact_ids=[str(item) for item in raw.get("input_artifact_ids", [])],
                output_artifact_ids=output_ids,
                read_state_refs=[str(item) for item in raw.get("read_state_refs", [])],
                write_state_refs=[str(item) for item in raw.get("write_state_refs", [])],
                pre_state_ref=raw.get("pre_state_ref"),
                post_state_ref=raw.get("post_state_ref"),
                request_event_id=raw.get("request_event_id"),
                lifecycle_id=raw.get("lifecycle_id"),
                public_payload=dict(raw.get("public_payload", {})),
                evidence_ref_ids=[str(item) for item in raw.get("evidence_ref_ids", [])],
                source_event_ref=str(raw.get("source_event_ref", event_id)),
            )
        )

    latest_state_writer: dict[str, str] = {}
    edge_keys: set[tuple[str, str, str, str | None, str | None]] = set()

    def add_edge(edge: InteractionEdge) -> None:
        key = (
            edge.edge_type.value,
            edge.source_event_id,
            edge.target_event_id,
            edge.artifact_id,
            edge.state_ref,
        )
        if key not in edge_keys:
            edge_keys.add(key)
            edges.append(edge)

    for raw, event in zip(ordered, events, strict=True):
        for artifact_id in event.input_artifact_ids:
            source_event_id = artifact_producers.get(artifact_id)
            if source_event_id is None:
                unresolved.append(
                    UnresolvedInteractionLink(
                        link_id=f"unresolved-artifact-{event.event_id}-{artifact_id}",
                        reason_code="missing_artifact_producer",
                        target_event_id=event.event_id,
                        source_ref_ids=[artifact_id],
                    )
                )
                continue
            add_edge(
                InteractionEdge(
                    edge_id=f"edge-data-{source_event_id}-{event.event_id}-{artifact_id}",
                    edge_type=DependencyType.data,
                    source_event_id=source_event_id,
                    target_event_id=event.event_id,
                    source_fact=f"artifact:{artifact_id}:produced",
                    target_precondition=f"artifact:{artifact_id}:consumed",
                    artifact_id=artifact_id,
                    evidence_ref_ids=[artifact_id],
                )
            )
        for state_ref in event.read_state_refs:
            source_event_id = latest_state_writer.get(state_ref)
            if source_event_id is None:
                unresolved.append(
                    UnresolvedInteractionLink(
                        link_id=f"unresolved-state-{event.event_id}-{stable_hash(state_ref)[:8]}",
                        reason_code="missing_state_writer",
                        target_event_id=event.event_id,
                        source_ref_ids=[state_ref],
                    )
                )
            else:
                add_edge(
                    InteractionEdge(
                        edge_id=f"edge-state-{source_event_id}-{event.event_id}-{stable_hash(state_ref)[:8]}",
                        edge_type=DependencyType.state,
                        source_event_id=source_event_id,
                        target_event_id=event.event_id,
                        source_fact=f"state:{state_ref}:written",
                        target_precondition=f"state:{state_ref}:read",
                        state_ref=state_ref,
                        evidence_ref_ids=[state_ref],
                    )
                )
        if event.request_event_id:
            if event.request_event_id not in event_ids:
                unresolved.append(
                    UnresolvedInteractionLink(
                        link_id=f"unresolved-request-{event.event_id}",
                        reason_code="missing_request_event",
                        source_event_id=event.request_event_id,
                        target_event_id=event.event_id,
                        source_ref_ids=[],
                    )
                )
            else:
                add_edge(
                    InteractionEdge(
                        edge_id=f"edge-control-{event.request_event_id}-{event.event_id}",
                        edge_type=DependencyType.control,
                        source_event_id=event.request_event_id,
                        target_event_id=event.event_id,
                        source_fact="request_dispatched",
                        target_precondition="request_received",
                        evidence_ref_ids=[event.request_event_id, event.event_id],
                    )
                )
        for dependency in raw.get("dependencies", []):
            source_event_id = str(dependency["source_event_id"])
            if source_event_id not in event_ids:
                unresolved.append(
                    UnresolvedInteractionLink(
                        link_id=f"unresolved-explicit-{event.event_id}-{source_event_id}",
                        reason_code="explicit_dependency_source_missing",
                        source_event_id=source_event_id,
                        target_event_id=event.event_id,
                        source_ref_ids=[
                            str(item) for item in dependency.get("evidence_ref_ids", [])
                        ],
                    )
                )
                continue
            edge_type = DependencyType(str(dependency["edge_type"]))
            add_edge(
                InteractionEdge(
                    edge_id=str(
                        dependency.get(
                            "edge_id", f"edge-{edge_type.value}-{source_event_id}-{event.event_id}"
                        )
                    ),
                    edge_type=edge_type,
                    source_event_id=source_event_id,
                    target_event_id=event.event_id,
                    source_fact=str(dependency["source_fact"]),
                    target_precondition=str(dependency["target_precondition"]),
                    artifact_id=dependency.get("artifact_id"),
                    state_ref=dependency.get("state_ref"),
                    guard=dependency.get("guard"),
                    join_semantics=JoinSemantics(str(dependency.get("join_semantics", "ALL"))),
                    join_k=dependency.get("join_k"),
                    evidence_ref_ids=[str(item) for item in dependency.get("evidence_ref_ids", [])],
                    observable=bool(dependency.get("observable", True)),
                )
            )
        for state_ref in event.write_state_refs:
            latest_state_writer[state_ref] = event.event_id

    artifact_ids = {artifact.artifact_id for artifact in artifacts}
    for artifact in artifacts:
        for parent_id in artifact.parent_artifact_ids:
            if parent_id not in artifact_ids:
                unresolved.append(
                    UnresolvedInteractionLink(
                        link_id=f"unresolved-parent-{artifact.artifact_id}-{parent_id}",
                        reason_code="missing_parent_artifact",
                        source_ref_ids=[artifact.artifact_id, parent_id],
                    )
                )

    graph_payload = {
        "schema_version": "2.0",
        "graph_id": f"graph-{trajectory.trajectory_id}",
        "trajectory_id": trajectory.trajectory_id,
        "observable_projection_version": "formal-observable-v1",
        "source_trajectory_hash": stable_hash(trajectory.model_dump(mode="json")),
        "events": [item.model_dump(mode="json") for item in events],
        "artifacts": [item.model_dump(mode="json") for item in artifacts],
        "edges": [item.model_dump(mode="json") for item in edges],
        "unresolved_links": [item.model_dump(mode="json") for item in unresolved],
        "normalization_audit_ref": audit_ref,
    }
    graph = InteractionGraph.model_validate(
        {**graph_payload, "graph_hash": stable_hash(graph_payload)}
    )
    reason_counts: dict[str, int] = {}
    for finding in unresolved:
        reason_counts[finding.reason_code] = reason_counts.get(finding.reason_code, 0) + 1
    audit = NormalizationAudit(
        trajectory_id=trajectory.trajectory_id,
        source_event_count=len(source_events),
        normalized_event_count=len(events),
        artifact_count=len(artifacts),
        edge_count=len(edges),
        unresolved_count=len(unresolved),
        reason_counts=reason_counts,
        passed=not unresolved,
    )
    return graph, audit


def normalize_trajectory(
    trajectory_path: Path,
    *,
    collection_root: Path,
    output_root: Path,
) -> tuple[Path, Path]:
    trajectory = RawInteractionTrajectory.model_validate_json(
        trajectory_path.read_text(encoding="utf-8")
    )
    target_root = output_root / trajectory.trajectory_id
    audit_path = target_root / "normalization_audit.json"
    graph_path = target_root / "interaction_graph.json"
    source_events = _source_events(trajectory, collection_root)
    graph, audit = normalize_source_events(
        trajectory,
        source_events,
        audit_ref=str(audit_path.relative_to(output_root)),
    )
    _atomic_json(graph_path, graph.model_dump(mode="json"))
    _atomic_json(audit_path, audit.model_dump(mode="json"))
    return graph_path, audit_path
