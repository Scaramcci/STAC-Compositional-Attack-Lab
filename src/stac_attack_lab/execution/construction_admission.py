"""Engineering admission is independent of sample acceptance and official outcomes."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.models import InteractionGraph, RawInteractionTrajectory

IDENTITY = re.compile(r"^[0-9a-f]{64}$")


def _identity(event: Any, name: str) -> str | None:
    value = event.public_payload.get(name)
    return value if isinstance(value, str) and IDENTITY.fullmatch(value) else None


def construction_admission(
    trajectory: RawInteractionTrajectory,
    graph: InteractionGraph,
    *,
    accepted_count: int,
    library_audit_passed: bool,
) -> dict[str, Any]:
    """Check observed causal paths, never infer dependencies from temporal adjacency."""
    events = {event.event_id: event for event in graph.events}
    identity_field = "actual_session_identity_sha256"
    scope_fields = ("workspace_identity_sha256", "memory_index_namespace_sha256")
    deliveries = [e for e in graph.events if e.operation == "deliver_external_ingress"]
    identities_valid = bool(deliveries) and all(
        _identity(e, identity_field) and all(_identity(e, name) for name in scope_fields)
        for e in deliveries
    )
    paths: list[list[str]] = []
    for first in graph.edges:
        write, read = events[first.source_event_id], events[first.target_event_id]
        if not (
            first.observable
            and first.evidence_ref_ids
            and first.edge_type in {"data", "state"}
            and write.event_type == "state_write"
            and write.component_role == "persistent_memory"
            and read.event_type == "state_read"
            and read.component_role == "persistent_memory"
            and write.status == read.status == "passed"
            and _identity(write, identity_field)
            and _identity(read, identity_field)
            and _identity(write, identity_field) != _identity(read, identity_field)
            and all(
                _identity(write, f) and _identity(write, f) == _identity(read, f)
                for f in scope_fields
            )
            and read.operation in {"memory_retrieve", "memory_retrieve_later_session"}
            and read.public_payload.get("retrieval_hit") is True
            and read.public_payload.get("restart_requested") is True
            and read.public_payload.get("previous_delivery_session_identity_sha256")
            == _identity(write, identity_field)
            and read.read_state_refs
            and read.output_artifact_ids
        ):
            continue
        pending = any(
            e.operation == "request_new_session"
            and e.status == "passed"
            and e.lifecycle_id == read.public_payload.get("new_session_request_action_id")
            and write.sequence_no < e.sequence_no < read.sequence_no
            for e in graph.events
        )
        if not pending:
            continue
        for second in graph.edges:
            use = events[second.target_event_id]
            if (
                second.source_event_id == read.event_id
                and second.observable
                and second.evidence_ref_ids
                and second.edge_type in {"data", "state"}
                and use.status == "passed"
                and use.sequence_no > read.sequence_no
                and _identity(use, identity_field) == _identity(read, identity_field)
                and use.event_type in {"message", "tool_call", "state_write"}
                and second.artifact_id in read.output_artifact_ids
                and second.artifact_id in use.input_artifact_ids
            ):
                paths.append([write.event_id, read.event_id, use.event_id])
    checks: dict[str, bool | None] = {
        "trajectory_complete": trajectory.collection_status == "complete"
        and trajectory.failure_category is None,
        "normalization_consistent": not graph.unresolved_links,
        "source_trajectory_bound": graph.source_trajectory_hash
        == stable_hash(trajectory.model_dump(mode="json")),
        "actual_session_and_scope_identity": bool(identities_valid),
        "cross_session_persistence_read_use": bool(paths),
        "accepted_sample_target": accepted_count >= 1,
        "library_audit": library_audit_passed,
        # A library audit cannot certify runtime networks, cleanup or request accounting.
        "runtime_budget_isolation_cleanup_review": None,
    }
    return {
        "schema_version": "1.0",
        "trajectory_id": trajectory.trajectory_id,
        "structural_checks_passed": all(
            v is True for k, v in checks.items() if k != "runtime_budget_isolation_cleanup_review"
        ),
        "pilot_admitted": False,
        "checks": checks,
        "failed_gates": [k for k, v in checks.items() if v is False],
        "pending_reviews": [k for k, v in checks.items() if v is None],
        "causal_paths": paths,
        "accepted_count": accepted_count,
        "official_outcome": "not_evaluated",
    }


def audit_construction_collection(collection: Path, library: Path) -> dict[str, Any]:
    from stac_attack_lab.execution.sample_generation import (
        _validate_collection_stage,
        _validate_mining_stage,
    )

    stage = _validate_collection_stage(collection)
    _validate_mining_stage(library.parent)
    import json

    manifest = json.loads((library.parent / "mining_stage_manifest.json").read_text())
    if manifest["collection_tree_hash"] != stage.collection_tree_hash:
        raise ValueError("admission_library_collection_mismatch")
    results = []
    inputs: dict[str, str] = {}
    raw_paths = sorted(collection.glob("trajectories/*/raw_trajectory.json"))
    if len(raw_paths) != 1:
        raise ValueError("construction_admission_requires_single_trajectory")
    for raw_path in raw_paths:
        trajectory = RawInteractionTrajectory.model_validate_json(raw_path.read_text())
        graph_path = (
            library.parent
            / "interactions/normalized"
            / trajectory.trajectory_id
            / "interaction_graph.json"
        )
        graph = InteractionGraph.model_validate_json(graph_path.read_text())
        inputs.update({str(p): file_hash(p) for p in (raw_path, graph_path)})
        results.append(
            construction_admission(
                trajectory,
                graph,
                accepted_count=manifest["accepted_count"],
                library_audit_passed=True,
            )
        )
    return {
        "pilot_admitted": False,
        "reports": results,
        "input_sha256": inputs,
        "note": "Runtime budget, isolation and cleanup still require recorded review.",
    }
