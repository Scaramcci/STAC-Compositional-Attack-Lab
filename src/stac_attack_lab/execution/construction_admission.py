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
    """Audit an observed persistence chain with per-gate evidence diagnostics.

    This function deliberately separates file persistence, lifecycle/session
    change, read/version matching and downstream consumption.  A context-access
    edge is never upgraded to semantic use or official success.
    """
    events = {event.event_id: event for event in graph.events}
    identity_field = "actual_session_identity_sha256"
    semantic_use_kinds = {
        "explicit_provider_output_reference",
        "deterministic_argument_derivation",
    }

    def identity(event: Any, name: str) -> str | None:
        return _identity(event, name)

    writes = [
        event
        for event in graph.events
        if event.event_type == "state_write"
        and event.component_role in {"persistent_memory", "workspace_file"}
        and event.status == "passed"
    ]
    reads = [
        event
        for event in graph.events
        if event.event_type == "state_read"
        and event.component_role in {"persistent_memory", "workspace_file"}
    ]
    lifecycle = [
        event
        for event in graph.events
        if event.event_type == "lifecycle"
        and event.status == "passed"
        and event.operation in {"request_new_session", "restart", "new_session_started"}
    ]

    def diagnostic(
        name: str,
        state: str,
        *,
        evidence: list[str] | None = None,
        missing: list[str] | None = None,
        explanation: str = "",
    ) -> dict[str, Any]:
        return {
            "state": state,
            "observed": state == "observed",
            "reason_code": f"{name}_{state}",
            "evidence_event_ids": evidence or [],
            "missing": missing or [],
            "explanation": explanation,
        }

    reliable_write = next(
        (event for event in writes if event.output_artifact_ids and event.post_state_ref), None
    )
    write_diag = diagnostic(
        "reliable_write",
        "observed" if reliable_write else ("failed" if writes else "unknown"),
        evidence=[reliable_write.event_id] if reliable_write else [],
        missing=[]
        if reliable_write
        else ["passed state_write with output artifact and post_state_ref"],
        explanation="A persistent write must expose a version artifact and post-state evidence.",
    )

    pairs: list[tuple[Any, Any, Any, list[str], Any]] = []
    context_paths: list[list[str]] = []
    candidate_diagnostics: list[dict[str, Any]] = []
    for write in writes:
        for read in reads:
            candidate: dict[str, Any] = {
                "write_event_id": write.event_id,
                "read_event_id": read.event_id,
                "read_class": read.public_payload.get("retrieval_class"),
                "gates": {},
            }
            if write.sequence_no >= read.sequence_no:
                continue
            reliable_read = (
                read.status == "passed"
                and read.public_payload.get("retrieval_hit") is True
                and bool(read.output_artifact_ids)
                and read.public_payload.get("result_empty") is not True
            )
            candidate["gates"]["reliable_read"] = reliable_read
            if not reliable_read:
                candidate_diagnostics.append(candidate)
                continue
            if read.operation not in {
                "memory_retrieve",
                "memory_retrieve_later_session",
                "workspace_file_read",
            }:
                continue
            sessions_observed = bool(
                identity(write, identity_field) and identity(read, identity_field)
            )
            session_changed = sessions_observed and identity(write, identity_field) != identity(
                read, identity_field
            )
            candidate["gates"]["actual_session_changed"] = session_changed
            if not session_changed:
                candidate_diagnostics.append(candidate)
                continue
            required_scope = ["workspace_identity_sha256"]
            if read.component_role == "persistent_memory":
                required_scope.append("memory_index_namespace_sha256")
            scope_consistent = all(
                identity(write, field) is not None
                and identity(write, field) == identity(read, field)
                for field in required_scope
            )
            candidate["gates"]["workspace_scope_consistent"] = scope_consistent
            if not scope_consistent:
                candidate_diagnostics.append(candidate)
                continue
            if write.component_role != read.component_role:
                candidate["gates"]["persistence_class_consistent"] = False
                candidate_diagnostics.append(candidate)
                continue
            matching_artifacts = set(write.output_artifact_ids) & set(read.input_artifact_ids)
            matching_artifacts |= {
                artifact.artifact_id
                for artifact in graph.artifacts
                if artifact.parent_artifact_ids
                and set(artifact.parent_artifact_ids) & set(write.output_artifact_ids)
                and artifact.artifact_id in read.output_artifact_ids
            }
            version_match = bool(matching_artifacts)
            if read.component_role == "workspace_file":
                version_match = version_match and (
                    write.public_payload.get("workspace_relative_path")
                    == read.public_payload.get("workspace_relative_path")
                    and bool(read.public_payload.get("workspace_relative_path"))
                )
            candidate["gates"]["read_matches_write_version"] = version_match
            if not version_match:
                candidate_diagnostics.append(candidate)
                continue
            transitions = [
                item
                for item in lifecycle
                if write.sequence_no < item.sequence_no < read.sequence_no
            ]
            expected_lifecycle = read.public_payload.get("new_session_request_action_id")
            transition = next(
                (
                    item
                    for item in transitions
                    if not expected_lifecycle or item.lifecycle_id == expected_lifecycle
                ),
                None,
            )
            candidate["gates"]["valid_lifecycle_transition"] = transition is not None
            if transition is None:
                candidate_diagnostics.append(candidate)
                continue
            for edge in graph.edges:
                if edge.source_event_id != read.event_id or edge.target_event_id not in events:
                    continue
                use = events[edge.target_event_id]
                if (
                    edge.edge_type not in {"data", "state"}
                    or not edge.observable
                    or use.status not in {"passed", "attempted"}
                    or use.sequence_no <= read.sequence_no
                    or identity(use, "workspace_identity_sha256")
                    != identity(read, "workspace_identity_sha256")
                ):
                    continue
                if (
                    edge.artifact_id
                    and edge.artifact_id in read.output_artifact_ids
                    and edge.artifact_id in use.input_artifact_ids
                ):
                    context_paths.append([write.event_id, read.event_id, use.event_id])
                    use_kind = use.public_payload.get("use_evidence_kind")
                    if use_kind in semantic_use_kinds:
                        pairs.append((write, read, use, [edge.edge_id], transition))
                        candidate["gates"]["downstream_consumption"] = True
            candidate.setdefault("gates", {}).setdefault("downstream_consumption", False)
            candidate_diagnostics.append(candidate)
    path_ids = [[write.event_id, read.event_id, use.event_id] for write, read, use, _, _ in pairs]
    best = pairs[0] if pairs else None
    if best:
        write, read, use, edge_ids, transition = best
        checks_detail = {
            "reliable_write": diagnostic("reliable_write", "observed", evidence=[write.event_id]),
            "valid_lifecycle_transition": diagnostic(
                "valid_lifecycle_transition", "observed", evidence=[transition.event_id]
            ),
            "actual_session_changed": diagnostic(
                "actual_session_changed", "observed", evidence=[write.event_id, read.event_id]
            ),
            "workspace_scope_consistent": diagnostic(
                "workspace_scope_consistent", "observed", evidence=[write.event_id, read.event_id]
            ),
            "reliable_read": diagnostic("reliable_read", "observed", evidence=[read.event_id]),
            "read_matches_write_version": diagnostic(
                "read_matches_write_version", "observed", evidence=[write.event_id, read.event_id]
            ),
            "context_reachability": diagnostic(
                "context_reachability", "observed", evidence=[read.event_id, use.event_id]
            ),
            "downstream_consumption": diagnostic(
                "downstream_consumption",
                "observed",
                evidence=[read.event_id, use.event_id] + edge_ids,
            ),
        }
    else:
        checks_detail = {
            "reliable_write": write_diag,
            "valid_lifecycle_transition": diagnostic(
                "valid_lifecycle_transition",
                "unknown" if not lifecycle else "failed",
                evidence=[item.event_id for item in lifecycle],
                missing=["lifecycle event between write and read"],
            ),
            "actual_session_changed": diagnostic(
                "actual_session_changed",
                "unknown" if not reads else "failed",
                missing=["distinct actual session identity hashes"],
            ),
            "workspace_scope_consistent": diagnostic(
                "workspace_scope_consistent",
                "unknown" if not writes or not reads else "failed",
                missing=["equal workspace and memory namespace identities"],
            ),
            "reliable_read": diagnostic(
                "reliable_read",
                "unknown" if not reads else "failed",
                evidence=[item.event_id for item in reads],
                missing=["successful read with non-empty output artifact"],
            ),
            "read_matches_write_version": diagnostic(
                "read_matches_write_version",
                "unknown",
                missing=["explicit write artifact/version overlap or state reference"],
            ),
            "context_reachability": diagnostic(
                "context_reachability",
                "observed" if context_paths else "unknown",
                evidence=context_paths[0] if context_paths else [],
                missing=[]
                if context_paths
                else ["read result correlated to a later provider request"],
            ),
            "downstream_consumption": diagnostic(
                "downstream_consumption",
                "failed" if context_paths else "unknown",
                missing=[
                    "explicit output reference or deterministic argument derivation; "
                    "context reachability alone is insufficient"
                ],
            ),
        }
    checks: dict[str, bool | None] = {
        "trajectory_complete": trajectory.collection_status == "complete"
        and trajectory.failure_category is None,
        "normalization_consistent": not graph.unresolved_links,
        "source_trajectory_bound": graph.source_trajectory_hash
        == stable_hash(trajectory.model_dump(mode="json")),
        "actual_session_and_scope_identity": checks_detail["actual_session_changed"]["state"]
        == "observed"
        and checks_detail["workspace_scope_consistent"]["state"] == "observed",
        "cross_session_persistence_read_use": bool(path_ids),
        "workspace_file_persistence_read_use": any(
            read.component_role == "workspace_file" for _, read, _, _, _ in pairs
        ),
        "semantic_memory_search_read_use": any(
            read.public_payload.get("retrieval_class") == "semantic_memory_search"
            for _, read, _, _, _ in pairs
        ),
        "direct_memory_get_read_use": any(
            read.public_payload.get("retrieval_class") == "direct_memory_get"
            for _, read, _, _, _ in pairs
        ),
        "accepted_sample_target": accepted_count >= 1,
        "library_audit": library_audit_passed,
        "runtime_budget_isolation_cleanup_review": None,
    }
    return {
        "schema_version": "1.2",
        "trajectory_id": trajectory.trajectory_id,
        "structural_checks_passed": all(
            v is True
            for k, v in checks.items()
            if k
            not in {
                "runtime_budget_isolation_cleanup_review",
                "workspace_file_persistence_read_use",
                "semantic_memory_search_read_use",
                "direct_memory_get_read_use",
            }
        ),
        "pilot_admitted": False,
        "checks": checks,
        "failed_gates": [
            k
            for k, v in checks.items()
            if v is False
            and k
            not in {
                "workspace_file_persistence_read_use",
                "semantic_memory_search_read_use",
                "direct_memory_get_read_use",
            }
        ],
        "pending_reviews": [k for k, v in checks.items() if v is None],
        "causal_paths": path_ids,
        "context_reachability_paths": context_paths,
        "candidate_diagnostics": candidate_diagnostics,
        "evidence_diagnostics": checks_detail,
        "accepted_count": accepted_count,
        "runtime_review": {
            "status": "pending",
            "items": [
                {
                    "reason_code": "runtime_budget_ledger_review_pending",
                    "state": "unknown",
                    "explanation": (
                        "Counts alone do not prove complete, crash-safe budget accounting."
                    ),
                },
                {
                    "reason_code": "runtime_batch_identity_review_pending",
                    "state": "unknown",
                    "explanation": "Batch identity must be checked against every provider ledger.",
                },
                {
                    "reason_code": "runtime_network_isolation_review_pending",
                    "state": "unknown",
                    "explanation": "No network topology evidence is part of the interaction graph.",
                },
                {
                    "reason_code": "runtime_cleanup_review_pending",
                    "state": "unknown",
                    "explanation": (
                        "Container/process cleanup requires separately recorded evidence."
                    ),
                },
            ],
        },
        "official_outcome": "not_evaluated",
        "note": (
            "ordinary file reads, memory_get and semantic memory_search remain separately "
            "classified; context reachability is not semantic use or official success"
        ),
    }


def audit_construction_collection(collection: Path, library: Path) -> dict[str, Any]:
    import json

    from stac_attack_lab.execution.sample_generation import (
        _validate_collection_stage,
        _validate_mining_stage,
    )

    diagnostics: list[dict[str, Any]] = []
    try:
        stage = _validate_collection_stage(collection)
        _validate_mining_stage(library.parent)
        manifest = json.loads((library.parent / "mining_stage_manifest.json").read_text())
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "schema_version": "1.2",
            "pilot_admitted": False,
            "reports": [],
            "failed_gates": ["input_integrity"],
            "pending_reviews": [],
            "diagnostics": [
                {
                    "state": "failed",
                    "reason_code": "missing_or_corrupt_input",
                    "detail": str(exc)[:500],
                }
            ],
            "input_sha256": {},
            "note": "Admission could not validate all inputs; no counts were fabricated.",
        }
    if manifest.get("collection_tree_hash") != stage.collection_tree_hash:
        return {
            "schema_version": "1.2",
            "pilot_admitted": False,
            "reports": [],
            "failed_gates": ["input_integrity"],
            "pending_reviews": [],
            "diagnostics": [
                {"state": "failed", "reason_code": "admission_library_collection_mismatch"}
            ],
            "input_sha256": {},
        }
    results = []
    inputs: dict[str, str] = {}
    raw_paths = sorted(collection.glob("trajectories/*/raw_trajectory.json"))
    if len(raw_paths) != 1:
        return {
            "schema_version": "1.2",
            "pilot_admitted": False,
            "reports": [],
            "failed_gates": ["single_trajectory_required"],
            "pending_reviews": [],
            "diagnostics": [
                {
                    "state": "failed",
                    "reason_code": "construction_admission_requires_single_trajectory",
                    "observed_count": len(raw_paths),
                }
            ],
            "input_sha256": {},
        }
    for raw_path in raw_paths:
        trajectory = RawInteractionTrajectory.model_validate_json(raw_path.read_text())
        graph_path = (
            library.parent
            / "interactions/normalized"
            / trajectory.trajectory_id
            / "interaction_graph.json"
        )
        try:
            graph = InteractionGraph.model_validate_json(graph_path.read_text())
        except (FileNotFoundError, OSError, ValueError) as exc:
            diagnostics.append(
                {
                    "state": "failed",
                    "reason_code": "missing_or_corrupt_graph",
                    "detail": str(exc)[:500],
                }
            )
            continue
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
        "diagnostics": diagnostics,
    }
