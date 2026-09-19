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
    """Validate each causal fact independently; labels alone never prove use."""
    event_ids = [event.event_id for event in graph.events]
    artifact_ids = [artifact.artifact_id for artifact in graph.artifacts]
    events = {event.event_id: event for event in graph.events}
    artifacts = {artifact.artifact_id: artifact for artifact in graph.artifacts}

    def ref_locatable(value: str) -> bool:
        if value in events or value in artifacts:
            return True
        namespace, separator, identity = value.partition(":")
        return bool(separator and namespace.strip() and identity.strip())

    integrity_reasons: list[str] = []
    if len(event_ids) != len(set(event_ids)):
        integrity_reasons.append("duplicate_event_id")
    if len(artifact_ids) != len(set(artifact_ids)):
        integrity_reasons.append("duplicate_artifact_id")
    for artifact in graph.artifacts:
        if artifact.producer_event_id not in events:
            integrity_reasons.append("missing_artifact_producer")
        elif artifact.artifact_id not in events[artifact.producer_event_id].output_artifact_ids:
            integrity_reasons.append("artifact_producer_inconsistent")
        if any(parent not in artifacts for parent in artifact.parent_artifact_ids):
            integrity_reasons.append("missing_parent_artifact")
        producer = events.get(artifact.producer_event_id) if artifact.producer_event_id else None
        for parent_id in artifact.parent_artifact_ids:
            parent = artifacts.get(parent_id)
            parent_producer = (
                events.get(parent.producer_event_id)
                if parent is not None and parent.producer_event_id is not None
                else None
            )
            if producer and parent_producer and parent_producer.sequence_no >= producer.sequence_no:
                integrity_reasons.append("parent_artifact_out_of_order")
    for event in graph.events:
        if any(item not in artifacts for item in event.input_artifact_ids):
            integrity_reasons.append("missing_consumed_artifact")
        for item in event.input_artifact_ids:
            producer_id = artifacts[item].producer_event_id if item in artifacts else None
            producer = events.get(producer_id) if producer_id is not None else None
            if producer and producer.sequence_no >= event.sequence_no:
                integrity_reasons.append("artifact_consumption_out_of_order")
    for edge in graph.edges:
        source, target = events.get(edge.source_event_id), events.get(edge.target_event_id)
        if source is None or target is None:
            integrity_reasons.append("edge_endpoint_missing")
        elif source.sequence_no >= target.sequence_no:
            integrity_reasons.append("edge_out_of_order")
        if edge.artifact_id and (
            source is None
            or target is None
            or edge.artifact_id not in artifacts
            or edge.artifact_id not in source.output_artifact_ids
            or edge.artifact_id not in target.input_artifact_ids
        ):
            integrity_reasons.append("edge_artifact_inconsistent")
        if not edge.evidence_ref_ids or any(
            not ref_locatable(value) for value in edge.evidence_ref_ids
        ):
            integrity_reasons.append("edge_evidence_unresolvable")
    integrity_reasons.extend(link.reason_code for link in graph.unresolved_links)
    integrity_reasons = list(dict.fromkeys(integrity_reasons))

    gate_names = (
        "reliable_write",
        "write_read_order",
        "write_version_consistent",
        "post_state_evidence",
        "reliable_read",
        "persistence_class_consistent",
        "actual_session_changed",
        "workspace_scope_consistent",
        "read_matches_write_version",
        "valid_lifecycle_transition",
        "read_consumer_same_session",
        "context_reachability",
        "downstream_consumption",
    )
    candidates: list[dict[str, Any]] = []
    causal_paths: list[list[str]] = []
    context_paths: list[list[str]] = []
    writes = [
        e
        for e in graph.events
        if e.event_type == "state_write"
        and e.component_role in {"persistent_memory", "workspace_file"}
    ]
    reads = [
        e
        for e in graph.events
        if e.event_type == "state_read"
        and e.component_role in {"persistent_memory", "workspace_file"}
    ]
    lifecycle = [
        e
        for e in graph.events
        if e.event_type == "lifecycle"
        and e.status == "passed"
        and e.operation in {"request_new_session", "restart", "new_session_started"}
    ]

    def state(value: bool | None) -> str:
        return "observed" if value is True else "failed" if value is False else "unknown"

    for write in writes:
        for read in reads:
            gates: dict[str, dict[str, Any]] = {
                name: {
                    "state": "unknown",
                    "reason_code": f"{name}_not_evaluated",
                    "evidence_ref_ids": [],
                }
                for name in gate_names
            }

            def record(
                name: str,
                value: bool | None,
                evidence: list[str] | None = None,
                reason: str | None = None,
            ) -> None:
                gates[name] = {  # noqa: B023 - invoked before the candidate loop advances
                    "state": state(value),
                    "reason_code": reason or f"{name}_{state(value)}",
                    "evidence_ref_ids": evidence or [],
                }

            write_artifacts = [
                artifacts[item] for item in write.output_artifact_ids if item in artifacts
            ]
            record("write_read_order", write.sequence_no < read.sequence_no)
            reliable_write = (
                write.status == "passed"
                and bool(write.evidence_ref_ids)
                and all(ref_locatable(value) for value in write.evidence_ref_ids)
                and bool(write_artifacts)
            )
            record("reliable_write", reliable_write, write.evidence_ref_ids + [write.event_id])
            write_versions = [
                a
                for a in write_artifacts
                if a.producer_event_id == write.event_id
                and a.source_ref_ids
                and all(ref_locatable(value) for value in a.source_ref_ids)
            ]
            record(
                "write_version_consistent",
                bool(write_versions),
                [a.artifact_id for a in write_versions],
            )
            record(
                "post_state_evidence",
                bool(write.post_state_ref and write.write_state_refs),
                [write.post_state_ref] if write.post_state_ref else [],
            )
            reliable_read = (
                read.status == "passed"
                and read.public_payload.get("retrieval_hit") is True
                and bool(read.output_artifact_ids)
                and read.public_payload.get("result_empty") is not True
                and bool(read.evidence_ref_ids)
                and all(ref_locatable(value) for value in read.evidence_ref_ids)
            )
            record("reliable_read", reliable_read, read.evidence_ref_ids + [read.event_id])
            class_match = write.component_role == read.component_role
            record("persistence_class_consistent", class_match)
            writer_session, reader_session = (
                _identity(write, "actual_session_identity_sha256"),
                _identity(read, "actual_session_identity_sha256"),
            )
            session_change: bool | None = (
                None
                if not writer_session or not reader_session
                else writer_session != reader_session
            )
            record("actual_session_changed", session_change, [write.event_id, read.event_id])
            required_scope = ["workspace_identity_sha256"] + (
                ["memory_index_namespace_sha256"]
                if read.component_role == "persistent_memory"
                else []
            )
            scope_values = [
                (_identity(write, field), _identity(read, field)) for field in required_scope
            ]
            scope_match: bool | None = (
                None
                if any(not left or not right for left, right in scope_values)
                else all(left == right for left, right in scope_values)
            )
            record("workspace_scope_consistent", scope_match, [write.event_id, read.event_id])
            matching = set(write.output_artifact_ids) & set(read.input_artifact_ids)
            matching |= {
                a.artifact_id
                for a in graph.artifacts
                if a.artifact_id in read.output_artifact_ids
                and set(a.parent_artifact_ids) & set(write.output_artifact_ids)
            }
            version_match = bool(matching)
            if read.component_role == "workspace_file":
                version_match = (
                    version_match
                    and bool(read.public_payload.get("version_match"))
                    and bool(read.public_payload.get("workspace_relative_path"))
                    and write.public_payload.get("workspace_relative_path")
                    == read.public_payload.get("workspace_relative_path")
                    and write.public_payload.get("content_hash_scope")
                    == read.public_payload.get("content_hash_scope")
                    == "redacted_utf8_content_projection"
                    and read.public_payload.get("read_scope")
                    == "complete_redacted_utf8_file_content"
                )
            record("read_matches_write_version", version_match, sorted(matching))
            lifecycle_id = read.public_payload.get("new_session_request_action_id")
            transition = next(
                (
                    item
                    for item in lifecycle
                    if lifecycle_id
                    and item.lifecycle_id == lifecycle_id
                    and write.sequence_no < item.sequence_no < read.sequence_no
                ),
                None,
            )
            record(
                "valid_lifecycle_transition",
                transition is not None if lifecycle_id else False,
                [transition.event_id] if transition else [],
                "lifecycle_binding_missing" if not lifecycle_id else None,
            )

            for edge in graph.edges:
                if (
                    edge.source_event_id != read.event_id
                    or not edge.artifact_id
                    or edge.artifact_id not in read.output_artifact_ids
                ):
                    continue
                consumer = events.get(edge.target_event_id)
                if consumer is None or consumer.sequence_no <= read.sequence_no:
                    continue
                same_session: bool | None = None
                consumer_session = _identity(consumer, "actual_session_identity_sha256")
                if reader_session and consumer_session:
                    same_session = reader_session == consumer_session
                record(
                    "read_consumer_same_session", same_session, [read.event_id, consumer.event_id]
                )
                reachability = consumer.public_payload.get("context_reachability_evidence")
                reachability_refs = reachability if isinstance(reachability, list) else []
                reachable = bool(reachability_refs)
                record(
                    "context_reachability",
                    reachable,
                    [str(item) for item in reachability_refs],
                )
                if reachable:
                    context_paths.append([write.event_id, read.event_id, consumer.event_id])
                claims = consumer.public_payload.get("consumption_evidence", [])
                claim = (
                    next(
                        (
                            item
                            for item in claims
                            if isinstance(item, dict)
                            and item.get("artifact_id") == edge.artifact_id
                            and item.get("kind")
                            in {
                                "deterministic_output_reference",
                                "deterministic_argument_derivation",
                            }
                            and item.get("verification_rule")
                            and item.get("source_field")
                            and item.get("target_field")
                            and item.get("evidence_ref") in consumer.evidence_ref_ids
                        ),
                        None,
                    )
                    if isinstance(claims, list)
                    else None
                )
                consumed = bool(claim) and same_session is True
                record(
                    "downstream_consumption",
                    consumed,
                    [edge.edge_id, str(claim.get("evidence_ref"))] if claim else [],
                )
                if all(
                    gates[name]["state"] == "observed"
                    for name in gate_names
                    if name != "context_reachability"
                ):
                    causal_paths.append([write.event_id, read.event_id, consumer.event_id])
            candidates.append(
                {
                    "write_event_id": write.event_id,
                    "read_event_id": read.event_id,
                    "read_class": read.public_payload.get("retrieval_class"),
                    "gates": gates,
                    "blocking_reason_codes": [
                        value["reason_code"]
                        for value in gates.values()
                        if value["state"] != "observed"
                        and value["reason_code"] != "context_reachability_failed"
                    ],
                }
            )

    def aggregate_gate(name: str) -> dict[str, Any]:
        values = [candidate["gates"][name] for candidate in candidates]
        if any(value["state"] == "observed" for value in values):
            selected = next(value for value in values if value["state"] == "observed")
            return dict(selected)
        if any(value["state"] == "failed" for value in values):
            selected = next(value for value in values if value["state"] == "failed")
            return dict(selected)
        return {"state": "unknown", "reason_code": f"{name}_unknown", "evidence_ref_ids": []}

    checks_detail = {name: aggregate_gate(name) for name in gate_names}
    checks: dict[str, bool | None] = {
        "trajectory_complete": trajectory.collection_status == "complete"
        and trajectory.failure_category is None,
        "normalization_consistent": not integrity_reasons,
        "source_trajectory_bound": graph.source_trajectory_hash
        == stable_hash(trajectory.model_dump(mode="json")),
        "actual_session_and_scope_identity": checks_detail["actual_session_changed"]["state"]
        == "observed"
        and checks_detail["workspace_scope_consistent"]["state"] == "observed",
        "cross_session_persistence_read_use": bool(causal_paths),
        "workspace_file_persistence_read_use": any(
            events[path[1]].component_role == "workspace_file" for path in causal_paths
        ),
        "semantic_memory_search_read_use": any(
            events[path[1]].public_payload.get("retrieval_class") == "semantic_memory_search"
            for path in causal_paths
        ),
        "direct_memory_get_read_use": any(
            events[path[1]].public_payload.get("retrieval_class") == "direct_memory_get"
            for path in causal_paths
        ),
        "accepted_sample_target": accepted_count >= 1,
        "library_audit": library_audit_passed,
        "runtime_budget_isolation_cleanup_review": None,
    }
    return {
        "schema_version": "1.3",
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
        "pipeline_execution": {"status": "completed"},
        "input_integrity": {
            "status": "passed" if not integrity_reasons else "failed",
            "reason_codes": integrity_reasons,
        },
        "structural_admission": {
            "status": "passed"
            if all(
                v is True
                for k, v in checks.items()
                if k
                not in {
                    "runtime_budget_isolation_cleanup_review",
                    "workspace_file_persistence_read_use",
                    "semantic_memory_search_read_use",
                    "direct_memory_get_read_use",
                }
            )
            else "failed"
        },
        "execution_authorization": {"status": "absent"},
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
        "causal_paths": causal_paths,
        "context_reachability_paths": context_paths,
        "candidate_diagnostics": candidates,
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
    structural_passed = (
        bool(results)
        and all(report.get("structural_checks_passed") is True for report in results)
        and not diagnostics
    )
    return {
        "schema_version": "1.3",
        "pipeline_execution": {"status": "completed"},
        "input_integrity": {"status": "passed" if not diagnostics else "failed"},
        "structural_admission": {"status": "passed" if structural_passed else "failed"},
        "runtime_review": {"status": "pending"},
        "execution_authorization": {"status": "absent"},
        "official_outcome": "not_evaluated",
        "pilot_admitted": False,
        "reports": results,
        "input_sha256": inputs,
        "note": "Runtime budget, isolation and cleanup still require recorded review.",
        "diagnostics": diagnostics,
    }
