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
    """Evaluate graph facts without conflating review or launch authorization."""
    identity_field = "actual_session_identity_sha256"
    events = {event.event_id: event for event in graph.events}
    artifacts = {artifact.artifact_id: artifact for artifact in graph.artifacts}

    def gate(
        name: str,
        state: str,
        *,
        event_ids: list[str] | None = None,
        edge_ids: list[str] | None = None,
        evidence_refs: list[str] | None = None,
        missing: list[str] | None = None,
        reason_code: str | None = None,
    ) -> dict[str, Any]:
        return {
            "state": state,
            "observed": state == "observed",
            "reason_code": reason_code or f"{name}_{state}",
            "evidence_event_ids": event_ids or [],
            "evidence_edge_ids": edge_ids or [],
            "evidence_ref_ids": evidence_refs or [],
            "missing": missing or [],
        }

    integrity_findings: list[dict[str, Any]] = []

    def integrity(reason_code: str, **detail: Any) -> None:
        integrity_findings.append({"state": "failed", "reason_code": reason_code, **detail})

    event_ids = [event.event_id for event in graph.events]
    artifact_ids = [artifact.artifact_id for artifact in graph.artifacts]
    if len(event_ids) != len(set(event_ids)):
        integrity("duplicate_event_id")
    if len(artifact_ids) != len(set(artifact_ids)):
        integrity("duplicate_artifact_id")
    for artifact in graph.artifacts:
        producer = events.get(str(artifact.producer_event_id))
        if producer is None:
            integrity("artifact_producer_missing", artifact_id=artifact.artifact_id)
        elif artifact.artifact_id not in producer.output_artifact_ids:
            integrity("artifact_producer_inconsistent", artifact_id=artifact.artifact_id)
        for parent_id in artifact.parent_artifact_ids:
            parent = artifacts.get(parent_id)
            if parent is None:
                integrity("parent_artifact_missing", artifact_id=artifact.artifact_id)
            elif producer is not None:
                parent_producer = events.get(str(parent.producer_event_id))
                if parent_producer is None or parent_producer.sequence_no >= producer.sequence_no:
                    integrity("parent_artifact_not_before_child", artifact_id=artifact.artifact_id)
    for event in graph.events:
        for artifact_id in event.input_artifact_ids:
            consumed_artifact = artifacts.get(artifact_id)
            producer = (
                events.get(str(consumed_artifact.producer_event_id)) if consumed_artifact else None
            )
            if consumed_artifact is None or producer is None:
                integrity(
                    "consumer_artifact_missing", event_id=event.event_id, artifact_id=artifact_id
                )
            elif producer.sequence_no >= event.sequence_no:
                integrity(
                    "artifact_consumption_out_of_order",
                    event_id=event.event_id,
                    artifact_id=artifact_id,
                )
    for edge in graph.edges:
        source, target = events.get(edge.source_event_id), events.get(edge.target_event_id)
        if source is None or target is None:
            integrity("edge_event_missing", edge_id=edge.edge_id)
        elif source.sequence_no >= target.sequence_no:
            integrity("edge_out_of_order", edge_id=edge.edge_id)
        if edge.artifact_id:
            if edge.artifact_id not in artifacts:
                integrity("edge_artifact_missing", edge_id=edge.edge_id)
            elif source and edge.artifact_id not in source.output_artifact_ids:
                integrity("edge_source_artifact_inconsistent", edge_id=edge.edge_id)
            elif target and edge.artifact_id not in target.input_artifact_ids:
                integrity("edge_target_artifact_inconsistent", edge_id=edge.edge_id)
    for unresolved in graph.unresolved_links:
        integrity(unresolved.reason_code, link_id=unresolved.link_id)

    writes = [
        event
        for event in graph.events
        if event.event_type == "state_write"
        and event.component_role in {"persistent_memory", "workspace_file"}
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

    def has_locatable_refs(event: Any, artifact_ids_for_event: list[str]) -> bool:
        refs = {ref for ref in event.evidence_ref_ids if isinstance(ref, str) and ref.strip()}
        artifact_refs = {
            ref
            for artifact_id in artifact_ids_for_event
            if artifact_id in artifacts
            for ref in artifacts[artifact_id].source_ref_ids
            if isinstance(ref, str) and ref.strip()
        }
        internal_event_refs = {
            ref
            for ref in artifact_refs
            if ref.startswith("event:") and ref.removeprefix("event:") in events
        }
        return bool(refs & artifact_refs or internal_event_refs)

    def strong_use(use: Any, artifact_id: str) -> tuple[bool, list[str]]:
        claims = use.public_payload.get("artifact_use_evidence", [])
        if not isinstance(claims, list) or artifact_id not in artifacts:
            return False, []
        source_hash = artifacts[artifact_id].content_hash
        for claim in claims:
            if not isinstance(claim, dict) or claim.get("source_artifact_id") != artifact_id:
                continue
            refs = [str(ref) for ref in claim.get("evidence_ref_ids", []) if str(ref).strip()]
            valid_refs = bool(refs and set(refs) <= set(use.evidence_ref_ids))
            valid_derivation = (
                claim.get("evidence_kind") == "deterministic_argument_derivation"
                and claim.get("verification_rule") == "sha256_exact_projection"
                and claim.get("source_content_sha256") == source_hash
                and claim.get("target_projection_sha256") == source_hash
            )
            if valid_refs and valid_derivation:
                return True, refs
        return False, []

    candidates: list[dict[str, Any]] = []
    successful_paths: list[tuple[Any, Any, Any, Any]] = []
    context_paths: list[list[str]] = []
    required_candidate_gates = (
        "reliable_write",
        "write_version_artifact",
        "post_state_evidence",
        "reliable_read",
        "persistence_class_consistent",
        "actual_session_changed",
        "workspace_scope_consistent",
        "read_matches_write_version",
        "valid_lifecycle_transition",
        "consumer_order",
        "consumer_session_consistent",
        "artifact_edge_bound",
        "downstream_consumption",
    )
    for write in writes:
        for read in reads:
            gates: dict[str, dict[str, Any]] = {}
            write_refs_ok = has_locatable_refs(write, write.output_artifact_ids)
            write_ok = bool(
                write.status == "passed"
                and write_refs_ok
                and write.output_artifact_ids
                and write.post_state_ref
                and write.write_state_refs
                and write.post_state_ref != write.pre_state_ref
            )
            gates["reliable_write"] = gate(
                "reliable_write",
                "observed" if write_ok else "failed",
                event_ids=[write.event_id],
                evidence_refs=list(write.evidence_ref_ids),
                missing=[] if write_ok else ["passed write with locatable request/result evidence"],
            )
            produced = [
                artifact_id
                for artifact_id in write.output_artifact_ids
                if artifact_id in artifacts
                and artifacts[artifact_id].producer_event_id == write.event_id
            ]
            gates["write_version_artifact"] = gate(
                "write_version_artifact",
                "observed" if produced else "failed",
                event_ids=[write.event_id],
                missing=[] if produced else ["producer-bound version artifact"],
            )
            post_ok = bool(
                write.post_state_ref
                and write.write_state_refs
                and write.post_state_ref != write.pre_state_ref
                and write_refs_ok
            )
            gates["post_state_evidence"] = gate(
                "post_state_evidence",
                "observed" if post_ok else "failed",
                event_ids=[write.event_id],
                evidence_refs=list(write.evidence_ref_ids),
                missing=[] if post_ok else ["changed post_state_ref with locatable evidence"],
            )
            read_refs_ok = has_locatable_refs(read, read.output_artifact_ids)
            read_ok = (
                read.status == "passed"
                and read.public_payload.get("retrieval_hit") is True
                and bool(read.output_artifact_ids)
                and read.public_payload.get("result_empty") is not True
                and read_refs_ok
            )
            gates["reliable_read"] = gate(
                "reliable_read",
                "observed" if read_ok else "failed",
                event_ids=[read.event_id],
                evidence_refs=list(read.evidence_ref_ids),
                missing=[] if read_ok else ["non-empty successful read with locatable evidence"],
            )
            class_ok = write.component_role == read.component_role
            gates["persistence_class_consistent"] = gate(
                "persistence_class_consistent",
                "observed" if class_ok else "failed",
                event_ids=[write.event_id, read.event_id],
            )
            write_identity, read_identity = (
                _identity(write, identity_field),
                _identity(read, identity_field),
            )
            session_state = (
                "unknown"
                if not write_identity or not read_identity
                else "observed"
                if write_identity != read_identity
                else "failed"
            )
            gates["actual_session_changed"] = gate(
                "actual_session_changed",
                session_state,
                event_ids=[write.event_id, read.event_id],
                missing=[]
                if session_state == "observed"
                else ["distinct actual session identities"],
            )
            scope_fields = ["workspace_identity_sha256"] + (
                ["memory_index_namespace_sha256"]
                if read.component_role == "persistent_memory"
                else []
            )
            scope_values = [
                (_identity(write, field), _identity(read, field)) for field in scope_fields
            ]
            scope_state = (
                "unknown"
                if any(not left or not right for left, right in scope_values)
                else "observed"
                if all(left == right for left, right in scope_values)
                else "failed"
            )
            gates["workspace_scope_consistent"] = gate(
                "workspace_scope_consistent",
                scope_state,
                event_ids=[write.event_id, read.event_id],
                missing=[]
                if scope_state == "observed"
                else ["equal, observed workspace and required namespace identities"],
            )
            lineage_ids = set(produced) & set(read.input_artifact_ids)
            lineage_ids |= {
                artifact_id
                for artifact_id in read.output_artifact_ids
                if artifact_id in artifacts
                and set(artifacts[artifact_id].parent_artifact_ids) & set(produced)
            }
            version_ok = bool(lineage_ids)
            if read.component_role == "workspace_file":
                version_ok = bool(
                    version_ok
                    and write.public_payload.get("workspace_relative_path")
                    == read.public_payload.get("workspace_relative_path")
                    and read.public_payload.get("version_match") is True
                )
            gates["read_matches_write_version"] = gate(
                "read_matches_write_version",
                "observed" if version_ok else "failed",
                event_ids=[write.event_id, read.event_id],
                missing=[]
                if version_ok
                else ["same controlled resource and producer-bound version"],
            )
            lifecycle_id = read.public_payload.get("new_session_request_action_id")
            transition = next(
                (
                    item
                    for item in lifecycle
                    if isinstance(lifecycle_id, str)
                    and lifecycle_id
                    and item.lifecycle_id == lifecycle_id
                    and write.sequence_no < item.sequence_no < read.sequence_no
                    and bool(item.evidence_ref_ids)
                ),
                None,
            )
            lifecycle_state = (
                "unknown"
                if not isinstance(lifecycle_id, str) or not lifecycle_id
                else ("observed" if transition else "failed")
            )
            gates["valid_lifecycle_transition"] = gate(
                "valid_lifecycle_transition",
                lifecycle_state,
                event_ids=[transition.event_id] if transition else [],
                evidence_refs=list(transition.evidence_ref_ids) if transition else [],
                missing=[] if transition else ["explicit matching lifecycle action binding"],
            )

            consumers: list[Any] = []
            matching_edges: list[Any] = []
            for edge in graph.edges:
                use = events.get(edge.target_event_id)
                if (
                    edge.source_event_id == read.event_id
                    and use is not None
                    and edge.observable
                    and edge.artifact_id in read.output_artifact_ids
                    and edge.artifact_id in use.input_artifact_ids
                ):
                    consumers.append(use)
                    matching_edges.append(edge)
            ordered = [use for use in consumers if use.sequence_no > read.sequence_no]
            gates["consumer_order"] = gate(
                "consumer_order",
                "observed" if ordered else ("failed" if consumers else "unknown"),
                event_ids=[read.event_id] + [use.event_id for use in ordered],
            )
            same_session = [
                use
                for use in ordered
                if _identity(use, identity_field) == read_identity
                and use.session_id == read.session_id
                and read_identity is not None
            ]
            gates["consumer_session_consistent"] = gate(
                "consumer_session_consistent",
                "observed" if same_session else ("failed" if ordered else "unknown"),
                event_ids=[read.event_id] + [use.event_id for use in ordered],
            )
            bound = [
                (edge, use)
                for edge, use in zip(matching_edges, consumers, strict=True)
                if use in same_session
            ]
            gates["artifact_edge_bound"] = gate(
                "artifact_edge_bound",
                "observed" if bound else ("failed" if consumers else "unknown"),
                edge_ids=[edge.edge_id for edge, _ in bound],
            )
            verified = [
                (edge, use, refs)
                for edge, use in bound
                if edge.artifact_id is not None
                for ok, refs in [strong_use(use, edge.artifact_id)]
                if ok
            ]
            gates["downstream_consumption"] = gate(
                "downstream_consumption",
                "observed" if verified else "unknown",
                event_ids=[read.event_id] + [use.event_id for _, use, _ in verified],
                edge_ids=[edge.edge_id for edge, _, _ in verified],
                evidence_refs=[ref for _, _, refs in verified for ref in refs],
                missing=[] if verified else ["edge-bound deterministic derivation evidence"],
            )
            # Request-boundary context evidence is a separate, currently optional fact.
            context_verified = []
            for edge, use in bound:
                edge_artifact = artifacts.get(str(edge.artifact_id))
                if edge_artifact is None:
                    continue
                claims = use.public_payload.get("artifact_context_evidence", [])
                if isinstance(claims, list) and any(
                    isinstance(claim, dict)
                    and claim.get("source_artifact_id") == edge.artifact_id
                    and claim.get("evidence_kind") == "provider_request_context_projection"
                    and claim.get("request_id")
                    and claim.get("content_projection_sha256") == edge_artifact.content_hash
                    and set(claim.get("evidence_ref_ids", [])) <= set(use.evidence_ref_ids)
                    and bool(claim.get("evidence_ref_ids"))
                    for claim in claims
                ):
                    context_verified.append(use)
            gates["context_reachability"] = gate(
                "context_reachability",
                "observed" if context_verified else "unknown",
                event_ids=[read.event_id] + [use.event_id for use in context_verified],
            )
            passed = not integrity_findings and all(
                gates[name]["state"] == "observed" for name in required_candidate_gates
            )
            candidate = {
                "write_event_id": write.event_id,
                "read_event_id": read.event_id,
                "read_class": read.public_payload.get("retrieval_class"),
                "status": "passed" if passed else "failed",
                "gates": gates,
                "blocking_reason_codes": [
                    gates[name]["reason_code"]
                    for name in required_candidate_gates
                    if gates[name]["state"] != "observed"
                ],
            }
            candidates.append(candidate)
            for edge, use, _ in verified:
                if passed:
                    successful_paths.append((write, read, use, edge))
            for use in context_verified:
                context_paths.append([write.event_id, read.event_id, use.event_id])

    def aggregate_gate(name: str) -> dict[str, Any]:
        values = [candidate["gates"][name] for candidate in candidates]
        if not values:
            return gate(name, "unknown", missing=["no write/read candidate"])
        rank = {"observed": 3, "failed": 2, "unknown": 1, "not_applicable": 0}
        return max(values, key=lambda value: rank[value["state"]])

    evidence_diagnostics = {
        name: aggregate_gate(name) for name in (*required_candidate_gates, "context_reachability")
    }
    path_ids = [
        [write.event_id, read.event_id, use.event_id] for write, read, use, _ in successful_paths
    ]
    required_checks = {
        "trajectory_complete": trajectory.collection_status == "complete"
        and trajectory.failure_category is None,
        "graph_integrity": not integrity_findings,
        "normalization_consistent": not graph.unresolved_links,
        "source_trajectory_bound": graph.source_trajectory_hash
        == stable_hash(trajectory.model_dump(mode="json")),
        "reliable_write": evidence_diagnostics["reliable_write"]["state"] == "observed",
        "post_state_evidence": evidence_diagnostics["post_state_evidence"]["state"] == "observed",
        "valid_lifecycle_transition": evidence_diagnostics["valid_lifecycle_transition"]["state"]
        == "observed",
        "consumer_session_consistent": evidence_diagnostics["consumer_session_consistent"]["state"]
        == "observed",
        "actual_session_and_scope_identity": (
            evidence_diagnostics["actual_session_changed"]["state"] == "observed"
            and evidence_diagnostics["workspace_scope_consistent"]["state"] == "observed"
        ),
        "cross_session_persistence_read_use": bool(path_ids),
        "accepted_sample_target": accepted_count >= 1,
        "library_audit": library_audit_passed,
    }
    capability_checks = {
        "workspace_file_persistence_read_use": any(
            read.component_role == "workspace_file" for _, read, _, _ in successful_paths
        ),
        "semantic_memory_search_read_use": any(
            read.public_payload.get("retrieval_class") == "semantic_memory_search"
            for _, read, _, _ in successful_paths
        ),
        "direct_memory_get_read_use": any(
            read.public_payload.get("retrieval_class") == "direct_memory_get"
            for _, read, _, _ in successful_paths
        ),
    }
    structural_passed = all(required_checks.values())
    runtime_review = {
        "status": "pending",
        "items": [
            {"reason_code": code, "state": "unknown"}
            for code in (
                "runtime_budget_ledger_review_pending",
                "runtime_batch_identity_review_pending",
                "runtime_network_isolation_review_pending",
                "runtime_cleanup_review_pending",
            )
        ],
    }
    authorization = {
        "status": "absent",
        "granted": False,
        "reason_code": "execution_authorization_not_granted",
    }
    checks: dict[str, bool | None] = {
        **required_checks,
        **capability_checks,
        "runtime_budget_isolation_cleanup_review": None,
    }
    return {
        "schema_version": "2.0",
        "trajectory_id": trajectory.trajectory_id,
        "pipeline_execution": {"status": "not_executed"},
        "input_integrity": {
            "status": "passed" if not integrity_findings else "failed",
            "findings": integrity_findings,
        },
        "structural_admission": {"status": "passed" if structural_passed else "failed"},
        "structural_checks_passed": structural_passed,
        "runtime_review": runtime_review,
        "execution_authorization": authorization,
        "official_outcome": {"status": "not_evaluated"},
        "pilot_admitted": bool(
            structural_passed and runtime_review["status"] == "passed" and authorization["granted"]
        ),
        "checks": checks,
        "failed_gates": [name for name, value in required_checks.items() if value is False],
        "pending_reviews": ["runtime_budget_isolation_cleanup_review"],
        "causal_paths": path_ids,
        "context_reachability_paths": context_paths,
        "candidate_diagnostics": candidates,
        "evidence_diagnostics": evidence_diagnostics,
        "accepted_count": accepted_count,
        "note": (
            "memory_search, memory_get, and file reads are separate capability metrics; "
            "context reachability is not semantic use or official success"
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
            "schema_version": "2.0",
            "pilot_admitted": False,
            "pipeline_execution": {"status": "not_executed"},
            "input_integrity": {"status": "failed"},
            "structural_admission": {"status": "not_run"},
            "runtime_review": {"status": "not_run"},
            "execution_authorization": {"status": "absent", "granted": False},
            "official_outcome": {"status": "not_evaluated"},
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
            "schema_version": "2.0",
            "pilot_admitted": False,
            "pipeline_execution": {"status": "not_executed"},
            "input_integrity": {"status": "failed"},
            "structural_admission": {"status": "not_run"},
            "runtime_review": {"status": "not_run"},
            "execution_authorization": {"status": "absent", "granted": False},
            "official_outcome": {"status": "not_evaluated"},
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
            "schema_version": "2.0",
            "pilot_admitted": False,
            "pipeline_execution": {"status": "not_executed"},
            "input_integrity": {"status": "failed"},
            "structural_admission": {"status": "not_run"},
            "runtime_review": {"status": "not_run"},
            "execution_authorization": {"status": "absent", "granted": False},
            "official_outcome": {"status": "not_evaluated"},
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
        and not diagnostics
        and all(
            report.get("structural_admission", {}).get("status") == "passed" for report in results
        )
    )
    runtime_review = {"status": "pending"}
    authorization = {"status": "absent", "granted": False}
    return {
        "schema_version": "2.0",
        "pilot_admitted": bool(
            structural_passed and runtime_review["status"] == "passed" and authorization["granted"]
        ),
        "pipeline_execution": {"status": "not_executed"},
        "input_integrity": {"status": "passed" if not diagnostics else "failed"},
        "structural_admission": {"status": "passed" if structural_passed else "failed"},
        "runtime_review": runtime_review,
        "execution_authorization": authorization,
        "official_outcome": {"status": "not_evaluated"},
        "reports": results,
        "input_sha256": inputs,
        "note": (
            "pilot_admitted means structural pass AND runtime review pass AND explicit "
            "execution authorization; structural success alone never grants launch"
        ),
        "diagnostics": diagnostics,
    }
