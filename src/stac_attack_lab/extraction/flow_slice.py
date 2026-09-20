from __future__ import annotations

import time
from collections import defaultdict, deque

from stac_attack_lab.flow.analysis import (
    DependencySlice,
    ExternalPrecondition,
    JoinRequirement,
    SliceBudget,
    SliceClaimRef,
)
from stac_attack_lab.flow.models import DependencyClaim, EffectGraph
from stac_attack_lab.hashing import stable_hash


def _slice_hash(payload: dict[str, object]) -> str:
    return stable_hash({key: value for key, value in payload.items() if key != "slice_hash"})


def slice_dependency_graph(
    graph: EffectGraph,
    *,
    sink_port_ids: list[str],
    budget: SliceBudget | None = None,
    join_requirements: list[JoinRequirement] | None = None,
) -> DependencySlice:
    limits = budget or SliceBudget()
    joins = join_requirements or []
    known_ports = {item.port_id: item for item in graph.ports}
    if not sink_port_ids or len(sink_port_ids) != len(set(sink_port_ids)):
        raise ValueError("slice_sink_ports_invalid")
    missing_sinks = sorted(set(sink_port_ids) - set(known_ports))
    if missing_sinks:
        raise ValueError("slice_sink_port_unknown:" + ",".join(missing_sinks))

    claims_by_target: dict[str, list[DependencyClaim]] = defaultdict(list)
    claims_by_id = {item.claim_id: item for item in graph.claims}
    for claim in graph.claims:
        claims_by_target[claim.target_port_id].append(claim)
    effects_by_port: dict[str, set[str]] = defaultdict(set)
    effects = {item.effect_id: item for item in graph.effects}
    for effect in graph.effects:
        for port_id in effect.input_port_ids + effect.output_port_ids:
            effects_by_port[port_id].add(effect.effect_id)

    selected_ports = set(sink_port_ids)
    selected_effects: set[str] = set()
    selected_claims: dict[str, SliceClaimRef] = {}
    external: dict[str, ExternalPrecondition] = {}
    truncation_reasons: set[str] = set()
    queue: deque[tuple[str, int]] = deque((port_id, 0) for port_id in sink_port_ids)
    visited_depth: dict[str, int] = {}
    candidates = 0
    started = time.monotonic()

    def mark_external(port_id: str, claim_id: str | None, reason: str) -> None:
        precondition_id = "external-" + stable_hash([port_id, claim_id, reason])[:20]
        external[precondition_id] = ExternalPrecondition(
            precondition_id=precondition_id,
            boundary_port_id=port_id,
            omitted_claim_id=claim_id,
            reason_code=reason,
        )

    def over_time() -> bool:
        return (time.monotonic() - started) * 1000 > limits.max_wall_time_ms

    while queue:
        port_id, depth = queue.popleft()
        previous_depth = visited_depth.get(port_id)
        if previous_depth is not None and previous_depth <= depth:
            continue
        visited_depth[port_id] = depth
        selected_ports.add(port_id)
        selected_effects.update(effects_by_port.get(port_id, set()))
        if over_time():
            truncation_reasons.add("slice_wall_time_budget_exceeded")
            mark_external(port_id, None, "slice_wall_time_boundary")
            break
        if depth >= limits.max_depth:
            if claims_by_target.get(port_id):
                truncation_reasons.add("slice_depth_budget_exceeded")
                mark_external(port_id, None, "slice_depth_boundary")
            continue
        for claim in sorted(claims_by_target.get(port_id, []), key=lambda item: item.claim_id):
            candidates += 1
            if candidates > limits.max_candidates:
                truncation_reasons.add("slice_candidate_budget_exceeded")
                mark_external(port_id, claim.claim_id, "slice_candidate_boundary")
                break
            if len(selected_claims) >= limits.max_edges:
                truncation_reasons.add("slice_edge_budget_exceeded")
                mark_external(port_id, claim.claim_id, "slice_edge_boundary")
                break
            prospective_ports = selected_ports | {claim.source_port_id, claim.target_port_id}
            prospective_effects = selected_effects | effects_by_port.get(
                claim.source_port_id, set()
            )
            if len(prospective_ports) + len(prospective_effects) > limits.max_nodes:
                truncation_reasons.add("slice_node_budget_exceeded")
                mark_external(claim.source_port_id, claim.claim_id, "slice_node_boundary")
                continue
            selected_claims[claim.claim_id] = SliceClaimRef(
                claim_id=claim.claim_id,
                source_port_id=claim.source_port_id,
                target_port_id=claim.target_port_id,
                relation=claim.relation,
                verdict=claim.dependency_verdict,
                origin="observed",
                required=False,
            )
            selected_ports.update({claim.source_port_id, claim.target_port_id})
            selected_effects.update(effects_by_port.get(claim.source_port_id, set()))
            if not effects_by_port.get(claim.source_port_id) and known_ports[
                claim.source_port_id
            ].owner_kind in {"domain", "invocation"}:
                mark_external(claim.source_port_id, claim.claim_id, "external_source_precondition")
            queue.append((claim.source_port_id, depth + 1))

    selected_joins: list[JoinRequirement] = []
    reference_consistency = "passed"
    for join in joins:
        if join.target_port_id not in selected_ports:
            continue
        selected_joins.append(join)
        for member_id in join.member_claim_ids:
            member_claim = claims_by_id.get(member_id)
            if member_claim is None:
                reference_consistency = "failed"
                mark_external(join.target_port_id, member_id, "template_required_claim_missing")
                continue
            existing = selected_claims.get(member_id)
            selected_claims[member_id] = SliceClaimRef(
                claim_id=member_id,
                source_port_id=member_claim.source_port_id,
                target_port_id=member_claim.target_port_id,
                relation=member_claim.relation,
                verdict=member_claim.dependency_verdict,
                origin=join.origin,
                required=True,
            )
            selected_ports.update({member_claim.source_port_id, member_claim.target_port_id})
            selected_effects.update(effects_by_port.get(member_claim.source_port_id, set()))
            if existing is None and len(selected_claims) > limits.max_edges:
                truncation_reasons.add("slice_edge_budget_exceeded")
                mark_external(member_claim.source_port_id, member_id, "slice_edge_boundary")

    selected_resources = {
        version_id
        for effect_id in selected_effects
        for version_id in effects[effect_id].resource_version_ids
    }
    selected_groups = {
        group.group_id for group in graph.effect_groups if set(group.effect_ids) & selected_effects
    }

    # Paths are a bounded display projection only. The slice remains the
    # authoritative fan-in/fan-out representation.
    effect_predecessors: dict[str, set[str]] = defaultdict(set)
    for selected_claim in selected_claims.values():
        target_effects = effects_by_port.get(selected_claim.target_port_id, set())
        source_effects = effects_by_port.get(selected_claim.source_port_id, set())
        for target_effect in target_effects:
            effect_predecessors[target_effect].update(source_effects)
    sink_effects = sorted(
        {
            effect_id
            for port_id in sink_port_ids
            for effect_id in effects_by_port.get(port_id, set())
        }
    )
    display_paths: list[list[str]] = []

    def display_walk(effect_id: str, suffix: list[str], seen: set[str]) -> None:
        if len(display_paths) >= 32 or effect_id in seen:
            return
        path = [effect_id, *suffix]
        parents = sorted(effect_predecessors.get(effect_id, set()) - seen)
        if not parents:
            display_paths.append(path)
            return
        for parent in parents:
            display_walk(parent, path, seen | {effect_id})

    for sink_effect in sink_effects:
        display_walk(sink_effect, [], set())

    payload: dict[str, object] = {
        "schema_version": "3.0",
        "slice_id": "slice-"
        + stable_hash(
            [
                graph.graph_hash,
                sorted(sink_port_ids),
                limits.model_dump(mode="json"),
                [item.model_dump(mode="json") for item in joins],
            ]
        )[:20],
        "source_graph_id": graph.graph_id,
        "source_graph_hash": graph.graph_hash,
        "sink_port_ids": sorted(sink_port_ids),
        "effect_ids": sorted(selected_effects),
        "port_ids": sorted(selected_ports),
        "resource_version_ids": sorted(selected_resources),
        "effect_group_ids": sorted(selected_groups),
        "claims": [
            item.model_dump(mode="json")
            for item in sorted(selected_claims.values(), key=lambda value: value.claim_id)
        ],
        "joins": [item.model_dump(mode="json") for item in selected_joins],
        "external_preconditions": [
            item.model_dump(mode="json")
            for item in sorted(external.values(), key=lambda value: value.precondition_id)
        ],
        "display_paths": sorted(display_paths),
        "budget": limits.model_dump(mode="json"),
        "candidate_count": candidates,
        "truncated": bool(truncation_reasons),
        "truncation_reasons": sorted(truncation_reasons),
        "graph_reference_consistency": reference_consistency,
        "replay_consistency": "not_evaluated",
    }
    payload["slice_hash"] = _slice_hash(payload)
    return DependencySlice.model_validate(payload)
