from __future__ import annotations

from collections import defaultdict

from stac_attack_lab.flow.analysis import (
    DependencySlice,
    MacroBinding,
    MacroBindingStatus,
)
from stac_attack_lab.flow.models import (
    ClaimVerdict,
    DependencyClaim,
    DependencyRelation,
    EffectGraph,
    PrimitiveKind,
)
from stac_attack_lab.hashing import stable_hash


def bind_supported_macros(
    graph: EffectGraph, dependency_slice: DependencySlice
) -> list[MacroBinding]:
    selected_effects = {
        item.effect_id: item
        for item in graph.effects
        if item.effect_id in dependency_slice.effect_ids
    }
    selected_claims = {
        item.claim_id: item
        for item in graph.claims
        if item.claim_id in {claim.claim_id for claim in dependency_slice.claims}
    }
    ports = {item.port_id: item for item in graph.ports}
    versions = {item.resource_version_id: item for item in graph.resource_versions}
    effects_by_port: dict[str, set[str]] = defaultdict(set)
    for effect in selected_effects.values():
        for port_id in effect.input_port_ids + effect.output_port_ids:
            effects_by_port[port_id].add(effect.effect_id)

    persist_recall_candidates: list[tuple[str, str, str]] = []
    for claim in selected_claims.values():
        if (
            claim.relation != DependencyRelation.read_from
            or claim.dependency_verdict != ClaimVerdict.verified
        ):
            continue
        source_port = ports[claim.source_port_id]
        if source_port.resource_version_id is None:
            continue
        version = versions[source_port.resource_version_id]
        writers = [
            effect
            for effect in selected_effects.values()
            if effect.primitive == PrimitiveKind.update
            and version.resource_version_id in effect.resource_version_ids
        ]
        readers = [selected_effects[item] for item in effects_by_port[claim.target_port_id]]
        for writer in writers:
            for reader in readers:
                writer_domains = [
                    item for item in graph.domains if item.domain_id in writer.domain_ids
                ]
                reader_domains = [
                    item for item in graph.domains if item.domain_id in reader.domain_ids
                ]
                writer_sessions = {
                    item.actual_session_id for item in writer_domains if item.actual_session_id
                }
                reader_sessions = {
                    item.actual_session_id for item in reader_domains if item.actual_session_id
                }
                scopes = {
                    item.workspace_scope
                    for item in [*writer_domains, *reader_domains]
                    if item.workspace_scope
                }
                if (
                    writer_sessions
                    and reader_sessions
                    and writer_sessions.isdisjoint(reader_sessions)
                    and len(scopes) == 1
                ):
                    persist_recall_candidates.append(
                        (writer.effect_id, reader.effect_id, claim.claim_id)
                    )
    if len(persist_recall_candidates) == 1:
        writer_id, reader_id, claim_id = persist_recall_candidates[0]
        persist = MacroBinding(
            binding_id="macro-binding-"
            + stable_hash(["PersistRecall", writer_id, reader_id, claim_id])[:20],
            macro_name="PersistRecall",
            macro_version="3.0.0",
            status=MacroBindingStatus.bound,
            effect_ids=[writer_id, reader_id],
            port_ids=[
                selected_claims[claim_id].source_port_id,
                selected_claims[claim_id].target_port_id,
            ],
            claim_ids=[claim_id],
            constraints={
                "session": "different_actual_session",
                "workspace": "same_scope",
                "resource": "exact_version_read_from",
            },
            reason_codes=["persist_recall_binding_verified"],
        )
    else:
        persist = MacroBinding(
            binding_id="macro-binding-"
            + stable_hash(["PersistRecall", dependency_slice.slice_id])[:20],
            macro_name="PersistRecall",
            macro_version="3.0.0",
            status=(
                MacroBindingStatus.unknown
                if len(persist_recall_candidates) > 1
                else MacroBindingStatus.unsupported
            ),
            effect_ids=[],
            port_ids=[],
            claim_ids=[],
            constraints={},
            reason_codes=[
                "persist_recall_binding_ambiguous"
                if persist_recall_candidates
                else "persist_recall_binding_not_observed"
            ],
        )

    by_target: dict[str, list[DependencyClaim]] = defaultdict(list)
    for claim in selected_claims.values():
        if (
            claim.relation
            in {
                DependencyRelation.data_dep,
                DependencyRelation.available_input,
            }
            and claim.dependency_verdict == ClaimVerdict.verified
        ):
            by_target[claim.target_port_id].append(claim)
    bind_candidates = [
        (target, claims)
        for target, claims in by_target.items()
        if len({item.source_port_id for item in claims}) >= 2
    ]
    if len(bind_candidates) == 1:
        target, members = bind_candidates[0]
        claim_ids = sorted(item.claim_id for item in members)
        source_ports = sorted({item.source_port_id for item in members})
        effect_ids = sorted(effects_by_port.get(target, set()))
        bind = MacroBinding(
            binding_id="macro-binding-" + stable_hash(["Bind", target, claim_ids])[:20],
            macro_name="Bind",
            macro_version="3.0.0",
            status=MacroBindingStatus.bound,
            effect_ids=effect_ids,
            port_ids=[*source_ports, target],
            claim_ids=claim_ids,
            constraints={"join": "multiple_verified_source_ports", "target": target},
            reason_codes=["multi_source_bind_verified"],
        )
    else:
        bind = MacroBinding(
            binding_id="macro-binding-" + stable_hash(["Bind", dependency_slice.slice_id])[:20],
            macro_name="Bind",
            macro_version="3.0.0",
            status=(
                MacroBindingStatus.unknown
                if len(bind_candidates) > 1
                else MacroBindingStatus.unsupported
            ),
            effect_ids=[],
            port_ids=[],
            claim_ids=[],
            constraints={},
            reason_codes=[
                "multi_source_bind_ambiguous"
                if bind_candidates
                else "multi_source_bind_not_observed"
            ],
        )
    return [persist, bind]
