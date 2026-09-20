from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from stac_attack_lab.execution.sample_generation import (
    COLLECTION_STAGE_MANIFEST,
    _validate_collection_stage,
)
from stac_attack_lab.extraction.flow_macros import bind_supported_macros
from stac_attack_lab.extraction.flow_slice import slice_dependency_graph
from stac_attack_lab.flow.analysis import (
    AnalysisInputRef,
    AnalysisManifest,
    AnalysisOutputRef,
    JoinRequirement,
    SliceBudget,
    SliceJoinSemantics,
)
from stac_attack_lab.flow.models import EffectGraph
from stac_attack_lab.flow.profile import load_observation_profile, observation_profile_hash
from stac_attack_lab.flow.registry import load_flow_registry
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.interactions.flow_v3 import (
    observations_from_interaction_graph,
    project_effect_graph,
)
from stac_attack_lab.interactions.models import InteractionGraph, RawInteractionTrajectory
from stac_attack_lab.interactions.normalizer import normalize_trajectory
from stac_attack_lab.primitives.formal_registry import load_formal_registry
from stac_attack_lab.reporting.flow_v3 import build_flow_analysis_report
from stac_attack_lab.verification.flow_admission import assess_flow_profiles
from stac_attack_lab.verification.flow_v3 import verify_effect_graph


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def _source_label(project_root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(project_root.resolve()))
    except ValueError:
        return str(path.resolve())


def _terminal_output_ports(graph: EffectGraph) -> list[str]:
    sources = {claim.source_port_id for claim in graph.claims}
    outputs = {
        port_id
        for effect in graph.effects
        for port_id in effect.output_port_ids
        if port_id not in sources
    }
    if not outputs:
        outputs = {port_id for effect in graph.effects for port_id in effect.output_port_ids}
    return sorted(outputs)


def _default_joins(graph: EffectGraph, sink_ports: list[str]) -> list[JoinRequirement]:
    joins: list[JoinRequirement] = []
    for target in sink_ports:
        members = sorted(claim.claim_id for claim in graph.claims if claim.target_port_id == target)
        if members:
            joins.append(
                JoinRequirement(
                    join_group_id="join-" + stable_hash([target, members])[:20],
                    target_port_id=target,
                    member_claim_ids=members,
                    semantics=SliceJoinSemantics.all,
                    origin="observed",
                )
            )
    return joins


def _load_inputs(
    project_root: Path, input_path: Path, normalized_root: Path
) -> tuple[
    Literal["collection", "interaction_graph"],
    list[InteractionGraph],
    list[AnalysisInputRef],
    dict[str, Any],
]:
    if input_path.is_file():
        graph = InteractionGraph.model_validate_json(input_path.read_text(encoding="utf-8"))
        return (
            "interaction_graph",
            [graph],
            [
                AnalysisInputRef(
                    relative_or_declared_path=str(input_path),
                    content_hash=file_hash(input_path),
                    kind="interaction_graph",
                )
            ],
            {},
        )
    benign_manifest_path = input_path / "benign_source_mode_manifest.json"
    benign_manifest: dict[str, Any] | None = None
    stage = None
    if benign_manifest_path.is_file():
        benign_manifest = json.loads(benign_manifest_path.read_text(encoding="utf-8"))
        manifest_hash = benign_manifest.pop("manifest_hash", None)
        if manifest_hash != stable_hash(benign_manifest):
            raise ValueError("v3_reanalysis_benign_manifest_hash_mismatch")
        benign_manifest["manifest_hash"] = manifest_hash
        if benign_manifest.get("source_mode") != "benign_interaction":
            raise ValueError("v3_reanalysis_benign_source_mode_invalid")
        collection_manifest_path = input_path / "collection_manifest.json"
        if file_hash(collection_manifest_path) != benign_manifest.get("collection_manifest_hash"):
            raise ValueError("v3_reanalysis_benign_collection_manifest_hash_mismatch")
    else:
        stage = _validate_collection_stage(input_path)
        legacy_registry = load_formal_registry(project_root / stage.config.registry_path)
        if legacy_registry.registry_hash != stage.registry_hash:
            raise ValueError("v3_reanalysis_legacy_registry_hash_mismatch")
    graphs: list[InteractionGraph] = []
    evidence_bundle_refs: list[AnalysisInputRef] = []
    policy_hashes: set[str] = set()
    refs = []
    if stage is not None:
        refs.append(
            AnalysisInputRef(
                relative_or_declared_path=str(input_path / COLLECTION_STAGE_MANIFEST),
                content_hash=file_hash(input_path / COLLECTION_STAGE_MANIFEST),
                kind="collection_stage_manifest",
            )
        )
    for raw_path in sorted(input_path.glob("trajectories/*/raw_trajectory.json")):
        trajectory = RawInteractionTrajectory.model_validate_json(
            raw_path.read_text(encoding="utf-8")
        )
        policy_hash = trajectory.provenance.get("provider_evidence_policy_hash")
        if policy_hash:
            policy_hashes.add(policy_hash)
        for evidence_ref in trajectory.evidence_refs:
            if evidence_ref.kind != "provider_boundary_evidence" or not evidence_ref.relative_path:
                continue
            evidence_path = input_path / evidence_ref.relative_path
            evidence_bundle_refs.append(
                AnalysisInputRef(
                    relative_or_declared_path=str(evidence_path),
                    content_hash=file_hash(evidence_path),
                    kind="provider_boundary_evidence",
                )
            )
        graph_path, _ = normalize_trajectory(
            raw_path, collection_root=input_path, output_root=normalized_root
        )
        graphs.append(InteractionGraph.model_validate_json(graph_path.read_text(encoding="utf-8")))
        refs.append(
            AnalysisInputRef(
                relative_or_declared_path=str(raw_path),
                content_hash=file_hash(raw_path),
                kind="raw_trajectory",
            )
        )
    if benign_manifest is not None:
        expected = benign_manifest.get("trajectory_hashes")
        observed = {
            path.parent.name: file_hash(path)
            for path in sorted(input_path.glob("trajectories/*/raw_trajectory.json"))
        }
        if expected != observed:
            raise ValueError("v3_reanalysis_benign_trajectory_hash_mismatch")
        refs.append(
            AnalysisInputRef(
                relative_or_declared_path=str(benign_manifest_path),
                content_hash=file_hash(benign_manifest_path),
                kind="benign_source_mode_manifest",
            )
        )
        return (
            "collection",
            graphs,
            refs,
            {
                "run_id": benign_manifest.get("collection_id"),
                "collection_manifest_hash": benign_manifest.get("collection_manifest_hash"),
                "collection_tree_hash": None,
                "collection_config_hash": benign_manifest.get("config_hash"),
                "collection_registry_hash": benign_manifest.get("registry_hash"),
                "sampling_strategy": {
                    "kind": "reviewed_benign_scenarios",
                    "selection": "configured_scenario_ids",
                },
                "evidence_bundle_refs": evidence_bundle_refs,
                "policy_hashes": sorted(policy_hashes),
                "origin_modes": ["benign_interaction"],
            },
        )
    assert stage is not None
    return (
        "collection",
        graphs,
        refs,
        {
            "run_id": stage.pipeline_id,
            "collection_manifest_hash": stage.collection_manifest_hash,
            "collection_tree_hash": stage.collection_tree_hash,
            "collection_config_hash": stage.config_hash,
            "collection_registry_hash": stage.registry_hash,
            "sampling_strategy": {
                "kind": "configured_collection",
                "selection": (
                    "unknown" if not stage.config.source_task_ids else "configured_source_task_ids"
                ),
            },
            "evidence_bundle_refs": evidence_bundle_refs,
            "policy_hashes": sorted(policy_hashes),
            "origin_modes": ["legacy_adversarial"],
        },
    )


def reanalyze_flow_v3(
    project_root: Path,
    *,
    input_path: Path,
    output_root: Path,
    profile_path: Path,
    registry_path: Path,
    sink_port_ids: list[str] | None = None,
    terminal_outputs: bool = False,
    budget: SliceBudget | None = None,
) -> Path:
    profile = load_observation_profile(profile_path)
    registry = load_flow_registry(registry_path)
    parameters = {
        "sink_port_ids": sorted(sink_port_ids or []),
        "terminal_outputs": terminal_outputs,
        "budget": (budget or SliceBudget()).model_dump(mode="json"),
        "join_policy": "all_observed_incoming_to_selected_sink",
    }
    if input_path.is_file():
        input_identity = file_hash(input_path)
    elif (input_path / "benign_source_mode_manifest.json").is_file():
        input_identity = file_hash(input_path / "benign_source_mode_manifest.json")
    else:
        input_identity = file_hash(input_path / COLLECTION_STAGE_MANIFEST)
    analysis_key = stable_hash(
        {
            "input": input_identity,
            "profile": observation_profile_hash(profile),
            "registry": registry.registry_hash,
            "parameters": parameters,
        }
    )
    analysis_id = datetime.now(UTC).strftime("v3-%Y%m%dT%H%M%S-%fZ-") + analysis_key[:10]
    analysis_root = output_root / analysis_id
    analysis_root.mkdir(parents=True, exist_ok=False, mode=0o700)
    input_mode, legacy_graphs, input_refs, collection = _load_inputs(
        project_root, input_path, analysis_root / "normalized"
    )
    graphs: list[EffectGraph] = []
    slices = []
    admissions = []
    macros = []
    for legacy in legacy_graphs:
        observations, artifacts, evidence = observations_from_interaction_graph(legacy)
        projected = project_effect_graph(
            source_graph_id=legacy.graph_id,
            source_graph_hash=legacy.graph_hash,
            observations=observations,
            artifacts=artifacts,
            evidence=evidence,
            profile=profile,
        )
        verified = verify_effect_graph(projected, evidence)
        selected_sinks = sorted(set(sink_port_ids or []))
        if terminal_outputs:
            selected_sinks = sorted(set(selected_sinks + _terminal_output_ports(verified)))
        if not selected_sinks:
            raise ValueError("v3_reanalysis_explicit_sink_required")
        dependency_slice = slice_dependency_graph(
            verified,
            sink_port_ids=selected_sinks,
            budget=budget,
            join_requirements=_default_joins(verified, selected_sinks),
        )
        admission = assess_flow_profiles(verified, dependency_slice, evidence)
        bindings = bind_supported_macros(verified, dependency_slice)
        graphs.append(verified)
        slices.append(dependency_slice)
        admissions.append(admission)
        macros.extend(bindings)
        stem = legacy.trajectory_id
        _atomic_json(
            analysis_root / "graphs" / f"{stem}.effect_graph.json",
            verified.model_dump(mode="json"),
        )
        _atomic_json(
            analysis_root / "slices" / f"{stem}.slice.json",
            dependency_slice.model_dump(mode="json"),
        )
        _atomic_json(
            analysis_root / "admission" / f"{stem}.json",
            admission.model_dump(mode="json"),
        )
    report = build_flow_analysis_report(
        analysis_id=analysis_id,
        analysis_key=analysis_key,
        input_mode=input_mode,
        graphs=graphs,
        slices=slices,
        admissions=admissions,
        macro_bindings=macros,
    )
    _atomic_json(analysis_root / "report.json", report.model_dump(mode="json"))
    output_refs = [
        AnalysisOutputRef(
            relative_path=str(path.relative_to(analysis_root)),
            content_hash=file_hash(path),
            kind=path.stem,
        )
        for path in sorted(analysis_root.rglob("*.json"))
    ]
    source_files = [
        Path(__file__),
        Path(project_effect_graph.__code__.co_filename),
        Path(verify_effect_graph.__code__.co_filename),
        Path(slice_dependency_graph.__code__.co_filename),
        Path(assess_flow_profiles.__code__.co_filename),
    ]
    manifest_payload: dict[str, Any] = {
        "schema_version": "3.0",
        "analysis_id": analysis_id,
        "analysis_key": analysis_key,
        "run_id": collection.get("run_id"),
        "template_id": None,
        "input_mode": input_mode,
        "input_refs": [item.model_dump(mode="json") for item in input_refs],
        "collection_manifest_hash": collection.get("collection_manifest_hash"),
        "collection_tree_hash": collection.get("collection_tree_hash"),
        "collection_config_hash": collection.get("collection_config_hash"),
        "collection_registry_hash": collection.get("collection_registry_hash"),
        "sampling_strategy": collection.get("sampling_strategy", {"kind": "unknown"}),
        "profile_id": profile.profile_id,
        "profile_version": profile.profile_version,
        "profile_hash": observation_profile_hash(profile),
        "registry_id": registry.registry_id,
        "registry_version": registry.registry_version,
        "registry_hash": registry.registry_hash,
        "projector_version": registry.projector_version,
        "verifier_version": registry.verifier_version,
        "policy_hashes": collection.get("policy_hashes", []),
        "processing_source_hashes": {
            _source_label(project_root, path): file_hash(path) for path in source_files
        },
        "parameters": {
            **parameters,
            "origin_modes": collection.get("origin_modes", ["unknown"]),
        },
        "evidence_bundle_refs": [
            item.model_dump(mode="json") for item in collection.get("evidence_bundle_refs", [])
        ],
        "output_refs": [item.model_dump(mode="json") for item in output_refs],
        "completeness": "partial" if report.truncated else "complete",
        "truncated": report.truncated,
        "truncation_reasons": report.truncation_reasons,
        "legacy_verdicts_inherited": False,
        "sampling_bias_acknowledged": True,
    }
    manifest_payload["manifest_hash"] = stable_hash(manifest_payload)
    manifest = AnalysisManifest.model_validate(manifest_payload)
    _atomic_json(analysis_root / "analysis_manifest.json", manifest.model_dump(mode="json"))
    return analysis_root


def validate_flow_analysis(analysis_root: Path) -> AnalysisManifest:
    manifest = AnalysisManifest.model_validate_json(
        (analysis_root / "analysis_manifest.json").read_text(encoding="utf-8")
    )
    for ref in manifest.output_refs:
        path = (analysis_root / ref.relative_path).resolve()
        if analysis_root.resolve() not in path.parents or not path.is_file():
            raise ValueError("analysis_output_reference_invalid")
        if file_hash(path) != ref.content_hash:
            raise ValueError("analysis_output_hash_mismatch")
    return manifest
