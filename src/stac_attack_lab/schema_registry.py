from __future__ import annotations

from pydantic import BaseModel

from stac_attack_lab.datasets.primitive_chain import (
    AcceptedSampleRecord,
    PrimitiveChainCandidate,
    PrimitiveChainSample,
    SampleLibraryManifest,
)
from stac_attack_lab.environments.safeclaw.contracts import (
    BaselineBinding,
    BenchmarkBinding,
    BenchmarkPublicPrompt,
    SafeClawEpisodeResult,
    SafeClawPublicTaskView,
    SafeClawTaskDescriptor,
)
from stac_attack_lab.execution.benign_collection import (
    BenignCollectionConfig,
    BenignPreparationManifest,
    BenignSourceModeManifest,
    BenignTraceAssessment,
)
from stac_attack_lab.execution.formal_attacker import (
    FormalAttackerInput,
    FormalAttackRealization,
)
from stac_attack_lab.execution.sample_generation import (
    SampleCollectionStageManifest,
    SampleLibraryAuditReport,
    SampleMiningStageManifest,
)
from stac_attack_lab.execution.sample_preflight import SampleCollectionPreflightReport
from stac_attack_lab.flow.analysis import (
    AnalysisManifest,
    DependencySlice,
    FlowAnalysisReport,
    FlowRegistry,
    InterventionRecord,
    MacroBinding,
)
from stac_attack_lab.flow.models import EffectGraph, ObservationProfile
from stac_attack_lab.interactions.benign import (
    BenignPolicyAction,
    BenignPolicyObservation,
    BenignScenario,
    BenignScenarioSet,
    NeutralizationResult,
)
from stac_attack_lab.interactions.construction import (
    ConstructionAttackerAction,
    ConstructionObservation,
)
from stac_attack_lab.interactions.models import (
    InteractionEvent,
    InteractionGraph,
    PrimitiveOccurrence,
    RawInteractionTrajectory,
)
from stac_attack_lab.planning.formal_base import (
    FormalCaseAssignment,
    FormalEvaluationPlan,
    FormalPlannerInput,
    SingleSamplePlannerInput,
)
from stac_attack_lab.primitives.core import CorePrimitiveSpec
from stac_attack_lab.primitives.macros import AttackMacroSpec
from stac_attack_lab.verification.formal_aggregate import FormalRunResult

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "core_primitive_spec": CorePrimitiveSpec,
    "attack_macro_spec": AttackMacroSpec,
    "raw_interaction_trajectory": RawInteractionTrajectory,
    "interaction_event": InteractionEvent,
    "interaction_graph": InteractionGraph,
    "primitive_occurrence": PrimitiveOccurrence,
    "primitive_chain_candidate": PrimitiveChainCandidate,
    "primitive_chain_sample": PrimitiveChainSample,
    "accepted_sample_record": AcceptedSampleRecord,
    "sample_library_manifest": SampleLibraryManifest,
    "safeclaw_task_descriptor": SafeClawTaskDescriptor,
    "safeclaw_public_task_view": SafeClawPublicTaskView,
    "benchmark_public_prompt": BenchmarkPublicPrompt,
    "formal_case_assignment": FormalCaseAssignment,
    "single_sample_planner_input": SingleSamplePlannerInput,
    "baseline_binding": BaselineBinding,
    "benchmark_binding": BenchmarkBinding,
    "formal_planner_input": FormalPlannerInput,
    "formal_evaluation_plan": FormalEvaluationPlan,
    "safeclaw_episode_result": SafeClawEpisodeResult,
    "formal_run_result": FormalRunResult,
    "construction_observation": ConstructionObservation,
    "construction_attacker_action": ConstructionAttackerAction,
    "formal_attacker_input": FormalAttackerInput,
    "formal_attack_realization": FormalAttackRealization,
    "sample_collection_preflight_report": SampleCollectionPreflightReport,
    "sample_collection_stage_manifest": SampleCollectionStageManifest,
    "sample_mining_stage_manifest": SampleMiningStageManifest,
    "sample_library_audit_report": SampleLibraryAuditReport,
    "observation_profile_v3": ObservationProfile,
    "effect_graph_v3": EffectGraph,
    "flow_registry_v3": FlowRegistry,
    "dependency_slice_v3": DependencySlice,
    "flow_analysis_manifest_v3": AnalysisManifest,
    "flow_analysis_report_v3": FlowAnalysisReport,
    "flow_macro_binding_v3": MacroBinding,
    "flow_intervention_record_v3": InterventionRecord,
    "benign_scenario": BenignScenario,
    "benign_scenario_set": BenignScenarioSet,
    "benign_policy_observation": BenignPolicyObservation,
    "benign_policy_action": BenignPolicyAction,
    "benign_collection_config": BenignCollectionConfig,
    "benign_source_mode_manifest": BenignSourceModeManifest,
    "benign_preparation_manifest": BenignPreparationManifest,
    "benign_trace_assessment": BenignTraceAssessment,
    "benign_neutralization_result": NeutralizationResult,
}


def validate_schema_registry() -> None:
    for name, model in SCHEMA_MODELS.items():
        schema = model.model_json_schema()
        if schema.get("type") != "object":
            raise ValueError(f"schema_root_not_object:{name}")
