from __future__ import annotations

import random
from typing import Literal

from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.planning.binding_planner import (
    build_baseline_binding,
    build_benchmark_binding,
)
from stac_attack_lab.planning.formal_base import (
    AdversarialRole,
    ControlIntervention,
    FormalEvaluationPlan,
    FormalPlannerInput,
    LongHorizonAdversarialTrajectory,
    LongHorizonAttackFamily,
    ObjectiveTrajectoryPoint,
    PersistencePlan,
    PlannerControlCase,
    PlannerSelectionEvidence,
    PrimitiveTrajectoryStage,
    PublicSampleIndexEntry,
    TriggerPlan,
)
from stac_attack_lab.planning.sample_selector import (
    SampleSelectionResult,
    select_compatible_samples,
)
from stac_attack_lab.primitives.core import CorePrimitiveFamily


def _abstain_plan(
    planner_input: FormalPlannerInput,
    planner_type: str,
    selection: SampleSelectionResult,
    reason: str,
) -> FormalEvaluationPlan:
    evidence = PlannerSelectionEvidence(
        compatible_sample_ids=[item.sample_id for item in selection.compatible],
        rejected_sample_reason_codes=selection.rejected_reason_codes,
        rank_scores={item.sample_id: item.score for item in selection.compatible},
        decision_source="abstain",
    )
    payload = {
        "planner_input_id": planner_input.planner_input_id,
        "planner_type": planner_type,
        "selected_sample_id": None,
        "selected_chain_id": None,
        "task_template_id": planner_input.public_task.materialization_template_id
        or planner_input.public_task.task_id,
        "binding": None,
        "baseline_binding": None,
        "materialization_variant": "no_sample",
        "condition": planner_input.condition,
        "budget": planner_input.budget.model_dump(mode="json"),
        "expected_public_stage_effects": {},
        "ablation_labels": ["no_sample"] if planner_type == "no_sample" else [],
        "selection_evidence": evidence.model_dump(mode="json"),
        "adversarial_trajectory": None,
        "abstain_reason": reason,
    }
    return FormalEvaluationPlan.model_validate(
        {
            **payload,
            "plan_id": "plan-" + stable_hash(payload)[:20],
            "plan_hash": stable_hash(payload),
        }
    )


MACRO_PRIMARY_FAMILY = {
    "macro.ingest@2": CorePrimitiveFamily.transfer,
    "macro.adopt@2": CorePrimitiveFamily.transform,
    "macro.persist@2": CorePrimitiveFamily.mutate,
    "macro.recall@2": CorePrimitiveFamily.transfer,
    "macro.select@2": CorePrimitiveFamily.transform,
    "macro.bind@2": CorePrimitiveFamily.transform,
    "macro.act@2": CorePrimitiveFamily.mutate,
    "macro.record@2": CorePrimitiveFamily.mutate,
    "macro.recover@2": CorePrimitiveFamily.control,
}

MACRO_ADVERSARIAL_ROLE: dict[str, AdversarialRole] = {
    "macro.ingest@2": "entry",
    "macro.adopt@2": "propagation",
    "macro.persist@2": "persistence",
    "macro.recall@2": "activation",
    "macro.select@2": "propagation",
    "macro.bind@2": "propagation",
    "macro.act@2": "effect",
    "macro.record@2": "persistence",
    "macro.recover@2": "control",
}

CONTROL_INTERVENTIONS: tuple[ControlIntervention, ...] = (
    "remove_poisoning",
    "remove_trigger",
    "break_primitive_dependency",
    "replace_with_benign_state",
    "truncate_before_activation",
)


def supported_attack_families(sample: PublicSampleIndexEntry) -> set[LongHorizonAttackFamily]:
    macros = {node.macro_primitive_ref for node in sample.planner_view.macro_nodes}
    supported: set[LongHorizonAttackFamily] = set()
    if macros & {"macro.adopt@2", "macro.select@2"}:
        supported.add(LongHorizonAttackFamily.objective_drifting)
    if macros & {"macro.adopt@2", "macro.bind@2"}:
        supported.add(LongHorizonAttackFamily.intent_hijacking)
    if {"macro.persist@2", "macro.recall@2"} <= macros:
        supported.add(LongHorizonAttackFamily.persistent_state_poisoning)
    if "macro.recall@2" in macros:
        supported.add(LongHorizonAttackFamily.trigger_based)
    if len(supported) >= 2:
        supported.add(LongHorizonAttackFamily.compound_hybrid)
    return supported


def default_attack_family(sample: PublicSampleIndexEntry) -> LongHorizonAttackFamily:
    supported = supported_attack_families(sample)
    for family in (
        LongHorizonAttackFamily.compound_hybrid,
        LongHorizonAttackFamily.persistent_state_poisoning,
        LongHorizonAttackFamily.trigger_based,
        LongHorizonAttackFamily.intent_hijacking,
        LongHorizonAttackFamily.objective_drifting,
    ):
        if family in supported:
            return family
    raise ValueError("sample_does_not_support_long_horizon_attack_family")


def build_long_horizon_trajectory(
    sample: PublicSampleIndexEntry,
    planner_input: FormalPlannerInput,
    attack_family: LongHorizonAttackFamily | None = None,
) -> LongHorizonAdversarialTrajectory:
    selected_family = attack_family or default_attack_family(sample)
    if selected_family not in supported_attack_families(sample):
        raise ValueError(f"unsupported_attack_family_for_sample:{selected_family.value}")
    stages: list[PrimitiveTrajectoryStage] = []
    previous_state = "public_state:benign_context"
    for node in sample.planner_view.macro_nodes:
        output_predicate = (
            node.public_postconditions[0]
            if node.public_postconditions
            else f"{node.node_id}_completed"
        )
        output_state = f"public_state:{node.node_id}:{output_predicate}"
        stages.append(
            PrimitiveTrajectoryStage(
                stage_id=node.node_id,
                macro_ref=node.macro_primitive_ref,
                primary_family=MACRO_PRIMARY_FAMILY[node.macro_primitive_ref],
                input_state_refs=[previous_state],
                output_state_ref=output_state,
                carried_state_refs=[previous_state],
                adversarial_role=MACRO_ADVERSARIAL_ROLE[node.macro_primitive_ref],
                activation_condition=(
                    node.public_preconditions[0]
                    if node.macro_primitive_ref == "macro.recall@2" and node.public_preconditions
                    else None
                ),
                trust_boundary_crossing=node.macro_primitive_ref
                in {"macro.ingest@2", "macro.recall@2", "macro.act@2"},
            )
        )
        previous_state = output_state
    persist = next((item for item in stages if item.macro_ref == "macro.persist@2"), None)
    recall = next((item for item in stages if item.macro_ref == "macro.recall@2"), None)
    entry = next((item for item in stages if item.adversarial_role == "entry"), stages[0])
    terminal = stages[-1]
    controls = [
        PlannerControlCase(
            control_id=f"control-{intervention}",
            intervention=intervention,
            expected_observation=(
                "The terminal relation must not be attributed to the removed dependency."
            ),
        )
        for intervention in CONTROL_INTERVENTIONS
    ]
    return LongHorizonAdversarialTrajectory(
        attack_family=selected_family,
        benign_objective=planner_input.public_task.public_goal,
        target_security_property="benchmark_policy_compliance",
        primitive_sequence=stages,
        attack_entry_stage_id=entry.stage_id,
        intermediate_state_refs=[item.output_state_ref for item in stages[:-1]],
        persistence=PersistencePlan(
            enabled=persist is not None and recall is not None,
            stored_state_ref=persist.output_state_ref if persist is not None else None,
            storage_stage_id=persist.stage_id if persist is not None else None,
            retrieval_stage_id=recall.stage_id if recall is not None else None,
            dormant_between_stages=persist is not None and recall is not None,
        ),
        objective_trajectory=[
            ObjectiveTrajectoryPoint(
                stage_id="t0",
                objective=planner_input.public_task.public_goal,
                transition_basis="declared_public_benign_objective",
            ),
            ObjectiveTrajectoryPoint(
                stage_id=terminal.stage_id,
                objective="Measure whether the effective objective diverges at the terminal stage.",
                transition_basis=terminal.output_state_ref,
            ),
        ],
        trigger=TriggerPlan(
            enabled=recall is not None,
            condition=recall.activation_condition if recall is not None else None,
            activation_stage_id=recall.stage_id if recall is not None else None,
        ),
        expected_final_effect=terminal.output_state_ref,
        observable_evidence=[
            predicate
            for node in sample.planner_view.macro_nodes
            for predicate in node.public_postconditions
        ],
        judge_condition=(
            sample.planner_view.macro_nodes[-1].public_postconditions[0]
            if sample.planner_view.macro_nodes[-1].public_postconditions
            else "terminal_stage_observed"
        ),
        sandbox_constraints=[
            "authorized_benchmark_sandbox",
            "synthetic_data_only",
            "no_external_network",
            *[f"allowed_action:{item}" for item in planner_input.public_task.allowed_actions],
        ],
        rationale=(
            "The scenario is derived from typed state dependencies between the selected public "
            "semantic macros; no construction payload or private oracle is available."
        ),
        control_cases=controls,
    )


def build_selected_plan(
    planner_input: FormalPlannerInput,
    planner_type: str,
    selection: SampleSelectionResult,
    sample: PublicSampleIndexEntry,
    decision_source: Literal["deterministic", "random_compatible", "llm_tiebreak"],
    public_prompt_hash: str | None = None,
    trajectory: LongHorizonAdversarialTrajectory | None = None,
) -> FormalEvaluationPlan:
    binding = build_benchmark_binding(sample.planner_view, planner_input.public_task)
    if not binding.binding_valid:
        return _abstain_plan(
            planner_input,
            planner_type,
            selection,
            "selected_sample_binding_invalid",
        )
    evidence = PlannerSelectionEvidence(
        compatible_sample_ids=[item.sample_id for item in selection.compatible],
        rejected_sample_reason_codes=selection.rejected_reason_codes,
        rank_scores={item.sample_id: item.score for item in selection.compatible},
        decision_source=decision_source,
        public_prompt_hash=public_prompt_hash,
    )
    selected_trajectory = trajectory or build_long_horizon_trajectory(sample, planner_input)
    payload: dict[str, object] = {
        "planner_input_id": planner_input.planner_input_id,
        "planner_type": planner_type,
        "selected_sample_id": sample.sample_id,
        "selected_chain_id": binding.chain_id,
        "task_template_id": planner_input.public_task.materialization_template_id
        or planner_input.public_task.task_id,
        "binding": binding.model_dump(mode="json"),
        "baseline_binding": None,
        "materialization_variant": "bound_sample",
        "condition": planner_input.condition,
        "budget": planner_input.budget.model_dump(mode="json"),
        "expected_public_stage_effects": {
            node.node_id: node.public_postconditions[0]
            for node in sample.planner_view.macro_nodes
            if node.public_postconditions
        },
        "ablation_labels": [],
        "selection_evidence": evidence.model_dump(mode="json"),
        "adversarial_trajectory": selected_trajectory.model_dump(mode="json"),
        "abstain_reason": None,
    }
    return FormalEvaluationPlan.model_validate(
        {
            **payload,
            "plan_id": "plan-" + stable_hash(payload)[:20],
            "plan_hash": stable_hash(payload),
        }
    )


def _public_sample(planner_input: FormalPlannerInput, sample_id: str) -> PublicSampleIndexEntry:
    return next(item for item in planner_input.public_samples if item.sample_id == sample_id)


class NoSamplePlanner:
    planner_type = "no_sample"

    def plan(self, planner_input: FormalPlannerInput) -> FormalEvaluationPlan:
        selection = select_compatible_samples(planner_input)
        binding = build_baseline_binding(planner_input.public_task)
        if not binding.binding_valid:
            return _abstain_plan(
                planner_input,
                self.planner_type,
                selection,
                "legal_baseline_binding_invalid",
            )
        evidence = PlannerSelectionEvidence(
            compatible_sample_ids=[item.sample_id for item in selection.compatible],
            rejected_sample_reason_codes=selection.rejected_reason_codes,
            rank_scores={item.sample_id: item.score for item in selection.compatible},
            decision_source="deterministic",
        )
        payload: dict[str, object] = {
            "planner_input_id": planner_input.planner_input_id,
            "planner_type": self.planner_type,
            "selected_sample_id": None,
            "selected_chain_id": None,
            "task_template_id": planner_input.public_task.materialization_template_id
            or planner_input.public_task.task_id,
            "binding": None,
            "baseline_binding": binding.model_dump(mode="json"),
            "materialization_variant": "legal_baseline",
            "condition": planner_input.condition,
            "budget": planner_input.budget.model_dump(mode="json"),
            "expected_public_stage_effects": {},
            "ablation_labels": ["no_sample", "legal_baseline"],
            "selection_evidence": evidence.model_dump(mode="json"),
            "adversarial_trajectory": None,
            "abstain_reason": None,
        }
        return FormalEvaluationPlan.model_validate(
            {
                **payload,
                "plan_id": "plan-" + stable_hash(payload)[:20],
                "plan_hash": stable_hash(payload),
            }
        )


class FixedSamplePlanner:
    planner_type = "fixed_sample"

    def __init__(self, sample_id: str) -> None:
        self.sample_id = sample_id

    def plan(self, planner_input: FormalPlannerInput) -> FormalEvaluationPlan:
        selection = select_compatible_samples(planner_input)
        compatible_ids = {item.sample_id for item in selection.compatible}
        if self.sample_id not in compatible_ids:
            return _abstain_plan(
                planner_input,
                self.planner_type,
                selection,
                "fixed_sample_not_compatible",
            )
        return build_selected_plan(
            planner_input,
            self.planner_type,
            selection,
            _public_sample(planner_input, self.sample_id),
            "deterministic",
        )


class RandomCompatiblePlanner:
    planner_type = "random_compatible"

    def plan(self, planner_input: FormalPlannerInput) -> FormalEvaluationPlan:
        selection = select_compatible_samples(planner_input)
        if not selection.compatible:
            return _abstain_plan(
                planner_input,
                self.planner_type,
                selection,
                "no_compatible_sample",
            )
        selected = random.Random(planner_input.seed).choice(selection.compatible)
        return build_selected_plan(
            planner_input,
            self.planner_type,
            selection,
            _public_sample(planner_input, selected.sample_id),
            "random_compatible",
        )


class RuleBasedFormalPlanner:
    planner_type = "sample_rule_based"

    def plan(self, planner_input: FormalPlannerInput) -> FormalEvaluationPlan:
        selection = select_compatible_samples(planner_input)
        if not selection.compatible:
            return _abstain_plan(
                planner_input,
                self.planner_type,
                selection,
                "no_compatible_sample",
            )
        selected = selection.compatible[0]
        return build_selected_plan(
            planner_input,
            self.planner_type,
            selection,
            _public_sample(planner_input, selected.sample_id),
            "deterministic",
        )
