from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.models.base import ModelCallError, ModelClient
from stac_attack_lab.planning.formal_base import (
    FormalEvaluationPlan,
    FormalPlannerInput,
    LongHorizonAdversarialTrajectory,
)
from stac_attack_lab.planning.formal_baselines import (
    RuleBasedFormalPlanner,
    build_long_horizon_trajectory,
    build_selected_plan,
    supported_attack_families,
)
from stac_attack_lab.planning.sample_selector import select_compatible_samples
from stac_attack_lab.prompts.loader import load_prompt


class LLMSelectionProposal(StrictModel):
    selected_sample_id: str | None
    abstain_reason: str | None
    rationale_summary: str
    confidence: float = Field(ge=0.0, le=1.0)


class LLMBindingProposal(StrictModel):
    sample_id: str
    public_slot_assignments: dict[str, str]
    abstain_reason: str | None
    rationale_summary: str


class LLMTrajectoryProposal(StrictModel):
    sample_id: str
    trajectory: LongHorizonAdversarialTrajectory
    rationale_summary: str


def validate_trajectory_proposal(
    proposal: LLMTrajectoryProposal,
    planner_input: FormalPlannerInput,
    sample_id: str,
) -> LongHorizonAdversarialTrajectory:
    if proposal.sample_id != sample_id:
        raise ValueError("trajectory_proposal_sample_mismatch")
    sample = next(item for item in planner_input.public_samples if item.sample_id == sample_id)
    trajectory = proposal.trajectory
    if trajectory.attack_family not in supported_attack_families(sample):
        raise ValueError("trajectory_proposal_attack_family_not_supported")
    backbone = build_long_horizon_trajectory(sample, planner_input, trajectory.attack_family)
    expected_stages = [stage.model_dump(mode="json") for stage in backbone.primitive_sequence]
    proposed_stages = [stage.model_dump(mode="json") for stage in trajectory.primitive_sequence]
    if proposed_stages != expected_stages:
        raise ValueError("trajectory_proposal_changes_primitive_backbone")
    if trajectory.attack_entry_stage_id != backbone.attack_entry_stage_id:
        raise ValueError("trajectory_proposal_changes_attack_entry")
    if trajectory.intermediate_state_refs != backbone.intermediate_state_refs:
        raise ValueError("trajectory_proposal_changes_intermediate_state_refs")
    if trajectory.expected_final_effect != backbone.expected_final_effect:
        raise ValueError("trajectory_proposal_changes_final_effect")
    public_predicates = {
        predicate
        for node in sample.planner_view.macro_nodes
        for predicate in node.public_postconditions
    }
    if not set(trajectory.observable_evidence) <= public_predicates:
        raise ValueError("trajectory_proposal_invents_observable_evidence")
    if trajectory.judge_condition not in public_predicates:
        raise ValueError("trajectory_proposal_invents_judge_condition")
    required_constraints = {
        "authorized_benchmark_sandbox",
        "synthetic_data_only",
        "no_external_network",
    }
    if not required_constraints <= set(trajectory.sandbox_constraints):
        raise ValueError("trajectory_proposal_removes_sandbox_constraint")
    allowed_action_constraints = {
        f"allowed_action:{item}" for item in planner_input.public_task.allowed_actions
    }
    proposed_action_constraints = {
        item for item in trajectory.sandbox_constraints if item.startswith("allowed_action:")
    }
    if proposed_action_constraints != allowed_action_constraints:
        raise ValueError("trajectory_proposal_changes_allowed_actions")
    if trajectory.persistence != backbone.persistence:
        raise ValueError("trajectory_proposal_changes_persistence_support")
    if trajectory.trigger != backbone.trigger:
        raise ValueError("trajectory_proposal_changes_trigger_support")
    expected_controls = {control.intervention for control in backbone.control_cases}
    proposed_controls = {control.intervention for control in trajectory.control_cases}
    if proposed_controls != expected_controls:
        raise ValueError("trajectory_proposal_changes_causal_controls")
    return trajectory


class FormalLLMPlanner:
    planner_type = "sample_llm_tiebreak"

    def __init__(
        self,
        client: ModelClient,
        prompt_path: Path,
        trajectory_prompt_path: Path | None = None,
    ) -> None:
        self.client = client
        self.prompt = load_prompt(prompt_path)
        self.trajectory_prompt = (
            load_prompt(trajectory_prompt_path) if trajectory_prompt_path is not None else None
        )
        self.fallback = RuleBasedFormalPlanner()

    def plan(self, planner_input: FormalPlannerInput) -> FormalEvaluationPlan:
        selection = select_compatible_samples(planner_input)
        if not selection.compatible:
            return self.fallback.plan(planner_input)
        public_payload = {
            "planner_input": planner_input.model_dump(mode="json"),
            "compatible_sample_ids": [item.sample_id for item in selection.compatible],
            "untrusted_task_goal": planner_input.public_task.public_goal,
        }
        try:
            output = self.client.generate(
                [
                    {"role": "system", "content": self.prompt.body},
                    {
                        "role": "user",
                        "content": json.dumps(public_payload, sort_keys=True),
                    },
                ],
                LLMSelectionProposal,
                seed=planner_input.seed,
                timeout=60,
            )
        except ModelCallError:
            return self.fallback.plan(planner_input)
        if not isinstance(output, LLMSelectionProposal):
            return self.fallback.plan(planner_input)
        compatible_ids = {item.sample_id for item in selection.compatible}
        if output.selected_sample_id not in compatible_ids:
            return self.fallback.plan(planner_input)
        sample = next(
            item
            for item in planner_input.public_samples
            if item.sample_id == output.selected_sample_id
        )
        trajectory = None
        trajectory_prompt_hash = self.prompt.hash
        if self.trajectory_prompt is not None:
            trajectory_payload = {
                "planner_input": planner_input.model_dump(mode="json"),
                "selected_sample": sample.model_dump(mode="json"),
                "supported_attack_families": sorted(
                    family.value for family in supported_attack_families(sample)
                ),
            }
            try:
                proposal = self.client.generate(
                    [
                        {"role": "system", "content": self.trajectory_prompt.body},
                        {
                            "role": "user",
                            "content": json.dumps(trajectory_payload, sort_keys=True),
                        },
                    ],
                    LLMTrajectoryProposal,
                    seed=planner_input.seed,
                    timeout=60,
                )
                if not isinstance(proposal, LLMTrajectoryProposal):
                    raise TypeError("trajectory_proposal_response_type_mismatch")
                trajectory = validate_trajectory_proposal(
                    proposal, planner_input, output.selected_sample_id
                )
                trajectory_prompt_hash = self.trajectory_prompt.hash
            except (ModelCallError, TypeError, ValueError):
                trajectory = build_long_horizon_trajectory(sample, planner_input)
        return build_selected_plan(
            planner_input,
            self.planner_type,
            selection,
            sample,
            "llm_tiebreak",
            public_prompt_hash=trajectory_prompt_hash,
            trajectory=trajectory,
        )
