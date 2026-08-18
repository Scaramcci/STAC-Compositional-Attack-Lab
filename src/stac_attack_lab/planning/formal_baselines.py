from __future__ import annotations

import random
from typing import Literal

from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.planning.binding_planner import (
    build_baseline_binding,
    build_benchmark_binding,
)
from stac_attack_lab.planning.formal_base import (
    FormalEvaluationPlan,
    FormalPlannerInput,
    PlannerSelectionEvidence,
    PublicSampleIndexEntry,
)
from stac_attack_lab.planning.sample_selector import (
    SampleSelectionResult,
    select_compatible_samples,
)


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
        "abstain_reason": reason,
    }
    return FormalEvaluationPlan.model_validate(
        {
            **payload,
            "plan_id": "plan-" + stable_hash(payload)[:20],
            "plan_hash": stable_hash(payload),
        }
    )


def build_selected_plan(
    planner_input: FormalPlannerInput,
    planner_type: str,
    selection: SampleSelectionResult,
    sample: PublicSampleIndexEntry,
    decision_source: Literal["deterministic", "random_compatible", "llm_tiebreak"],
    public_prompt_hash: str | None = None,
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
