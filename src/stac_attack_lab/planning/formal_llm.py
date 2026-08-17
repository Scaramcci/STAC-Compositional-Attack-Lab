from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.models.base import ModelCallError, ModelClient
from stac_attack_lab.planning.formal_base import FormalEvaluationPlan, FormalPlannerInput
from stac_attack_lab.planning.formal_baselines import (
    RuleBasedFormalPlanner,
    build_selected_plan,
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


class FormalLLMPlanner:
    planner_type = "sample_llm_tiebreak"

    def __init__(self, client: ModelClient, prompt_path: Path) -> None:
        self.client = client
        self.prompt = load_prompt(prompt_path)
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
        return build_selected_plan(
            planner_input,
            self.planner_type,
            selection,
            sample,
            "llm_tiebreak",
            public_prompt_hash=self.prompt.hash,
        )
