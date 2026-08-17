from __future__ import annotations

from pydantic import Field

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.planning.formal_base import FormalPlannerInput, PublicSampleIndexEntry


class RankedSample(StrictModel):
    sample_id: str
    score: float
    reason_codes: list[str]


class SampleSelectionResult(StrictModel):
    compatible: list[RankedSample]
    rejected_reason_codes: dict[str, list[str]] = Field(default_factory=dict)


def _budget_errors(sample: PublicSampleIndexEntry, planner_input: FormalPlannerInput) -> list[str]:
    profile = sample.planner_view.budget_profile
    budget = planner_input.budget
    limits = {
        "max_sessions": budget.max_sessions,
        "max_turns": budget.max_turns,
        "max_tool_calls": budget.max_tool_calls,
        "max_tokens": budget.max_tokens,
    }
    return [
        f"budget_insufficient:{name}"
        for name, required in profile.items()
        if name in limits and required > limits[name]
    ]


def select_compatible_samples(planner_input: FormalPlannerInput) -> SampleSelectionResult:
    task = planner_input.public_task
    compatible: list[RankedSample] = []
    rejected: dict[str, list[str]] = {}
    task_capabilities = set(task.public_capabilities)
    task_roles = set(task.component_roles)
    for sample in planner_input.public_samples:
        errors: list[str] = []
        missing_capabilities = set(sample.planner_view.required_capabilities) - task_capabilities
        errors.extend(
            f"missing_capability:{capability}" for capability in sorted(missing_capabilities)
        )
        missing_roles = set(sample.planner_view.component_role_signature) - task_roles
        errors.extend(f"missing_component_role:{role}" for role in sorted(missing_roles))
        errors.extend(_budget_errors(sample, planner_input))
        if errors:
            rejected[sample.sample_id] = errors
            continue
        evidence_score = {
            "direct": 4.0,
            "interventional": 3.5,
            "mixed": 3.0,
            "deterministic": 2.0,
        }[sample.planner_view.evidence_strength]
        capability_specificity = len(sample.planner_view.required_capabilities) / max(
            len(task_capabilities), 1
        )
        score = evidence_score + capability_specificity
        compatible.append(
            RankedSample(
                sample_id=sample.sample_id,
                score=score,
                reason_codes=["capability_type_budget_compatible"],
            )
        )
    compatible.sort(key=lambda item: (-item.score, item.sample_id))
    return SampleSelectionResult(compatible=compatible, rejected_reason_codes=rejected)
