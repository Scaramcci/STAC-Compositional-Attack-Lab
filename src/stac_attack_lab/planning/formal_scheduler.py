from __future__ import annotations

import random
from collections.abc import Sequence

from stac_attack_lab.environments.safeclaw.contracts import (
    BenchmarkPublicPrompt,
    SafeClawPublicTaskView,
)
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.planning.binding_planner import (
    build_baseline_binding,
    build_benchmark_binding,
)
from stac_attack_lab.planning.formal_base import (
    FormalBudget,
    FormalCaseAssignment,
    PublicSampleIndexEntry,
    SingleSamplePlannerInput,
)


def sample_compatibility_errors(
    sample: PublicSampleIndexEntry,
    public_task: SafeClawPublicTaskView,
    budget: FormalBudget,
) -> list[str]:
    errors: list[str] = []
    missing_capabilities = set(sample.planner_view.required_capabilities) - set(
        public_task.public_capabilities
    )
    errors.extend(f"missing_capability:{capability}" for capability in sorted(missing_capabilities))
    missing_roles = set(sample.planner_view.component_role_signature) - set(
        public_task.component_roles
    )
    errors.extend(f"missing_component_role:{role}" for role in sorted(missing_roles))
    limits = {
        "max_sessions": budget.max_sessions,
        "max_turns": budget.max_turns,
        "max_tool_calls": budget.max_tool_calls,
        "max_tokens": budget.max_tokens,
    }
    errors.extend(
        f"budget_insufficient:{name}"
        for name, required in sample.planner_view.budget_profile.items()
        if name in limits and required > limits[name]
    )
    binding = build_benchmark_binding(sample.planner_view, public_task)
    if not binding.binding_valid:
        errors.extend(binding.validation_reason_codes)
    return sorted(set(errors))


def _rank(sample: PublicSampleIndexEntry, public_task: SafeClawPublicTaskView) -> tuple[float, str]:
    evidence_score = {
        "direct": 4.0,
        "interventional": 3.5,
        "mixed": 3.0,
        "deterministic": 2.0,
    }[sample.planner_view.evidence_strength]
    specificity = len(sample.planner_view.required_capabilities) / max(
        len(public_task.public_capabilities), 1
    )
    return (-(evidence_score + specificity), sample.sample_id)


def compatible_samples(
    samples: Sequence[PublicSampleIndexEntry],
    public_task: SafeClawPublicTaskView,
    budget: FormalBudget,
) -> list[PublicSampleIndexEntry]:
    compatible = [
        sample for sample in samples if not sample_compatibility_errors(sample, public_task, budget)
    ]
    return sorted(compatible, key=lambda item: _rank(item, public_task))


class FormalAssignmentScheduler:
    scheduler_version = "formal-assignment-scheduler-v1"

    def assign(
        self,
        *,
        case_id: str,
        pair_group: str,
        condition: str,
        seed: int,
        budget: FormalBudget,
        public_task: SafeClawPublicTaskView,
        benchmark_public_prompt: BenchmarkPublicPrompt,
        public_samples: Sequence[PublicSampleIndexEntry],
        task_set_hash: str,
        library_hash: str,
        registry_hash: str,
    ) -> FormalCaseAssignment:
        if public_task.task_id != benchmark_public_prompt.task_id:
            raise ValueError("scheduler_public_prompt_task_mismatch")
        selected: PublicSampleIndexEntry | None = None
        if condition == "no_sample":
            baseline = build_baseline_binding(public_task)
            if not baseline.binding_valid:
                raise ValueError("scheduler_legal_baseline_binding_invalid")
        else:
            candidates = compatible_samples(public_samples, public_task, budget)
            if not candidates:
                raise ValueError("scheduler_no_compatible_sample")
            if condition == "random_compatible":
                selected = random.Random(seed).choice(candidates)
            else:
                selected = candidates[0]
        payload = {
            "schema_version": "3.0",
            "assignment_id": "assignment-"
            + stable_hash(
                {
                    "case_id": case_id,
                    "condition": condition,
                    "seed": seed,
                    "scheduler": self.scheduler_version,
                    "selected_sample_id": selected.sample_id if selected else None,
                }
            )[:20],
            "case_id": case_id,
            "pair_group": pair_group,
            "benchmark_task_id": public_task.task_id,
            "benchmark_public_prompt": benchmark_public_prompt.model_dump(mode="json"),
            "benchmark_public_prompt_hash": benchmark_public_prompt.prompt_hash,
            "selected_sample_id": selected.sample_id if selected else None,
            "selected_sample_hash": selected.sample_hash if selected else None,
            "condition": condition,
            "seed": seed,
            "budget": budget.model_dump(mode="json"),
            "task_set_hash": task_set_hash,
            "library_hash": library_hash,
            "registry_hash": registry_hash,
        }
        return FormalCaseAssignment.model_validate(
            {**payload, "assignment_hash": stable_hash(payload)}
        )

    def planner_input(
        self,
        assignment: FormalCaseAssignment,
        public_task: SafeClawPublicTaskView,
        public_samples: Sequence[PublicSampleIndexEntry],
    ) -> SingleSamplePlannerInput:
        sample_by_id = {sample.sample_id: sample for sample in public_samples}
        selected = (
            sample_by_id.get(assignment.selected_sample_id)
            if assignment.selected_sample_id is not None
            else None
        )
        if assignment.selected_sample_id is not None and selected is None:
            raise ValueError("assigned_sample_missing_from_library")
        if selected is not None and selected.sample_hash != assignment.selected_sample_hash:
            raise ValueError("assigned_sample_hash_mismatch")
        return SingleSamplePlannerInput(
            planner_input_id=f"input-{assignment.case_id}",
            assignment_id=assignment.assignment_id,
            public_task=public_task,
            benchmark_public_prompt=assignment.benchmark_public_prompt,
            selected_sample=selected,
            budget=assignment.budget,
            condition=assignment.condition,
            seed=assignment.seed,
        )


def assert_pair_invariants(assignments: Sequence[FormalCaseAssignment]) -> None:
    by_pair: dict[str, list[FormalCaseAssignment]] = {}
    for assignment in assignments:
        by_pair.setdefault(assignment.pair_group, []).append(assignment)
    invariant_fields = (
        "benchmark_task_id",
        "benchmark_public_prompt_hash",
        "seed",
        "budget",
        "task_set_hash",
        "library_hash",
        "registry_hash",
    )
    for pair_group, group in by_pair.items():
        reference = group[0]
        for candidate in group[1:]:
            for field in invariant_fields:
                if getattr(candidate, field) != getattr(reference, field):
                    raise ValueError(f"pair_invariant_mismatch:{pair_group}:{field}")
