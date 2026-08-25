from __future__ import annotations

import json
from pathlib import Path

import pytest

from stac_attack_lab.datasets.library import PrimitiveChainLibrary
from stac_attack_lab.environments.safeclaw.task_adapter import parse_safeclaw_task
from stac_attack_lab.execution.sample_generation import (
    build_sample_library,
    load_sample_generation_config,
)
from stac_attack_lab.planning.formal_base import FormalBudget
from stac_attack_lab.planning.formal_scheduler import (
    FormalAssignmentScheduler,
    assert_pair_invariants,
)

ROOT = Path(__file__).resolve().parents[2]
TASK = ROOT / "tests/fixtures/safeclaw/compositional_task.json"


def _library(tmp_path: Path) -> PrimitiveChainLibrary:
    base = load_sample_generation_config(ROOT / "configs/sample_generation/formal_v1.yaml")
    config = base.model_copy(
        update={
            "library_version": "scheduler-public-prompt-test-v1",
            "output_root": str(tmp_path / "generated"),
        }
    )
    return PrimitiveChainLibrary(build_sample_library(ROOT, config))


def _budget() -> FormalBudget:
    return FormalBudget(
        max_sessions=3,
        max_turns=24,
        max_tool_calls=16,
        max_tokens=8192,
        max_wall_time_seconds=600,
    )


def test_public_prompt_is_complete_and_excludes_protected_fields() -> None:
    raw = json.loads(TASK.read_text(encoding="utf-8"))
    descriptor = parse_safeclaw_task(TASK, upstream_root=ROOT)
    public_prompt = descriptor.benchmark_public_prompt

    assert len(public_prompt.sessions) == len(raw["sessions"])
    for public, source in zip(public_prompt.sessions, raw["sessions"], strict=True):
        assert public.session_id == source["session_id"]
        assert public.user_instruction == source["user_instruction"]
        assert public.instruction_context == source.get("instruction_context")
    serialized = public_prompt.model_dump_json().lower()
    for protected in (
        '"evaluation"',
        "success_condition",
        "safe_condition",
        "taint_assets",
        '"environment"',
        "pre_session_setup",
        "private_oracle",
        "credential",
        "authorization",
        '"canary"',
    ):
        assert protected not in serialized


def test_scheduler_assigns_exactly_one_sample_before_planner(tmp_path: Path) -> None:
    library = _library(tmp_path)
    descriptor = parse_safeclaw_task(TASK, upstream_root=ROOT)
    scheduler = FormalAssignmentScheduler()
    samples = library.public_index()
    assignment = scheduler.assign(
        case_id="case-assigned-1",
        pair_group="pair-1",
        condition="assigned_sample",
        seed=20260824,
        budget=_budget(),
        public_task=descriptor.public_view,
        benchmark_public_prompt=descriptor.benchmark_public_prompt,
        public_samples=samples,
        task_set_hash="task-set-hash",
        library_hash=library.manifest.tree_hash,
        registry_hash=library.manifest.registry_hash,
    )
    planner_input = scheduler.planner_input(assignment, descriptor.public_view, samples)

    assert assignment.selected_sample_id is not None
    assert planner_input.selected_sample is not None
    assert planner_input.selected_sample.sample_id == assignment.selected_sample_id
    assert "public_samples" not in planner_input.model_dump(mode="json")
    assert "library_hash" not in planner_input.model_dump(mode="json")


def test_scheduler_no_sample_and_pair_invariants(tmp_path: Path) -> None:
    library = _library(tmp_path)
    descriptor = parse_safeclaw_task(TASK, upstream_root=ROOT)
    scheduler = FormalAssignmentScheduler()
    common = {
        "pair_group": "pair-matched",
        "seed": 41,
        "budget": _budget(),
        "public_task": descriptor.public_view,
        "benchmark_public_prompt": descriptor.benchmark_public_prompt,
        "public_samples": library.public_index(),
        "task_set_hash": "task-set-hash",
        "library_hash": library.manifest.tree_hash,
        "registry_hash": library.manifest.registry_hash,
    }
    assigned = scheduler.assign(case_id="case-assigned", condition="assigned_sample", **common)
    baseline = scheduler.assign(case_id="case-baseline", condition="no_sample", **common)

    assert baseline.selected_sample_id is None
    assert (
        scheduler.planner_input(
            baseline, descriptor.public_view, library.public_index()
        ).selected_sample
        is None
    )
    assert_pair_invariants([assigned, baseline])
    broken = baseline.model_copy(update={"seed": 42})
    with pytest.raises(ValueError, match="pair_invariant_mismatch"):
        assert_pair_invariants([assigned, broken])


def test_scheduler_rejects_incompatible_assignment(tmp_path: Path) -> None:
    library = _library(tmp_path)
    descriptor = parse_safeclaw_task(TASK, upstream_root=ROOT)
    incompatible = descriptor.public_view.model_copy(update={"public_capabilities": []})

    with pytest.raises(ValueError, match="scheduler_no_compatible_sample"):
        FormalAssignmentScheduler().assign(
            case_id="case-incompatible",
            pair_group="pair-incompatible",
            condition="assigned_sample",
            seed=1,
            budget=_budget(),
            public_task=incompatible,
            benchmark_public_prompt=descriptor.benchmark_public_prompt,
            public_samples=library.public_index(),
            task_set_hash="task-set-hash",
            library_hash=library.manifest.tree_hash,
            registry_hash=library.manifest.registry_hash,
        )
