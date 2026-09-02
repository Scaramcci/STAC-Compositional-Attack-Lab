from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from stac_attack_lab.datasets.library import PrimitiveChainLibrary
from stac_attack_lab.environments.safeclaw.contracts import SafeClawTrack
from stac_attack_lab.environments.safeclaw.materializer import materialize_safeclaw_task
from stac_attack_lab.environments.safeclaw.task_adapter import parse_safeclaw_task
from stac_attack_lab.execution.sample_generation import (
    build_sample_library,
    load_sample_generation_config,
)
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.planning.formal_base import FormalBudget, FormalPlannerInput
from stac_attack_lab.planning.formal_baselines import (
    NoSamplePlanner,
    RuleBasedFormalPlanner,
)

ROOT = Path(__file__).resolve().parents[2]
TASK = ROOT / "tests/fixtures/safeclaw/compositional_task.json"


def _library(tmp_path: Path) -> PrimitiveChainLibrary:
    base = load_sample_generation_config(ROOT / "tests/fixtures/sample_generation.json")
    config = base.model_copy(
        update={
            "library_version": "safeclaw-materializer-test-v1",
            "output_root": str(tmp_path / "generated"),
        }
    )
    return PrimitiveChainLibrary(build_sample_library(ROOT, config))


def _plan(tmp_path: Path) -> tuple[object, object, PrimitiveChainLibrary]:
    descriptor = parse_safeclaw_task(TASK, upstream_root=ROOT)
    library = _library(tmp_path)
    planner_input = FormalPlannerInput(
        planner_input_id="safeclaw-materializer-input",
        assignment_id="assignment-safeclaw-materializer",
        public_task=descriptor.public_view,
        benchmark_public_prompt=descriptor.benchmark_public_prompt,
        selected_sample=library.public_index()[0],
        budget=FormalBudget(
            max_sessions=3,
            max_turns=24,
            max_tool_calls=16,
            max_tokens=8192,
            max_wall_time_seconds=600,
        ),
        condition="sample_rule_based",
        seed=31,
    )
    plan = RuleBasedFormalPlanner().plan(planner_input)
    return descriptor, plan, library


def _slot_values() -> dict[str, str]:
    return {
        "untrusted_source": "SYNTHETIC_UNTRUSTED_MARKER",
        "agent_context": "Authorized synthetic context.",
        "persistent_memory": "Store only SYNTHETIC_UNTRUSTED_MARKER in benchmark memory.",
        "session_lifecycle": "Authorized second benchmark session.",
        "effect_tool": "sim_google.synthetic_effect",
        "sandbox_external_state": "SYNTHETIC_TERMINAL_STATE",
    }


def _baseline_slot_values() -> dict[str, str]:
    return {
        "untrusted_source": "SYNTHETIC_BENIGN_REFERENCE",
        "agent_context": "Authorized benign baseline context.",
        "persistent_memory": "Summarize SYNTHETIC_BENIGN_REFERENCE.",
        "session_lifecycle": "Authorized second benchmark session.",
        "effect_tool": "sim_google.synthetic_effect",
        "sandbox_external_state": "SYNTHETIC_TERMINAL_STATE",
    }


def test_task_adapter_physically_separates_public_and_private_fields() -> None:
    descriptor = parse_safeclaw_task(TASK, upstream_root=ROOT)

    assert descriptor.track == SafeClawTrack.compositional
    assert descriptor.supported is True
    assert descriptor.private_oracle_ref.endswith("#/evaluation")
    public = descriptor.public_view.model_dump_json()
    assert "CANARY_PRIVATE_EVALUATION_ONLY" not in public
    assert "success_condition" not in public
    assert descriptor.official_success_condition_hash


def test_task_adapter_accepts_separate_public_formal_overlay(tmp_path: Path) -> None:
    task = json.loads(TASK.read_text(encoding="utf-8"))
    formal_overlay = task.pop("formal_experiment")
    official = tmp_path / "official-without-overlay.json"
    official.write_text(json.dumps(task), encoding="utf-8")

    descriptor = parse_safeclaw_task(
        official,
        upstream_root=tmp_path,
        formal_experiment=formal_overlay,
    )

    assert descriptor.track == SafeClawTrack.compositional
    assert descriptor.supported is True
    assert descriptor.materialization_template_id == "safeclaw-persistence-chain-v1"
    assert "evaluation" not in descriptor.public_view.model_dump_json()


def test_materializer_changes_only_allowlisted_fields_and_preserves_oracle(
    tmp_path: Path,
) -> None:
    descriptor, plan, library = _plan(tmp_path)
    assert plan.selected_sample_id is not None
    execution_view = library.execution_view(plan.selected_sample_id)
    original = json.loads(TASK.read_text(encoding="utf-8"))
    materialized = materialize_safeclaw_task(
        TASK,
        descriptor,
        plan,
        execution_view,
        _slot_values(),
        tmp_path / "secure-materialization",
    )
    result = json.loads(materialized.path.read_text(encoding="utf-8"))

    assert stable_hash(result["evaluation"]) == stable_hash(original["evaluation"])
    assert result["environment"]["workspace_files"]["source.txt"] == ("SYNTHETIC_UNTRUSTED_MARKER")
    assert materialized.reference.materialized_task_hash != stable_hash(original)
    assert stat.S_IMODE(materialized.path.stat().st_mode) == 0o600


def test_official_conformance_task_cannot_be_materialized(tmp_path: Path) -> None:
    task = json.loads(TASK.read_text(encoding="utf-8"))
    task.pop("formal_experiment")
    official = tmp_path / "official.json"
    official.write_text(json.dumps(task), encoding="utf-8")
    descriptor = parse_safeclaw_task(official, upstream_root=tmp_path)
    _, plan, library = _plan(tmp_path)
    assert plan.selected_sample_id is not None

    with pytest.raises(ValueError, match="conformance_task_cannot_be_materialized"):
        materialize_safeclaw_task(
            official,
            descriptor,
            plan,
            library.execution_view(plan.selected_sample_id),
            _slot_values(),
            tmp_path / "materialized",
        )


def test_forbidden_oracle_binding_pointer_is_explicitly_unsupported(
    tmp_path: Path,
) -> None:
    task = json.loads(TASK.read_text(encoding="utf-8"))
    task["formal_experiment"]["bindable_slots"][0]["json_pointer"] = (
        "/evaluation/success_condition/private_marker"
    )
    invalid = tmp_path / "invalid-template.json"
    invalid.write_text(json.dumps(task), encoding="utf-8")
    descriptor = parse_safeclaw_task(invalid, upstream_root=tmp_path)

    assert descriptor.supported is False
    assert descriptor.unsupported_reason is not None
    assert "forbidden_binding_pointer" in descriptor.unsupported_reason


def test_no_sample_uses_same_template_with_only_preregistered_content_delta(
    tmp_path: Path,
) -> None:
    descriptor, sample_plan, library = _plan(tmp_path)
    assert sample_plan.selected_sample_id is not None
    baseline_input = FormalPlannerInput(
        planner_input_id="safeclaw-baseline-input",
        assignment_id="assignment-safeclaw-baseline",
        public_task=descriptor.public_view,
        benchmark_public_prompt=descriptor.benchmark_public_prompt,
        selected_sample=None,
        budget=sample_plan.budget,
        condition="no_sample",
        seed=31,
    )
    baseline_plan = NoSamplePlanner().plan(baseline_input)
    assert baseline_plan.baseline_binding is not None
    assert baseline_plan.abstain_reason is None

    sample = materialize_safeclaw_task(
        TASK,
        descriptor,
        sample_plan,
        library.execution_view(sample_plan.selected_sample_id),
        _slot_values(),
        tmp_path / "sample-materialization",
    )
    baseline = materialize_safeclaw_task(
        TASK,
        descriptor,
        baseline_plan,
        None,
        _baseline_slot_values(),
        tmp_path / "baseline-materialization",
    )
    sample_task = json.loads(sample.path.read_text(encoding="utf-8"))
    baseline_task = json.loads(baseline.path.read_text(encoding="utf-8"))
    sample_manifest = json.loads(
        (sample.path.parent / sample.reference.binding_manifest_ref).read_text(encoding="utf-8")
    )
    baseline_manifest = json.loads(
        (baseline.path.parent / baseline.reference.binding_manifest_ref).read_text(encoding="utf-8")
    )

    assert sample.reference.task_id == baseline.reference.task_id
    assert sample.reference.template_id == baseline.reference.template_id
    assert sample_plan.budget == baseline_plan.budget
    assert sample_manifest["template_hash"] == baseline_manifest["template_hash"]
    assert (
        sample_manifest["official_evaluation_hash"]
        == (baseline_manifest["official_evaluation_hash"])
    )
    assert sample_manifest["changed_pointers"] == baseline_manifest["changed_pointers"]
    assert sample_task["evaluation"] == baseline_task["evaluation"]
    assert (
        sample_task["environment"]["sim_google_data"]
        == (baseline_task["environment"]["sim_google_data"])
    )
    assert sample_task["sessions"][1] == baseline_task["sessions"][1]
    assert (
        sample_task["environment"]["workspace_files"]
        != (baseline_task["environment"]["workspace_files"])
    )
    assert sample_task["sessions"][0] != baseline_task["sessions"][0]
    assert baseline_manifest["materialization_variant"] == "legal_baseline"


def test_materializer_rejects_unbound_extra_value(tmp_path: Path) -> None:
    descriptor, plan, library = _plan(tmp_path)
    assert plan.selected_sample_id is not None
    values = {**_slot_values(), "unregistered_slot": "SYNTHETIC_EXTRA"}

    with pytest.raises(ValueError, match="materialization_value_slot_set_mismatch"):
        materialize_safeclaw_task(
            TASK,
            descriptor,
            plan,
            library.execution_view(plan.selected_sample_id),
            values,
            tmp_path / "invalid-extra-value",
        )


def test_dependency_ablation_changes_exactly_one_preregistered_slot(
    tmp_path: Path,
) -> None:
    descriptor, treatment_plan, library = _plan(tmp_path)
    assert treatment_plan.selected_sample_id is not None
    selected_sample = library.public_index()[0]
    ablation_input = FormalPlannerInput(
        planner_input_id="safeclaw-materializer-ablation-input",
        assignment_id="assignment-safeclaw-materializer-ablation",
        public_task=descriptor.public_view,
        benchmark_public_prompt=descriptor.benchmark_public_prompt,
        selected_sample=selected_sample,
        budget=treatment_plan.budget,
        condition="dependency_ablation",
        seed=31,
    )
    ablation_plan = RuleBasedFormalPlanner().plan(ablation_input)
    intervention = ablation_plan.dependency_ablation
    assert intervention is not None

    treatment_values = _slot_values()
    ablation_values = dict(treatment_values)
    ablation_values[intervention.materialization_slot_id] = _baseline_slot_values()[
        intervention.materialization_slot_id
    ]
    execution_view = library.execution_view(treatment_plan.selected_sample_id)
    treatment = materialize_safeclaw_task(
        TASK,
        descriptor,
        treatment_plan,
        execution_view,
        treatment_values,
        tmp_path / "dependency-treatment",
    )
    ablation = materialize_safeclaw_task(
        TASK,
        descriptor,
        ablation_plan,
        execution_view,
        ablation_values,
        tmp_path / "dependency-ablation",
    )
    treatment_task = json.loads(treatment.path.read_text(encoding="utf-8"))
    ablation_task = json.loads(ablation.path.read_text(encoding="utf-8"))

    def pointer_value(document: object, pointer: str) -> object:
        current = document
        for part in pointer.removeprefix("/").split("/"):
            if isinstance(current, list):
                current = current[int(part)]
            else:
                assert isinstance(current, dict)
                current = current[part]
        return current

    slot_pointers = {
        slot.slot_id: slot.json_pointer for slot in descriptor.public_view.bindable_slots
    }
    differing_pointers = [
        pointer
        for pointer in slot_pointers.values()
        if pointer_value(treatment_task, pointer) != pointer_value(ablation_task, pointer)
    ]
    selected_pointer = slot_pointers[intervention.materialization_slot_id]
    assert differing_pointers == [selected_pointer]
    assert (
        pointer_value(ablation_task, selected_pointer)
        == _baseline_slot_values()[intervention.materialization_slot_id]
    )

    manifest = json.loads(
        (ablation.path.parent / ablation.reference.binding_manifest_ref).read_text(encoding="utf-8")
    )
    assert manifest["dependency_ablation"]["intervention_id"] == intervention.intervention_id
    assert manifest["dependency_ablation"]["replacement_applied"] is True
    assert manifest["dependency_ablation"]["applied_value_hash"] == stable_hash(
        ablation_values[intervention.materialization_slot_id]
    )
