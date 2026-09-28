from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from stac_attack_lab.attack_program.models import AttackCandidate, Patch, Split
from stac_attack_lab.attack_program.pipeline import (
    GateError,
    build_catalog,
    make_split,
    materialize,
    validate_catalog,
    validate_split,
)
from stac_attack_lab.hashing import stable_hash

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def baseline():
    catalog = build_catalog(ROOT)
    split = make_split(catalog)
    entry = catalog.entries[0]
    surface = entry.attack_surfaces[0]
    return catalog, split, entry, surface


def candidate(entry, pointer, value="External CI/CD notice"):
    return AttackCandidate(
        candidate_id="c1",
        task_id=entry.task_id,
        task_group_id=entry.task_group_id,
        source_split="development",
        patches=[Patch(pointer=pointer, value=value)],
    )


def test_real_official_task_mirror_and_protected_fields(baseline):
    catalog, split, entry, surface = baseline
    out = materialize(ROOT, catalog, split, candidate(entry, surface.pointer))
    assert out["environment"]["workspace_files"][4]["content"] == "External CI/CD notice"
    assert out["environment"]["sim_google_data"][0]["content"] == "External CI/CD notice"
    original = __import__("json").loads((ROOT / entry.task_path).read_text())
    assert out["sessions"] == original["sessions"]
    assert out["evaluation"] == original["evaluation"]
    assert out["metadata"] == original["metadata"]
    assert out["environment"]["auth_profiles_file"] == original["environment"]["auth_profiles_file"]
    assert "description" not in entry.public_view
    assert "evaluation" not in entry.public_view


def test_different_official_group_materializes_without_test_claim(baseline):
    catalog, split, _, _ = baseline
    entry = next(e for e in catalog.entries if e.task_id == "cdf-3.9-001")
    patch = AttackCandidate(
        candidate_id="cdf-validation",
        task_id=entry.task_id,
        task_group_id=entry.task_group_id,
        source_split="validation",
        patches=[Patch(pointer=entry.attack_surfaces[0].pointer, value="External notice")],
    )
    task = materialize(ROOT, catalog, split, patch)
    assert task["metadata"]["task_id"] == "cdf-3.9-001"
    assert split.group_assignments[entry.template_group_id] == "validation"
    assert "test" not in split.group_assignments.values()


def test_recomputed_catalog_hash_cannot_hide_private_public_leak(baseline):
    catalog, _, _, _ = baseline
    tampered = catalog.model_dump()
    tampered["entries"][0]["public_view"]["description"] = "private attack explanation"
    body = {k: tampered[k] for k in ("upstream_commit", "schema_hash", "patch_hash", "entries")}
    tampered["catalog_hash"] = stable_hash(body)
    with pytest.raises(GateError, match="catalog_source_or_semantics_mismatch"):
        validate_catalog(type(catalog).model_validate(tampered), ROOT)


@pytest.mark.parametrize(
    "pointer",
    [
        "/sessions/0/user_instruction",
        "/evaluation/success_condition/checks/0/pattern",
        "/environment/auth_profiles_file/content",
        "../../etc/passwd",
        "/environment/workspace_files/99/content",
    ],
)
def test_undeclared_or_protected_pointer_rejected(baseline, pointer):
    catalog, split, entry, _ = baseline
    with pytest.raises(GateError, match="undeclared_attack_surface"):
        materialize(ROOT, catalog, split, candidate(entry, pointer))


def test_wrong_type_private_oracle_and_length_rejected(baseline):
    catalog, split, entry, surface = baseline
    with pytest.raises(ValidationError):
        Patch(pointer=surface.pointer, value={"content": "wrong"})
    for payload, reason in [
        ("CANARY_DB_PASS_nlfvow", "private_oracle_payload_leak"),
        ("x" * 8193, "payload_length_invalid"),
    ]:
        with pytest.raises(GateError, match=reason):
            materialize(ROOT, catalog, split, candidate(entry, surface.pointer, payload))


def test_split_exposure_and_hash_recompute_cannot_hide_semantic_violation(baseline):
    catalog, split, entry, _ = baseline
    tampered = split.model_dump()
    tampered["group_assignments"][entry.template_group_id] = "test"
    body = {k: tampered[k] for k in ("catalog_hash", "rule", "group_assignments", "known_exposure")}
    tampered["split_hash"] = stable_hash(body)
    with pytest.raises(GateError, match="exposed_task_in_test"):
        validate_split(Split.model_validate(tampered), catalog)
    # A second variant of the same group is never an independently assignable test task.
    assert catalog.entries[0].template_group_id == catalog.entries[1].template_group_id
