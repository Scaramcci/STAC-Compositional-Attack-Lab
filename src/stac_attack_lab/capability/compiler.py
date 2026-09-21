from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from stac_attack_lab.capability.models import (
    CapabilityCase,
    CapabilityExperimentConfig,
    CapabilityProfile,
    CompatibilityConfig,
    CompilationManifest,
    RuntimeTask,
    VariantKind,
    VictimPublicView,
)
from stac_attack_lab.capability.registry import validate_registry
from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.environments.safeclaw.evidence_policy import (
    validate_provider_evidence_policy,
)
from stac_attack_lab.environments.safeclaw.redaction import scan_for_secrets
from stac_attack_lab.hashing import file_hash, stable_hash

PRIVATE_TOKENS = (
    "harmful_status",
    "private_oracle",
    "planned_node",
    "attack_success",
    "constraint_profile",
)
ModelT = TypeVar("ModelT", bound=StrictModel)


def validate_split_assignments(assignments: list[tuple[str, str]]) -> None:
    observed: dict[str, str] = {}
    for split_group_id, split in assignments:
        if split_group_id in observed and observed[split_group_id] != split:
            raise ValueError("capability_split_group_crosses_data_split")
        observed[split_group_id] = split


def _load_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("capability_config_root_not_object")
    return payload


def _validate_hashed(model_type: type[ModelT], payload: dict[str, Any], field: str) -> ModelT:
    data = dict(payload)
    canonical = model_type.model_construct(**data).model_dump(mode="json", exclude={field})
    data[field] = stable_hash(canonical)
    return model_type.model_validate(data)


def _public_view(case: CapabilityCase) -> VictimPublicView:
    contract = case.task_contract
    view = _validate_hashed(
        VictimPublicView,
        {
            "task_id": contract.base_task_id,
            "user_goal": contract.legitimate_goal,
            "trusted_rules": contract.trusted_rules,
            "trusted_ledger_path": "workspace/trusted/acceptance-ledger.json",
            "low_trust_material_path": "workspace/inbox/vendor-delivery-note.txt",
            "low_trust_material": case.low_trust_material,
            "allowed_operations": contract.allowed_operations,
        },
        "public_view_hash",
    )
    serialized = view.model_dump_json().lower()
    if any(token in serialized for token in PRIVATE_TOKENS):
        raise ValueError("capability_private_view_leak")
    if scan_for_secrets(view.model_dump(mode="json")):
        raise ValueError("capability_public_view_secret_detected")
    return view


def compile_cases(config_path: Path, output_root: Path) -> Path:
    config = CapabilityExperimentConfig.model_validate(_load_object(config_path))
    profile = config.capability_profile
    contract = config.task_contract
    surface = config.attack_surface
    composition = config.composition
    materials = config.materials
    if surface.editable_json_pointers != ["/low_trust_material"]:
        raise ValueError("capability_f1_editable_pointer_not_minimal")
    validate_registry()
    output_root.mkdir(parents=True, exist_ok=False)
    (output_root / "cases").mkdir()
    (output_root / "capability_profile.json").write_text(
        profile.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    registry = validate_registry()
    (output_root / "primitive_registry.json").write_text(
        json.dumps([item.model_dump(mode="json") for item in registry], indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    case_refs: list[str] = []
    case_hashes: dict[str, str] = {}
    runtime_task_hashes: dict[str, str] = {}
    invariant_hashes: set[str] = set()
    for variant in VariantKind:
        case_id = f"{contract.case_id}-{variant.value}"
        case = _validate_hashed(
            CapabilityCase,
            {
                "case_id": case_id,
                "variant": variant,
                "task_contract": contract,
                "attack_surface": surface,
                "composition": composition,
                "low_trust_material": materials[variant],
                "contract_hash": stable_hash(contract.model_dump(mode="json")),
            },
            "case_hash",
        )
        public = _public_view(case)
        initial_state = {
            "trusted_ledger": contract.trusted_ledger,
            "projects": {
                project_id: {
                    key: value
                    for key, value in project.items()
                    if key != contract.oracle.trusted_proof_field
                }
                for project_id, project in contract.trusted_ledger.items()
            },
            "artifacts": {},
            "session": {"label": "s1", "actual_key": f"{case_id}-actual-s1"},
        }
        runtime = _validate_hashed(
            RuntimeTask,
            {
                "case": case,
                "public_view": public,
                "initial_state": initial_state,
                "private_oracle": contract.oracle,
            },
            "runtime_task_hash",
        )
        case_root = output_root / "cases" / case_id
        case_root.mkdir()
        (case_root / "case.json").write_text(
            case.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        (case_root / "public_view.json").write_text(
            public.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        (case_root / "runtime_task.json").write_text(
            runtime.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        case_refs.append(str(Path("cases") / case_id / "runtime_task.json"))
        case_hashes[case_id] = case.case_hash
        runtime_task_hashes[case_id] = runtime.runtime_task_hash
        invariant_hashes.add(case.contract_hash)
    if len(invariant_hashes) != 1:
        raise ValueError("capability_variant_pairing_invariant_broken")
    manifest = _validate_hashed(
        CompilationManifest,
        {
            "compilation_id": f"capability-{stable_hash(case_hashes)[:16]}",
            "created_at": datetime.now(UTC).isoformat(),
            "upstream_commit": profile.upstream_commit,
            "profile_hash": stable_hash(profile.model_dump(mode="json")),
            "registry_hash": stable_hash([item.model_dump(mode="json") for item in registry]),
            "source_config_hash": file_hash(config_path),
            "case_refs": case_refs,
            "case_hashes": case_hashes,
            "runtime_task_hashes": runtime_task_hashes,
        },
        "manifest_hash",
    )
    (output_root / "manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return output_root


def validate_compilation(root: Path) -> CompilationManifest:
    manifest = CompilationManifest.model_validate_json(
        (root / "manifest.json").read_text(encoding="utf-8")
    )
    if len(manifest.case_refs) != len(set(manifest.case_refs)):
        raise ValueError("capability_compilation_case_ref_duplicate")
    profile = CapabilityProfile.model_validate_json(
        (root / "capability_profile.json").read_text(encoding="utf-8")
    )
    if stable_hash(profile.model_dump(mode="json")) != manifest.profile_hash:
        raise ValueError("capability_manifest_profile_hash_mismatch")
    registry_payload = json.loads((root / "primitive_registry.json").read_text(encoding="utf-8"))
    registry = validate_registry()
    expected_registry = [item.model_dump(mode="json") for item in registry]
    if (
        registry_payload != expected_registry
        or stable_hash(registry_payload) != manifest.registry_hash
    ):
        raise ValueError("capability_manifest_registry_mismatch")
    seen_contracts: set[str] = set()
    seen_variants: set[VariantKind] = set()
    seen_case_ids: set[str] = set()
    split_assignments: list[tuple[str, str]] = []
    for ref in manifest.case_refs:
        path = (root / ref).resolve()
        if root.resolve() not in path.parents:
            raise ValueError("capability_manifest_ref_outside_root")
        runtime = RuntimeTask.model_validate_json(path.read_text(encoding="utf-8"))
        if runtime.case.case_id in seen_case_ids:
            raise ValueError("capability_compilation_case_id_duplicate")
        seen_case_ids.add(runtime.case.case_id)
        seen_variants.add(runtime.case.variant)
        if manifest.case_hashes.get(runtime.case.case_id) != runtime.case.case_hash:
            raise ValueError("capability_manifest_case_hash_mismatch")
        if manifest.runtime_task_hashes.get(runtime.case.case_id) != runtime.runtime_task_hash:
            raise ValueError("capability_manifest_runtime_task_hash_mismatch")
        seen_contracts.add(runtime.case.contract_hash)
        split_assignments.append(
            (runtime.case.task_contract.split_group_id, runtime.case.task_contract.split)
        )
        expected_public = _public_view(runtime.case)
        if runtime.public_view != expected_public:
            raise ValueError("capability_public_view_semantic_mismatch")
        expected_projects = {
            project_id: {
                key: value
                for key, value in project.items()
                if key != runtime.private_oracle.trusted_proof_field
            }
            for project_id, project in runtime.case.task_contract.trusted_ledger.items()
        }
        if runtime.initial_state.get("trusted_ledger") != runtime.case.task_contract.trusted_ledger:
            raise ValueError("capability_initial_trusted_ledger_mismatch")
        if runtime.initial_state.get("projects") != expected_projects:
            raise ValueError("capability_initial_business_state_mismatch")
    if (
        len(seen_contracts) != 1
        or len(manifest.case_refs) != 3
        or seen_variants != set(VariantKind)
        or set(manifest.case_hashes) != seen_case_ids
        or set(manifest.runtime_task_hashes) != seen_case_ids
    ):
        raise ValueError("capability_compilation_pairing_incomplete")
    validate_split_assignments(split_assignments)
    return manifest


def inventory_upstream(upstream_root: Path) -> dict[str, Any]:
    expected_commit = "a11f5cceaba0676be721021f8d232638fd111305"
    task_paths = sorted((upstream_root / "tasks").glob("*/*.json"))
    schema = upstream_root / "schema/task_schema.json"
    judge = upstream_root / "scripts/judge.py"
    if not schema.is_file() or not judge.is_file():
        raise ValueError("capability_upstream_sources_missing")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=upstream_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if commit != expected_commit:
        raise ValueError("capability_upstream_commit_mismatch")
    dirty = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=upstream_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if dirty:
        raise ValueError("capability_upstream_worktree_not_clean")
    pse_task = upstream_root / "tasks/pse/pse-2.1-002.json"
    pse_payload = _load_object(pse_task)
    return {
        "upstream_commit": commit,
        "upstream_worktree_clean": True,
        "task_count": len(task_paths),
        "task_ids": [path.stem for path in task_paths],
        "schema_path": "schema/task_schema.json",
        "schema_hash": file_hash(schema),
        "evaluator_path": "scripts/judge.py",
        "evaluator_hash": file_hash(judge),
        "pse_reference_task": "tasks/pse/pse-2.1-002.json",
        "pse_reference_task_hash": file_hash(pse_task),
        "pse_metric": pse_payload.get("evaluation", {}).get("metric"),
        "extension_task_id": "cap-f1-001",
        "extension_upstream_schema_compatible": False,
        "compatibility_boundaries": [
            {
                "reason_code": "official_pse_attack_success_uses_any_check",
                "research_handling": "preserve official output; compute final harm independently",
            },
            {
                "reason_code": "official_failed_preconditions_do_not_abort_session",
                "research_handling": (
                    "record precondition failure and fail the dependent research cell"
                ),
            },
            {
                "reason_code": "official_unknown_precondition_type_is_treated_as_passed",
                "research_handling": "capability preconditions use a closed allowlist",
            },
            {
                "reason_code": "official_session_key_shared_without_restart",
                "research_handling": "record actual session key; labels never prove isolation",
            },
            {
                "reason_code": "official_memory_checks_post_state_without_actor_lineage",
                "research_handling": "post-state can support official score but not Victim Persist",
            },
        ],
        "network_requests_performed": False,
    }


def validate_compatibility_config(path: Path) -> CompatibilityConfig:
    config = CompatibilityConfig.model_validate(_load_object(path))
    validate_provider_evidence_policy(config.provider_evidence_policy)
    return config
