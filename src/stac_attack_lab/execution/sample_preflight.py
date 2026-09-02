from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Literal

from pydantic import Field

from stac_attack_lab.config import RoleModelConfig, configured_openai_models, load_simple_yaml
from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.execution.sample_generation import SampleGenerationConfig
from stac_attack_lab.hashing import file_hash
from stac_attack_lab.interactions.safeclaw_collection import SafeClawConstructionTaskSet
from stac_attack_lab.prompts.loader import load_prompt


class SampleCollectionPreflightCheck(StrictModel):
    check_id: str
    passed: bool
    reason_code: str
    public_details: dict[str, str] = Field(default_factory=dict)


class SampleCollectionPreflightReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    passed: bool
    execution_started: Literal[False] = False
    checks: list[SampleCollectionPreflightCheck]


CommandRunner = Callable[[list[str], Path | None], subprocess.CompletedProcess[str]]


def _default_runner(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def run_sample_collection_preflight(
    project_root: Path,
    config: SampleGenerationConfig,
    *,
    environment: Mapping[str, str] | None = None,
    command_runner: CommandRunner = _default_runner,
) -> SampleCollectionPreflightReport:
    env = environment if environment is not None else os.environ
    checks: list[SampleCollectionPreflightCheck] = []

    def add(
        check_id: str,
        passed: bool,
        passed_reason: str,
        failed_reason: str,
        details: dict[str, str] | None = None,
    ) -> None:
        checks.append(
            SampleCollectionPreflightCheck(
                check_id=check_id,
                passed=passed,
                reason_code=passed_reason if passed else failed_reason,
                public_details=details or {},
            )
        )

    real_adapter = config.source_adapter == "safeclaw_adaptive_construction"
    add(
        "real_adapter",
        real_adapter,
        "safeclaw_adaptive_adapter_configured",
        "sample_collection_not_using_real_adapter",
    )
    add(
        "execution_gate",
        config.execution_enabled,
        "sample_collection_explicitly_enabled",
        "sample_collection_execution_disabled",
    )
    split_ok = "test" not in config.allowed_source_splits
    add(
        "construction_split",
        split_ok,
        "formal_test_split_excluded",
        "formal_test_split_allowed",
    )
    overlap = set(config.source_task_ids) & set(config.formal_excluded_task_ids)
    add(
        "formal_exclusion",
        not overlap,
        "construction_and_formal_tasks_disjoint",
        "construction_formal_task_overlap",
        {"overlap": ",".join(sorted(overlap))},
    )
    required_safety = {
        "synthetic_canary_only",
        "no_external_network",
        "no_host_files",
        "no_real_credentials",
        "isolated_container",
    }
    missing_safety = required_safety - set(config.safety_constraint_ids)
    add(
        "safety_constraints",
        not missing_safety,
        "required_safety_constraints_present",
        "required_safety_constraints_missing",
        {"missing": ",".join(sorted(missing_safety))},
    )
    path_fields = {
        "task_set": config.construction_task_set_path,
        "upstream": config.upstream_dir,
        "safety_patch": config.safety_patch_path,
        "bridge": config.construction_bridge_path,
        "attacker_model_config": config.construction_attacker_model_config_path,
        "attacker_prompt": config.construction_attacker_prompt_path,
        "registry": config.registry_path,
    }
    missing_paths = [
        name
        for name, raw in path_fields.items()
        if raw is None or not (project_root / raw).exists()
    ]
    add(
        "required_paths",
        not missing_paths,
        "sample_collection_paths_present",
        "sample_collection_paths_missing",
        {"missing": ",".join(sorted(missing_paths))},
    )
    task_set: SafeClawConstructionTaskSet | None = None
    if (
        config.construction_task_set_path
        and (project_root / config.construction_task_set_path).is_file()
    ):
        try:
            task_set = SafeClawConstructionTaskSet.model_validate_json(
                (project_root / config.construction_task_set_path).read_text(encoding="utf-8")
            )
        except ValueError:
            task_set = None
    task_ids_match = False
    task_hashes_match = False
    formal_hash_match = False
    if task_set is not None:
        task_ids_match = set(config.source_task_ids) <= {
            task.source_task_id for task in task_set.tasks
        }
        task_hashes_match = all(
            (project_root / task.template_path).is_file()
            and file_hash(project_root / task.template_path) == task.template_hash
            for task in task_set.tasks
        )
        formal_hash_match = set(config.formal_excluded_task_ids) == set(
            task_set.formal_excluded_task_ids
        )
    add(
        "task_set",
        task_ids_match and task_hashes_match and formal_hash_match,
        "construction_task_set_pinned_and_disjoint",
        "construction_task_set_invalid",
    )
    prompt_ok = False
    if config.construction_attacker_prompt_path:
        prompt_path = project_root / config.construction_attacker_prompt_path
        if prompt_path.is_file():
            prompt = load_prompt(prompt_path)
            prompt_ok = prompt.front_matter.get("output_schema") == "ConstructionAttackerAction"
    add(
        "attacker_prompt",
        prompt_ok,
        "construction_attacker_prompt_contract_valid",
        "construction_attacker_prompt_contract_invalid",
    )
    attacker_model: RoleModelConfig | None = None
    if config.construction_attacker_model_config_path:
        model_path = project_root / config.construction_attacker_model_config_path
        if model_path.is_file():
            attacker_model = RoleModelConfig.model_validate(load_simple_yaml(model_path))
    add(
        "attacker_model",
        attacker_model is not None,
        "construction_attacker_model_is_real",
        "construction_attacker_model_missing",
    )
    attacker_model_available = True
    if attacker_model is not None and attacker_model.provider == "openai_compatible":
        attacker_model_available = attacker_model.model in configured_openai_models(env)
    add(
        "attacker_model_availability",
        attacker_model_available,
        "construction_attacker_model_available",
        "construction_attacker_model_not_available",
        {"model_id": attacker_model.model if attacker_model is not None else "missing"},
    )
    required_env = [
        name
        for name in (
            config.victim_model_env,
            config.victim_base_url_env,
            config.victim_api_key_env,
            config.embedding_model_env,
            config.embedding_base_url_env,
            config.embedding_api_key_env,
        )
        if name
    ]
    embedding_configured = (
        config.embedding_provider == "openai"
        and config.embedding_model_env is not None
        and config.embedding_base_url_env is not None
        and config.embedding_api_key_env is not None
    )
    add(
        "embedding_configuration",
        embedding_configured,
        "sample_collection_embedding_configuration_complete",
        "sample_collection_embedding_configuration_incomplete",
    )
    if attacker_model is not None:
        required_env.extend(["OPENAI_BASE_URL", "OPENAI_API_KEY"])
    missing_env = sorted({name for name in required_env if not env.get(name)})
    add(
        "model_environment",
        not missing_env and len(required_env) >= 6,
        "sample_collection_model_environment_present",
        "sample_collection_model_environment_missing",
        {"missing_variable_names": ",".join(missing_env)},
    )
    victim_model = env.get(config.victim_model_env or "")
    victim_allowed = (
        victim_model is None
        or not config.allowed_victim_models
        or victim_model in config.allowed_victim_models
    )
    add(
        "victim_model",
        victim_allowed,
        "sample_collection_victim_model_allowed",
        "sample_collection_victim_model_not_allowed",
        {
            "configured_model": victim_model or "missing",
            "allowed_models": ",".join(config.allowed_victim_models),
        },
    )
    upstream = project_root / config.upstream_dir if config.upstream_dir else None
    observed_commit = "unavailable"
    if upstream is not None and upstream.is_dir():
        result = command_runner(["git", "rev-parse", "HEAD"], upstream)
        if result.returncode == 0:
            observed_commit = result.stdout.strip()
    commit_ok = task_set is not None and observed_commit == task_set.upstream_commit
    add(
        "upstream_commit",
        commit_ok,
        "safeclaw_upstream_commit_matches",
        "safeclaw_upstream_commit_mismatch",
        {"observed": observed_commit},
    )
    patch_ok = False
    if upstream is not None and config.safety_patch_path:
        patch = project_root / config.safety_patch_path
        if upstream.is_dir() and patch.is_file():
            patch_check = command_runner(
                ["git", "apply", "--unidiff-zero", "--check", str(patch)], upstream
            )
            patch_ok = patch_check.returncode == 0
    add(
        "safety_patch",
        patch_ok,
        "safeclaw_safety_patch_applies",
        "safeclaw_safety_patch_not_applicable",
    )
    docker = command_runner(["docker", "info", "--format", "{{json .ServerVersion}}"], None)
    image = command_runner(
        ["docker", "image", "inspect", config.image_tag, "--format", "{{json .Id}}"],
        None,
    )
    add("docker", docker.returncode == 0, "docker_available", "docker_unavailable")
    add(
        "docker_image",
        image.returncode == 0,
        "safeclaw_image_present",
        "safeclaw_image_missing",
        {"image_tag": config.image_tag},
    )
    disk_base = upstream if upstream is not None and upstream.exists() else project_root
    free_gb = shutil.disk_usage(disk_base).free // (1024**3)
    add(
        "free_disk",
        free_gb >= config.minimum_free_disk_gb,
        "sample_collection_disk_sufficient",
        "sample_collection_disk_insufficient",
        {
            "free_gb": str(free_gb),
            "required_gb": str(config.minimum_free_disk_gb),
        },
    )
    output = project_root / config.output_root / config.library_version / "interactions/raw"
    temporary_files = list(output.rglob("*.tmp")) if output.exists() else []
    add(
        "resumable_output",
        not temporary_files,
        "collection_output_new_or_resumable",
        "collection_output_has_incomplete_atomic_files",
        {"temporary_file_count": str(len(temporary_files))},
    )
    return SampleCollectionPreflightReport(
        passed=all(check.passed for check in checks),
        checks=checks,
    )
