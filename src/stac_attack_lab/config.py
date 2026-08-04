from __future__ import annotations

import ast
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, PositiveInt, field_validator, model_validator

from stac_attack_lab.contracts import StrictModel

GPT_MODEL_ID = "gpt-5.5"
REQUIRED_ROLES = {"planner", "attacker", "victim", "prompt_writer", "verifier", "judge"}
OPENAI_ROLES = REQUIRED_ROLES - {"victim"}


class StartupValidationError(ValueError):
    """Fail-closed configuration error whose text never contains secret values."""


class RoleModelConfig(StrictModel):
    provider: Literal["fake", "gemini", "openai_compatible", "huihui_local"]
    model: str
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_output_tokens: PositiveInt = 1200
    timeout_seconds: PositiveInt = 60


class ExperimentConfig(StrictModel):
    experiment_id: str
    profile: Literal["fake", "gemini_development", "stac_offline", "formal_evaluation"] = "fake"
    dataset_version: str = "mvp-v0.1"
    planner_type: str = "fixed"
    conditions: list[str] = Field(default_factory=lambda: ["clean", "fixed_full"])
    task_limit: PositiveInt = 2
    seeds: list[int] = Field(default_factory=lambda: [1])
    max_turns: PositiveInt = 12
    max_tool_calls: PositiveInt = 8
    max_tokens: PositiveInt = 4096
    benign_interference_steps: int = Field(default=3, ge=0)
    defense_enabled: bool = False
    network_enabled: bool = False
    models: dict[str, RoleModelConfig]

    @field_validator("seeds")
    @classmethod
    def nonempty_seeds(cls, value: list[int]) -> list[int]:
        if not value:
            raise ValueError("seeds_must_not_be_empty")
        return value

    @model_validator(mode="after")
    def validate_role_profile(self) -> ExperimentConfig:
        missing = REQUIRED_ROLES - set(self.models)
        if missing:
            raise ValueError("missing_model_roles:" + ",".join(sorted(missing)))
        if self.profile == "fake":
            if any(self.models[role].provider != "fake" for role in REQUIRED_ROLES):
                raise ValueError("fake_profile_requires_fake_roles")
            if self.network_enabled:
                raise ValueError("fake_profile_requires_network_disabled")
        elif self.profile == "gemini_development":
            if any(self.models[role].provider != "gemini" for role in REQUIRED_ROLES):
                raise ValueError("gemini_development_requires_gemini_roles")
        elif self.profile in {"stac_offline", "formal_evaluation"}:
            for role in OPENAI_ROLES:
                model = self.models[role]
                if model.provider != "openai_compatible" or model.model != GPT_MODEL_ID:
                    raise ValueError(f"{self.profile}_{role}_must_use_{GPT_MODEL_ID}")
            victim = self.models["victim"]
            expected_provider = "gemini" if self.profile == "stac_offline" else "huihui_local"
            if victim.provider != expected_provider:
                raise ValueError(f"{self.profile}_victim_must_use_{expected_provider}")
            if not self.network_enabled:
                raise ValueError(f"{self.profile}_requires_network_enabled")
        return self


def _parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if value in {"true", "false"}:
        return value == "true"
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part.strip()) for part in inner.split(",")]
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def load_simple_yaml(path: Path) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if ":" not in line:
            raise ValueError(f"unsupported yaml line: {raw_line}")
        key, raw_value = line.split(":", 1)
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if raw_value.strip() == "":
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _parse_scalar(raw_value)
    return root


def load_experiment_config(path: Path) -> ExperimentConfig:
    return ExperimentConfig.model_validate(load_simple_yaml(path))


def configured_openai_models(environment: Mapping[str, str] | None = None) -> list[str]:
    env = environment if environment is not None else os.environ
    raw = env.get("OPENAI_MODEL_list")
    if raw is None:
        raw = env.get("OPENAI_MODEL_LIST", "")
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        try:
            parsed = ast.literal_eval(raw)
        except (SyntaxError, ValueError):
            parsed = [part.strip() for part in raw.split(",")]
    if isinstance(parsed, str):
        parsed = [parsed]
    if not isinstance(parsed, (list, tuple)):
        return []
    return [str(item).strip() for item in parsed if str(item).strip()]


def validate_startup(
    config: ExperimentConfig, environment: Mapping[str, str] | None = None
) -> None:
    env = environment if environment is not None else os.environ
    providers = {model.provider for model in config.models.values()}
    missing: list[str] = []
    if "openai_compatible" in providers:
        for name in ("OPENAI_BASE_URL", "OPENAI_API_KEY"):
            if not env.get(name):
                missing.append(name)
        if not (env.get("OPENAI_MODEL_list") or env.get("OPENAI_MODEL_LIST")):
            missing.append("OPENAI_MODEL_list")
    if "gemini" in providers and not env.get("GEMINI_API_KEY"):
        missing.append("GEMINI_API_KEY")
    if "huihui_local" in providers and not env.get("HUIHUI_BASE_URL"):
        missing.append("HUIHUI_BASE_URL")
    if missing:
        raise StartupValidationError("missing_environment_variables:" + ",".join(sorted(missing)))
    if "openai_compatible" in providers and GPT_MODEL_ID not in configured_openai_models(env):
        raise StartupValidationError("invalid_model_configuration:gpt-5.5_not_configured")
    for role, model in config.models.items():
        if model.provider == "openai_compatible" and model.model != GPT_MODEL_ID:
            raise StartupValidationError(f"invalid_model_configuration:{role}_model")
