from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field

from stac_attack_lab.contracts import StrictModel


class RoleModelConfig(StrictModel):
    provider: str
    model: str
    temperature: float = 0.0
    max_output_tokens: int = 1200
    timeout_seconds: int = 60


class ExperimentConfig(StrictModel):
    experiment_id: str
    dataset_version: str = "mvp-v0.1"
    planner_type: str = "fixed"
    conditions: list[str] = Field(default_factory=lambda: ["clean", "fixed_full"])
    task_limit: int = 2
    seeds: list[int] = Field(default_factory=lambda: [1])
    max_turns: int = 12
    max_tool_calls: int = 8
    max_tokens: int = 4096
    benign_interference_steps: int = 3
    defense_enabled: bool = False
    network_enabled: bool = False
    models: dict[str, RoleModelConfig]


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
