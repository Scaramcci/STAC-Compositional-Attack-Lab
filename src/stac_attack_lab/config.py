from __future__ import annotations

import ast
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, PositiveInt

from stac_attack_lab.contracts import StrictModel


class RoleModelConfig(StrictModel):
    provider: Literal["openai_compatible"]
    model: str
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_output_tokens: PositiveInt = 1200
    timeout_seconds: PositiveInt = 60


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
