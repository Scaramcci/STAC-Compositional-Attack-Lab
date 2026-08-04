from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

MODEL_NAME = "huihui-qwen3-14b-abliterated-v2"


class ModelDiscoveryError(ValueError):
    pass


def is_valid_huggingface_model(path: Path) -> bool:
    if not path.is_dir() or not (path / "config.json").is_file():
        return False
    tokenizer = any(
        (path / name).is_file()
        for name in ("tokenizer.json", "tokenizer_config.json", "tokenizer.model")
    )
    weights = any(path.glob("*.safetensors")) or any(path.glob("pytorch_model*.bin"))
    return tokenizer and weights


def discover_huihui_model(project_root: Path, environment: Mapping[str, str] | None = None) -> Path:
    env = environment if environment is not None else os.environ
    override = env.get("HUIHUI_MODEL_PATH")
    if override:
        candidate = Path(override).expanduser().resolve()
        if not is_valid_huggingface_model(candidate):
            raise ModelDiscoveryError("invalid_model_configuration:HUIHUI_MODEL_PATH")
        return candidate
    models_root = (project_root / "../../../models").resolve()
    if not models_root.is_dir():
        raise ModelDiscoveryError("invalid_model_configuration:models_directory_missing")
    candidates = sorted(
        path
        for path in models_root.iterdir()
        if path.is_dir() and "huihui" in path.name.lower() and is_valid_huggingface_model(path)
    )
    exact = [path for path in candidates if path.name.lower() == MODEL_NAME]
    if exact:
        return exact[0]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise ModelDiscoveryError("invalid_model_configuration:huihui_model_not_found")
    raise ModelDiscoveryError("invalid_model_configuration:multiple_huihui_models")
