from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stac_attack_lab.config import _parse_scalar
from stac_attack_lab.hashing import stable_hash


@dataclass(frozen=True)
class PromptAsset:
    path: Path
    front_matter: dict[str, Any]
    body: str

    @property
    def prompt_id(self) -> str:
        return str(self.front_matter["prompt_id"])

    @property
    def version(self) -> str:
        return str(self.front_matter["version"])

    @property
    def hash(self) -> str:
        return stable_hash({"front_matter": self.front_matter, "body": self.body})


def load_prompt(path: Path) -> PromptAsset:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"missing front matter: {path}")
    _, rest = text.split("---\n", 1)
    header, body = rest.split("---\n", 1)
    meta: dict[str, Any] = {}
    for line in header.splitlines():
        if not line.strip():
            continue
        key, value = line.split(":", 1)
        meta[key.strip()] = _parse_scalar(value)
    for required in [
        "prompt_id",
        "version",
        "role",
        "input_schema",
        "output_schema",
        "temperature",
        "max_output_tokens",
    ]:
        if required not in meta:
            raise ValueError(f"prompt {path} missing {required}")
    return PromptAsset(path=path, front_matter=meta, body=body.strip())
