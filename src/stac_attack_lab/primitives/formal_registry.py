from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field, model_validator

from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.primitives.core import CorePrimitiveSpec, EvidencePolicy
from stac_attack_lab.primitives.macros import AttackMacroSpec


class FormalPrimitiveRegistry(StrictModel):
    schema_version: str = "2.0"
    registry_id: str
    registry_version: str
    observable_projection_version: str
    core_primitives: list[CorePrimitiveSpec]
    attack_macros: list[AttackMacroSpec]
    component_roles: list[str]
    evidence_policy: EvidencePolicy = Field(default_factory=EvidencePolicy)

    @model_validator(mode="after")
    def validate_registry(self) -> FormalPrimitiveRegistry:
        core_ids = [item.primitive_id for item in self.core_primitives]
        macro_ids = [item.macro_id for item in self.attack_macros]
        if len(core_ids) != len(set(core_ids)):
            raise ValueError("duplicate_core_primitive_id")
        if len(macro_ids) != len(set(macro_ids)):
            raise ValueError("duplicate_attack_macro_id")
        known_core = set(core_ids)
        aliases: set[str] = set()
        for macro in self.attack_macros:
            for node in macro.core_nodes:
                if node.primitive_ref not in known_core:
                    raise ValueError(f"macro_references_unknown_core:{node.primitive_ref}")
            for alias in macro.aliases:
                if alias in aliases:
                    raise ValueError(f"duplicate_macro_alias:{alias}")
                aliases.add(alias)
        if len(self.component_roles) != len(set(self.component_roles)):
            raise ValueError("duplicate_component_role")
        return self

    @property
    def registry_hash(self) -> str:
        return stable_hash(self.model_dump(mode="json"))

    def resolve_macro(self, macro_or_alias: str) -> AttackMacroSpec:
        for macro in self.attack_macros:
            if macro.macro_id == macro_or_alias or macro_or_alias in macro.aliases:
                return macro
        raise KeyError(f"unknown_attack_macro:{macro_or_alias}")

    def core_by_id(self, primitive_id: str) -> CorePrimitiveSpec:
        for primitive in self.core_primitives:
            if primitive.primitive_id == primitive_id:
                return primitive
        raise KeyError(f"unknown_core_primitive:{primitive_id}")

    def public_snapshot(self) -> dict[str, Any]:
        return {
            "registry_id": self.registry_id,
            "registry_version": self.registry_version,
            "registry_hash": self.registry_hash,
            "observable_projection_version": self.observable_projection_version,
            "core_primitive_ids": [item.primitive_id for item in self.core_primitives],
            "attack_macro_ids": [item.macro_id for item in self.attack_macros],
            "component_roles": self.component_roles,
        }


def _load_yaml_or_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError("PyYAML is required for non-JSON YAML registry files") from exc
        value = yaml.safe_load(text)
    if not isinstance(value, dict):
        raise ValueError("formal_registry_root_must_be_mapping")
    return value


def load_formal_registry(path: Path) -> FormalPrimitiveRegistry:
    return FormalPrimitiveRegistry.model_validate(_load_yaml_or_json(path))
