"""JSON schemas for the current attack program contracts."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from stac_attack_lab.attack_program.models import (
    AttackCandidate,
    Catalog,
    DevelopmentInput,
    LibraryManifest,
    R3Case,
    R3Config,
    R3Manifest,
    R3Plan,
    R3PlannerInput,
    R3Result,
    RawExampleView,
    RawObservation,
    RuntimeEvent,
    Split,
    StructuredExampleView,
)

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "attack_program_candidate": AttackCandidate,
    "attack_program_catalog": Catalog,
    "attack_program_development_input": DevelopmentInput,
    "attack_program_library_manifest": LibraryManifest,
    "attack_program_observation": RawObservation,
    "attack_program_runtime_event": RuntimeEvent,
    "attack_program_r3_case": R3Case,
    "attack_program_r3_config": R3Config,
    "attack_program_r3_manifest": R3Manifest,
    "attack_program_r3_plan": R3Plan,
    "attack_program_r3_planner_input": R3PlannerInput,
    "attack_program_r3_result": R3Result,
    "attack_program_raw_view": RawExampleView,
    "attack_program_split": Split,
    "attack_program_structured_view": StructuredExampleView,
}


def validate_schema_registry() -> None:
    for name, model in SCHEMA_MODELS.items():
        if model.model_json_schema().get("type") != "object":
            raise ValueError(f"schema_root_not_object:{name}")


def build_schemas(directory: Path = Path("schemas")) -> list[Path]:
    validate_schema_registry()
    directory.mkdir(parents=True, exist_ok=True)
    result: list[Path] = []
    for name, model in SCHEMA_MODELS.items():
        path = directory / f"{name}.schema.json"
        path.write_text(json.dumps(model.model_json_schema(), indent=2) + "\n", encoding="utf-8")
        result.append(path)
    return result


if __name__ == "__main__":
    build_schemas()
