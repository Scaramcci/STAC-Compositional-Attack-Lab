from __future__ import annotations

import json
from pathlib import Path

from stac_attack_lab.flow.models import ObservationProfile
from stac_attack_lab.hashing import stable_hash


def load_observation_profile(path: Path) -> ObservationProfile:
    profile = ObservationProfile.model_validate_json(path.read_text(encoding="utf-8"))
    return profile


def observation_profile_hash(profile: ObservationProfile) -> str:
    return stable_hash(profile.model_dump(mode="json"))


def write_observation_profile(path: Path, profile: ObservationProfile) -> None:
    path.write_text(
        json.dumps(profile.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
