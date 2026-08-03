from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from stac_attack_lab.hashing import stable_hash


def write_snapshot(root: Path, name: str, snapshot: dict[str, Any]) -> str:
    ref = f"snapshots/{name}-{stable_hash(snapshot)[:12]}.json"
    path = root / ref
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)
    return ref


def load_snapshot(root: Path, ref: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((root / ref).read_text(encoding="utf-8")))
