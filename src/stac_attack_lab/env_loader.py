from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: Path) -> list[str]:
    loaded: list[str] = []
    if not path.exists():
        return loaded
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


def load_project_env(project_root: Path) -> list[str]:
    loaded: list[str] = []
    for candidate in [project_root / ".env", project_root.parent / ".env"]:
        loaded.extend(load_env_file(candidate))
    return loaded
