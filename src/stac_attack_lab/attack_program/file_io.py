"""Exclusive JSON output for attack-program artifacts."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def write_json_exclusive(
    path: Path,
    value: Any,
    *,
    private: bool = False,
    sort_keys: bool = False,
    durable: bool = False,
) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=sort_keys, ensure_ascii=False, indent=2)
        stream.write("\n")
        if durable:
            stream.flush()
            os.fsync(stream.fileno())
