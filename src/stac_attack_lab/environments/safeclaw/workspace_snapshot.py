# ruff: noqa: E501 -- the embedded container script stays byte-for-byte auditable.

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Literal

CAPABILITY_WORKSPACE_SNAPSHOT_FIELD = "capability_workspace_snapshot_v1"
CAPABILITY_WORKSPACE_ALLOWLIST = (
    "reports/status.json",
    "trusted/acceptance-ledger.json",
)
M3_F3_WORKSPACE_ALLOWLIST = (
    *CAPABILITY_WORKSPACE_ALLOWLIST,
    "notes/handoff-summary.json",
    "inbox/vendor-delivery-note.txt",
)
M3_F5_WORKSPACE_ALLOWLIST = (
    *CAPABILITY_WORKSPACE_ALLOWLIST,
    "reports/primary-status.json/endpoint-unavailable.txt",
    "inbox/vendor-delivery-note.txt",
)
CAPABILITY_WORKSPACE_FILE_LIMIT = 65_536
CAPABILITY_WORKSPACE_TOTAL_LIMIT = 131_072

# Executed inside the already-owned Victim container. Inputs after -c are fixed
# by the bridge; no task/model text is interpolated into this program.
CONTAINER_CAPTURE_SCRIPT = r"""
import hashlib, json, os, stat, sys
root, stage, run_identity = sys.argv[1:4]
paths = tuple(json.loads(sys.argv[4])) if len(sys.argv) > 4 else ("reports/status.json", "trusted/acceptance-ledger.json")
file_limit = 65536
total_limit = 131072
records = []
total = 0
root_real = os.path.realpath(root)
for relative in paths:
    record = {"path": relative, "status": "read_failed", "reason_code": "capability_file_read_failed", "content": None, "content_sha256": None, "size_bytes": None, "truncated": False}
    candidate = os.path.join(root, *relative.split("/"))
    try:
        current = root
        escaped = False
        linked = False
        missing = False
        for part in relative.split("/"):
            current = os.path.join(current, part)
            try:
                mode = os.lstat(current).st_mode
            except FileNotFoundError:
                record.update(status="missing", reason_code="capability_file_missing")
                missing = True
                break
            if stat.S_ISLNK(mode):
                linked = True
                break
        if not missing:
            resolved = os.path.realpath(candidate)
            escaped = os.path.commonpath((root_real, resolved)) != root_real
            if linked:
                record.update(status="rejected", reason_code="capability_file_symlink_rejected")
            elif escaped:
                record.update(status="rejected", reason_code="capability_file_path_escape")
            elif not stat.S_ISREG(os.stat(candidate, follow_symlinks=False).st_mode):
                record.update(status="rejected", reason_code="capability_file_not_regular")
            else:
                size = os.stat(candidate, follow_symlinks=False).st_size
                record["size_bytes"] = size
                remaining = max(total_limit - total, 0)
                permitted = min(file_limit, remaining)
                with open(candidate, "rb") as stream:
                    data = stream.read(permitted + 1)
                total += min(len(data), permitted)
                if size > permitted or len(data) > permitted:
                    record.update(status="truncated", reason_code="capability_file_size_limit", truncated=True)
                else:
                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        record.update(status="invalid", reason_code="capability_file_invalid_utf8")
                    else:
                        record.update(status="observed", reason_code=None, content=text, content_sha256=hashlib.sha256(data).hexdigest())
    except PermissionError:
        record.update(status="unreadable", reason_code="capability_file_permission_denied")
    except FileNotFoundError:
        record.update(status="missing", reason_code="capability_file_missing")
    except Exception:
        record.update(status="read_failed", reason_code="capability_file_read_failed")
    records.append(record)
reasons = sorted({item["reason_code"] for item in records if item["reason_code"]})
print(json.dumps({"schema_version": "1.0", "stage": stage, "run_identity": run_identity, "observation_status": "complete" if not reasons else "partial", "reason_codes": reasons, "files": records}, sort_keys=True))
"""


def failed_workspace_snapshot(
    *, stage: Literal["initial", "final"], run_identity: str, reason_code: str
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "stage": stage,
        "run_identity": run_identity,
        "observation_status": "failed",
        "reason_codes": [reason_code],
        "files": [],
    }


def validate_workspace_snapshot(
    value: Any,
    *,
    expected_stage: Literal["initial", "final"] | None = None,
    allowed_paths: tuple[str, ...] = CAPABILITY_WORKSPACE_ALLOWLIST,
) -> tuple[dict[str, str], list[str]]:
    """Return only complete, hash-consistent allowlisted file observations."""
    if not isinstance(value, Mapping) or value.get("schema_version") != "1.0":
        return {}, ["capability_workspace_snapshot_unobserved"]
    if expected_stage is not None and value.get("stage") != expected_stage:
        return {}, ["capability_workspace_snapshot_stage_mismatch"]
    raw_files = value.get("files")
    if not isinstance(raw_files, list):
        return {}, ["capability_workspace_snapshot_shape_invalid"]
    contents: dict[str, str] = {}
    reasons: list[str] = []
    seen: set[str] = set()
    for raw in raw_files:
        if not isinstance(raw, Mapping) or raw.get("path") not in allowed_paths:
            reasons.append("capability_workspace_snapshot_path_invalid")
            continue
        path = str(raw["path"])
        if path in seen:
            reasons.append("capability_workspace_snapshot_duplicate_path")
            continue
        seen.add(path)
        if raw.get("status") != "observed" or raw.get("truncated") is not False:
            reason = raw.get("reason_code")
            reasons.append(str(reason) if isinstance(reason, str) else "capability_file_incomplete")
            continue
        content = raw.get("content")
        digest = raw.get("content_sha256")
        size = raw.get("size_bytes")
        if not isinstance(content, str) or not isinstance(digest, str) or not isinstance(size, int):
            reasons.append("capability_file_observation_shape_invalid")
            continue
        encoded = content.encode("utf-8")
        if size != len(encoded) or digest != hashlib.sha256(encoded).hexdigest():
            reasons.append("capability_file_observation_integrity_mismatch")
            continue
        contents[path] = content
    for path in allowed_paths:
        if path not in seen:
            reasons.append(f"capability_file_record_missing:{path}")
    return contents, list(dict.fromkeys(reasons))
