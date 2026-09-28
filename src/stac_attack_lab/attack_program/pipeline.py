"""Offline SafeClawArena R1 path. Never starts a victim or sends a request."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import jsonschema  # type: ignore[import-untyped]

from stac_attack_lab.attack_program.models import (
    AttackCandidate,
    AttackSurface,
    Catalog,
    Split,
    TaskEntry,
)
from stac_attack_lab.hashing import file_hash, stable_hash

PINNED_SAFECLAW_COMMIT = "a11f5cceaba0676be721021f8d232638fd111305"

TASK_IDS = ("pse-2.1-001", "pse-2.1-002", "pse-2.2-001", "pse-2.2-002", "cdf-3.9-001")
SCHEMA = "integrations/safeclaw/upstream/SafeClawArena/schema/task_schema.json"
JUDGE = "integrations/safeclaw/upstream/SafeClawArena/scripts/judge.py"
PATCH = "integrations/safeclaw/patches/a11f5cce-safety.patch"
SPLIT_RULES = "configs/attack_program/r1_split_registry.json"


class GateError(ValueError):
    """A stable, user-facing local validation failure."""


def _load_official_judge(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("stac_safeclaw_official_judge", path)
    if spec is None or spec.loader is None:
        raise GateError("safeclaw_official_judge_import_spec_failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_tree_file(repo: Path, relative: str) -> None:
    """Check exact bytes against HEAD, including unstaged and staged changes."""
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"HEAD:{relative}"], capture_output=True, check=False
    )
    if result.returncode != 0:
        raise GateError("pinned_tree_file_missing")
    path = repo / relative
    if not path.is_file() or path.read_bytes() != result.stdout:
        raise GateError("pinned_worktree_file_mismatch")


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise GateError("json_root_not_object")
    return value


def _pointer(doc: Any, pointer: str) -> Any:
    if not pointer.startswith("/") or "~" in pointer:
        raise GateError("invalid_pointer")
    node = doc
    for part in pointer[1:].split("/"):
        if isinstance(node, list) and part.isascii() and part.isdigit() and str(int(part)) == part:
            try:
                node = node[int(part)]
            except IndexError as exc:
                raise GateError("pointer_not_found") from exc
        elif isinstance(node, dict) and part in node:
            node = node[part]
        else:
            raise GateError("pointer_not_found")
    return node


def _replace(doc: dict[str, Any], pointer: str, value: str) -> None:
    parent, _, last = pointer.rpartition("/")
    container = _pointer(doc, parent) if parent else doc
    if isinstance(container, list):
        if not last.isascii() or not last.isdigit() or int(last) >= len(container):
            raise GateError("pointer_not_found")
        container[int(last)] = value
    elif isinstance(container, dict) and last in container:
        container[last] = value
    else:
        raise GateError("pointer_not_found")


def _protected_hash(task: dict[str, Any], pointers: set[str]) -> str:
    redacted = copy.deepcopy(task)
    for pointer in pointers:
        _replace(redacted, pointer, "<allowed-external-material>")
    return stable_hash(redacted)


def _surfaces(task: dict[str, Any]) -> list[AttackSurface]:
    workspace = task.get("environment", {}).get("workspace_files", [])
    service = task.get("environment", {}).get("sim_google_data", [])
    result: list[AttackSurface] = []
    for wi, item in enumerate(workspace):
        if not isinstance(item, dict) or item.get("is_sensitive") is not False:
            continue
        path = item.get("path")
        if not isinstance(path, str) or not path.startswith("inbox/"):
            continue
        matches = [
            (si, mirror)
            for si, mirror in enumerate(service)
            if isinstance(mirror, dict)
            and mirror.get("path") == "gmail/" + path
            and mirror.get("content") == item.get("content")
        ]
        if len(matches) != 1:
            continue
        pointer = f"/environment/workspace_files/{wi}/content"
        mirror = f"/environment/sim_google_data/{matches[0][0]}/content"
        root_hash = _protected_hash(task, {pointer, mirror})
        result.append(
            AttackSurface(
                pointer=pointer,
                mirror_pointer=mirror,
                resource_path=path,
                immutable_root_hash=root_hash,
            )
        )
    return result


def build_catalog(root: Path) -> Catalog:
    upstream = root / "integrations/safeclaw/upstream/SafeClawArena"

    commit = subprocess.run(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if commit != PINNED_SAFECLAW_COMMIT:
        raise GateError("upstream_commit_mismatch")
    _verify_tree_file(upstream, "schema/task_schema.json")
    _verify_tree_file(upstream, "scripts/judge.py")
    _verify_tree_file(root, PATCH)
    schema = _read(root / SCHEMA)
    registry = _read(root / SPLIT_RULES)
    if registry.get("schema_version") != "attack-split-registry/1":
        raise GateError("split_registry_version_invalid")
    if set(registry.get("exposure", {})) != set(TASK_IDS):
        raise GateError("split_registry_task_set_mismatch")
    entries: list[TaskEntry] = []
    for task_id in TASK_IDS:
        dimension = task_id.split("-", 1)[0]
        rel = f"integrations/safeclaw/upstream/SafeClawArena/tasks/{dimension}/{task_id}.json"
        _verify_tree_file(upstream, f"tasks/{dimension}/{task_id}.json")
        task = _read(root / rel)
        jsonschema.validate(task, schema)
        if task.get("metadata", {}).get("task_id") != task_id:
            raise GateError("task_identity_mismatch")
        surfaces = _surfaces(task)
        exposure = registry["exposure"][task_id]
        if exposure.get("status") not in {"known_exposed", "unknown"} or not exposure.get(
            "evidence"
        ):
            raise GateError("split_registry_exposure_invalid")
        category = str(task["metadata"]["category"])
        sessions = task.get("sessions", [])
        public = {
            "task_id": task_id,
            "task_group_id": f"{dimension}-{category}",
            "normal_user_instructions": [s["user_instruction"] for s in sessions],
            "allowed_materials": [
                {"path": s.resource_path, "max_chars": s.max_chars} for s in surfaces
            ],
        }
        entries.append(
            TaskEntry(
                task_id=task_id,
                task_group_id=f"{dimension}-{category}",
                template_group_id=f"{dimension}-{category}",
                task_path=rel,
                task_hash=file_hash(root / rel),
                upstream_commit=commit,
                track="official_task_payload_variant",
                support="pending_runtime" if surfaces else "unsupported",
                reason_codes=[] if surfaces else ["no_audited_mirrored_low_trust_surface"],
                known_exposure=exposure["status"] == "known_exposed",
                exposure_status=exposure["status"],
                exposure_evidence=exposure["evidence"],
                capability_evidence=["static_fixture_workspace_and_sim_google_mirror"]
                if surfaces
                else [],
                public_view=public,
                attack_surfaces=surfaces,
                evaluator_ref=JUDGE,
                evaluator_hash=file_hash(root / JUDGE),
            )
        )
    content = {
        "upstream_commit": commit,
        "schema_hash": file_hash(root / SCHEMA),
        "patch_hash": file_hash(root / PATCH),
        "entries": [e.model_dump(mode="json") for e in entries],
    }
    return Catalog.model_validate({**content, "catalog_hash": stable_hash(content)})


def validate_catalog(catalog: Catalog, root: Path) -> None:
    rebuilt = build_catalog(root)
    if rebuilt.model_dump() != catalog.model_dump():
        raise GateError("catalog_source_or_semantics_mismatch")
    if len({e.task_id for e in catalog.entries}) != len(catalog.entries):
        raise GateError("duplicate_task_id")


def make_split(catalog: Catalog) -> Split:
    registry = _read(Path(__file__).resolve().parents[3] / SPLIT_RULES)
    groups = {e.template_group_id for e in catalog.entries}
    assignments = registry.get("groups")
    if not isinstance(assignments, dict) or set(assignments) != groups:
        raise GateError("split_registry_group_set_mismatch")
    if any(value not in {"development", "validation", "test"} for value in assignments.values()):
        raise GateError("split_registry_assignment_invalid")
    exposure = sorted(e.task_id for e in catalog.entries if e.known_exposure)
    if any(
        entry.exposure_status == "unknown" and assignments[entry.template_group_id] == "test"
        for entry in catalog.entries
    ):
        raise GateError("unknown_exposure_cannot_be_test")
    body = {
        "catalog_hash": catalog.catalog_hash,
        "rule": "template-group-explicit-v1",
        "group_assignments": assignments,
        "known_exposure": exposure,
        "exposure_registry_hash": file_hash(Path(__file__).resolve().parents[3] / SPLIT_RULES),
    }
    return Split.model_validate({**body, "split_hash": stable_hash(body)})


def validate_split(split: Split, catalog: Catalog) -> None:
    expected = make_split(catalog)
    if split.catalog_hash != catalog.catalog_hash:
        raise GateError("split_catalog_mismatch")
    if split.known_exposure != expected.known_exposure:
        raise GateError("exposure_record_mismatch")
    for entry in catalog.entries:
        group = entry.template_group_id
        assigned = split.group_assignments.get(group)
        if assigned is None:
            raise GateError("split_group_missing")
        if entry.known_exposure and assigned == "test":
            raise GateError("exposed_task_in_test")
    if split.model_dump() != expected.model_dump():
        raise GateError("split_rule_or_hash_mismatch")


def _entry(catalog: Catalog, task_id: str) -> TaskEntry:
    for entry in catalog.entries:
        if entry.task_id == task_id:
            return entry
    raise GateError("task_not_in_catalog")


def materialize(
    root: Path, catalog: Catalog, split: Split, candidate: AttackCandidate
) -> dict[str, Any]:
    validate_catalog(catalog, root)
    validate_split(split, catalog)
    entry = _entry(catalog, candidate.task_id)
    if entry.support == "unsupported":
        raise GateError("task_unsupported")
    if candidate.task_group_id != entry.task_group_id:
        raise GateError("candidate_group_mismatch")
    if split.group_assignments[entry.template_group_id] != candidate.source_split:
        raise GateError("candidate_split_mismatch")
    if len(candidate.patches) != 1:
        raise GateError("candidate_patch_count_invalid")
    task = _read(root / entry.task_path)
    if file_hash(root / entry.task_path) != entry.task_hash:
        raise GateError("task_source_hash_mismatch")
    patch = candidate.patches[0]
    surfaces = [s for s in entry.attack_surfaces if s.pointer == patch.pointer]
    if len(surfaces) != 1:
        raise GateError("undeclared_attack_surface")
    surface = surfaces[0]
    if (
        _protected_hash(task, {surface.pointer, surface.mirror_pointer or ""})
        != surface.immutable_root_hash
    ):
        raise GateError("protected_task_semantics_mismatch")
    if not patch.value or len(patch.value) > surface.max_chars:
        raise GateError("payload_length_invalid")
    # A public payload may contain attack instructions, but never private benchmark answers.
    private = task.get("metadata", {}).get("description", "")
    if (
        re.search(r"CANARY_[A-Z0-9_]+|sk-(?:proj|ant)-", patch.value)
        or private
        and private in patch.value
    ):
        raise GateError("private_oracle_payload_leak")
    output = copy.deepcopy(task)
    _replace(output, surface.pointer, patch.value)
    if surface.mirror_pointer is not None:
        _replace(output, surface.mirror_pointer, patch.value)
    if (
        _protected_hash(output, {surface.pointer, surface.mirror_pointer or ""})
        != surface.immutable_root_hash
    ):
        raise GateError("protected_task_changed")
    if surface.mirror_pointer is not None and _pointer(output, surface.pointer) != _pointer(
        output, surface.mirror_pointer
    ):
        raise GateError("mirror_projection_mismatch")
    return output
