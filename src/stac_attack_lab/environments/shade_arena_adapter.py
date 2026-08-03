from __future__ import annotations

from pathlib import Path

EXPECTED_FILES = [
    "README.md",
    "config.yaml",
    "task_completion.py",
    "environments/workspace_environment.py",
    "task_evaluation/evaluation_factory.py",
    "utils/experiment_runner.py",
]


def default_shade_arena_path(project_root: Path) -> Path:
    return project_root.parent / "papers/projects/AgentLAB/code/official/SHADE_Arena"


def smoke_available(project_root: Path | None = None) -> tuple[bool, str]:
    root = project_root or Path(__file__).resolve().parents[3]
    shade_root = default_shade_arena_path(root)
    if not shade_root.exists():
        return False, f"SHADE_Arena checkout not found at {shade_root}"
    missing = [name for name in EXPECTED_FILES if not (shade_root / name).exists()]
    if missing:
        return False, "SHADE_Arena checkout missing expected files: " + ", ".join(missing)
    task_dirs = sorted(path.name for path in (shade_root / "task_pairs").glob("*") if path.is_dir())
    tool_files = sorted(path.name for path in (shade_root / "tools").glob("*_tools.py"))
    return (
        True,
        f"SHADE_Arena smoke ok: {len(task_dirs)} task domains, {len(tool_files)} tool modules",
    )
