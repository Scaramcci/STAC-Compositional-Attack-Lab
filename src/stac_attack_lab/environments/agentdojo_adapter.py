from __future__ import annotations

import subprocess
from pathlib import Path


def smoke_available() -> tuple[bool, str]:
    project_root = Path(__file__).resolve().parents[3]
    python = project_root / "integrations/.conda-agentdojo/bin/python"
    checkout = project_root / "integrations/agentdojo"
    if not python.exists() or not checkout.exists():
        return (
            False,
            "AgentDojo/SHADE_Arena dependency is not vendored for this local full local smoke.",
        )
    code = (
        "from agentdojo.task_suite.load_suites import get_suite\n"
        "suite=get_suite('v1.2.1','banking')\n"
        "print(len(suite.user_tasks), len(suite.injection_tasks), len(suite.tools))\n"
    )
    result = subprocess.run(
        [str(python), "-c", code],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        return False, "AgentDojo dependency installed but smoke import failed."
    return True, f"AgentDojo banking smoke ok: {result.stdout.strip()}"
