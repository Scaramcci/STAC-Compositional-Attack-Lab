from __future__ import annotations

from typing import Any

from stac_attack_lab.environments.safeclaw.contracts import (
    SafeClawEpisodeResult,
    SafeClawExecutionStatus,
)
from stac_attack_lab.verification.formal_models import OfficialSafeClawVerdict


def _boolean_leaves(value: Any, prefix: str = "") -> dict[str, bool | None]:
    leaves: dict[str, bool | None] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            leaves.update(_boolean_leaves(item, path))
    elif isinstance(value, bool) or value is None:
        leaves[prefix] = value
    return leaves


def parse_safeclaw_official(
    episode: SafeClawEpisodeResult, sanitized_result: dict[str, Any] | None
) -> OfficialSafeClawVerdict:
    completed = episode.status == SafeClawExecutionStatus.completed
    gaps: list[str] = []
    payload = sanitized_result or {}
    if sanitized_result is None:
        gaps.append("sanitized_official_result_missing")
    task_id = payload.get("task_id")
    if task_id is not None and str(task_id) != episode.task_id:
        completed = False
        gaps.append("official_task_identity_mismatch")
    raw_attack = payload.get("attack_succeeded")
    attack_succeeded = raw_attack if isinstance(raw_attack, bool) else None
    if completed and attack_succeeded is None:
        gaps.append("official_attack_succeeded_missing")
    raw_score = payload.get("score")
    security_score = (
        float(raw_score)
        if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool)
        else None
    )
    checks = _boolean_leaves(payload.get("checks", {}))
    safe_checks = {
        key: value
        for key, value in checks.items()
        if any(token in key.lower() for token in ("safe", "security", "detect"))
    }
    success_checks = {
        key: value
        for key, value in checks.items()
        if any(token in key.lower() for token in ("success", "attack", "goal"))
    }
    raw_utility = payload.get("utility_success")
    utility_success = raw_utility if isinstance(raw_utility, bool) else None
    if utility_success is None:
        utility_value = next(
            (
                value
                for key, value in checks.items()
                if "utility" in key.lower() or "user_task" in key.lower()
            ),
            None,
        )
        utility_success = utility_value if isinstance(utility_value, bool) else None
    if completed and utility_success is None:
        gaps.append("official_utility_signal_missing")
    taint = payload.get("taint_leakage", [])
    if isinstance(taint, list):
        taint_channels = sorted(
            {
                str(item.get("channel", item.get("sink", "unknown")))
                if isinstance(item, dict)
                else str(item)
                for item in taint
            }
        )
    else:
        taint_channels = []
        gaps.append("official_taint_shape_invalid")
    return OfficialSafeClawVerdict(
        evaluator_version=f"safeclaw@{episode.upstream_commit}",
        execution_complete=completed,
        attack_succeeded=attack_succeeded,
        security_score=security_score,
        utility_success=utility_success,
        safe_check_results=safe_checks,
        success_check_results=success_checks,
        taint_channels=taint_channels,
        evidence_ref_ids=[episode.official_checks_ref] if episode.official_checks_ref else [],
        instrumentation_gaps=gaps,
    )
