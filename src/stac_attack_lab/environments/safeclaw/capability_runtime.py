from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from stac_attack_lab.capability.evidence import seal_episode_evidence, write_private_json
from stac_attack_lab.capability.models import RuntimeEvent, RuntimeTask, StateCheckpoint
from stac_attack_lab.execution.deadline import wall_clock_deadline
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.interactions.base import CollectionBudget
from stac_attack_lab.interactions.construction import ConstructionAttackerAction
from stac_attack_lab.interactions.safeclaw_collection import (
    ConstructionVictimDriver,
    SafeClawConstructionTask,
)
from stac_attack_lab.recording.events import append_jsonl


def _workspace_contents(value: Mapping[str, Any] | None) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    raw = value.get("workspace_file_contents")
    if isinstance(raw, dict):
        return {str(key): item for key, item in raw.items() if isinstance(item, str)}
    if isinstance(raw, list):
        result: dict[str, str] = {}
        for item in raw:
            if (
                isinstance(item, dict)
                and isinstance(item.get("path"), str)
                and isinstance(item.get("content"), str)
            ):
                result[item["path"]] = item["content"]
        return result
    return {}


def project_business_state(
    task: RuntimeTask, public_state: Mapping[str, Any] | None, *, session_key: str | None
) -> tuple[dict[str, Any] | None, str]:
    contents = _workspace_contents(public_state)
    text = contents.get("reports/status.json")
    if text is None:
        return None, "capability_status_artifact_unobserved"
    try:
        parsed = json.loads(text)
    except (UnicodeError, json.JSONDecodeError):
        return None, "capability_status_artifact_invalid_json"
    if not isinstance(parsed, dict) or not isinstance(parsed.get("projects"), dict):
        return None, "capability_status_artifact_shape_invalid"
    projects = parsed["projects"]
    if any(
        not isinstance(key, str) or not isinstance(item, dict) for key, item in projects.items()
    ):
        return None, "capability_status_artifact_projects_invalid"
    return (
        {
            "trusted_ledger": task.case.task_contract.trusted_ledger,
            "trusted_ledger_snapshot_sha256": (
                stable_hash(contents["trusted/acceptance-ledger.json"])
                if "trusted/acceptance-ledger.json" in contents
                else None
            ),
            "projects": projects,
            "session": {"label": "s1", "actual_key": session_key},
        },
        "capability_status_artifact_observed",
    )


def _status(raw: str, *, committed: bool = False) -> str:
    if raw == "attempted":
        return "attempted"
    if raw == "passed":
        return "committed" if committed else "observed"
    if raw == "rejected" or raw == "blocked":
        return "blocked"
    if raw == "error":
        return "error"
    return "unknown"


def map_safeclaw_capability_events(
    task: RuntimeTask,
    source_events: list[dict[str, Any]],
    *,
    run_id: str,
    episode_id: str,
    reviewed_message: str,
    session_started: bool = False,
    source_delivered: bool = False,
) -> list[RuntimeEvent]:
    result: list[RuntimeEvent] = []
    raw_to_request: dict[str, str] = {}
    identities_by_session: dict[str, set[str]] = {}
    for source in source_events:
        payload = source.get("public_payload")
        identity = (
            payload.get("actual_session_identity_sha256") if isinstance(payload, dict) else None
        )
        if isinstance(identity, str) and identity and isinstance(source.get("session_id"), str):
            identities_by_session.setdefault(source["session_id"], set()).add(identity)

    def add(
        event_type: str,
        actor: str,
        status: str,
        *,
        raw: dict[str, Any] | None = None,
        **updates: object,
    ) -> RuntimeEvent:
        raw_payload = raw.get("public_payload") if raw else None
        raw_payload = raw_payload if isinstance(raw_payload, dict) else {}
        session_label = raw.get("session_id") if raw else None
        observed_identities = (
            identities_by_session.get(session_label, set())
            if isinstance(session_label, str)
            else set()
        )
        actual_identity = raw_payload.get("actual_session_identity_sha256")
        if not actual_identity and len(observed_identities) == 1:
            actual_identity = next(iter(observed_identities))
        item = RuntimeEvent.model_validate(
            {
                "run_id": run_id,
                "episode_id": episode_id,
                "event_id": f"cap-event-{len(result) + 1:04d}",
                "sequence_no": len(result) + 1,
                "actor": actor,
                "event_type": event_type,
                "session_label": str(raw.get("session_id") or "unknown") if raw else "unknown",
                "actual_session_key": actual_identity,
                "status": status,
                **updates,
            }
        )
        result.append(item)
        return item

    if session_started:
        add("session_started", "environment", "observed")
    if source_delivered:
        add(
            "source_delivered",
            "user",
            "observed",
            resource_id="safeclaw.user_message",
            evidence={
                "public_view_hash": task.public_view.public_view_hash,
                "reviewed_message_sha256": stable_hash(reviewed_message),
            },
        )
    for raw in sorted(source_events, key=lambda item: int(item.get("sequence_no", 0))):
        raw_type = raw.get("event_type")
        payload = raw.get("public_payload")
        payload = payload if isinstance(payload, dict) else {}
        raw_id = str(raw.get("event_id") or "")
        invocation = str(payload.get("provider_tool_call_id") or raw_id)
        if raw_type == "tool_call":
            tool = payload.get("tool_name")
            arguments = payload.get("arguments_projection")
            if not isinstance(tool, str) or not isinstance(arguments, dict):
                continue
            add(
                "tool_selected",
                "victim",
                _status(str(raw.get("status"))),
                raw=raw,
                invocation_id=invocation,
                tool_name=tool,
            )
            request = add(
                "tool_request",
                "victim",
                "attempted"
                if raw.get("status") == "attempted"
                else _status(str(raw.get("status"))),
                raw=raw,
                invocation_id=invocation,
                attempt_id=f"attempt-{invocation}",
                tool_name=tool,
                arguments=arguments,
                evidence={
                    "arguments_complete": payload.get("arguments_redaction_changed") is False,
                    "capability_set_hash": stable_hash(task.case.task_contract.allowed_operations),
                    "raw_source_event_id": raw_id,
                },
            )
            raw_to_request[raw_id] = request.event_id
        elif raw_type == "tool_result":
            request_ref = str(raw.get("request_event_id") or "")
            mapped_request = raw_to_request.get(request_ref)
            if mapped_request is None:
                continue
            outputs = raw.get("output_artifacts")
            output = outputs[0] if isinstance(outputs, list) and outputs else {}
            add(
                "tool_result",
                "tool",
                _status(str(raw.get("status")), committed=False),
                raw=raw,
                invocation_id=invocation,
                attempt_id=f"attempt-{invocation}",
                tool_name=payload.get("tool_name")
                if isinstance(payload.get("tool_name"), str)
                else None,
                resource_id=str(output.get("artifact_id"))
                if isinstance(output, dict) and output.get("artifact_id")
                else None,
                evidence={
                    "request_event_id": mapped_request,
                    "receipt": (raw.get("evidence_ref_ids") or [None])[0],
                    "raw_source_event_id": raw_id,
                    "raw_result_projection_sha256": payload.get("raw_result_projection_sha256"),
                },
            )
        elif raw_type in {"state_write", "state_read"}:
            path = payload.get("workspace_relative_path")
            state_request_ref: str | None = raw_to_request.get(
                str(raw.get("request_event_id") or "")
            )
            post_ref = raw.get("post_state_ref")
            before = None
            after = None
            if isinstance(post_ref, str) and ":" in post_ref:
                after = post_ref.rsplit(":", 1)[-1]
            event_type = "state_write" if raw_type == "state_write" else "state_read"
            evidence: dict[str, Any] = {
                "request_event_id": state_request_ref,
                "receipt": (raw.get("evidence_ref_ids") or [None])[-1],
                "raw_source_event_id": raw_id,
            }
            if event_type == "state_read":
                artifacts = raw.get("output_artifacts")
                artifact = artifacts[0] if isinstance(artifacts, list) and artifacts else {}
                version = artifact.get("content_hash") if isinstance(artifact, dict) else None
                before = str(version) if version else None
                parents = (
                    artifact.get("parent_artifact_ids") if isinstance(artifact, dict) else None
                )
                verified_parent = (
                    isinstance(parents, list)
                    and len(parents) == 1
                    and parents[0] in raw.get("input_artifact_ids", [])
                    and payload.get("version_match") is True
                )
                evidence.update(
                    {
                        "source_resource_version": before if verified_parent else None,
                        "source_kind": "observed_write" if verified_parent else "unknown",
                        "source_artifact_id": parents[0]
                        if verified_parent and isinstance(parents, list)
                        else None,
                        "read_complete": payload.get("read_completeness")
                        in {"complete_content", "synthetic_exact_content"},
                    }
                )
            add(
                event_type,
                "victim",
                _status(str(raw.get("status")), committed=event_type == "state_write"),
                raw=raw,
                invocation_id=None,
                resource_id=f"workspace/{path}" if isinstance(path, str) else None,
                resource_version_before=before,
                resource_version_after=after,
                evidence=evidence,
            )
        elif raw_type == "message" and raw.get("operation") == "extract_victim_response":
            add(
                "response",
                "victim",
                _status(str(raw.get("status"))),
                raw=raw,
                evidence={
                    "text": str(payload.get("response") or ""),
                    "provider_finish_reason": payload.get("provider_finish_reason"),
                    "response_observation": payload.get("observation"),
                    "raw_source_event_id": raw_id,
                },
            )
    return result


class SafeClawCapabilityRuntimeAdapter:
    """Reviewed single-session capability run over the existing SafeClaw driver contract."""

    backend_kind = "safeclaw_production_driver"

    def __init__(
        self,
        driver: ConstructionVictimDriver,
        runtime_task: SafeClawConstructionTask,
        *,
        reviewed_message: str | None = None,
    ):
        self.driver = driver
        self.runtime_task = runtime_task
        self.reviewed_message = reviewed_message

    def run(
        self,
        task: RuntimeTask,
        output_root: Path,
        *,
        run_id: str,
        budget: CollectionBudget,
    ) -> tuple[list[RuntimeEvent], StateCheckpoint, StateCheckpoint]:
        output_root.mkdir(parents=True, exist_ok=False)
        os.chmod(output_root, 0o700)
        episode_id = f"episode-{task.case.case_id}"
        reviewed_message = self.reviewed_message or task.case.task_contract.legitimate_goal
        source_events: list[dict[str, Any]] = []
        provider_records: list[dict[str, Any]] = []
        boundary_records: list[dict[str, Any]] = []
        initial_public: dict[str, Any] | None = None
        final_public: dict[str, Any] | None = None
        failure: str | None = None
        cleanup_error: str | None = None
        started = False
        delivered = False
        try:
            with wall_clock_deadline(float(budget.max_wall_time_seconds)):
                self.driver.start(self.runtime_task, seed=0, budget=budget)
                started = True
                initial_public = self.driver.public_state_snapshot()
                step = self.driver.apply(
                    ConstructionAttackerAction(
                        action_id=f"{task.case.case_id}:reviewed-message",
                        action_type="deliver_message",
                        delivery_surface="safeclaw_user_message",
                        public_message=reviewed_message,
                        rationale_summary="Frozen legitimate task message.",
                    )
                )
                delivered = True
                source_events.extend(step.source_events)
                finished = self.driver.finish()
                source_events.extend(finished.source_events)
                initial_public = finished.initial_public_state or initial_public
                final_public = finished.final_public_state
                provider_records = finished.provider_request_records
                boundary_records = finished.evidence_records
                if finished.embedding_request_records:
                    raise ValueError("capability_embedding_attempt_observed")
                if finished.failure_category or finished.status != "complete":
                    failure = finished.failure_category or f"victim_{finished.status}"
        except Exception as exc:
            failure = f"{type(exc).__name__}:{str(exc)[:500]}"
            partial, _ = self.driver.observed_snapshot()
            source_events.extend(item for item in partial if item not in source_events)
            try:
                self.driver.abort()
            except Exception as cleanup_exc:
                cleanup_error = f"{type(cleanup_exc).__name__}:{str(cleanup_exc)[:500]}"

        ledger_snapshot = getattr(self.driver, "provider_request_records_snapshot", None)
        if callable(ledger_snapshot):
            recovered = ledger_snapshot()
            if len(recovered) > len(provider_records):
                provider_records = recovered
        boundary_snapshot = getattr(self.driver, "boundary_evidence_snapshot", None)
        if callable(boundary_snapshot):
            recovered_boundary = boundary_snapshot()
            if len(recovered_boundary) > len(boundary_records):
                boundary_records = recovered_boundary
        cleanup_status = getattr(self.driver, "last_cleanup_status", "unknown")
        cleanup_error = cleanup_error or getattr(self.driver, "last_cleanup_error", None)
        if cleanup_error:
            failure = failure or "cleanup_failed"

        events = map_safeclaw_capability_events(
            task,
            source_events,
            run_id=run_id,
            episode_id=episode_id,
            reviewed_message=reviewed_message,
            session_started=started,
            source_delivered=delivered,
        )
        identities = {item.actual_session_key for item in events if item.actual_session_key}
        if len(identities) > 1:
            failure = failure or "capability_multiple_actual_sessions_unsupported"
        actual_session = next(iter(identities)) if len(identities) == 1 else None
        initial_state, initial_reason = project_business_state(
            task, initial_public, session_key=actual_session
        )
        final_state, final_reason = project_business_state(
            task, final_public, session_key=actual_session
        )
        initial = StateCheckpoint(
            checkpoint_id="initial",
            stage="initial",
            state=initial_state,
            state_hash=stable_hash(initial_state) if initial_state is not None else None,
            capture_status="observed" if initial_state is not None else "unknown",
            reason_code=initial_reason,
        )
        final = StateCheckpoint(
            checkpoint_id="final",
            stage="final",
            state=final_state,
            state_hash=stable_hash(final_state) if final_state is not None else None,
            capture_status="observed" if final_state is not None else "unknown",
            reason_code=final_reason,
        )
        write_private_json(output_root / "runtime_task.json", task.model_dump(mode="json"))
        event_path = output_root / "runtime_events.jsonl"
        for event in events:
            append_jsonl(event_path, event.model_dump(mode="json"))
        raw_path = output_root / "safeclaw_source_events.jsonl"
        for source_event in source_events:
            append_jsonl(raw_path, source_event)
        write_private_json(
            output_root / "checkpoints/initial.json", initial.model_dump(mode="json")
        )
        write_private_json(output_root / "checkpoints/final.json", final.model_dump(mode="json"))
        ledger_path = output_root / "provider_attempt_ledger.jsonl"
        for record in provider_records:
            append_jsonl(ledger_path, record)
        boundary_path = output_root / "provider_boundary_evidence.jsonl"
        for record in boundary_records:
            append_jsonl(boundary_path, record)
        if not boundary_path.exists():
            boundary_path.touch(mode=0o600)
        if not ledger_path.exists():
            ledger_path.touch(mode=0o600)
        attempts = sum(
            item.get("upstream_attempt_count", 1 if item.get("accepted") is True else 0)
            for item in provider_records
            if isinstance(
                item.get("upstream_attempt_count", 1 if item.get("accepted") is True else 0), int
            )
        )
        write_private_json(
            output_root / "runtime_review.json",
            {
                "status": "failed" if failure else "completed",
                "failure_category": failure,
                "cleanup_error": cleanup_error,
                "cleanup_status": cleanup_status,
                "backend_kind": self.backend_kind,
                "provider_attempts": attempts if provider_records else None,
                "network_requests_performed": attempts > 0 if provider_records else None,
                "embedding_attempts": 0,
                "provider_evidence_record_count": len(boundary_records),
                "provider_evidence_ordered_digest": stable_hash(
                    [item.get("record_sha256") for item in boundary_records]
                ),
            },
        )
        seal_episode_evidence(output_root, episode_id=episode_id)
        return events, initial, final
