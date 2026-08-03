from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from stac_attack_lab.contracts import ActorRole, AttackEvent
from stac_attack_lab.environments.base import ToolCall, ToolResult
from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.recording.events import append_jsonl, read_jsonl
from stac_attack_lab.recording.snapshots import write_snapshot


class RunRecorder:
    def __init__(self, run_dir: Path, run_id: str, trace_id: str, episode_id: str) -> None:
        self.run_dir = run_dir
        self.run_id = run_id
        self.trace_id = trace_id
        self.episode_id = episode_id
        self.events_path = run_dir / "events.jsonl"
        self.artifacts_dir = run_dir / "artifacts"
        self._seen = {event["event_id"] for event in read_jsonl(self.events_path)}

    def sequence_no(self) -> int:
        return len(read_jsonl(self.events_path))

    def write_manifest(self, manifest: dict[str, Any]) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        path = self.run_dir / "manifest.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)

    def record_tool_event(
        self,
        *,
        event_id: str,
        actor_role: ActorRole,
        stage_id: str | None,
        primitive_id: str | None,
        call: ToolCall,
        result: ToolResult,
        pre_snapshot: dict[str, Any],
        post_snapshot: dict[str, Any],
        input_artifact_ids: list[str],
        parent_event_ids: list[str] | None = None,
    ) -> AttackEvent:
        if event_id in self._seen:
            return AttackEvent.model_validate(
                next(e for e in read_jsonl(self.events_path) if e["event_id"] == event_id)
            )
        started = time.time()
        seq = self.sequence_no()
        pre_ref = write_snapshot(self.run_dir, f"{seq:04d}-pre", pre_snapshot)
        post_ref = write_snapshot(self.run_dir, f"{seq:04d}-post", post_snapshot)
        for artifact in result.output_artifacts:
            path = self.run_dir / artifact.payload_ref
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"artifact_id": artifact.artifact_id, "hash": artifact.content_hash}),
                encoding="utf-8",
            )
        event = AttackEvent(
            schema_version="1.0",
            run_id=self.run_id,
            trace_id=self.trace_id,
            episode_id=self.episode_id,
            event_id=event_id,
            parent_event_ids=parent_event_ids or [],
            sequence_no=seq,
            logical_time=seq,
            actor_role=actor_role,
            component=result.component,
            trust_boundary=result.trust_boundary,
            event_type=call.tool_name,
            stage_id=stage_id,
            primitive_id=primitive_id,
            input_artifact_ids=input_artifact_ids,
            output_artifact_ids=[artifact.artifact_id for artifact in result.output_artifacts],
            request_hash=stable_hash(call.model_dump(mode="json")),
            response_hash=stable_hash(result.model_dump(mode="json")),
            pre_snapshot_ref=pre_ref,
            post_snapshot_ref=post_ref,
            status=result.status,
            error_code=result.error_code,
            duration_ms=int((time.time() - started) * 1000),
            evidence_refs=result.evidence_refs,
        )
        append_jsonl(self.events_path, event.model_dump(mode="json"))
        self._seen.add(event_id)
        return event

    def record_status(self, status: str) -> None:
        path = self.run_dir / "status.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"status": status}, indent=2), encoding="utf-8")
        tmp.replace(path)

    def events(self) -> list[AttackEvent]:
        return [AttackEvent.model_validate(item) for item in read_jsonl(self.events_path)]
