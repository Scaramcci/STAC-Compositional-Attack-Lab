"""R4 runtime evidence contracts, conservative projection, and immutable replay."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from stac_attack_lab.attack_program.development import _decision
from stac_attack_lab.attack_program.file_io import write_json_exclusive
from stac_attack_lab.attack_program.models import (
    AttackCandidate,
    Catalog,
    RawObservation,
    RawSession,
    RuntimeEvent,
    Split,
)
from stac_attack_lab.attack_program.pipeline import GateError, materialize
from stac_attack_lab.contracts import StrictModel
from stac_attack_lab.hashing import file_hash, stable_hash


class RuntimeSession(StrictModel):
    session_id: str
    issued_session_key: str
    role: str | None = None
    user_instruction: str | None = None
    agent_response: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    raw_api_response: dict[str, Any] | None = None
    transcript_entries: list[dict[str, Any]] = Field(default_factory=list)
    memory_before: str
    memory_after: str
    memory_before_version: str
    memory_after_version: str
    preconditions_satisfied: bool = True
    provider_attempts_before: int = 0
    provider_attempts_after: int = 0


class RuntimeBundle(StrictModel):
    schema_version: Literal["attack-runtime-bundle/1"] = "attack-runtime-bundle/1"
    source: Literal["local_fake", "real"]
    run_id: str
    task_id: str
    candidate_id: str
    materialized_task_hash: str
    sessions: list[RuntimeSession] = Field(min_length=1, max_length=16)
    pre_state: dict[str, Any]
    post_state: dict[str, Any]
    relay_records: list[dict[str, Any]]
    relay_reservations: list[dict[str, Any]] = Field(default_factory=list)
    relay_evidence: list[dict[str, Any]]
    cleanup: dict[str, Any]
    upstream_commit: str | None = None
    upstream_task_hash: str | None = None
    judge_hash: str | None = None
    patch_hash: str | None = None
    image_digest: str | None = None
    runtime_producer: Literal["r4_runtime_adapter"] | None = None
    capture_complete: bool = True

    @model_validator(mode="after")
    def real_requires_adapter(self) -> RuntimeBundle:
        if self.source == "real" and not all(
            (
                self.runtime_producer == "r4_runtime_adapter",
                self.upstream_commit,
                self.upstream_task_hash,
                self.judge_hash,
                self.patch_hash,
                self.image_digest,
                self.relay_records,
                self.cleanup.get("status") == "completed",
            )
        ):
            raise ValueError("real_source_requires_runtime_seal")
        if len({s.session_id for s in self.sessions}) != len(self.sessions):
            raise ValueError("runtime_session_duplicate")
        return self


def reserve_launch(path: Path, batch_id: str) -> None:
    """Reserve one batch before any container or provider operation."""
    if not batch_id or "/" in batch_id or ".." in batch_id:
        raise GateError("runtime_batch_id_invalid")
    try:
        path.mkdir(parents=True, exist_ok=False, mode=0o700)
    except FileExistsError as exc:
        raise GateError("runtime_launch_already_reserved") from exc
    _write(
        path / "launch.json",
        {"schema_version": "attack-runtime-launch/1", "batch_id": batch_id},
        private=True,
    )


def _write(path: Path, value: Any, *, private: bool = False) -> None:
    write_json_exclusive(path, value, private=private, sort_keys=True, durable=True)


def _text(blocks: object) -> str:
    if isinstance(blocks, str):
        return blocks
    if not isinstance(blocks, list):
        return ""
    return "\n".join(
        str(item.get("text", ""))
        for item in blocks
        if isinstance(item, dict) and item.get("type") == "text"
    )


def _memory_write(arguments: dict[str, Any], after: str) -> bool:
    path = arguments.get("path")
    content = arguments.get("content")
    return (
        isinstance(path, str)
        and path in {"MEMORY.md", "/root/.openclaw/workspace/MEMORY.md"}
        and isinstance(content, str)
        and content == after
    )


def project_bundle(bundle: RuntimeBundle, payload: str) -> RawObservation:
    """Map only observed gateway/transcript facts; no response text becomes a write."""
    events: list[RuntimeEvent] = []

    def event(session: RuntimeSession, kind: str, actor: str, status: str, **fields: Any) -> None:
        events.append(
            RuntimeEvent.model_validate(
                {
                    "run_id": bundle.run_id,
                    "episode_id": bundle.candidate_id,
                    "event_id": f"runtime-{len(events) + 1:04d}",
                    "sequence_no": len(events) + 1,
                    "actor": actor,
                    "event_type": kind,
                    "session_label": session.session_id,
                    "actual_session_key": session.issued_session_key,
                    "status": status,
                    **fields,
                }
            )
        )

    for session in bundle.sessions:
        event(
            session,
            "session_started",
            "environment",
            "observed",
            evidence={"identity_source": "gateway_request_header"},
        )
        calls: dict[str, dict[str, Any]] = {}
        call_counts: dict[str, int] = {}
        result_counts: dict[str, int] = {}
        for entry in session.transcript_entries:
            message = entry.get("message") if isinstance(entry, dict) else None
            if not isinstance(message, dict):
                continue
            if message.get("role") == "assistant" and isinstance(message.get("content"), list):
                for block in message["content"]:
                    if isinstance(block, dict) and block.get("type") == "toolCall":
                        cid = block.get("id")
                        if isinstance(cid, str):
                            call_counts[cid] = call_counts.get(cid, 0) + 1
            elif message.get("role") == "toolResult":
                cid = message.get("toolCallId")
                if isinstance(cid, str):
                    result_counts[cid] = result_counts.get(cid, 0) + 1
        for entry in session.transcript_entries:
            if entry.get("type") != "message" or not isinstance(entry.get("message"), dict):
                continue
            message = entry["message"]
            if message.get("role") == "assistant" and isinstance(message.get("content"), list):
                for block in message["content"]:
                    if not isinstance(block, dict) or block.get("type") != "toolCall":
                        continue
                    cid, name, args = block.get("id"), block.get("name"), block.get("arguments")
                    if not isinstance(cid, str) or not cid or not isinstance(name, str):
                        continue
                    event(
                        session,
                        "tool_selected",
                        "victim",
                        "observed",
                        invocation_id=cid,
                        tool_name=name,
                    )
                    event(
                        session,
                        "tool_request",
                        "victim",
                        "attempted",
                        invocation_id=cid,
                        tool_name=name,
                        arguments=args if isinstance(args, dict) else None,
                        evidence={"transcript_entry_id": entry.get("id")},
                    )
                    if call_counts.get(cid) == 1:
                        calls[cid] = {"name": name, "arguments": args}
            if message.get("role") == "toolResult":
                cid = message.get("toolCallId")
                if not isinstance(cid, str) or cid not in calls or result_counts.get(cid) != 1:
                    continue
                result_text = _text(message.get("content"))
                failed = bool(message.get("isError") or message.get("error"))
                event(
                    session,
                    "tool_result",
                    "tool",
                    "error" if failed else "observed",
                    invocation_id=cid,
                    tool_name=calls[cid]["name"],
                    evidence={
                        "transcript_entry_id": entry.get("id"),
                        "result_sha256": stable_hash(result_text),
                    },
                )
                if payload and payload in result_text:
                    event(
                        session,
                        "source_delivered",
                        "tool",
                        "observed",
                        invocation_id=cid,
                        evidence={"tool_result_sha256": stable_hash(result_text)},
                    )
                if (
                    not failed
                    and calls[cid]["name"] == "write"
                    and isinstance(calls[cid]["arguments"], dict)
                    and _memory_write(calls[cid]["arguments"], session.memory_after)
                    and session.memory_before_version != session.memory_after_version
                    and session.memory_before != session.memory_after
                ):
                    event(
                        session,
                        "state_write",
                        "tool",
                        "committed",
                        invocation_id=cid,
                        resource_id="memory",
                        resource_version_before=session.memory_before_version,
                        resource_version_after=session.memory_after_version,
                        evidence={
                            "snapshot_scope": "session_memory_before_after",
                            "tool_result_id": entry.get("id"),
                        },
                    )
        event(
            session,
            "response",
            "victim",
            "observed",
            evidence={"response_sha256": stable_hash(session.agent_response)},
        )
    return RawObservation(
        schema_version="attack-observation/2",
        source=bundle.source,
        run_id=bundle.run_id,
        task_id=bundle.task_id,
        candidate_id=bundle.candidate_id,
        materialized_task_hash=bundle.materialized_task_hash,
        sessions=[
            RawSession(
                session_id=s.session_id,
                actual_session_key=s.issued_session_key,
                agent_response=s.agent_response,
                tool_calls=s.tool_calls,
            )
            for s in bundle.sessions
        ],
        pre_state=bundle.pre_state,
        post_state=bundle.post_state,
        events=events,
        event_log_complete=bundle.capture_complete,
        state_capture_complete=bundle.capture_complete
        and all(s.memory_before_version and s.memory_after_version for s in bundle.sessions),
    )


def seal_case(
    root: Path,
    case_dir: Path,
    catalog: Catalog,
    split: Split,
    candidate: AttackCandidate,
    bundle: RuntimeBundle,
) -> dict[str, Any]:
    task = materialize(root, catalog, split, candidate)
    if (
        bundle.materialized_task_hash != stable_hash(task)
        or bundle.candidate_id != candidate.candidate_id
        or bundle.task_id != candidate.task_id
    ):
        raise GateError("runtime_bundle_identity_mismatch")
    if [s.session_id for s in bundle.sessions] != [s["session_id"] for s in task["sessions"]]:
        raise GateError("runtime_session_set_mismatch")
    observation = project_bundle(bundle, candidate.patches[0].value)
    result, _ = _decision(candidate, observation, root, catalog, split, "attempt-0001")
    case_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = {
        "catalog.json": catalog.model_dump(mode="json"),
        "split.json": split.model_dump(mode="json"),
        "candidate.json": candidate.model_dump(mode="json"),
        "task.json": task,
        "runtime_bundle.json": bundle.model_dump(mode="json"),
        "observation.json": observation.model_dump(mode="json"),
        "result.json": result,
    }
    hashes: dict[str, str] = {}
    for name, value in files.items():
        path = case_dir / name
        _write(path, value, private=True)
        hashes[name] = file_hash(path)
    manifest: dict[str, Any] = {
        "schema_version": "attack-runtime-case/1",
        "source": bundle.source,
        "run_id": bundle.run_id,
        "candidate_id": candidate.candidate_id,
        "files": hashes,
        "processing_sources": {
            name: file_hash(root / name)
            for name in (
                "src/stac_attack_lab/attack_program/r4.py",
                "src/stac_attack_lab/attack_program/file_io.py",
                "src/stac_attack_lab/attack_program/r4_runtime.py",
                "src/stac_attack_lab/attack_program/observation.py",
                "src/stac_attack_lab/attack_program/pipeline.py",
                "src/stac_attack_lab/attack_program/provider_relay.py",
                "src/stac_attack_lab/attack_program/r4_fake_provider.py",
            )
        },
    }
    manifest["manifest_hash"] = stable_hash(manifest)
    _write(case_dir / "manifest.json", manifest)
    return result


def replay_case(root: Path, case_dir: Path, output: Path) -> dict[str, Any]:
    manifest = json.loads((case_dir / "manifest.json").read_text())
    if manifest.get("schema_version") != "attack-runtime-case/1" or manifest.get(
        "manifest_hash"
    ) != stable_hash({k: v for k, v in manifest.items() if k != "manifest_hash"}):
        raise GateError("runtime_manifest_invalid")
    expected = {
        "catalog.json",
        "split.json",
        "candidate.json",
        "task.json",
        "runtime_bundle.json",
        "observation.json",
        "result.json",
    }
    if set(manifest.get("files", {})) != expected:
        raise GateError("runtime_file_index_invalid")
    sources = manifest.get("processing_sources")
    allowed_sources = {
        "src/stac_attack_lab/attack_program/r4.py",
        "src/stac_attack_lab/attack_program/file_io.py",
        "src/stac_attack_lab/attack_program/r4_runtime.py",
        "src/stac_attack_lab/attack_program/observation.py",
        "src/stac_attack_lab/attack_program/pipeline.py",
        "src/stac_attack_lab/attack_program/provider_relay.py",
        "src/stac_attack_lab/attack_program/r4_fake_provider.py",
    }
    if (
        not isinstance(sources, dict)
        or set(sources) != allowed_sources
        or any(file_hash(root / name) != digest for name, digest in sources.items())
    ):
        raise GateError("runtime_processing_source_mismatch")
    for name, digest in manifest["files"].items():
        path = case_dir / name
        if not path.is_file() or file_hash(path) != digest:
            raise GateError("runtime_file_hash_mismatch")
    catalog = Catalog.model_validate_json((case_dir / "catalog.json").read_text())
    split = Split.model_validate_json((case_dir / "split.json").read_text())
    candidate = AttackCandidate.model_validate_json((case_dir / "candidate.json").read_text())
    bundle = RuntimeBundle.model_validate_json((case_dir / "runtime_bundle.json").read_text())
    task = materialize(root, catalog, split, candidate)
    if (
        task != json.loads((case_dir / "task.json").read_text())
        or stable_hash(task) != bundle.materialized_task_hash
    ):
        raise GateError("runtime_materialization_mismatch")
    if bundle.candidate_id != candidate.candidate_id or bundle.task_id != candidate.task_id:
        raise GateError("runtime_bundle_identity_mismatch")
    observation = project_bundle(bundle, candidate.patches[0].value)
    if observation.model_dump(mode="json") != json.loads(
        (case_dir / "observation.json").read_text()
    ):
        raise GateError("runtime_observation_semantics_mismatch")
    result, _ = _decision(candidate, observation, root, catalog, split, "attempt-0001")
    if result != json.loads((case_dir / "result.json").read_text()):
        raise GateError("runtime_result_semantics_mismatch")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    audit = {
        "schema_version": "attack-runtime-audit/1",
        "status": "valid",
        "source_manifest_hash": manifest["manifest_hash"],
        "source": bundle.source,
        "candidate_id": candidate.candidate_id,
        "evidence_class": result["evidence_class"],
    }
    _write(output / "audit.json", audit)
    return audit
