"""Bounded R4 Attacker generation and its handoff to frozen Victim batches.

Generation is an independent A phase.  The default path only prepares a
versioned request view; a loopback fake is the sole executable path in this
repository.  A real endpoint is never probed by this module.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import ValidationError

from stac_attack_lab.attack_program.file_io import write_json_exclusive
from stac_attack_lab.attack_program.models import (
    AttackCandidate,
    R4GenerationPlan,
    R4GenerationSlot,
    R4GenerationSummary,
)
from stac_attack_lab.attack_program.pipeline import (
    GateError,
    build_catalog,
    make_split,
    materialize,
)
from stac_attack_lab.attack_program.r4_batch import endpoint_identity, prepare_disabled
from stac_attack_lab.attack_program.redaction import scan_for_secrets
from stac_attack_lab.hashing import file_hash, stable_hash
from stac_attack_lab.models.base import ModelCallError
from stac_attack_lab.models.openai_compatible import OpenAICompatibleClient, ProviderRequestLedger

MAX_RESPONSE_BYTES = 256 * 1024
SLOT_RE = re.compile(r"slot-[0-9]{3}$")


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateError("r4_generation_record_missing_or_invalid") from exc


def load_plan(path: Path) -> R4GenerationPlan:
    try:
        plan = R4GenerationPlan.model_validate(_read(path), strict=True)
    except ValidationError as exc:
        raise GateError("r4_generation_plan_invalid") from exc
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", plan.plan_id):
        raise GateError("r4_generation_plan_id_invalid")
    return plan


def _loopback(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}


def _public_request(root: Path, plan: R4GenerationPlan, prompt: str) -> dict[str, Any]:
    catalog = build_catalog(root)
    split = make_split(catalog)
    entry = next((item for item in catalog.entries if item.task_id == plan.task_id), None)
    if entry is None:
        raise GateError("r4_generation_task_not_in_catalog")
    if (
        entry.task_group_id != plan.task_group_id
        or split.group_assignments.get(entry.template_group_id) != plan.source_split
    ):
        raise GateError("r4_generation_task_or_split_mismatch")
    allowed_surfaces = [
        {
            "pointer": surface.pointer,
            "value_type": surface.value_type,
            "max_chars": surface.max_chars,
            "stage": surface.stage,
            "owner": surface.owner,
            "trust": surface.trust,
            "resource_path": surface.resource_path,
        }
        for surface in entry.attack_surfaces
    ]
    public_task = {
        "task_id": entry.task_id,
        "task_group_id": entry.task_group_id,
        "normal_user_instructions": entry.public_view.get("normal_user_instructions", []),
        "allowed_materials": entry.public_view.get("allowed_materials", []),
    }
    request = {
        "schema_version": "attack-r4-public-generation-request/1",
        "plan_id": plan.plan_id,
        "task_id": entry.task_id,
        "task_group_id": entry.task_group_id,
        "source_split": plan.source_split,
        "public_goal": plan.public_goal,
        "public_task": public_task,
        "allowed_surfaces": allowed_surfaces,
        "candidate_schema": AttackCandidate.model_json_schema(),
        "limits": {
            "max_patches": 1,
            "max_chars": max(surface.max_chars for surface in entry.attack_surfaces),
        },
        "generation": {
            "slot_count": plan.slot_count,
            "seed": plan.generation_seed,
            "no_retry": True,
            "concurrency": 1,
        },
        "prompt": prompt,
    }
    findings = scan_for_secrets(request)
    if findings:
        raise GateError("r4_generation_public_secret_scan_failed")
    return request


def _write(path: Path, value: Any, *, private: bool = True) -> None:
    write_json_exclusive(path, value, private=private, sort_keys=True, durable=True)


def _prepare_dir(
    root: Path,
    plan_path: Path,
    prompt_path: Path,
    output: Path,
    *,
    override: R4GenerationPlan | None = None,
) -> tuple[R4GenerationPlan, str, dict[str, Any]]:
    plan = override or load_plan(plan_path)
    prompt = prompt_path.read_text(encoding="utf-8")
    if not prompt.strip() or len(prompt.encode("utf-8")) > 64 * 1024:
        raise GateError("r4_generation_prompt_invalid")
    if scan_for_secrets(prompt):
        raise GateError("r4_generation_prompt_secret_scan_failed")
    request = _public_request(root, plan, prompt)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / "slots").mkdir(mode=0o700)
    (output / "candidates").mkdir(mode=0o700)
    _write(output / "plan.json", plan.model_dump(mode="json"))
    (output / "prompt.txt").write_text(prompt, encoding="utf-8")
    os.chmod(output / "prompt.txt", 0o600)
    _write(output / "public_request.json", request)
    return plan, prompt, request


def prepare_generation(
    root: Path,
    plan_path: Path,
    prompt_path: Path,
    output: Path,
    *,
    model_id: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    plan = load_plan(plan_path)
    if model_id is not None or base_url is not None:
        if not model_id or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", model_id) or not base_url:
            raise GateError("r4_generation_model_identity_invalid")
        plan = plan.model_copy(
            update={
                "attacker_model_id": model_id,
                "attacker_endpoint_identity": endpoint_identity(base_url),
            }
        )
    plan, prompt, request = _prepare_dir(root, plan_path, prompt_path, output, override=plan)
    summary = R4GenerationSummary(
        plan_id=plan.plan_id,
        task_id=plan.task_id,
        source_split=plan.source_split,
        assigned_slots=plan.slot_count,
        attacker_http_attempts=0,
        valid_candidates=0,
        invalid_candidates=0,
        duplicate_candidates=0,
        not_started=plan.slot_count,
        slots=[
            R4GenerationSlot(slot_id=f"slot-{i:03d}", status="not_started", request_attempted=False)
            for i in range(1, plan.slot_count + 1)
        ],
        candidate_files=[],
        status="prepared_disabled",
        plan_hash=stable_hash(plan.model_dump(mode="json")),
        prompt_hash=stable_hash(prompt),
        public_request_hash=stable_hash(request),
    )
    _write(output / "summary.json", summary.model_dump(mode="json"))
    return summary.model_dump(mode="json")


def _response_text(client: OpenAICompatibleClient) -> str:
    raw = client.last_raw_response
    if not isinstance(raw, str):
        raise GateError("r4_generation_response_missing")
    if len(raw.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise GateError("r4_generation_response_too_large")
    if scan_for_secrets(raw):
        raise GateError("r4_generation_response_secret_scan_failed")
    return raw


def generation_authorization_preview(
    root: Path, plan_path: Path, prompt_path: Path
) -> dict[str, Any]:
    plan = load_plan(plan_path)
    prompt = prompt_path.read_text(encoding="utf-8")
    if not plan.attacker_model_id or not plan.attacker_endpoint_identity:
        raise GateError("r4_generation_real_identity_missing")
    if endpoint_identity(plan.attacker_endpoint_identity) != plan.attacker_endpoint_identity:
        raise GateError("r4_generation_real_endpoint_invalid")
    request = _public_request(root, plan, prompt)
    source = root / "src/stac_attack_lab"
    sources = {
        name: file_hash(source / name)
        for name in (
            "attack_program/r4_generation.py",
            "attack_program/models.py",
            "attack_program/pipeline.py",
            "attack_program/r4_batch.py",
            "models/openai_compatible.py",
        )
    }
    return {
        "status": "preview_only_not_authorization",
        "authorization_record": {
            "schema_version": "attack-r4-generation-authorization/1",
            "plan_hash": stable_hash(plan.model_dump(mode="json")),
            "prompt_hash": stable_hash(prompt),
            "public_request_hash": stable_hash(request),
            "source_file_hashes": sources,
            "model_id": plan.attacker_model_id,
            "endpoint_identity": plan.attacker_endpoint_identity,
            "max_attacker_http_attempts": 3,
            "scope": "real_development_generation",
        },
    }


def generation_status(output: Path) -> dict[str, Any]:
    if not output.exists():
        return {"status": "not_prepared", "attacker_http_attempts": 0}
    summary_path = output / "summary.json"
    ledger_path = output / "attacker_http.jsonl"
    starts = []
    if ledger_path.exists():
        starts = [
            json.loads(line)
            for line in ledger_path.read_text(encoding="utf-8").splitlines()
            if json.loads(line).get("stage") == "attempt_started"
        ]
    if (output / "generation_terminal.json").exists():
        summary = R4GenerationSummary.model_validate(_read(summary_path), strict=True)
        return {
            "status": summary.status,
            "assigned_slots": summary.assigned_slots,
            "attacker_http_attempts": len(starts),
            "valid_candidates": summary.valid_candidates,
            "invalid_candidates": summary.invalid_candidates,
            "duplicate_candidates": summary.duplicate_candidates,
            "not_started": summary.not_started,
            "next": "inspect sealed artifacts; no relaunch",
        }
    return {
        "status": "prepared_disabled" if summary_path.exists() else "interrupted_or_uncertain",
        "attacker_http_attempts": len(starts),
        "next": "reconcile ledger and output; no relaunch or resend",
    }


def run_generation(
    root: Path,
    plan_path: Path,
    prompt_path: Path,
    output: Path,
    *,
    model_id: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    local_fake: bool = False,
    authorization: Path | None = None,
    authorization_sha256: str | None = None,
    acknowledge_real_authorization: bool = False,
) -> dict[str, Any]:
    """Run one request per slot after a distinct A-phase approval for real HTTP."""
    if output.exists():
        raise GateError("r4_generation_launch_already_reserved_status_reconcile_required")
    plan_for_gate = load_plan(plan_path)
    if not local_fake:
        if (
            authorization is None
            or authorization_sha256 is None
            or not acknowledge_real_authorization
        ):
            raise GateError("r4_generation_real_not_authorized")
        if model_id is not None or base_url is not None:
            raise GateError("r4_generation_real_identity_override_forbidden")
        if not plan_for_gate.attacker_model_id or not plan_for_gate.attacker_endpoint_identity:
            raise GateError("r4_generation_real_identity_missing")
        if (
            endpoint_identity(plan_for_gate.attacker_endpoint_identity)
            != plan_for_gate.attacker_endpoint_identity
        ):
            raise GateError("r4_generation_real_endpoint_invalid")
        approved = _read(authorization)
        expected = generation_authorization_preview(root, plan_path, prompt_path)[
            "authorization_record"
        ]
        if approved != expected or authorization_sha256 != file_hash(authorization):
            raise GateError("r4_generation_authorization_mismatch")
        if not os.environ.get(plan_for_gate.attacker_api_key_env):
            raise GateError("r4_generation_api_key_missing")
        api_key = os.environ[plan_for_gate.attacker_api_key_env]
    if local_fake and (not model_id or not base_url or not _loopback(base_url)):
        raise GateError("r4_generation_local_fake_endpoint_required")
    plan, prompt, public_request = _prepare_dir(root, plan_path, prompt_path, output)
    selected_model = model_id or plan.attacker_model_id
    selected_url = base_url or plan.attacker_endpoint_identity
    if selected_model is None or selected_url is None:
        raise GateError("r4_generation_model_identity_missing")
    if not api_key:
        raise GateError("r4_generation_api_key_missing")
    previous_url = os.environ.get(plan.attacker_endpoint_env)
    previous_key = os.environ.get(plan.attacker_api_key_env)
    os.environ[plan.attacker_endpoint_env] = selected_url
    os.environ[plan.attacker_api_key_env] = api_key
    slots: list[R4GenerationSlot] = []
    candidate_files: list[str] = []
    seen_hashes: set[str] = set()
    ledger = ProviderRequestLedger(
        max_requests=plan.max_attacker_http_attempts,
        path=output / "attacker_http.jsonl",
        batch_id=plan.plan_id,
    )
    started = time.monotonic()
    status: Literal["completed", "interrupted"] = "interrupted"
    try:
        client = OpenAICompatibleClient(
            model_id=selected_model,
            max_output_tokens=plan.max_output_tokens,
            base_url_env=plan.attacker_endpoint_env,
            api_key_env=plan.attacker_api_key_env,
            request_ledger=ledger,
            http_502_retries=plan.http_502_retries,
            max_response_bytes=MAX_RESPONSE_BYTES,
        )
        for index in range(1, plan.slot_count + 1):
            slot_id = f"slot-{index:03d}"
            if time.monotonic() - started > plan.wall_clock_seconds:
                slots.append(
                    R4GenerationSlot(
                        slot_id=slot_id,
                        status="not_started",
                        request_attempted=False,
                        reason_code="wall_clock_exhausted",
                    )
                )
                continue
            before_requests = len(ledger.records)
            sequence = before_requests + 1
            try:
                response = client.generate(
                    [
                        {
                            "role": "user",
                            "content": json.dumps(
                                {**public_request, "slot_id": slot_id}, ensure_ascii=False
                            ),
                        }
                    ],
                    AttackCandidate,
                    seed=plan.generation_seed,
                    timeout=plan.request_timeout_seconds,
                )
                raw = _response_text(client)
                (output / "slots" / f"{slot_id}.response.txt").write_text(raw, encoding="utf-8")
                os.chmod(output / "slots" / f"{slot_id}.response.txt", 0o600)
                response_hash = stable_hash(raw)
                candidate = AttackCandidate.model_validate(response, strict=True)
                if (
                    candidate.task_id != plan.task_id
                    or candidate.task_group_id != plan.task_group_id
                    or candidate.source_split != plan.source_split
                ):
                    raise GateError("r4_generation_candidate_identity_mismatch")
                catalog = build_catalog(root)
                task = materialize(root, catalog, make_split(catalog), candidate)
                candidate_hash = stable_hash(candidate.model_dump(mode="json"))
                payload_hash = stable_hash(
                    {
                        "task_id": candidate.task_id,
                        "patches": [p.model_dump(mode="json") for p in candidate.patches],
                    }
                )
                if payload_hash in seen_hashes:
                    slots.append(
                        R4GenerationSlot(
                            slot_id=slot_id,
                            status="duplicate",
                            request_attempted=True,
                            request_sequence=sequence,
                            model_candidate_id=candidate.candidate_id,
                            candidate_hash=candidate_hash,
                            reason_code="duplicate_candidate_payload",
                            response_hash=response_hash,
                            response_bytes=len(raw.encode()),
                            usage=client.last_usage,
                            usage_observation="returned"
                            if client.last_usage is not None
                            else "unknown",
                        )
                    )
                    continue
                seen_hashes.add(payload_hash)
                candidate_path = output / "candidates" / f"{slot_id}.json"
                _write(
                    candidate_path,
                    {
                        "candidate": candidate.model_dump(mode="json"),
                        "candidate_hash": candidate_hash,
                        "materialized_task_hash": stable_hash(task),
                        "slot_id": slot_id,
                        "plan_hash": stable_hash(plan.model_dump(mode="json")),
                    },
                )
                candidate_files.append(str(candidate_path.relative_to(output)))
                slots.append(
                    R4GenerationSlot(
                        slot_id=slot_id,
                        status="valid",
                        request_attempted=True,
                        request_sequence=sequence,
                        model_candidate_id=candidate.candidate_id,
                        candidate_hash=candidate_hash,
                        materialized_task_hash=stable_hash(task),
                        response_hash=response_hash,
                        response_bytes=len(raw.encode()),
                        usage=client.last_usage,
                        usage_observation="returned"
                        if client.last_usage is not None
                        else "unknown",
                    )
                )
            except (
                ValidationError,
                GateError,
                ModelCallError,
                ValueError,
                KeyError,
                TypeError,
            ) as exc:
                attempted = len(ledger.records) > before_requests
                slots.append(
                    R4GenerationSlot(
                        slot_id=slot_id,
                        status="invalid" if attempted else "error",
                        request_attempted=attempted,
                        request_sequence=sequence if attempted else None,
                        reason_code=str(exc),
                        usage=client.last_usage,
                        usage_observation="returned"
                        if client.last_usage is not None
                        else "unknown",
                    )
                )
        status = "completed"
    finally:
        ledger.close()
        if previous_url is None:
            os.environ.pop(plan.attacker_endpoint_env, None)
        else:
            os.environ[plan.attacker_endpoint_env] = previous_url
        if previous_key is None:
            os.environ.pop(plan.attacker_api_key_env, None)
        else:
            os.environ[plan.attacker_api_key_env] = previous_key
    return _finish_summary(plan, prompt, public_request, output, slots, candidate_files, status)


def prepare_generation_result(
    plan: R4GenerationPlan,
    prompt: str,
    request: dict[str, Any],
    output: Path,
    status: Literal["completed", "interrupted", "rejected"],
) -> dict[str, Any]:
    slots = [
        R4GenerationSlot(slot_id=f"slot-{i:03d}", status="not_started", request_attempted=False)
        for i in range(1, plan.slot_count + 1)
    ]
    return _finish_summary(plan, prompt, request, output, slots, [], status)


def _finish_summary(
    plan: R4GenerationPlan,
    prompt: str,
    request: dict[str, Any],
    output: Path,
    slots: list[R4GenerationSlot],
    candidate_files: list[str],
    status: Literal["completed", "interrupted", "rejected"],
) -> dict[str, Any]:
    summary = R4GenerationSummary(
        plan_id=plan.plan_id,
        task_id=plan.task_id,
        source_split=plan.source_split,
        assigned_slots=plan.slot_count,
        attacker_http_attempts=sum(item.request_attempted for item in slots),
        valid_candidates=sum(item.status == "valid" for item in slots),
        invalid_candidates=sum(item.status in {"invalid", "error"} for item in slots),
        duplicate_candidates=sum(item.status == "duplicate" for item in slots),
        not_started=sum(item.status == "not_started" for item in slots),
        slots=slots,
        candidate_files=candidate_files,
        status=status,
        plan_hash=stable_hash(plan.model_dump(mode="json")),
        prompt_hash=stable_hash(prompt),
        public_request_hash=stable_hash(request),
    )
    _write(output / "summary.json", summary.model_dump(mode="json"))
    _write(
        output / "generation_terminal.json",
        {
            "status": status,
            "attacker_http_attempts": summary.attacker_http_attempts,
            "terminal_hash": stable_hash(summary.model_dump(mode="json")),
            "artifact_file_hashes": {
                name: file_hash(output / name)
                for name in ["plan.json", "prompt.txt", "public_request.json", *candidate_files]
            },
        },
    )
    return summary.model_dump(mode="json")


def prepare_victim_candidates(
    root: Path, generation_dir: Path, output: Path, *, local_fake_mode: str | None = None
) -> dict[str, Any]:
    summary = R4GenerationSummary.model_validate(
        _read(generation_dir / "summary.json"), strict=True
    )
    if summary.status != "completed":
        raise GateError("r4_generation_not_completed")
    terminal = _read(generation_dir / "generation_terminal.json")
    expected_candidate_files = [
        f"candidates/{slot.slot_id}.json" for slot in summary.slots if slot.status == "valid"
    ]
    if summary.candidate_files != expected_candidate_files:
        raise GateError("r4_generation_candidate_index_invalid")
    expected_files = ["plan.json", "prompt.txt", "public_request.json", *expected_candidate_files]
    if terminal.get("artifact_file_hashes") != {
        name: file_hash(generation_dir / name) for name in expected_files
    }:
        raise GateError("r4_generation_artifact_tampered")
    if (
        stable_hash(_read(generation_dir / "plan.json")) != summary.plan_hash
        or stable_hash(_read(generation_dir / "public_request.json")) != summary.public_request_hash
        or stable_hash((generation_dir / "prompt.txt").read_text(encoding="utf-8"))
        != summary.prompt_hash
        or terminal.get("terminal_hash") != stable_hash(summary.model_dump(mode="json"))
    ):
        raise GateError("r4_generation_artifact_tampered")
    if summary.assigned_slots != 3 or summary.attacker_http_attempts > 3 or len(summary.slots) != 3:
        raise GateError("r4_generation_denominator_invalid")
    if summary.valid_candidates != len(summary.candidate_files) or summary.valid_candidates != sum(
        s.status == "valid" for s in summary.slots
    ):
        raise GateError("r4_generation_candidate_index_invalid")
    if len(set(summary.candidate_files)) != len(summary.candidate_files):
        raise GateError("r4_generation_candidate_index_invalid")
    ledger_rows = [
        json.loads(line)
        for line in (generation_dir / "attacker_http.jsonl").read_text().splitlines()
    ]
    starts = [row for row in ledger_rows if row.get("stage") == "attempt_started"]
    if len(starts) != summary.attacker_http_attempts or [
        row.get("sequence") for row in starts
    ] != list(range(1, len(starts) + 1)):
        raise GateError("r4_generation_ledger_mismatch")
    validated: list[tuple[R4GenerationSlot, AttackCandidate]] = []
    catalog = build_catalog(root)
    split = make_split(catalog)
    plan = load_plan(generation_dir / "plan.json")
    if plan.task_id != summary.task_id or plan.source_split != summary.source_split:
        raise GateError("r4_generation_plan_identity_mismatch")
    for slot in summary.slots:
        if slot.status != "valid":
            continue
        artifact = _read(generation_dir / "candidates" / f"{slot.slot_id}.json")
        candidate = AttackCandidate.model_validate(artifact["candidate"], strict=True)
        task = materialize(root, catalog, split, candidate)
        if (
            stable_hash(candidate.model_dump(mode="json")) != slot.candidate_hash
            or artifact.get("candidate_hash") != slot.candidate_hash
            or artifact.get("materialized_task_hash") != slot.materialized_task_hash
            or stable_hash(task) != slot.materialized_task_hash
            or artifact.get("plan_hash") != summary.plan_hash
            or artifact.get("slot_id") != slot.slot_id
            or candidate.task_id != summary.task_id
            or candidate.task_group_id != plan.task_group_id
            or candidate.source_split != summary.source_split
        ):
            raise GateError("r4_generation_candidate_artifact_mismatch")
        validated.append((slot, candidate))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    records: list[dict[str, Any]] = []
    for slot, candidate in validated:
        try:
            candidate_file = output / f"{slot.slot_id}-candidate.json"
            _write(candidate_file, candidate.model_dump(mode="json"))
            batch = output / slot.slot_id
            manifest = prepare_disabled(root, candidate_file, batch, local_fake=local_fake_mode)
            records.append(
                {
                    "slot_id": slot.slot_id,
                    "status": "prepared_disabled",
                    "batch": str(batch),
                    "manifest_hash": manifest["manifest_hash"],
                    "candidate_hash": slot.candidate_hash,
                }
            )
        except (GateError, ValidationError, OSError, ValueError) as exc:
            records.append({"slot_id": slot.slot_id, "status": "rejected", "reason_code": str(exc)})
    result = {
        "schema_version": "attack-r4-victim-preparation/1",
        "source_generation": str(generation_dir),
        "assigned_generation_slots": summary.assigned_slots,
        "attacker_http_attempts": summary.attacker_http_attempts,
        "invalid_candidates": summary.invalid_candidates,
        "duplicate_candidates": summary.duplicate_candidates,
        "valid_candidates": summary.valid_candidates,
        "victim_planned": summary.valid_candidates,
        "prepared": sum(r["status"] == "prepared_disabled" for r in records),
        # Preparation is not execution.  Keep lifecycle counts explicit so a
        # prepared batch with no binding/activation is reported as not started.
        "planned": summary.valid_candidates,
        "started": sum(r["status"] in {"started", "completed"} for r in records),
        "completed": sum(r["status"] == "completed" for r in records),
        "not_started": summary.valid_candidates
        - sum(r["status"] in {"started", "completed"} for r in records),
        "victim_not_started": summary.valid_candidates
        - sum(r["status"] in {"started", "completed"} for r in records),
        "unselected_generation_slots": summary.assigned_slots - summary.valid_candidates,
        "records": records,
    }
    _write(output / "summary.json", result)
    return result
