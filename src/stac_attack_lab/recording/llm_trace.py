from __future__ import annotations

from pathlib import Path

from stac_attack_lab.hashing import stable_hash
from stac_attack_lab.recording.events import append_jsonl


class LLMTraceRecorder:
    def __init__(self, path: Path) -> None:
        self.path = path

    def record(
        self,
        role: str,
        prompt_id: str,
        prompt_version: str,
        model_id: str,
        params: dict[str, object],
        request: object,
        response: object,
    ) -> None:
        append_jsonl(
            self.path,
            {
                "schema_version": "1.0",
                "role": role,
                "prompt_id": prompt_id,
                "prompt_version": prompt_version,
                "prompt_hash": stable_hash({"prompt_id": prompt_id, "version": prompt_version}),
                "model_id": model_id,
                "params": params,
                "request_hash": stable_hash(request),
                "response_hash": stable_hash(response),
                "tokens": 0,
                "duration_ms": 0,
                "error": None,
            },
        )
