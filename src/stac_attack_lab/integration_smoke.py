from __future__ import annotations

import ast
import json
import os
from pathlib import Path
from typing import cast

from stac_attack_lab.contracts import PromptWriterOutput
from stac_attack_lab.env_loader import load_project_env
from stac_attack_lab.models.base import ModelCallError, ModelClient
from stac_attack_lab.models.gemini import GeminiClient
from stac_attack_lab.models.huihui import HuihuiLocalClient
from stac_attack_lab.models.openai_compatible import OpenAICompatibleClient


def first_openai_model() -> str:
    mixed_case_key = "OPENAI_MODEL" + "_list"
    raw = (
        os.environ.get("OPENAI_MODEL_LIST")
        or os.environ.get(mixed_case_key)
        or os.environ.get("OPENAI_MODEL")
        or ""
    )
    if not raw:
        return "gpt-4o-mini"
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list) and parsed:
            return str(parsed[0])
    except json.JSONDecodeError:
        pass
    try:
        parsed_literal = ast.literal_eval(raw)
        if isinstance(parsed_literal, list) and parsed_literal:
            return str(parsed_literal[0])
    except (SyntaxError, ValueError):
        pass
    return raw.split(",")[0].strip()


def smoke_models(project_root: Path) -> dict[str, object]:
    loaded = load_project_env(project_root)
    prompt = [{"role": "user", "content": "Create a safe synthetic prompt-writer smoke output."}]
    results: dict[str, object] = {"loaded_env_keys": sorted(loaded), "providers": {}}
    providers: dict[str, object] = {}
    results["providers"] = providers
    gemini = GeminiClient()
    clients: list[tuple[str, ModelClient, str]] = [("gemini", gemini, gemini.model_id)]
    if os.environ.get("STAC_SMOKE_OPENAI_COMPATIBLE") == "1":
        clients.append(
            (
                "openai_compatible",
                OpenAICompatibleClient(first_openai_model()),
                first_openai_model(),
            )
        )
    else:
        providers["openai_compatible"] = {
            "ok": False,
            "skipped": "set STAC_SMOKE_OPENAI_COMPATIBLE=1",
        }
    if os.environ.get("STAC_SMOKE_HUIHUI") == "1":
        model = os.environ.get("HUIHUI_MODEL") or "huihui"
        clients.append(("huihui_local", HuihuiLocalClient(model), model))
    else:
        providers["huihui_local"] = {"ok": False, "skipped": "set STAC_SMOKE_HUIHUI=1"}
    for name, client, model_id in clients:
        try:
            output = cast(
                PromptWriterOutput,
                client.generate(prompt, PromptWriterOutput, seed=1, timeout=30),
            )
            providers[name] = {
                "ok": True,
                "model": model_id,
                "output_schema": output.__class__.__name__,
                "status": output.status,
            }
        except ModelCallError as exc:
            providers[name] = {"ok": False, "model": model_id, "error": str(exc)}
    return results
