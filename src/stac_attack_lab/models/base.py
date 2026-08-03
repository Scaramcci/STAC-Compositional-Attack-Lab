from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel


class ModelClient(Protocol):
    def generate(
        self,
        messages: list[dict[str, str]],
        response_schema: type[BaseModel],
        seed: int,
        timeout: int,
    ) -> BaseModel: ...


class ModelCallError(Exception):
    pass
