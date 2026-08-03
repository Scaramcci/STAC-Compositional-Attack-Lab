from __future__ import annotations

import json
from typing import TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def parse_json_output(text: str, model: type[T]) -> T:
    return model.model_validate(json.loads(text))
