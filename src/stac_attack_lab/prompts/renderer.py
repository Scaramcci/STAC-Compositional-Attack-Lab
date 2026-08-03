from __future__ import annotations

import re

from stac_attack_lab.prompts.loader import PromptAsset


def render(asset: PromptAsset, variables: dict[str, str]) -> str:
    text = asset.body
    for match in re.findall(r"{{\\s*([a-zA-Z0-9_]+)\\s*}}", text):
        if match not in variables:
            raise ValueError(f"missing template variable {match}")
    for key, value in variables.items():
        text = re.sub(r"{{\\s*" + re.escape(key) + r"\\s*}}", value, text)
    return text
