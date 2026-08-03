from __future__ import annotations

from stac_attack_lab.contracts import StrictModel


class BudgetState(StrictModel):
    turns_remaining: int
    tool_calls_remaining: int
    tokens_remaining: int

    def spend_tool_call(self) -> BudgetState:
        return self.model_copy(
            update={
                "turns_remaining": max(0, self.turns_remaining - 1),
                "tool_calls_remaining": max(0, self.tool_calls_remaining - 1),
            }
        )
