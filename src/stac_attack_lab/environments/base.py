from __future__ import annotations

from typing import Protocol

from pydantic import Field

from stac_attack_lab.contracts import (
    AttackArtifact,
    Component,
    EventStatus,
    StrictModel,
    TrustBoundary,
)


class ToolCall(StrictModel):
    tool_name: str
    arguments: dict[str, str]


class ToolResult(StrictModel):
    tool_name: str
    component: Component
    trust_boundary: TrustBoundary
    status: EventStatus
    response: dict[str, str | bool | list[str]]
    output_artifacts: list[AttackArtifact] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    error_code: str | None = None


class Environment(Protocol):
    def reset(self, seed: int) -> None: ...

    def snapshot(self) -> dict[str, object]: ...

    def restore(self, snapshot: dict[str, object]) -> None: ...

    def step(self, call: ToolCall, event_id: str, logical_step: int) -> ToolResult: ...

    def public_spec(self) -> dict[str, object]: ...

    def private_oracle(self) -> dict[str, object]: ...
