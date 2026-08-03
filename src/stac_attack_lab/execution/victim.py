from __future__ import annotations

from pathlib import Path

from stac_attack_lab.contracts import AttackNode
from stac_attack_lab.environments.base import ToolCall
from stac_attack_lab.hashing import file_hash


def victim_prompt_hash(project_root: Path) -> str:
    return file_hash(project_root / "prompts/runtime/victim_system.md")


class VictimRunner:
    def tool_call_for_node(
        self,
        node: AttackNode,
        *,
        entry_artifact_id: str | None,
        source_memory_id: str | None,
        canary_id: str,
    ) -> ToolCall:
        if node.primitive_id == "tool_response_injection":
            return ToolCall(
                tool_name="retrieval_tool.search", arguments={"query": node.template_vars["query"]}
            )
        if node.primitive_id == "memory_write":
            return ToolCall(
                tool_name="memory_store.write",
                arguments={
                    "content": node.template_vars["canary_preference"],
                    "source_artifact_id": entry_artifact_id or "",
                },
            )
        if node.primitive_id == "memory_retrieval":
            return ToolCall(
                tool_name="memory_retriever.query", arguments={"query": node.template_vars["query"]}
            )
        if node.primitive_id == "canary_tool_trigger":
            return ToolCall(
                tool_name="action_tool.emit_canary",
                arguments={"canary_id": canary_id, "source_memory_id": source_memory_id or ""},
            )
        return ToolCall(tool_name="unknown", arguments={})
