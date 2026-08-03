from __future__ import annotations

from typing import Protocol

from stac_attack_lab.contracts import AttackGraph, PlannerDecision


class Planner(Protocol):
    planner_type: str

    def decide(
        self,
        graph: AttackGraph,
        passed_node_ids: set[str],
        budget_remaining: int,
        retry_counts: dict[str, int],
    ) -> PlannerDecision: ...


def legal_frontier(graph: AttackGraph, passed_node_ids: set[str]) -> list[str]:
    blocked = {edge.target_node_id: edge.source_node_id for edge in graph.edges}
    frontier: list[str] = []
    for node in graph.nodes:
        if node.node_id in passed_node_ids:
            continue
        parent = blocked.get(node.node_id)
        if parent is None or parent in passed_node_ids:
            frontier.append(node.node_id)
    return frontier
