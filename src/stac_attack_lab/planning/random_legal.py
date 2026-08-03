from __future__ import annotations

import random

from stac_attack_lab.contracts import AttackGraph, PlannerDecision
from stac_attack_lab.planning.base import legal_frontier
from stac_attack_lab.planning.fixed import FixedPlanner


class RandomLegalPlanner(FixedPlanner):
    planner_type = "random_legal"

    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)

    def decide(
        self,
        graph: AttackGraph,
        passed_node_ids: set[str],
        budget_remaining: int,
        retry_counts: dict[str, int],
    ) -> PlannerDecision:
        frontier = legal_frontier(graph, passed_node_ids)
        if len(frontier) <= 1:
            return super().decide(graph, passed_node_ids, budget_remaining, retry_counts)
        chosen = self.rng.choice(frontier)
        node = next(item for item in graph.nodes if item.node_id == chosen)
        decision = super().decide(
            graph, passed_node_ids | (set(frontier) - {chosen}), budget_remaining, retry_counts
        )
        return decision.model_copy(
            update={"selected_node_id": node.node_id, "selected_primitive_id": node.primitive_id}
        )
