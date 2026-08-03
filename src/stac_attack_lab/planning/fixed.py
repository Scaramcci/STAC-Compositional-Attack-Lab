from __future__ import annotations

from stac_attack_lab.contracts import AttackGraph, PlannerDecision
from stac_attack_lab.planning.base import legal_frontier


class FixedPlanner:
    planner_type = "fixed"

    def decide(
        self,
        graph: AttackGraph,
        passed_node_ids: set[str],
        budget_remaining: int,
        retry_counts: dict[str, int],
    ) -> PlannerDecision:
        frontier = legal_frontier(graph, passed_node_ids)
        if not frontier:
            return PlannerDecision(
                decision_id="fixed-stop-success",
                action="stop_success",
                selected_node_id=None,
                selected_primitive_id=None,
                satisfied_preconditions=[],
                unsatisfied_preconditions=[],
                public_evidence_event_ids=[],
                budget_after_action=budget_remaining,
                rationale_summary="All legal nodes are complete.",
                confidence=1.0,
            )
        if budget_remaining <= 0:
            return PlannerDecision(
                decision_id="fixed-stop-failure",
                action="stop_failure",
                selected_node_id=None,
                selected_primitive_id=None,
                satisfied_preconditions=[],
                unsatisfied_preconditions=frontier,
                public_evidence_event_ids=[],
                budget_after_action=0,
                rationale_summary="Budget is exhausted.",
                confidence=1.0,
            )
        node = next(item for item in graph.nodes if item.node_id == frontier[0])
        return PlannerDecision(
            decision_id=f"fixed-{node.node_id}",
            action="execute_node",
            selected_node_id=node.node_id,
            selected_primitive_id=node.primitive_id,
            satisfied_preconditions=[p.predicate_id for p in node.preconditions],
            unsatisfied_preconditions=[],
            public_evidence_event_ids=[],
            budget_after_action=max(0, budget_remaining - 1),
            rationale_summary="Execute the next verified chain node.",
            confidence=1.0,
        )
