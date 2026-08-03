from __future__ import annotations

from collections import defaultdict, deque

from stac_attack_lab.contracts import AttackGraph
from stac_attack_lab.errors import ContractError
from stac_attack_lab.registry import primitive_registry


class GraphValidator:
    def __init__(self) -> None:
        self.registry = primitive_registry()

    def validate(self, graph: AttackGraph) -> None:
        nodes = {node.node_id: node for node in graph.nodes}
        if not nodes:
            raise ContractError("graph has no nodes")
        if len(nodes) != len(graph.nodes):
            raise ContractError("duplicate node_id")
        for node in graph.nodes:
            if node.primitive_id not in self.registry:
                raise ContractError(f"unknown primitive {node.primitive_id}")
            if node.budget > graph.max_tool_calls:
                raise ContractError(f"node {node.node_id} budget exceeds graph tool budget")
        facts = {pred.predicate_id for node in graph.nodes for pred in node.postconditions}
        for edge in graph.edges:
            if edge.source_node_id not in nodes or edge.target_node_id not in nodes:
                raise ContractError(f"edge {edge.edge_id} references missing node")
            target_preconditions = {
                p.predicate_id for p in nodes[edge.target_node_id].preconditions
            }
            if edge.target_precondition not in target_preconditions:
                raise ContractError(f"edge {edge.edge_id} target precondition not on target")
            if edge.source_fact not in facts:
                raise ContractError(f"edge {edge.edge_id} source fact unavailable")
        if not graph.allow_bounded_retry_cycles:
            self._check_dag(graph)
        self._check_reachable_terminal(graph)
        if sum(node.budget for node in graph.nodes) > graph.max_tool_calls:
            raise ContractError("sum node budgets exceeds graph max_tool_calls")
        for constraint in graph.safety_constraints:
            if constraint not in {
                "local_canary_only",
                "no_network",
                "no_shell",
                "synthetic_data_only",
            }:
                raise ContractError(f"unknown or unsafe constraint {constraint}")

    def _check_dag(self, graph: AttackGraph) -> None:
        indegree = {node.node_id: 0 for node in graph.nodes}
        outgoing: dict[str, list[str]] = defaultdict(list)
        for edge in graph.edges:
            outgoing[edge.source_node_id].append(edge.target_node_id)
            indegree[edge.target_node_id] += 1
        ready = deque([node_id for node_id, degree in indegree.items() if degree == 0])
        seen = 0
        while ready:
            node_id = ready.popleft()
            seen += 1
            for target in outgoing[node_id]:
                indegree[target] -= 1
                if indegree[target] == 0:
                    ready.append(target)
        if seen != len(graph.nodes):
            raise ContractError("graph contains a cycle")

    def _check_reachable_terminal(self, graph: AttackGraph) -> None:
        if not graph.required_terminal_predicates:
            raise ContractError("missing terminal predicates")
        produced = {pred.predicate_id for node in graph.nodes for pred in node.postconditions}
        missing = [
            p.predicate_id
            for p in graph.required_terminal_predicates
            if p.predicate_id not in produced
        ]
        if missing:
            raise ContractError(f"terminal predicate not reachable: {missing}")
