"""Orchestrate IAMData -> permission graph -> escalation paths.

Ported from adnannazirahmed/IAM-Visualizer (backend/src/pipeline.py:process_iam_data),
imports adjusted.
"""

from typing import Dict, List, Tuple

from iam_model import IAMData, GraphOutput, EffectivePermission, PolicyStatement
from graph_builder import GraphBuilder
from policy_evaluator import PolicyEvaluator
from escalation import detect_escalation_paths


def process_iam_data(iam_data: IAMData) -> GraphOutput:
    builder = GraphBuilder(iam_data)
    graph_output = builder.build()

    evaluator = PolicyEvaluator()
    effective_permissions_map: Dict[str, List[EffectivePermission]] = {}

    def get_policy_statements(policy_node_id: str) -> List[Tuple[str, PolicyStatement]]:
        for p in iam_data.policies:
            if f"policy::{p.policy_name}" == policy_node_id:
                return [(p.policy_name, stmt) for stmt in p.document.statements]
        for entity_list in (iam_data.users, iam_data.roles, iam_data.groups):
            for entity in entity_list:
                for p in entity.inline_policies:
                    if f"policy::{p.policy_name}" == policy_node_id:
                        return [(p.policy_name, stmt) for stmt in p.document.statements]
        return []

    for node_id, node in builder.nodes_dict.items():
        if node.type.value not in ("user", "role", "group"):
            continue
        statements: List[Tuple[str, PolicyStatement]] = []
        for link in builder.links_list:
            if link.source == node_id and link.relationship.value == "has_policy":
                statements.extend(get_policy_statements(link.target))
        if node.type.value == "user":
            for link in builder.links_list:
                if link.source == node_id and link.relationship.value == "member_of":
                    for glink in builder.links_list:
                        if glink.source == link.target and glink.relationship.value == "has_policy":
                            statements.extend(get_policy_statements(glink.target))

        perms = evaluator.effective_permissions(node.arn, statements)
        effective_permissions_map[node_id] = perms
        node.effective_permissions = [
            f"{p.effect.value}: {p.action} on {p.resource}" for p in perms
        ]

    escalation_paths = detect_escalation_paths(graph_output, effective_permissions_map)
    graph_output.escalation_paths = escalation_paths
    graph_output.metadata.escalation_count = len(escalation_paths)
    return graph_output
