"""Orchestrate IAMData -> permission graph -> escalation paths.

Ported from adnannazirahmed/IAM-Visualizer (backend/src/pipeline.py:process_iam_data),
imports adjusted.
"""

from typing import Dict, List, Tuple

from iam_model import IAMData, GraphOutput, EffectivePermission, PolicyStatement
from graph_builder import GraphBuilder, inline_policy_node_id, managed_policy_node_id
from policy_evaluator import PolicyEvaluator
from escalation import detect_escalation_paths, is_explicitly_denied


def process_iam_data(iam_data: IAMData) -> GraphOutput:
    builder = GraphBuilder(iam_data)
    graph_output = builder.build()

    evaluator = PolicyEvaluator()
    effective_permissions_map: Dict[str, List[EffectivePermission]] = {}
    identity_statements_map: Dict[str, List[Tuple[str, PolicyStatement]]] = {}

    policy_statements: Dict[str, List[Tuple[str, PolicyStatement]]] = {}
    for policy in iam_data.policies:
        node_id = managed_policy_node_id(policy.policy_name)
        policy_statements[node_id] = [(node_id, stmt) for stmt in policy.document.statements]
    for owner_type, entity_list in (
        ("user", iam_data.users), ("role", iam_data.roles), ("group", iam_data.groups),
    ):
        for entity in entity_list:
            owner_name = getattr(entity, f"{owner_type}_name")
            for policy in entity.inline_policies:
                node_id = inline_policy_node_id(owner_type, owner_name, policy.policy_name)
                policy_statements[node_id] = [(node_id, stmt) for stmt in policy.document.statements]

    def get_policy_statements(policy_node_id: str) -> List[Tuple[str, PolicyStatement]]:
        if policy_node_id in policy_statements:
            return policy_statements[policy_node_id]
        # Compatibility for old serialized graphs and direct tests.
        for p in iam_data.policies:
            if managed_policy_node_id(p.policy_name) == policy_node_id:
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
        identity_statements_map[node_id] = statements
        effective_permissions_map[node_id] = perms
        node.effective_permissions = [
            f"{p.effect.value}: {p.action} on {p.resource}"
            + (" (conditional)" if p.conditional else "") for p in perms
        ]

    # Direct same-account role trust can authorize assumption without a separate
    # Allow, but an applicable explicit Deny on the caller still wins.
    filtered_links = []
    nodes = {node.id: node for node in graph_output.nodes}
    for link in graph_output.links:
        if link.relationship.value == "can_assume":
            target_arn = nodes.get(link.target).arn if nodes.get(link.target) else "*"
            denied_by_effective = is_explicitly_denied(
                effective_permissions_map.get(link.source, []), "sts:AssumeRole", target_arn
            )
            denied_by_statement = any(
                statement.effect.value == "Deny"
                and not statement.conditions
                and (
                    any(evaluator.matches_action(action, "sts:AssumeRole") for action in statement.actions)
                    or (
                        statement.not_actions
                        and not any(evaluator.matches_action(action, "sts:AssumeRole")
                                    for action in statement.not_actions)
                    )
                )
                and (
                    any(evaluator.matches_resource(resource, target_arn)
                        for resource in statement.resources)
                    or (
                        statement.not_resources
                        and not any(evaluator.matches_resource(resource, target_arn)
                                    for resource in statement.not_resources)
                    )
                )
                for _, statement in identity_statements_map.get(link.source, [])
            )
            if denied_by_effective or denied_by_statement:
                continue
        filtered_links.append(link)
    graph_output.links = filtered_links
    graph_output.metadata.link_count = len(filtered_links)

    escalation_paths = detect_escalation_paths(graph_output, effective_permissions_map)
    graph_output.escalation_paths = escalation_paths
    graph_output.metadata.escalation_count = len(escalation_paths)
    return graph_output
