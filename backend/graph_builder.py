"""Build the IAM permission graph (identities / policies as nodes; can_assume /
has_policy / member_of as edges).

Ported from adnannazirahmed/IAM-Visualizer (backend/src/graph_builder.py), imports
adjusted. One change: `_detect_cycles` is skipped on large graphs — `nx.simple_cycles`
is exponential in the worst case and a real account's graph can be big.
"""

import networkx as nx
from typing import Dict, List

from iam_model import (
    IAMData, GraphOutput, GraphNode, GraphLink, NodeType,
    RelationshipType, RiskLevel, GraphMetadata, PolicyEffect, IAMRole,
)
from policy_evaluator import PolicyEvaluator

CYCLE_DETECTION_NODE_LIMIT = 400


class GraphBuilder:
    def __init__(self, iam_data: IAMData):
        self.iam_data = iam_data
        self.graph = nx.DiGraph()
        self.evaluator = PolicyEvaluator()
        self.nodes_dict: Dict[str, GraphNode] = {}
        self.links_list: List[GraphLink] = []
        self.policies_by_arn = {p.arn: p for p in self.iam_data.policies}
        self.policies_by_name = {p.policy_name: p for p in self.iam_data.policies}

    def build(self) -> GraphOutput:
        self._add_users()
        self._add_groups()
        self._add_roles()
        self._add_policies()
        self._build_relationships()
        self._detect_cycles()
        return GraphOutput(
            metadata=GraphMetadata(
                account_id=self.iam_data.account_id,
                node_count=len(self.nodes_dict),
                link_count=len(self.links_list),
            ),
            nodes=list(self.nodes_dict.values()),
            links=self.links_list,
            escalation_paths=[],
        )

    def _add_node(self, node: GraphNode):
        self.nodes_dict[node.id] = node
        self.graph.add_node(node.id, type=node.type.value, name=node.name)

    def _add_link(self, link: GraphLink):
        self.links_list.append(link)
        self.graph.add_edge(link.source, link.target, relationship=link.relationship.value)

    def _add_users(self):
        for user in self.iam_data.users:
            self._add_node(GraphNode(
                id=f"user::{user.user_name}", type=NodeType.USER,
                name=user.user_name, arn=user.arn,
            ))

    def _add_groups(self):
        for group in self.iam_data.groups:
            self._add_node(GraphNode(
                id=f"group::{group.group_name}", type=NodeType.GROUP,
                name=group.group_name, arn=group.arn,
            ))

    def _add_roles(self):
        for role in self.iam_data.roles:
            self._add_node(GraphNode(
                id=f"role::{role.role_name}", type=NodeType.ROLE,
                name=role.role_name, arn=role.arn,
                reachable=self._is_externally_reachable(role),
            ))

    def _is_externally_reachable(self, role: IAMRole) -> bool:
        # False only if every Allow+sts:AssumeRole trust statement trusts exclusively
        # AWS service principals (e.g. "sso.amazonaws.com") — meaning no AWS account,
        # IAM user/role, or federated identity can ever assume this role, so it can
        # never be a real attacker's starting point.
        assume_statements = [
            s for s in role.assume_role_policy_document.statements
            if s.effect == PolicyEffect.ALLOW and "sts:AssumeRole" in s.actions
        ]
        if not assume_statements:
            return True
        for stmt in assume_statements:
            if not stmt.principals:
                return True
            for principal in stmt.principals:
                if not principal.endswith(".amazonaws.com"):
                    return True
        return False

    def _add_policies(self):
        for policy in self.iam_data.policies:
            self._add_node(GraphNode(
                id=f"policy::{policy.policy_name}", type=NodeType.POLICY,
                name=policy.policy_name, arn=policy.arn,
            ))

    def _build_relationships(self):
        for user in self.iam_data.users:
            user_id = f"user::{user.user_name}"
            for group_name in user.group_list:
                group_id = f"group::{group_name}"
                if group_id in self.nodes_dict:
                    self._add_link(GraphLink(source=user_id, target=group_id,
                                             relationship=RelationshipType.MEMBER_OF))
            for inline in user.inline_policies:
                inline_id = f"policy::{inline.policy_name}"
                self._add_node(GraphNode(id=inline_id, type=NodeType.POLICY,
                                         name=inline.policy_name, arn=inline.arn))
                self._add_link(GraphLink(source=user_id, target=inline_id,
                                         relationship=RelationshipType.HAS_POLICY))
            for att in user.attached_managed_policies:
                self._add_link(GraphLink(source=user_id, target=f"policy::{att.policy_name}",
                                         relationship=RelationshipType.HAS_POLICY))

        for group in self.iam_data.groups:
            group_id = f"group::{group.group_name}"
            for inline in group.inline_policies:
                inline_id = f"policy::{inline.policy_name}"
                self._add_node(GraphNode(id=inline_id, type=NodeType.POLICY,
                                         name=inline.policy_name, arn=inline.arn))
                self._add_link(GraphLink(source=group_id, target=inline_id,
                                         relationship=RelationshipType.HAS_POLICY))
            for att in group.attached_managed_policies:
                self._add_link(GraphLink(source=group_id, target=f"policy::{att.policy_name}",
                                         relationship=RelationshipType.HAS_POLICY))

        for role in self.iam_data.roles:
            role_id = f"role::{role.role_name}"
            for inline in role.inline_policies:
                inline_id = f"policy::{inline.policy_name}"
                self._add_node(GraphNode(id=inline_id, type=NodeType.POLICY,
                                         name=inline.policy_name, arn=inline.arn))
                self._add_link(GraphLink(source=role_id, target=inline_id,
                                         relationship=RelationshipType.HAS_POLICY))
            for att in role.attached_managed_policies:
                self._add_link(GraphLink(source=role_id, target=f"policy::{att.policy_name}",
                                         relationship=RelationshipType.HAS_POLICY))

            for stmt in role.assume_role_policy_document.statements:
                if stmt.effect != PolicyEffect.ALLOW or "sts:AssumeRole" not in stmt.actions:
                    continue
                for principal in stmt.principals:
                    if ":user/" in principal:
                        source_id = f"user::{principal.split('/')[-1]}"
                    elif ":role/" in principal:
                        source_id = f"role::{principal.split('/')[-1]}"
                    else:
                        source_id = None
                    if source_id and source_id in self.nodes_dict:
                        self._add_link(GraphLink(source=source_id, target=role_id,
                                                 relationship=RelationshipType.CAN_ASSUME))

    def _detect_cycles(self):
        if self.graph.number_of_nodes() > CYCLE_DETECTION_NODE_LIMIT:
            return
        try:
            for cycle in nx.simple_cycles(self.graph):
                for node_id in cycle:
                    if node_id in self.nodes_dict:
                        self.nodes_dict[node_id].risk_level = RiskLevel.MEDIUM
        except Exception:
            pass
