"""Privilege-escalation detection over the IAM permission graph.

Ported from adnannazirahmed/IAM-Visualizer (backend/src/escalation.py). Changes:

  * Escalation IDs are deterministic (`<identity>::<technique>`) instead of
    `uuid4()` — Winnow guarantees stable finding IDs across processes/workers.
  * Each (identity, technique) pair is emitted at most once (shortest path kept),
    so `escalation_count` and per-node `escalation_paths` stay meaningful.

The two false-positive filters are preserved verbatim:
  * roles only assumable by AWS service principals are skipped as start points
    (via `GraphNode.reachable`, set in graph_builder);
  * Allows scoped only to `arn:aws:iam::*:role/aws-service-role/` don't count
    (AWS blocks direct IAM-API tampering with true service-linked roles).
"""

import collections
import re
from typing import Dict, List

from iam_model import RiskLevel, EscalationPath, EffectivePermission, PolicyEffect, RelationshipType


class EscalationRule:
    def __init__(self, name: str, risk: RiskLevel, description: str, required: List[List[str]]):
        self.name = name
        self.risk = risk
        self.description = description
        self.required = required


RULES = [
    EscalationRule("CreateNewPolicyVersion", RiskLevel.CRITICAL, "Create a new policy version to grant excessive permissions", [["iam:CreatePolicyVersion"]]),
    EscalationRule("SetExistingDefaultPolicyVersion", RiskLevel.CRITICAL, "Set an existing policy version as default", [["iam:SetDefaultPolicyVersion"]]),
    EscalationRule("CreateEC2WithExistingIP", RiskLevel.HIGH, "Pass role to a new EC2 instance", [["iam:PassRole"], ["ec2:RunInstances"]]),
    EscalationRule("CreateUserAccessKey", RiskLevel.HIGH, "Create a new access key for another user", [["iam:CreateAccessKey"]]),
    EscalationRule("CreateLoginProfile", RiskLevel.HIGH, "Create a login profile for console access", [["iam:CreateLoginProfile"]]),
    EscalationRule("UpdateLoginProfile", RiskLevel.HIGH, "Update a login profile to change password", [["iam:UpdateLoginProfile"]]),
    EscalationRule("AttachUserPolicy", RiskLevel.CRITICAL, "Attach a policy to a user", [["iam:AttachUserPolicy"]]),
    EscalationRule("AttachGroupPolicy", RiskLevel.CRITICAL, "Attach a policy to a group", [["iam:AttachGroupPolicy"]]),
    EscalationRule("AttachRolePolicy", RiskLevel.CRITICAL, "Attach a policy to a role", [["iam:AttachRolePolicy"]]),
    EscalationRule("PutUserPolicy", RiskLevel.CRITICAL, "Put an inline policy on a user", [["iam:PutUserPolicy"]]),
    EscalationRule("PutGroupPolicy", RiskLevel.CRITICAL, "Put an inline policy on a group", [["iam:PutGroupPolicy"]]),
    EscalationRule("PutRolePolicy", RiskLevel.CRITICAL, "Put an inline policy on a role", [["iam:PutRolePolicy"]]),
    EscalationRule("AddUserToGroup", RiskLevel.HIGH, "Add a user to a highly privileged group", [["iam:AddUserToGroup"]]),
    EscalationRule("UpdateAssumeRolePolicy", RiskLevel.HIGH, "Update assume role policy to allow assumption", [["iam:UpdateAssumeRolePolicy"]]),
    EscalationRule("PassRoleLambda", RiskLevel.CRITICAL, "Pass role to a new Lambda function and invoke it", [["iam:PassRole"], ["lambda:CreateFunction"], ["lambda:InvokeFunction"]]),
    EscalationRule("PassRoleCloudFormation", RiskLevel.CRITICAL, "Pass role to a CloudFormation stack", [["iam:PassRole"], ["cloudformation:CreateStack"]]),
    EscalationRule("PassRoleDataPipeline", RiskLevel.HIGH, "Pass role to a Data Pipeline", [["iam:PassRole"], ["datapipeline:CreatePipeline"], ["datapipeline:PutPipelineDefinition"]]),
    EscalationRule("PassRoleGlue", RiskLevel.HIGH, "Pass role to a Glue dev endpoint", [["iam:PassRole"], ["glue:CreateDevEndpoint"]]),
    EscalationRule("UpdateExistingGlueDevEndpoint", RiskLevel.MEDIUM, "Update an existing Glue dev endpoint", [["glue:UpdateDevEndpoint"]]),
    EscalationRule("PassRoleSageMaker", RiskLevel.HIGH, "Pass role to a SageMaker notebook", [["iam:PassRole"], ["sagemaker:CreateNotebookInstance"], ["sagemaker:CreatePresignedNotebookInstanceUrl"]]),
    EscalationRule("PassRoleSSM", RiskLevel.HIGH, "Pass role to SSM", [["iam:PassRole"], ["ssm:StartSession", "ssm:SendCommand"]]),
]

_RISK_SCORE = {
    RiskLevel.CRITICAL: 1.0, RiskLevel.HIGH: 0.75, RiskLevel.MEDIUM: 0.5,
    RiskLevel.LOW: 0.25, RiskLevel.NONE: 0.0,
}

SERVICE_LINKED_ROLE_RESOURCE = re.compile(
    r"^arn:aws:iam::[^:]*:role/aws-service-role/", re.IGNORECASE
)


def action_matches(allowed_action: str, target_action: str) -> bool:
    regex = "^" + allowed_action.replace("*", ".*").replace("?", ".") + "$"
    return bool(re.match(regex, target_action, re.IGNORECASE))


def has_permission(eff_perms: List[EffectivePermission], target_action: str) -> bool:
    for p in eff_perms:
        if p.effect == PolicyEffect.DENY and action_matches(p.action, target_action):
            return False
    for p in eff_perms:
        if p.effect == PolicyEffect.ALLOW and action_matches(p.action, target_action):
            if SERVICE_LINKED_ROLE_RESOURCE.match(p.resource):
                continue
            return True
    return False


def get_risk_score(risk: RiskLevel) -> float:
    return _RISK_SCORE.get(risk, 0.0)


def detect_escalation_paths(graph, effective_permissions_map: Dict[str, List[EffectivePermission]]) -> List[EscalationPath]:
    nodes_map = {n.id: n for n in graph.nodes}

    adj = collections.defaultdict(list)
    for link in graph.links:
        if link.relationship in (RelationshipType.CAN_ASSUME, RelationshipType.MEMBER_OF):
            adj[link.source].append(link.target)

    paths: List[EscalationPath] = []
    seen = set()  # (start_id, technique) — emit each once, shortest path wins

    for start_id, start_node in nodes_map.items():
        if start_node.type not in ("user", "role", "group"):
            continue
        if start_node.type == "role" and not start_node.reachable:
            continue

        queue = collections.deque([(start_id, [start_id])])
        visited = {start_id}
        while queue:
            curr_id, path_so_far = queue.popleft()
            perms = effective_permissions_map.get(curr_id, [])

            for rule in RULES:
                key = (start_id, rule.name)
                if key in seen:
                    continue
                if not all(any(has_permission(perms, act) for act in group) for group in rule.required):
                    continue
                seen.add(key)

                rule_score = get_risk_score(rule.risk)
                if rule_score > start_node.risk_score:
                    start_node.risk_score = rule_score
                    start_node.risk_level = rule.risk

                esc_id = f"{start_id}::{rule.name}"
                start_node.escalation_paths.append(esc_id)
                paths.append(EscalationPath(
                    id=esc_id,
                    technique=rule.name,
                    risk=rule.risk,
                    path=path_so_far,
                    required_permissions=[a for grp in rule.required for a in grp],
                    description=rule.description,
                    affected_identity=start_id,
                ))

            for nxt in adj[curr_id]:
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path_so_far + [nxt]))

    return paths
