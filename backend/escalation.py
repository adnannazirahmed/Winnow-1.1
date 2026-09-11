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
from typing import Dict, List

from iam_model import RiskLevel, EscalationPath, EffectivePermission, PolicyEffect, RelationshipType
from policy_evaluator import PolicyEvaluator


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

def action_matches(allowed_action: str, target_action: str) -> bool:
    return PolicyEvaluator.matches_action(allowed_action, target_action)


def _action_applies(permission: EffectivePermission, target_action: str) -> bool:
    if not action_matches(permission.action, target_action):
        return False
    return not any(action_matches(pattern, target_action) for pattern in permission.excluded_actions)


def _resource_applies(permission: EffectivePermission, target_resource: str = "*") -> bool:
    if target_resource == "*":
        return True
    if not PolicyEvaluator.matches_resource(permission.resource, target_resource):
        return False
    return not any(
        PolicyEvaluator.matches_resource(pattern, target_resource)
        for pattern in permission.excluded_resources
    )


def is_explicitly_denied(
    eff_perms: List[EffectivePermission], target_action: str, target_resource: str = "*"
) -> bool:
    return any(
        permission.effect == PolicyEffect.DENY
        and not permission.conditional
        and _action_applies(permission, target_action)
        and (
            _resource_applies(permission, target_resource)
            if target_resource != "*"
            else permission.resource == "*" and not permission.excluded_resources
        )
        for permission in eff_perms
    )


def matching_permission(
    eff_perms: List[EffectivePermission], target_action: str, target_resource: str = "*"
):
    if is_explicitly_denied(eff_perms, target_action, target_resource):
        return None
    for permission in eff_perms:
        if permission.effect != PolicyEffect.ALLOW:
            continue
        if not _action_applies(permission, target_action):
            continue
        if not _resource_applies(permission, target_resource):
            continue
        if permission.resource.lower().startswith("arn:aws:iam::") and ":role/aws-service-role/" in permission.resource.lower():
            continue
        return permission
    return None


def has_permission(eff_perms: List[EffectivePermission], target_action: str) -> bool:
    return matching_permission(eff_perms, target_action) is not None


def get_risk_score(risk: RiskLevel) -> float:
    return _RISK_SCORE.get(risk, 0.0)


def detect_escalation_paths(graph, effective_permissions_map: Dict[str, List[EffectivePermission]]) -> List[EscalationPath]:
    nodes_map = {n.id: n for n in graph.nodes}

    adj = collections.defaultdict(list)
    for link in graph.links:
        # Group policies are already folded into each user's permission set. Walking
        # into a group here would lose user-level Denies and create false paths.
        if link.relationship == RelationshipType.CAN_ASSUME:
            adj[link.source].append(link.target)

    links_by_pair = {(link.source, link.target): link for link in graph.links}

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
                matched = []
                for alternatives in rule.required:
                    selected = next(
                        ((action, matching_permission(perms, action)) for action in alternatives
                         if matching_permission(perms, action) is not None),
                        None,
                    )
                    if selected is None:
                        matched = []
                        break
                    matched.append(selected)
                if not matched:
                    continue

                # Self-scoped credential actions are still worth review, but they are
                # not cross-identity privilege escalation paths.
                if rule.name in {"CreateUserAccessKey", "CreateLoginProfile", "UpdateLoginProfile"}:
                    if start_node.arn and all(
                        permission.resource == start_node.arn for _, permission in matched
                    ):
                        continue
                seen.add(key)

                rule_score = get_risk_score(rule.risk)
                if rule_score > start_node.risk_score:
                    start_node.risk_score = rule_score
                    start_node.risk_level = rule.risk

                esc_id = f"{start_id}::{rule.name}"
                start_node.escalation_paths.append(esc_id)
                evidence = []
                unknowns = []
                for action, permission in matched:
                    item = permission.model_dump(mode="json")
                    item["matched_action"] = action
                    item["evidence_type"] = "permission"
                    evidence.append(item)
                    if permission.conditional:
                        unknowns.append(f"Conditions on {action} require request context")
                    conditional_denies = [
                        deny for deny in perms
                        if deny.effect == PolicyEffect.DENY and deny.conditional
                        and _action_applies(deny, action)
                    ]
                    if conditional_denies:
                        unknowns.append(f"A conditional Deny may apply to {action}")
                        evidence.extend([
                            dict(deny.model_dump(mode="json"), matched_action=action,
                                 evidence_type="conditional_deny")
                            for deny in conditional_denies
                        ])
                for source, target in zip(path_so_far, path_so_far[1:]):
                    link = links_by_pair.get((source, target))
                    if link:
                        evidence.append({
                            "evidence_type": "relationship",
                            "source": source,
                            "target": target,
                            "relationship": link.relationship.value,
                            "statement": link.evidence,
                        })
                        unknowns.extend(link.unknowns)
                unknowns = list(dict.fromkeys(unknowns))

                paths.append(EscalationPath(
                    id=esc_id,
                    technique=rule.name,
                    risk=rule.risk,
                    path=path_so_far,
                    required_permissions=[action for action, _ in matched],
                    description=rule.description,
                    affected_identity=start_id,
                    decision="candidate" if unknowns else "allowed",
                    matched_permissions=evidence,
                    unknowns=unknowns,
                ))

            for nxt in adj[curr_id]:
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path_so_far + [nxt]))

    return paths
