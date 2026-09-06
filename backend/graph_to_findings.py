"""Bridge: permission-graph escalation paths -> Winnow Vulnerability dicts.

The graph engine (iam_graph.process_iam_data) emits `EscalationPath` objects.
Winnow's remediator, AI detector, and visualizer all consume `Vulnerability`
dicts keyed by a stable `pattern_id`. This module maps the 21 escalation
techniques onto that shape (reusing existing Winnow `pattern_id`s where they
exist) and tags each finding `detection_source='graph'`.
"""

from typing import Dict, List

from iam_model import GraphOutput, RiskLevel

_SEVERITY = {
    RiskLevel.CRITICAL: "CRITICAL",
    RiskLevel.HIGH: "HIGH",
    RiskLevel.MEDIUM: "MEDIUM",
    RiskLevel.LOW: "LOW",
    RiskLevel.NONE: "LOW",
}

_RESOURCE_TYPE = {
    "user": "aws_iam_user",
    "role": "aws_iam_role",
    "group": "aws_iam_group",
    "policy": "aws_iam_policy",
}

# technique name -> {pattern_id, title, mitre, hint}
# pattern_id reuses Winnow's existing PRIVILEGE_ESCALATION_PATTERNS keys where one
# fits; a handful are new (registered in remediator.PATTERN_STRATEGY).
TECHNIQUE_MAP: Dict[str, Dict] = {
    "CreateNewPolicyVersion": {
        "pattern_id": "iam:CreatePolicyVersion", "title": "Rewrite an Attached Managed Policy",
        "mitre": ["T1098.001"], "hint": "Restrict iam:CreatePolicyVersion to non-privileged policy ARNs"},
    "SetExistingDefaultPolicyVersion": {
        "pattern_id": "iam:SetDefaultPolicyVersion", "title": "Activate a Privileged Policy Version",
        "mitre": ["T1098.001"], "hint": "Restrict iam:SetDefaultPolicyVersion to specific policy ARNs"},
    "CreateEC2WithExistingIP": {
        "pattern_id": "iam:PassRole", "title": "Pass Role to a New EC2 Instance",
        "mitre": ["T1098.003", "T1611"], "hint": "Restrict iam:PassRole with iam:PassedToService = ec2.amazonaws.com and specific role ARNs"},
    "CreateUserAccessKey": {
        "pattern_id": "iam:CreateAccessKey", "title": "Create Access Keys for Another User",
        "mitre": ["T1098.004"], "hint": "Restrict iam:CreateAccessKey to arn:aws:iam::<acct>:user/${aws:username}"},
    "CreateLoginProfile": {
        "pattern_id": "iam:CreateLoginProfile", "title": "Create a Console Login Profile",
        "mitre": ["T1098.005"], "hint": "Restrict iam:CreateLoginProfile to self"},
    "UpdateLoginProfile": {
        "pattern_id": "iam:UpdateLoginProfile", "title": "Reset Another User's Console Password",
        "mitre": ["T1098.005"], "hint": "Restrict iam:UpdateLoginProfile to self"},
    "AttachUserPolicy": {
        "pattern_id": "iam:AttachUserPolicy", "title": "Attach Admin Policy to a User",
        "mitre": ["T1098.001"], "hint": "Remove iam:AttachUserPolicy or restrict to approved policy ARNs"},
    "AttachGroupPolicy": {
        "pattern_id": "iam:AttachGroupPolicy", "title": "Attach Admin Policy to a Group",
        "mitre": ["T1098.001"], "hint": "Remove iam:AttachGroupPolicy or restrict to approved policy ARNs"},
    "AttachRolePolicy": {
        "pattern_id": "iam:AttachRolePolicy", "title": "Attach Admin Policy to a Role",
        "mitre": ["T1098.003"], "hint": "Remove iam:AttachRolePolicy or restrict to approved policy ARNs"},
    "PutUserPolicy": {
        "pattern_id": "iam:PutUserPolicy", "title": "Put an Inline Policy on a User",
        "mitre": ["T1098.001"], "hint": "Remove iam:PutUserPolicy; use reviewed managed policies"},
    "PutGroupPolicy": {
        "pattern_id": "iam:PutGroupPolicy", "title": "Put an Inline Policy on a Group",
        "mitre": ["T1098.001"], "hint": "Remove iam:PutGroupPolicy; use reviewed managed policies"},
    "PutRolePolicy": {
        "pattern_id": "iam:PutRolePolicy", "title": "Put an Inline Policy on a Role",
        "mitre": ["T1098.003"], "hint": "Remove iam:PutRolePolicy; use reviewed managed policies"},
    "AddUserToGroup": {
        "pattern_id": "iam:AddUserToGroup", "title": "Add Self to a Privileged Group",
        "mitre": ["T1098.001"], "hint": "Restrict iam:AddUserToGroup to specific low-privilege groups"},
    "UpdateAssumeRolePolicy": {
        "pattern_id": "iam:UpdateAssumeRolePolicy", "title": "Rewrite a Role Trust Policy",
        "mitre": ["T1550.001"], "hint": "Restrict iam:UpdateAssumeRolePolicy with a permissions boundary"},
    "PassRoleLambda": {
        "pattern_id": "iam:PassRole", "title": "Pass Role to a New Lambda Function",
        "mitre": ["T1098.003", "T1611"], "hint": "Restrict iam:PassRole with iam:PassedToService = lambda.amazonaws.com and specific role ARNs"},
    "PassRoleCloudFormation": {
        "pattern_id": "iam:PassRole", "title": "Pass Role to a CloudFormation Stack",
        "mitre": ["T1098.003", "T1611"], "hint": "Restrict iam:PassRole with iam:PassedToService = cloudformation.amazonaws.com"},
    "PassRoleDataPipeline": {
        "pattern_id": "iam:PassRole", "title": "Pass Role to a Data Pipeline",
        "mitre": ["T1611"], "hint": "Restrict iam:PassRole with iam:PassedToService = datapipeline.amazonaws.com"},
    "PassRoleGlue": {
        "pattern_id": "iam:PassRole", "title": "Pass Role to a Glue Dev Endpoint",
        "mitre": ["T1611"], "hint": "Restrict iam:PassRole with iam:PassedToService = glue.amazonaws.com"},
    "UpdateExistingGlueDevEndpoint": {
        "pattern_id": "glue:UpdateDevEndpoint", "title": "Hijack an Existing Glue Dev Endpoint",
        "mitre": ["T1611"], "hint": "Restrict glue:UpdateDevEndpoint to specific endpoints"},
    "PassRoleSageMaker": {
        "pattern_id": "iam:PassRole", "title": "Pass Role to a SageMaker Notebook",
        "mitre": ["T1611"], "hint": "Restrict iam:PassRole with iam:PassedToService = sagemaker.amazonaws.com"},
    "PassRoleSSM": {
        "pattern_id": "iam:PassRole", "title": "Pass Role to an SSM Session/Command",
        "mitre": ["T1611"], "hint": "Restrict iam:PassRole and ssm:StartSession/SendCommand to specific targets"},
}

_FALLBACK = {"pattern_id": "escalation_path", "title": "Privilege Escalation Path",
             "mitre": ["T1098.001"], "hint": "Restrict the actions in the escalation chain"}


def _split_node(node_id: str):
    kind, _, name = node_id.partition("::")
    return kind, (name or node_id)


def _render_path(path: List[str]) -> List[str]:
    steps: List[str] = []
    for i, node_id in enumerate(path):
        kind, name = _split_node(node_id)
        label = f"{kind.capitalize()}: {name}"
        steps.append(label if i == 0 else f"assumes {label}" if kind == "role" else f"member of {label}")
    return steps


def graph_to_findings(graph_output: GraphOutput) -> List[Dict]:
    findings: List[Dict] = []
    for esc in graph_output.escalation_paths:
        meta = TECHNIQUE_MAP.get(esc.technique, _FALLBACK)
        kind, ident_name = _split_node(esc.affected_identity)
        perms = list(esc.required_permissions)
        attack_path = _render_path(esc.path) + [
            f"Technique: {esc.technique}",
            f"Requires: {', '.join(perms)}",
        ]
        findings.append({
            "id": "",
            "pattern_id": meta["pattern_id"],
            "title": meta["title"],
            "description": f"{esc.description}. Reachable from {kind} {ident_name}"
                           + (f" via {len(esc.path) - 1} assume/membership hop(s)" if len(esc.path) > 1 else "")
                           + f". Required permissions: {', '.join(perms)}.",
            "severity": _SEVERITY.get(esc.risk, "MEDIUM"),
            "resource_type": _RESOURCE_TYPE.get(kind, "aws_iam_role"),
            "resource_name": ident_name,
            "policy_document": {
                "action": perms[0] if perms else "",
                "statement": {"Effect": "Allow", "Action": perms, "Resource": "*"},
                "escalation": True,
                "technique": esc.technique,
                "required_permissions": perms,
            },
            "attack_path": attack_path,
            "mitre_techniques": list(meta["mitre"]),
            "remediation_hint": meta["hint"],
            "detection_source": "graph",
        })
    return findings
