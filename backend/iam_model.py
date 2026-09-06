"""Pydantic models for AWS IAM entities and the permission-graph output.

Ported from adnannazirahmed/IAM-Visualizer (backend/src/models.py). These are the
shared contract between:

- iam_ingest.py       (produces IAM entity models from GAAD or a pasted config)
- policy_evaluator.py (consumes PolicyStatement models)
- graph_builder.py    (produces GraphNode / GraphLink models)
- escalation.py       (produces EscalationPath models)
- graph_to_findings.py (turns EscalationPath into Winnow Vulnerability dicts)
- visualizer.py       (serializes GraphOutput into the API response)
"""

from __future__ import annotations

import enum
from typing import Optional

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────
#  Enums
# ──────────────────────────────────────────────

class RiskLevel(str, enum.Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RelationshipType(str, enum.Enum):
    CAN_ASSUME = "can_assume"
    HAS_POLICY = "has_policy"
    MEMBER_OF = "member_of"
    CAN_ACCESS = "can_access"


class NodeType(str, enum.Enum):
    USER = "user"
    ROLE = "role"
    GROUP = "group"
    POLICY = "policy"
    RESOURCE = "resource"


class PolicyEffect(str, enum.Enum):
    ALLOW = "Allow"
    DENY = "Deny"


# ──────────────────────────────────────────────
#  IAM Policy Models
# ──────────────────────────────────────────────

class PolicyCondition(BaseModel):
    operator: str  # e.g. "StringEquals", "ArnLike"
    key: str       # e.g. "aws:SourceIp", "iam:PassedToService"
    values: list[str]


class PolicyStatement(BaseModel):
    sid: Optional[str] = None
    effect: PolicyEffect
    actions: list[str] = Field(default_factory=list)
    not_actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    not_resources: list[str] = Field(default_factory=list)
    conditions: list[PolicyCondition] = Field(default_factory=list)
    principals: list[str] = Field(default_factory=list)  # trust policies


class PolicyDocument(BaseModel):
    version: str = "2012-10-17"
    statements: list[PolicyStatement] = Field(default_factory=list)


class ManagedPolicyAttachment(BaseModel):
    policy_name: str
    policy_arn: str


# ──────────────────────────────────────────────
#  IAM Identity Models
# ──────────────────────────────────────────────

class IAMPolicy(BaseModel):
    policy_name: str
    policy_id: str = ""
    arn: str
    path: str = "/"
    default_version_id: str = "v1"
    attachment_count: int = 0
    is_attachable: bool = True
    document: PolicyDocument = Field(default_factory=PolicyDocument)


class IAMUser(BaseModel):
    user_name: str
    user_id: str = ""
    arn: str
    path: str = "/"
    group_list: list[str] = Field(default_factory=list)
    attached_managed_policies: list[ManagedPolicyAttachment] = Field(default_factory=list)
    inline_policies: list[IAMPolicy] = Field(default_factory=list)


class IAMRole(BaseModel):
    role_name: str
    role_id: str = ""
    arn: str
    path: str = "/"
    assume_role_policy_document: PolicyDocument = Field(default_factory=PolicyDocument)
    attached_managed_policies: list[ManagedPolicyAttachment] = Field(default_factory=list)
    inline_policies: list[IAMPolicy] = Field(default_factory=list)
    instance_profile_list: list[str] = Field(default_factory=list)


class IAMGroup(BaseModel):
    group_name: str
    group_id: str = ""
    arn: str
    path: str = "/"
    members: list[str] = Field(default_factory=list)
    attached_managed_policies: list[ManagedPolicyAttachment] = Field(default_factory=list)
    inline_policies: list[IAMPolicy] = Field(default_factory=list)


class IAMData(BaseModel):
    """Complete parsed IAM data — from a live account scan or a pasted config."""
    users: list[IAMUser] = Field(default_factory=list)
    roles: list[IAMRole] = Field(default_factory=list)
    groups: list[IAMGroup] = Field(default_factory=list)
    policies: list[IAMPolicy] = Field(default_factory=list)
    account_id: str = "000000000000"


# ──────────────────────────────────────────────
#  Effective permission (output of policy evaluator)
# ──────────────────────────────────────────────

class EffectivePermission(BaseModel):
    action: str
    resource: str
    effect: PolicyEffect
    source_policy: str = ""
    conditions: list[PolicyCondition] = Field(default_factory=list)


# ──────────────────────────────────────────────
#  Graph output models (contract with the visualizer / frontend)
# ──────────────────────────────────────────────

class GraphNode(BaseModel):
    id: str  # "user::alice", "role::admin-role", "policy::AdminAccess"
    type: NodeType
    name: str
    arn: str = ""
    risk_level: RiskLevel = RiskLevel.NONE
    risk_score: float = 0.0
    policies: list[str] = Field(default_factory=list)
    effective_permissions: list[str] = Field(default_factory=list)
    escalation_paths: list[str] = Field(default_factory=list)
    reachable: bool = True  # role nodes: False if only an AWS service principal can assume


class GraphLink(BaseModel):
    source: str
    target: str
    relationship: RelationshipType
    permissions: list[str] = Field(default_factory=list)
    is_escalation: bool = False
    risk_level: RiskLevel = RiskLevel.NONE
    label: str = ""


class EscalationPath(BaseModel):
    id: str
    technique: str
    risk: RiskLevel
    path: list[str]  # ordered node IDs
    required_permissions: list[str]
    description: str
    affected_identity: str = ""


class GraphMetadata(BaseModel):
    account_id: str = "000000000000"
    generated_at: str = ""
    source: str = "static"  # "static" or "live"
    node_count: int = 0
    link_count: int = 0
    escalation_count: int = 0


class GraphOutput(BaseModel):
    metadata: GraphMetadata = Field(default_factory=GraphMetadata)
    nodes: list[GraphNode] = Field(default_factory=list)
    links: list[GraphLink] = Field(default_factory=list)
    escalation_paths: list[EscalationPath] = Field(default_factory=list)
