"""Turn raw IAM input into a normalized `IAMData`.

Two sources feed the same downstream pipeline:

  * `parse_gaad()`        — a live `iam:GetAccountAuthorizationDetails` response
                            (the AWS-native shape). Ported from
                            adnannazirahmed/IAM-Visualizer (backend/src/iam_parser.py).
  * `config_to_iamdata()` — a pasted config: a Terraform plan / iam-vulnerable
                            export (`{"resources": [...]}`) or a raw policy
                            document (`{"Policy": {...}}` or a bare
                            `{"Version": ..., "Statement": [...]}`).
"""

import json
import logging
from urllib.parse import unquote
from typing import Any, Dict, List, Optional

from iam_model import (
    IAMData, IAMUser, IAMRole, IAMGroup, IAMPolicy,
    PolicyDocument, PolicyStatement, PolicyEffect, PolicyCondition,
    ManagedPolicyAttachment,
)

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  GAAD parser (AWS-native shape)
# ──────────────────────────────────────────────

class IAMParser:
    def parse(self, raw_data: Dict[str, Any]) -> IAMData:
        """Parse a merged get_account_authorization_details response into IAMData."""
        iam_data = IAMData(account_id="000000000000")

        for pol_data in raw_data.get("Policies", []):
            try:
                policy = self._parse_managed_policy(pol_data)
                if policy:
                    iam_data.policies.append(policy)
            except Exception as e:
                logger.warning("Failed to parse policy %s: %s",
                               pol_data.get("PolicyName", "unknown"), e)

        for user_data in raw_data.get("UserDetailList", []):
            try:
                user = self._parse_user(user_data)
                if user:
                    iam_data.users.append(user)
            except Exception as e:
                logger.warning("Failed to parse user %s: %s",
                               user_data.get("UserName", "unknown"), e)

        for role_data in raw_data.get("RoleDetailList", []):
            try:
                role = self._parse_role(role_data)
                if role:
                    iam_data.roles.append(role)
            except Exception as e:
                logger.warning("Failed to parse role %s: %s",
                               role_data.get("RoleName", "unknown"), e)

        for group_data in raw_data.get("GroupDetailList", []):
            try:
                group = self._parse_group(group_data)
                if group:
                    iam_data.groups.append(group)
            except Exception as e:
                logger.warning("Failed to parse group %s: %s",
                               group_data.get("GroupName", "unknown"), e)

        return iam_data

    def _parse_managed_policy(self, data: Dict[str, Any]) -> Optional[IAMPolicy]:
        policy_name = data.get("PolicyName")
        if not policy_name:
            return None
        policy = IAMPolicy(
            policy_name=policy_name,
            policy_id=data.get("PolicyId", ""),
            arn=data.get("Arn", ""),
            path=data.get("Path", "/"),
            default_version_id=data.get("DefaultVersionId", "v1"),
            attachment_count=data.get("AttachmentCount", 0),
            is_attachable=data.get("IsAttachable", True),
        )
        for version in data.get("PolicyVersionList", []):
            if version.get("IsDefaultVersion"):
                doc_raw = version.get("Document")
                if doc_raw:
                    policy.document = self.parse_policy_document(doc_raw)
                break
        return policy

    def _parse_user(self, data: Dict[str, Any]) -> Optional[IAMUser]:
        user_name = data.get("UserName")
        if not user_name:
            return None
        return IAMUser(
            user_name=user_name,
            user_id=data.get("UserId", ""),
            arn=data.get("Arn", ""),
            path=data.get("Path", "/"),
            group_list=data.get("GroupList", []),
            attached_managed_policies=self._parse_attached_policies(data.get("AttachedManagedPolicies", [])),
            inline_policies=self._parse_inline_policies(data.get("UserPolicyList", [])),
        )

    def _parse_role(self, data: Dict[str, Any]) -> Optional[IAMRole]:
        role_name = data.get("RoleName")
        if not role_name:
            return None
        role = IAMRole(
            role_name=role_name,
            role_id=data.get("RoleId", ""),
            arn=data.get("Arn", ""),
            path=data.get("Path", "/"),
            attached_managed_policies=self._parse_attached_policies(data.get("AttachedManagedPolicies", [])),
            inline_policies=self._parse_inline_policies(data.get("RolePolicyList", [])),
            instance_profile_list=[
                ip.get("InstanceProfileName", "") for ip in data.get("InstanceProfileList", [])
            ],
        )
        assume_doc = data.get("AssumeRolePolicyDocument")
        if assume_doc:
            role.assume_role_policy_document = self.parse_policy_document(assume_doc)
        return role

    def _parse_group(self, data: Dict[str, Any]) -> Optional[IAMGroup]:
        group_name = data.get("GroupName")
        if not group_name:
            return None
        return IAMGroup(
            group_name=group_name,
            group_id=data.get("GroupId", ""),
            arn=data.get("Arn", ""),
            path=data.get("Path", "/"),
            attached_managed_policies=self._parse_attached_policies(data.get("AttachedManagedPolicies", [])),
            inline_policies=self._parse_inline_policies(data.get("GroupPolicyList", [])),
        )

    def _parse_attached_policies(self, data: List[Dict[str, Any]]) -> List[ManagedPolicyAttachment]:
        out = []
        for att in data:
            if "PolicyName" in att and "PolicyArn" in att:
                out.append(ManagedPolicyAttachment(policy_name=att["PolicyName"], policy_arn=att["PolicyArn"]))
        return out

    def _parse_inline_policies(self, data: List[Dict[str, Any]]) -> List[IAMPolicy]:
        out = []
        for pol_data in data:
            name = pol_data.get("PolicyName")
            if not name:
                continue
            doc = pol_data.get("PolicyDocument")
            out.append(IAMPolicy(
                policy_name=name,
                arn=f"inline-policy/{name}",
                document=self.parse_policy_document(doc) if doc else PolicyDocument(),
            ))
        return out

    def parse_policy_document(self, doc: Any) -> PolicyDocument:
        """Accepts a dict or a (possibly URL-encoded) JSON string."""
        if isinstance(doc, str):
            try:
                doc = json.loads(unquote(doc))
            except Exception:
                logger.warning("Failed to decode/parse string policy document.")
                return PolicyDocument()
        if not isinstance(doc, dict):
            return PolicyDocument()

        policy_doc = PolicyDocument(version=doc.get("Version", "2012-10-17"))
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            parsed = self._parse_statement(stmt)
            if parsed:
                policy_doc.statements.append(parsed)
        return policy_doc

    def _parse_statement(self, stmt: Dict[str, Any]) -> Optional[PolicyStatement]:
        effect_str = stmt.get("Effect")
        if effect_str not in ("Allow", "Deny"):
            return None
        statement = PolicyStatement(
            sid=stmt.get("Sid"),
            effect=PolicyEffect.ALLOW if effect_str == "Allow" else PolicyEffect.DENY,
            actions=_force_list(stmt.get("Action")),
            not_actions=_force_list(stmt.get("NotAction")),
            resources=_force_list(stmt.get("Resource")),
            not_resources=_force_list(stmt.get("NotResource")),
            principals=_parse_principals(stmt.get("Principal")),
        )
        conditions_raw = stmt.get("Condition", {})
        if isinstance(conditions_raw, dict):
            for op, kv in conditions_raw.items():
                if isinstance(kv, dict):
                    for k, v in kv.items():
                        statement.conditions.append(
                            PolicyCondition(operator=op, key=k, values=_force_list(v))
                        )
        return statement


def _force_list(val: Any) -> List[str]:
    if not val:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def _parse_principals(principal: Any) -> List[str]:
    if not principal:
        return []
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        out: List[str] = []
        for v in principal.values():
            out.extend(_force_list(v))
        return out
    if isinstance(principal, list):
        return [str(p) for p in principal]
    return []


_PARSER = IAMParser()


def parse_gaad(raw_data: Dict[str, Any], account_id: str = "000000000000") -> IAMData:
    iam_data = _PARSER.parse(raw_data)
    iam_data.account_id = account_id
    return iam_data


# ──────────────────────────────────────────────
#  Pasted-config adapter (Terraform / iam-vulnerable / raw policy)
# ──────────────────────────────────────────────

_POLICY_RESOURCE_TYPES = {"aws_iam_policy"}
_INLINE_POLICY_RESOURCE_TYPES = {
    "aws_iam_role_policy": "role",
    "aws_iam_user_policy": "user",
    "aws_iam_group_policy": "group",
}
_IDENTITY_RESOURCE_TYPES = {
    "aws_iam_role": "role",
    "aws_iam_user": "user",
    "aws_iam_group": "group",
}


def _arn_to_name(arn: str) -> str:
    return arn.split("/")[-1] if arn else arn


def _attachments(values: Dict[str, Any]) -> List[ManagedPolicyAttachment]:
    arns = values.get("attached_policy_arns") or values.get("managed_policy_arns") or []
    if isinstance(arns, str):
        arns = [arns]
    return [ManagedPolicyAttachment(policy_name=_arn_to_name(a), policy_arn=a) for a in arns if a]


def _inline_from_values(values: Dict[str, Any]) -> List[IAMPolicy]:
    """`values['policy']` on an identity resource is a list of {name, policy} (Terraform)."""
    raw = values.get("policy") or values.get("inline_policy") or []
    if isinstance(raw, dict):
        raw = [raw]
    out: List[IAMPolicy] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("PolicyName") or f"inline-{i}"
        doc = entry.get("policy", entry.get("PolicyDocument", entry))
        out.append(IAMPolicy(
            policy_name=name, arn=f"inline-policy/{name}",
            document=_PARSER.parse_policy_document(doc),
        ))
    return out


def config_to_iamdata(config: Any, config_type: str = "terraform") -> IAMData:
    if isinstance(config, str):
        config = json.loads(config)
    if not isinstance(config, dict):
        raise ValueError("IAM config must be a JSON object")

    # Raw policy document — no identities, just a policy to scan.
    if "resources" not in config:
        doc = config.get("Policy") or (config if "Statement" in config else None)
        if doc is None:
            return IAMData()
        name = config.get("ResourceName", "PastedPolicy")
        return IAMData(policies=[IAMPolicy(
            policy_name=name, arn=f"inline-policy/{name}",
            document=_PARSER.parse_policy_document(doc),
        )])

    resources = config.get("resources")
    if not resources:
        resources = (config.get("planned_values", {})
                     .get("root_module", {})
                     .get("resources", []))

    iam_data = IAMData()
    identities: Dict[str, Any] = {}  # f"{kind}:{name}" -> model

    for resource in resources:
        rtype = resource.get("type")
        values = resource.get("values", resource)
        name = values.get("name", resource.get("name", "unknown"))

        if rtype in _POLICY_RESOURCE_TYPES:
            iam_data.policies.append(IAMPolicy(
                policy_name=name,
                arn=values.get("arn", f"arn:aws:iam::{iam_data.account_id}:policy/{name}"),
                document=_PARSER.parse_policy_document(values.get("policy", {})),
            ))
        elif rtype in _IDENTITY_RESOURCE_TYPES:
            kind = _IDENTITY_RESOURCE_TYPES[rtype]
            attached = _attachments(values)
            inline = _inline_from_values(values)
            if kind == "role":
                model = IAMRole(
                    role_name=name, arn=values.get("arn", ""),
                    assume_role_policy_document=_PARSER.parse_policy_document(
                        values.get("assume_role_policy", {})),
                    attached_managed_policies=attached, inline_policies=inline,
                )
                iam_data.roles.append(model)
            elif kind == "user":
                model = IAMUser(
                    user_name=name, arn=values.get("arn", ""),
                    group_list=values.get("group_list") or values.get("groups") or [],
                    attached_managed_policies=attached, inline_policies=inline,
                )
                iam_data.users.append(model)
            else:
                model = IAMGroup(
                    group_name=name, arn=values.get("arn", ""),
                    attached_managed_policies=attached, inline_policies=inline,
                )
                iam_data.groups.append(model)
            identities[f"{kind}:{name}"] = model

    # Second pass: standalone inline-policy resources (aws_iam_role_policy, ...)
    for resource in resources:
        rtype = resource.get("type")
        if rtype not in _INLINE_POLICY_RESOURCE_TYPES:
            continue
        kind = _INLINE_POLICY_RESOURCE_TYPES[rtype]
        values = resource.get("values", resource)
        target = values.get(kind) or values.get("name")
        model = identities.get(f"{kind}:{target}")
        pol_name = values.get("name", f"{target}-inline")
        pol = IAMPolicy(
            policy_name=pol_name, arn=f"inline-policy/{pol_name}",
            document=_PARSER.parse_policy_document(values.get("policy", {})),
        )
        if model is not None:
            model.inline_policies.append(pol)
        else:
            iam_data.policies.append(pol)

    return iam_data
