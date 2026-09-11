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
    ManagedPolicyAttachment, AnalysisCoverage,
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
    iam_data.coverage = AnalysisCoverage(
        input_format="aws_account_authorization_details",
        total_resources=sum(len(raw_data.get(key, [])) for key in (
            "UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"
        )),
        iam_resources=(len(iam_data.users) + len(iam_data.groups)
                       + len(iam_data.roles) + len(iam_data.policies)),
        conditions_present=_has_conditions(iam_data),
        warnings=[
            "Organization SCPs, session policies, and runtime request context are not included"
        ],
    )
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
_ATTACHMENT_RESOURCE_TYPES = {
    "aws_iam_role_policy_attachment": "role",
    "aws_iam_user_policy_attachment": "user",
    "aws_iam_group_policy_attachment": "group",
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


def _collect_module_resources(module: Any) -> List[Dict[str, Any]]:
    if not isinstance(module, dict):
        return []
    resources = [r for r in module.get("resources", []) if isinstance(r, dict)]
    for child in module.get("child_modules", []) or []:
        resources.extend(_collect_module_resources(child))
    return resources


def _has_conditions(iam_data: IAMData) -> bool:
    policies = list(iam_data.policies)
    for entities in (iam_data.users, iam_data.roles, iam_data.groups):
        for entity in entities:
            policies.extend(entity.inline_policies)
            if isinstance(entity, IAMRole):
                policies.append(IAMPolicy(
                    policy_name=f"{entity.role_name}-trust", arn="",
                    document=entity.assume_role_policy_document,
                ))
    return any(stmt.conditions for policy in policies for stmt in policy.document.statements)


def _attach_policy(model: Any, policy_arn: str) -> None:
    if not model or not policy_arn:
        return
    attachment = ManagedPolicyAttachment(
        policy_name=_arn_to_name(policy_arn), policy_arn=policy_arn
    )
    if attachment not in model.attached_managed_policies:
        model.attached_managed_policies.append(attachment)


def config_to_iamdata(config: Any, config_type: str = "terraform") -> IAMData:
    if isinstance(config, str):
        config = json.loads(config)
    if not isinstance(config, dict):
        raise ValueError("IAM config must be a JSON object")

    root_module = config.get("planned_values", {}).get("root_module")
    is_terraform_plan = isinstance(root_module, dict)

    # Raw policy document — no identities, just a policy to scan.
    if "resources" not in config and not is_terraform_plan:
        doc = config.get("Policy") or (config if "Statement" in config else None)
        if doc is None:
            raise ValueError("Unsupported IAM input: expected a policy, resources, or Terraform plan")
        name = config.get("ResourceName", "PastedPolicy")
        result = IAMData(policies=[IAMPolicy(
            policy_name=name, arn=f"inline-policy/{name}",
            document=_PARSER.parse_policy_document(doc),
        )])
        result.coverage = AnalysisCoverage(
            input_format="raw_policy", total_resources=1, iam_resources=1,
            conditions_present=_has_conditions(result),
            warnings=["No identity attachments, trust policies, boundaries, or organization policies were supplied"],
        )
        return result

    resources = config.get("resources")
    if not isinstance(resources, list) or (is_terraform_plan and not resources):
        resources = _collect_module_resources(root_module)

    iam_data = IAMData()
    identities: Dict[str, Any] = {}  # f"{kind}:{name}" -> model

    unsupported_iam = []
    boundary_count = 0
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
            if values.get("permissions_boundary"):
                boundary_count += 1
        elif isinstance(rtype, str) and rtype.startswith("aws_iam_") and (
            rtype not in _INLINE_POLICY_RESOURCE_TYPES
            and rtype not in _ATTACHMENT_RESOURCE_TYPES
            and rtype not in {"aws_iam_policy_attachment", "aws_iam_group_membership",
                              "aws_iam_user_group_membership"}
        ):
            unsupported_iam.append(rtype)

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

    # Third pass: managed-policy attachments and group membership resources.
    for resource in resources:
        rtype = resource.get("type")
        values = resource.get("values", resource)
        if rtype in _ATTACHMENT_RESOURCE_TYPES:
            kind = _ATTACHMENT_RESOURCE_TYPES[rtype]
            target = values.get(kind)
            _attach_policy(identities.get(f"{kind}:{target}"), values.get("policy_arn", ""))
        elif rtype == "aws_iam_policy_attachment":
            policy_arn = values.get("policy_arn", "")
            for kind, plural in (("user", "users"), ("role", "roles"), ("group", "groups")):
                for target in values.get(plural, []) or []:
                    _attach_policy(identities.get(f"{kind}:{target}"), policy_arn)
        elif rtype == "aws_iam_group_membership":
            group = values.get("group")
            for user_name in values.get("users", []) or []:
                user = identities.get(f"user:{user_name}")
                if user and group and group not in user.group_list:
                    user.group_list.append(group)
        elif rtype == "aws_iam_user_group_membership":
            user = identities.get(f"user:{values.get('user')}")
            if user:
                for group in values.get("groups", []) or []:
                    if group not in user.group_list:
                        user.group_list.append(group)

    warnings = []
    if not resources:
        warnings.append("The Terraform plan contains no resources")
    if unsupported_iam:
        warnings.append("Unsupported IAM resources: " + ", ".join(sorted(set(unsupported_iam))))
    if boundary_count:
        warnings.append(
            f"{boundary_count} permissions boundary reference(s) were found; boundary policy evaluation is not yet included"
        )
    warnings.append("Organization SCPs, session policies, and runtime request context are not included")
    recognized = (
        len(iam_data.users) + len(iam_data.roles) + len(iam_data.groups)
        + len(iam_data.policies)
    )
    if resources and not recognized:
        warnings.append("No supported IAM identities or policies were found")
    iam_data.coverage = AnalysisCoverage(
        input_format="terraform_plan" if is_terraform_plan else "resource_export",
        total_resources=len(resources),
        iam_resources=recognized,
        skipped_resources=len(unsupported_iam),
        conditions_present=_has_conditions(iam_data),
        complete=not unsupported_iam and bool(recognized),
        warnings=warnings,
    )

    return iam_data
