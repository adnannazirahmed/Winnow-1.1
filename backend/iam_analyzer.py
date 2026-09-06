import json
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class Vulnerability:
    id: str
    pattern_id: str
    title: str
    description: str
    severity: str
    resource_type: str
    resource_name: str
    policy_document: Dict
    attack_path: List[str]
    mitre_techniques: List[str]
    remediation_hint: str
    detection_source: str = 'rule'

class IAMAnalyzer:
    PRIVILEGE_ESCALATION_PATTERNS = {
        'iam:AttachUserPolicy': {
            'severity': 'CRITICAL',
            'title': 'User Can Attach Admin Policy',
            'description': 'Allows attaching any managed policy including AdministratorAccess',
            'mitre': ['T1098.001'],
            'hint': 'Remove iam:AttachUserPolicy or restrict to specific policies'
        },
        'iam:PutUserPolicy': {
            'severity': 'CRITICAL',
            'title': 'User Can Put Inline Policy',
            'description': 'Allows creating inline policies with arbitrary permissions',
            'mitre': ['T1098.001'],
            'hint': 'Remove iam:PutUserPolicy or restrict policy content'
        },
        'iam:CreateAccessKey': {
            'severity': 'HIGH',
            'title': 'Create Access Keys for Other Users',
            'description': 'Can create access keys for any user, enabling credential theft',
            'mitre': ['T1098.004'],
            'hint': 'Restrict to own user only with condition keys'
        },
        'iam:UpdateLoginProfile': {
            'severity': 'HIGH',
            'title': 'Update Login Profile',
            'description': 'Can change password for any user',
            'mitre': ['T1098.005'],
            'hint': 'Restrict to self only'
        },
        'sts:AssumeRole': {
            'severity': 'HIGH',
            'title': 'Role Assumption',
            'description': 'Can assume roles with elevated permissions',
            'mitre': ['T1550.001'],
            'hint': 'Add condition keys to restrict role assumption'
        },
        'iam:PassRole': {
            'severity': 'HIGH',
            'title': 'Pass Role to Services',
            'description': 'Can pass privileged roles to EC2, Lambda, etc.',
            'mitre': ['T1098.003'],
            'hint': 'Restrict to specific roles with condition keys'
        },
        'iam:CreateRole': {
            'severity': 'MEDIUM',
            'title': 'Create Role',
            'description': 'Can create roles with arbitrary trust policies',
            'mitre': ['T1098.003'],
            'hint': 'Restrict trust policy via permissions boundary'
        },
        'iam:PutRolePolicy': {
            'severity': 'HIGH',
            'title': 'Put Role Policy',
            'description': 'Can attach inline policies to any role',
            'mitre': ['T1098.003'],
            'hint': 'Remove or restrict to specific roles'
        },
        'iam:AttachRolePolicy': {
            'severity': 'HIGH',
            'title': 'Attach Role Policy',
            'description': 'Can attach managed policies to any role',
            'mitre': ['T1098.003'],
            'hint': 'Restrict to specific policies'
        },
        'iam:UpdateAssumeRolePolicy': {
            'severity': 'HIGH',
            'title': 'Update Assume Role Policy',
            'description': 'Can modify trust policy to allow self-assumption',
            'mitre': ['T1550.001'],
            'hint': 'Restrict with permissions boundary'
        },
        'organizations:AttachPolicy': {
            'severity': 'CRITICAL',
            'title': 'Attach SCP',
            'description': 'Can attach Service Control Policies',
            'mitre': ['T1484.002'],
            'hint': 'Restrict to specific SCPs'
        },
        'organizations:MoveAccount': {
            'severity': 'HIGH',
            'title': 'Move Account',
            'description': 'Can move accounts between OUs to bypass SCPs',
            'mitre': ['T1484.002'],
            'hint': 'Restrict organizational unit movement'
        },
        'ec2:RunInstances': {
            'severity': 'MEDIUM',
            'title': 'Run Instances with Role',
            'description': 'Can launch EC2 with instance profile for privilege escalation',
            'mitre': ['T1611'],
            'hint': 'Restrict iam:PassRole to specific roles'
        },
        'lambda:CreateFunction': {
            'severity': 'MEDIUM',
            'title': 'Create Lambda Function',
            'description': 'Can create Lambda with privileged execution role',
            'mitre': ['T1611'],
            'hint': 'Restrict iam:PassRole for Lambda'
        },
        'lambda:UpdateFunctionCode': {
            'severity': 'MEDIUM',
            'title': 'Update Lambda Code',
            'description': 'Can modify Lambda code to execute arbitrary commands',
            'mitre': ['T1611'],
            'hint': 'Restrict to specific functions'
        },
        'glue:CreateDevEndpoint': {
            'severity': 'MEDIUM',
            'title': 'Create Glue Dev Endpoint',
            'description': 'Can create Glue endpoint with privileged role',
            'mitre': ['T1611'],
            'hint': 'Restrict iam:PassRole for Glue'
        },
        'datapipeline:CreatePipeline': {
            'severity': 'LOW',
            'title': 'Create Data Pipeline',
            'description': 'Can create pipeline with privileged role',
            'mitre': ['T1611'],
            'hint': 'Restrict iam:PassRole for Data Pipeline'
        },
        'cloudformation:CreateStack': {
            'severity': 'MEDIUM',
            'title': 'Create CloudFormation Stack',
            'description': 'Can create stack with service role for escalation',
            'mitre': ['T1611'],
            'hint': 'Restrict iam:PassRole for CloudFormation'
        },
        'iam:CreatePolicyVersion': {
            'severity': 'HIGH',
            'title': 'Create Policy Version',
            'description': 'Can create new version of managed policy',
            'mitre': ['T1098.001'],
            'hint': 'Restrict to specific policies'
        },
        'iam:SetDefaultPolicyVersion': {
            'severity': 'HIGH',
            'title': 'Set Default Policy Version',
            'description': 'Can set vulnerable policy version as default',
            'mitre': ['T1098.001'],
            'hint': 'Restrict to specific policies'
        }
    }

    RESOURCE_RISK_PATTERNS = {
        '*': {
            'severity_modifier': '+1',
            'note': 'Wildcard resource allows access to all resources'
        }
    }

    def analyze(self, iam_config: Any, config_type: str = 'terraform') -> List[Dict]:
        """Stateless entry point. IDs are assigned per-analysis so the same
        input always yields the same IDs, regardless of process/worker."""
        if config_type == 'terraform':
            vulnerabilities = self._analyze_terraform(iam_config)
        elif config_type == 'json':
            vulnerabilities = self._analyze_json(iam_config)
        elif config_type == 'iam_vulnerable':
            vulnerabilities = self._analyze_iam_vulnerable(iam_config)
        else:
            vulnerabilities = self._analyze_generic(iam_config)

        for i, vuln in enumerate(vulnerabilities, start=1):
            vuln['id'] = f"VULN-{i:04d}"
        return vulnerabilities

    def _analyze_terraform(self, config: Dict) -> List[Dict]:
        vulnerabilities = []
        if isinstance(config, str):
            config = json.loads(config)
        
        resources = config.get('resources', config.get('planned_values', {}).get('root_module', {}).get('resources', []))
        
        for resource in resources:
            if resource.get('type') in ['aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy', 'aws_iam_group_policy']:
                vulns = self._analyze_policy_resource(resource)
                vulnerabilities.extend(vulns)
            elif resource.get('type') in ['aws_iam_role', 'aws_iam_user', 'aws_iam_group']:
                vulns = self._analyze_identity_resource(resource)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities

    def _analyze_json(self, config: Dict) -> List[Dict]:
        vulnerabilities = []
        if isinstance(config, str):
            config = json.loads(config)
        
        if 'Policy' in config:
            vulns = self._analyze_policy_document(config['Policy'], config.get('ResourceName', 'unknown'))
            vulnerabilities.extend(vulns)
        
        return vulnerabilities

    def _analyze_iam_vulnerable(self, config: Dict) -> List[Dict]:
        vulnerabilities = []
        if isinstance(config, str):
            config = json.loads(config)
        
        resources = config.get('resources', [])
        for resource in resources:
            if resource.get('type') == 'aws_iam_policy':
                vulns = self._analyze_policy_resource(resource)
                vulnerabilities.extend(vulns)
            elif resource.get('type') in ['aws_iam_role', 'aws_iam_user']:
                vulns = self._analyze_identity_resource(resource)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities

    def _analyze_generic(self, config: Any) -> List[Dict]:
        if isinstance(config, dict) and 'Policy' in config:
            return self._analyze_policy_document(config['Policy'], 'unknown')
        return []

    def _analyze_policy_resource(self, resource: Dict) -> List[Dict]:
        vulnerabilities = []
        values = resource.get('values', resource)
        
        policy_doc = values.get('policy', {})
        if isinstance(policy_doc, str):
            try:
                policy_doc = json.loads(policy_doc)
            except:
                pass
        
        name = values.get('name', resource.get('name', 'unknown'))
        vulns = self._analyze_policy_document(policy_doc, name, resource.get('type', 'policy'))
        vulnerabilities.extend(vulns)
        
        return vulnerabilities

    def _analyze_identity_resource(self, resource: Dict) -> List[Dict]:
        vulnerabilities = []
        values = resource.get('values', resource)
        
        name = values.get('name', resource.get('name', 'unknown'))
        resource_type = resource.get('type', 'identity')
        
        attached_policies = values.get('attached_policy_arns', [])
        inline_policies = values.get('policy', [])
        
        for policy_arn in attached_policies:
            vuln = Vulnerability(
                id='',
                pattern_id='attached_managed_policy',
                title=f'Attached Managed Policy: {policy_arn}',
                description=f'{resource_type} {name} has managed policy attached: {policy_arn}',
                severity='MEDIUM',
                resource_type=resource_type,
                resource_name=name,
                policy_document={'attached_policy_arn': policy_arn},
                attack_path=[f'Identity: {name}', f'Policy: {policy_arn}'],
                mitre_techniques=['T1098.001'],
                remediation_hint='Review managed policy permissions; use least privilege'
            )
            vulnerabilities.append(asdict(vuln))
        
        for policy in inline_policies:
            if isinstance(policy, dict):
                policy_doc = policy.get('policy', policy)
                vulns = self._analyze_policy_document(policy_doc, name, resource_type)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities

    def _analyze_policy_document(self, policy_doc: Dict, resource_name: str, resource_type: str = 'policy') -> List[Dict]:
        vulnerabilities = []
        
        if not policy_doc:
            return vulnerabilities
        
        statements = policy_doc.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for idx, statement in enumerate(statements):
            vulns = self._analyze_statement(statement, resource_name, resource_type, idx)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities

    def _analyze_statement(self, statement: Dict, resource_name: str, resource_type: str, stmt_idx: int) -> List[Dict]:
        vulnerabilities = []
        
        effect = statement.get('Effect', 'Allow')
        if effect != 'Allow':
            return vulnerabilities
        
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        
        conditions = statement.get('Condition', {})
        
        for action in actions:
            if not isinstance(action, str):
                continue
            action = action.strip()

            # Full wildcard: one authoritative finding rather than one per
            # pattern (a bare "*" technically matches every pattern).
            if action == '*':
                vulnerabilities.append(asdict(Vulnerability(
                    id='',
                    pattern_id='full_admin',
                    title='Full Admin Access',
                    description=f'Statement grants full admin access (*) on resources: {resources}',
                    severity='CRITICAL',
                    resource_type=resource_type,
                    resource_name=resource_name,
                    policy_document={'statement': statement, 'action': action},
                    attack_path=[f'Identity: {resource_name}', 'Action: *', f'Resources: {resources}'],
                    mitre_techniques=['T1098.001'],
                    remediation_hint='Replace wildcard with specific actions; apply least privilege'
                )))
                continue

            # Service wildcard (e.g. "iam:*", "s3:*"): summarize once instead
            # of emitting a finding per covered pattern.
            if action.endswith(':*'):
                covered = [
                    p for p in self.PRIVILEGE_ESCALATION_PATTERNS
                    if p.lower().startswith(action[:-1].lower())
                ]
                severity = 'CRITICAL' if any(
                    self.PRIVILEGE_ESCALATION_PATTERNS[p]['severity'] == 'CRITICAL' for p in covered
                ) else ('HIGH' if covered else 'MEDIUM')
                if '*' in resources and severity != 'CRITICAL':
                    severity = self._escalate_severity(severity)
                mitre = sorted({
                    t for p in covered for t in self.PRIVILEGE_ESCALATION_PATTERNS[p]['mitre']
                }) or ['T1098.001']
                detail = f' Includes escalation-capable actions: {", ".join(covered[:5])}.' if covered else ''
                vulnerabilities.append(asdict(Vulnerability(
                    id='',
                    pattern_id='service_wildcard',
                    title=f'Service-Wide Wildcard: {action}',
                    description=f'Grants every action in the {action[:-2]} service.{detail}',
                    severity=severity,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    policy_document={'statement': statement, 'action': action},
                    attack_path=self._build_attack_path(action, resource_name, resources),
                    mitre_techniques=mitre,
                    remediation_hint=f'Enumerate the {action[:-2]} actions actually used and list them explicitly'
                )))
                continue

            for pattern, details in self.PRIVILEGE_ESCALATION_PATTERNS.items():
                if self._match_action(action, pattern):
                    severity = details['severity']

                    if '*' in resources and severity != 'CRITICAL':
                        severity = self._escalate_severity(severity)

                    attack_path = self._build_attack_path(action, resource_name, resources)

                    vuln = Vulnerability(
                        id='',
                        pattern_id=pattern,
                        title=details['title'],
                        description=f"{details['description']} (Action: {action})",
                        severity=severity,
                        resource_type=resource_type,
                        resource_name=resource_name,
                        policy_document={'statement': statement, 'action': action},
                        attack_path=attack_path,
                        mitre_techniques=details['mitre'],
                        remediation_hint=details['hint']
                    )
                    vulnerabilities.append(asdict(vuln))

        return vulnerabilities

    def _match_action(self, action: str, pattern: str) -> bool:
        """Match a policy action against a known escalation pattern.

        Wildcard actions ("*", "iam:*") are handled by the caller, so this
        only covers exact matches and prefix wildcards like "iam:Attach*".
        """
        if action.lower() == pattern.lower():
            return True
        if action.endswith('*') and len(action) > 1:
            return pattern.lower().startswith(action[:-1].lower())
        return False

    def _escalate_severity(self, severity: str) -> str:
        escalation = {'LOW': 'MEDIUM', 'MEDIUM': 'HIGH', 'HIGH': 'CRITICAL'}
        return escalation.get(severity, severity)

    def _build_attack_path(self, action: str, resource_name: str, resources: List[str]) -> List[str]:
        path = [f'Identity: {resource_name}', f'Action: {action}']
        if resources:
            path.append(f'Target Resources: {", ".join(resources[:3])}')
            if len(resources) > 3:
                path.append(f'... and {len(resources) - 3} more')
        return path

    # ------------------------------------------------------------------
    #  Supplementary scan over the normalized IAMData model.
    #  Runs alongside the graph escalation engine: it flags dangerous
    #  permissions per policy regardless of whether an identity can
    #  actually reach them (which the graph engine, with its reachability
    #  filter, deliberately does not). Findings are tagged 'rule'.
    # ------------------------------------------------------------------

    @staticmethod
    def _statement_to_dict(stmt) -> Dict:
        cond: Dict[str, Dict[str, list]] = {}
        for c in stmt.conditions:
            cond.setdefault(c.operator, {})[c.key] = list(c.values)
        return {
            'Effect': stmt.effect.value,
            'Action': list(stmt.actions),
            'Resource': list(stmt.resources) or ['*'],
            'Condition': cond,
        }

    @staticmethod
    def _allow_statements_after_denies(statements) -> List[Dict]:
        """Allow statements as dicts, with any action a same-document Deny covers
        on a matching resource removed. Keeps the rule scan from flagging a
        permission the policy itself denies (e.g. Allow iam:X + Deny iam:*)."""
        import re as _re
        denies = [s for s in statements if s.effect.value == 'Deny']

        def _covers(deny, action, resources):
            deny_res = deny.resources or ['*']
            if not any(r == '*' or r in resources or (resources and '*' in resources) for r in deny_res):
                return False
            for pat in (deny.actions or []):
                rx = '^' + _re.escape(pat).replace('\\*', '.*').replace('\\?', '.') + '$'
                if _re.match(rx, action, _re.IGNORECASE):
                    return True
            return False

        out = []
        for stmt in statements:
            if stmt.effect.value != 'Allow':
                continue
            d = IAMAnalyzer._statement_to_dict(stmt)
            d['Action'] = [a for a in d['Action']
                           if not any(_covers(dn, a, d['Resource']) for dn in denies)]
            if d['Action']:
                out.append(d)
        return out

    def scan_iamdata(self, iam_data) -> List[Dict]:
        vulnerabilities: List[Dict] = []

        for policy in iam_data.policies:
            for idx, d in enumerate(self._allow_statements_after_denies(policy.document.statements)):
                vulnerabilities.extend(self._analyze_statement(
                    d, policy.policy_name, 'aws_iam_policy', idx))

        for kind, entities in (('aws_iam_user', iam_data.users),
                               ('aws_iam_role', iam_data.roles),
                               ('aws_iam_group', iam_data.groups)):
            for entity in entities:
                name = getattr(entity, 'user_name', None) or getattr(entity, 'role_name', None) \
                    or getattr(entity, 'group_name', 'unknown')
                for att in entity.attached_managed_policies:
                    vulnerabilities.append(asdict(Vulnerability(
                        id='',
                        pattern_id='attached_managed_policy',
                        title=f'Attached Managed Policy: {att.policy_arn}',
                        description=f'{kind} {name} has managed policy attached: {att.policy_arn}',
                        severity='MEDIUM',
                        resource_type=kind,
                        resource_name=name,
                        policy_document={'attached_policy_arn': att.policy_arn},
                        attack_path=[f'Identity: {name}', f'Policy: {att.policy_arn}'],
                        mitre_techniques=['T1098.001'],
                        remediation_hint='Review managed policy permissions; use least privilege',
                    )))
                for pol in entity.inline_policies:
                    for idx, d in enumerate(self._allow_statements_after_denies(pol.document.statements)):
                        vulnerabilities.extend(self._analyze_statement(d, name, kind, idx))

        return vulnerabilities

    def generate_dummy_data(self) -> Dict:
        """A small but realistic account that exercises the whole engine:
        a direct escalation, one via group membership, one via assume-role,
        a role only a service can assume (filtered out), and a user whose
        escalation permission is neutralized by an explicit Deny."""
        acct = "123456789012"
        return {
            "resources": [
                {
                    "type": "aws_iam_user",
                    "name": "CompromisedUser",
                    "values": {
                        "name": "CompromisedUser",
                        "arn": f"arn:aws:iam::{acct}:user/CompromisedUser",
                        "group_list": ["Developers"],
                        "attached_policy_arns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
                        "policy": [
                            {
                                "name": "DirectEscalation",
                                "policy": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {"Effect": "Allow",
                                         "Action": ["iam:AttachUserPolicy", "iam:CreateAccessKey"],
                                         "Resource": "*"},
                                        {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
                                    ],
                                },
                            }
                        ],
                    },
                },
                {
                    "type": "aws_iam_group",
                    "name": "Developers",
                    "values": {
                        "name": "Developers",
                        "arn": f"arn:aws:iam::{acct}:group/Developers",
                        "attached_policy_arns": ["arn:aws:iam::aws:policy/PowerUserAccess"],
                        "policy": [
                            {
                                "name": "TeamPipeline",
                                "policy": {
                                    "Version": "2012-10-17",
                                    "Statement": [{
                                        "Effect": "Allow",
                                        "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
                                        "Resource": "*",
                                    }],
                                },
                            }
                        ],
                    },
                },
                {
                    "type": "aws_iam_role",
                    "name": "DeployRole",
                    "values": {
                        "name": "DeployRole",
                        "arn": f"arn:aws:iam::{acct}:role/DeployRole",
                        "assume_role_policy": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"AWS": f"arn:aws:iam::{acct}:user/CompromisedUser"},
                                "Action": "sts:AssumeRole",
                            }],
                        },
                        "attached_policy_arns": [f"arn:aws:iam::{acct}:policy/PolicyToolsPolicy"],
                    },
                },
                {
                    "type": "aws_iam_policy",
                    "name": "PolicyToolsPolicy",
                    "values": {
                        "name": "PolicyToolsPolicy",
                        "arn": f"arn:aws:iam::{acct}:policy/PolicyToolsPolicy",
                        "policy": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["iam:CreatePolicyVersion", "iam:PutRolePolicy"],
                                "Resource": "*",
                            }],
                        },
                    },
                },
                {
                    "type": "aws_iam_role",
                    "name": "EC2AppRole",
                    "values": {
                        "name": "EC2AppRole",
                        "arn": f"arn:aws:iam::{acct}:role/EC2AppRole",
                        "assume_role_policy": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }],
                        },
                        "attached_policy_arns": [f"arn:aws:iam::{acct}:policy/BroadAdminPolicy"],
                    },
                },
                {
                    "type": "aws_iam_policy",
                    "name": "BroadAdminPolicy",
                    "values": {
                        "name": "BroadAdminPolicy",
                        "arn": f"arn:aws:iam::{acct}:policy/BroadAdminPolicy",
                        "policy": {
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
                        },
                    },
                },
                {
                    "type": "aws_iam_user",
                    "name": "Auditor",
                    "values": {
                        "name": "Auditor",
                        "arn": f"arn:aws:iam::{acct}:user/Auditor",
                        "policy": [
                            {
                                "name": "AuditAccess",
                                "policy": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
                                        {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
                                    ],
                                },
                            }
                        ],
                    },
                },
            ]
        }
