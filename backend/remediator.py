import os
import json
import logging
import re
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

logger = logging.getLogger(__name__)

# Remediation strategy groups keyed by the analyzer's stable pattern_id.
# This is the explicit contract with iam_analyzer.PRIVILEGE_ESCALATION_PATTERNS:
# renaming a human-readable title no longer silently breaks remediation.
PATTERN_STRATEGY = {
    'iam:AttachUserPolicy': 'attach_policy',
    'iam:AttachRolePolicy': 'attach_policy',
    'iam:PutUserPolicy': 'put_policy',
    'iam:PutRolePolicy': 'put_policy',
    'iam:CreatePolicyVersion': 'policy_version',
    'iam:SetDefaultPolicyVersion': 'policy_version',
    'iam:CreateAccessKey': 'access_key',
    'iam:UpdateLoginProfile': 'login_profile',
    'sts:AssumeRole': 'assume_role',
    'iam:UpdateAssumeRolePolicy': 'assume_role',
    'iam:PassRole': 'pass_role',
    'iam:CreateRole': 'create_role',
    'ec2:RunInstances': 'service_escalation',
    'lambda:CreateFunction': 'service_escalation',
    'lambda:UpdateFunctionCode': 'service_escalation',
    'glue:CreateDevEndpoint': 'service_escalation',
    'datapipeline:CreatePipeline': 'service_escalation',
    'cloudformation:CreateStack': 'service_escalation',
    'organizations:AttachPolicy': 'organizations',
    'organizations:MoveAccount': 'organizations',
    'full_admin': 'full_admin',
    'service_wildcard': 'service_wildcard',
    'attached_managed_policy': 'managed_policy_review',
}


@dataclass
class RemediationAction:
    action: str
    description: str
    priority: str
    code_example: str
    explanation: str


class Remediator:
    SYSTEM_PROMPT = """You are an AWS IAM security expert specializing in privilege escalation remediation. 
Your task is to analyze IAM vulnerabilities and provide specific, actionable remediation steps.

For each vulnerability, provide:
1. A clear summary of the risk
2. Specific remediation actions with priority (CRITICAL/HIGH/MEDIUM/LOW)
3. Code examples showing the vulnerable vs hardened policy
4. Compliance notes (CIS, NIST, PCI-DSS references where applicable)

Be precise, practical, and follow AWS security best practices. Output valid JSON only."""

    VULNERABILITY_PROMPT_TEMPLATE = """Analyze this IAM vulnerability and provide remediation:

Vulnerability Details:
- ID: {vuln_id}
- Title: {title}
- Description: {description}
- Severity: {severity}
- Resource Type: {resource_type}
- Resource Name: {resource_name}
- Policy Statement: {policy_statement}
- Attack Path: {attack_path}
- MITRE Techniques: {mitre_techniques}
- Current Hint: {remediation_hint}

Provide remediation as JSON with this structure:
{{
    "summary": "Brief risk summary",
    "risk_score": 0-100,
    "actions": [
        {{
            "action": "Specific action name",
            "description": "Detailed description",
            "priority": "CRITICAL|HIGH|MEDIUM|LOW",
            "code_example": "Before/after policy JSON",
            "explanation": "Why this fixes the issue"
        }}
    ],
    "hardened_policy": {{...}},
    "compliance_notes": ["CIS 1.16", "NIST AC-6", "PCI-DSS 7.1"]
}}"""

    def __init__(self):
        self.client = None
        self.api_key = os.environ.get('ANTHROPIC_API_KEY')
        self.model = os.environ.get('REMEDIATOR_MODEL', 'claude-3-haiku-20240307')
        # Cap on AI calls per analysis request; the rest use the rule-based
        # fallback. Prevents unbounded cost/latency fan-out per request.
        self.max_ai_calls_per_batch = int(os.environ.get('MAX_AI_REMEDIATIONS', '5'))
        self._cache: Dict[str, Dict] = {}
        self._cache_lock = threading.Lock()
        self._cache_max = 256
        if self.api_key and ANTHROPIC_AVAILABLE:
            try:
                self.client = anthropic.Anthropic(
                    api_key=self.api_key,
                    timeout=float(os.environ.get('ANTHROPIC_TIMEOUT_SECONDS', '30')),
                    max_retries=1,
                )
            except Exception as e:
                logger.warning(f"Failed to init Anthropic client: {e}")
                self.client = None
        else:
            logger.warning("Anthropic API key not set or anthropic package not available. Using fallback remediation.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def batch_remediate(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remediate a batch. At most `max_ai_calls_per_batch` uncached AI
        calls are made; everything else is served from cache or fallback."""
        results = []
        ai_calls_used = 0
        for vuln in vulnerabilities:
            cached = self._cache_get(vuln)
            if cached is not None:
                results.append(self._bind(cached, vuln))
                continue
            if self.client and ai_calls_used < self.max_ai_calls_per_batch:
                ai_calls_used += 1
                result = self._get_ai_remediation(vuln)
            else:
                result = self._get_fallback_remediation(vuln)
            self._cache_put(vuln, result)
            results.append(result)
        return results

    def get_remediation(self, vulnerability: Dict) -> Dict:
        cached = self._cache_get(vulnerability)
        if cached is not None:
            return self._bind(cached, vulnerability)
        if self.client:
            result = self._get_ai_remediation(vulnerability)
        else:
            result = self._get_fallback_remediation(vulnerability)
        self._cache_put(vulnerability, result)
        return result

    # ------------------------------------------------------------------
    # Caching (keyed by what determines remediation content, not by ID)
    # ------------------------------------------------------------------

    def _cache_key(self, vuln: Dict) -> str:
        pd = vuln.get('policy_document', {})
        action = pd.get('action', '')
        return json.dumps([
            vuln.get('pattern_id', ''),
            vuln.get('title', ''),
            vuln.get('severity', ''),
            action,
            pd.get('statement', {}),
        ], sort_keys=True, default=str)

    def _cache_get(self, vuln: Dict) -> Optional[Dict]:
        with self._cache_lock:
            return self._cache.get(self._cache_key(vuln))

    def _cache_put(self, vuln: Dict, result: Dict) -> None:
        with self._cache_lock:
            if len(self._cache) >= self._cache_max:
                self._cache.pop(next(iter(self._cache)))
            self._cache[self._cache_key(vuln)] = result

    def _bind(self, cached: Dict, vuln: Dict) -> Dict:
        """Re-bind a cached remediation to this vulnerability's ID."""
        bound = dict(cached)
        bound['vulnerability_id'] = vuln.get('id')
        return bound

    # ------------------------------------------------------------------
    # AI path
    # ------------------------------------------------------------------

    def _get_ai_remediation(self, vulnerability: Dict) -> Dict:
        try:
            prompt = self.VULNERABILITY_PROMPT_TEMPLATE.format(
                vuln_id=vulnerability.get('id', 'UNKNOWN'),
                title=vulnerability.get('title', 'Unknown'),
                description=vulnerability.get('description', ''),
                severity=vulnerability.get('severity', 'MEDIUM'),
                resource_type=vulnerability.get('resource_type', 'unknown'),
                resource_name=vulnerability.get('resource_name', 'unknown'),
                policy_statement=json.dumps(vulnerability.get('policy_document', {}), indent=2, default=str)[:4000],
                attack_path=' -> '.join(vulnerability.get('attack_path', [])),
                mitre_techniques=', '.join(vulnerability.get('mitre_techniques', [])),
                remediation_hint=vulnerability.get('remediation_hint', '')
            )

            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                temperature=0.1,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )

            content = response.content[0].text
            result = self._parse_json_object(content)
            if result is None:
                raise ValueError("Model response contained no parseable JSON object")

            return {
                'vulnerability_id': vulnerability.get('id'),
                'original_severity': vulnerability.get('severity'),
                'risk_score': result.get('risk_score', 50),
                'summary': result.get('summary', ''),
                'actions': result.get('actions', []),
                'hardened_policy': result.get('hardened_policy', {}),
                'compliance_notes': result.get('compliance_notes', []),
                'source': 'ai'
            }
        except Exception as e:
            logger.error(f"AI remediation failed: {e}")
            return self._get_fallback_remediation(vulnerability)

    @staticmethod
    def _parse_json_object(raw: str) -> Optional[Dict]:
        """Tolerant JSON extraction: models often wrap JSON in prose or
        markdown fences."""
        raw = raw.strip()
        if not raw:
            return None
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            pass
        fenced = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw, re.DOTALL)
        candidates = [fenced.group(1)] if fenced else []
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            candidates.append(m.group(0))
        for candidate in candidates:
            try:
                data = json.loads(candidate)
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                continue
        return None

    # ------------------------------------------------------------------
    # Rule-based fallback, keyed by pattern_id
    # ------------------------------------------------------------------

    def _strategy_for(self, vulnerability: Dict) -> str:
        pattern_id = vulnerability.get('pattern_id', '')
        if pattern_id in PATTERN_STRATEGY:
            return PATTERN_STRATEGY[pattern_id]
        # AI-detected findings carry the offending action instead.
        action = str(vulnerability.get('policy_document', {}).get('action', ''))
        if action in PATTERN_STRATEGY:
            return PATTERN_STRATEGY[action]
        if action == '*':
            return 'full_admin'
        return 'generic'

    def _get_fallback_remediation(self, vulnerability: Dict) -> Dict:
        vuln_title = vulnerability.get('title', '')
        severity = vulnerability.get('severity', 'MEDIUM')
        resource_name = vulnerability.get('resource_name', 'unknown')
        policy_doc = vulnerability.get('policy_document', {})

        strategy = self._strategy_for(vulnerability)
        actions = self._generate_fallback_actions(strategy, severity)
        hardened_policy = self._generate_hardened_policy(policy_doc, strategy)

        risk_scores = {'CRITICAL': 95, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25}
        attack_path = vulnerability.get('attack_path') or ['unknown path']

        return {
            'vulnerability_id': vulnerability.get('id'),
            'original_severity': severity,
            'risk_score': risk_scores.get(severity, 50),
            'summary': f"Vulnerability in {resource_name}: {vuln_title}. Allows privilege escalation via {attack_path[0]}.",
            'actions': actions,
            'hardened_policy': hardened_policy,
            'compliance_notes': self._get_compliance_notes(strategy, severity),
            'source': 'rule'
        }

    def _generate_fallback_actions(self, strategy: str, severity: str) -> List[Dict]:
        actions: List[Dict] = []

        if strategy == 'attach_policy':
            actions.append({
                'action': 'Remove iam:AttachUserPolicy/AttachRolePolicy',
                'description': 'Remove the ability to attach arbitrary managed policies. If attachment is needed, restrict to specific policy ARNs using condition keys.',
                'priority': 'CRITICAL',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"},
                    "After": {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "arn:aws:iam::123456789012:policy/SpecificPolicy"}
                }, indent=2),
                'explanation': 'Wildcard attachment allows escalation to AdministratorAccess. Restrict to specific approved policies.'
            })
            actions.append({
                'action': 'Apply Permissions Boundary',
                'description': 'Set a permissions boundary on the identity to limit maximum permissions regardless of attached policies.',
                'priority': 'HIGH',
                'code_example': json.dumps({
                    "PermissionsBoundary": "arn:aws:iam::123456789012:policy/DeveloperBoundary"
                }, indent=2),
                'explanation': 'Permissions boundaries provide a guardrail that cannot be bypassed by attaching policies.'
            })

        elif strategy == 'put_policy':
            actions.append({
                'action': 'Remove iam:PutUserPolicy/PutRolePolicy',
                'description': 'Remove inline policy creation capability. Use managed policies instead for better auditability.',
                'priority': 'CRITICAL',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": "iam:PutUserPolicy", "Resource": "*"},
                    "After": {"Effect": "Deny", "Action": "iam:PutUserPolicy", "Resource": "*"}
                }, indent=2),
                'explanation': 'Inline policies cannot be centrally managed and are often used for stealthy privilege escalation.'
            })

        elif strategy == 'policy_version':
            actions.append({
                'action': 'Restrict Policy Versioning Actions',
                'description': 'Limit iam:CreatePolicyVersion and iam:SetDefaultPolicyVersion to non-privileged, explicitly approved policies.',
                'priority': 'HIGH',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"], "Resource": "*"},
                    "After": {"Effect": "Allow", "Action": ["iam:CreatePolicyVersion"], "Resource": "arn:aws:iam::123456789012:policy/app-scoped-*"}
                }, indent=2),
                'explanation': 'Creating or activating a new policy version on a privileged policy grants arbitrary permissions.'
            })

        elif strategy == 'access_key':
            actions.append({
                'action': 'Restrict CreateAccessKey to Self',
                'description': 'Add condition to only allow creating access keys for the current user.',
                'priority': 'HIGH',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
                    "After": {
                        "Effect": "Allow",
                        "Action": "iam:CreateAccessKey",
                        "Resource": "arn:aws:iam::123456789012:user/${aws:username}"
                    }
                }, indent=2),
                'explanation': 'Prevents creating access keys for other users (credential theft).'
            })

        elif strategy == 'login_profile':
            actions.append({
                'action': 'Restrict UpdateLoginProfile to Self',
                'description': 'Only allow changing your own console password.',
                'priority': 'HIGH',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": "iam:UpdateLoginProfile", "Resource": "*"},
                    "After": {"Effect": "Allow", "Action": "iam:UpdateLoginProfile", "Resource": "arn:aws:iam::123456789012:user/${aws:username}"}
                }, indent=2),
                'explanation': 'Prevents account takeover by resetting other users\' passwords.'
            })

        elif strategy == 'assume_role':
            actions.append({
                'action': 'Restrict Role Assumption with Conditions',
                'description': 'Add condition keys to restrict which roles can be assumed and under what circumstances.',
                'priority': 'HIGH',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"},
                    "After": {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": "arn:aws:iam::123456789012:role/AllowedRole*",
                        "Condition": {
                            "Bool": {"aws:MultiFactorAuthPresent": "true"},
                            "StringEquals": {"aws:RequestedRegion": "us-east-1"}
                        }
                    }
                }, indent=2),
                'explanation': 'Requires MFA and restricts to specific roles/regions for defense in depth.'
            })

        elif strategy == 'pass_role':
            actions.append({
                'action': 'Restrict iam:PassRole to Specific Roles',
                'description': 'Limit which roles can be passed to services like EC2, Lambda.',
                'priority': 'HIGH',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                    "After": {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::123456789012:role/AppSpecificRole"}
                }, indent=2),
                'explanation': 'Prevents passing privileged roles (e.g., AdminRole) to compute resources.'
            })

        elif strategy == 'create_role':
            actions.append({
                'action': 'Use Permissions Boundary for Role Creation',
                'description': 'Enforce permissions boundary on role creation to prevent escalation.',
                'priority': 'HIGH',
                'code_example': json.dumps({
                    "Condition": {
                        "StringEquals": {
                            "iam:PermissionsBoundary": "arn:aws:iam::123456789012:policy/RoleBoundary"
                        }
                    }
                }, indent=2),
                'explanation': 'Ensures any created role cannot exceed the boundary permissions.'
            })

        elif strategy == 'organizations':
            actions.append({
                'action': 'Restrict Organizations Management Actions',
                'description': 'Limit SCP attachment and account moves to a dedicated management-account break-glass role.',
                'priority': 'CRITICAL',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": "organizations:*", "Resource": "*"},
                    "After": {"Effect": "Allow", "Action": ["organizations:Describe*", "organizations:List*"], "Resource": "*"}
                }, indent=2),
                'explanation': 'SCP manipulation can disable guardrails for the entire organization.'
            })

        elif strategy == 'service_escalation':
            actions.append({
                'action': 'Restrict Service Role Passing',
                'description': 'Limit iam:PassRole to only the specific service roles needed.',
                'priority': 'MEDIUM',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": ["lambda:CreateFunction", "iam:PassRole"], "Resource": "*"},
                    "After": {
                        "Effect": "Allow",
                        "Action": "lambda:CreateFunction",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "iam:PassedToService": "lambda.amazonaws.com"
                            }
                        }
                    }
                }, indent=2),
                'explanation': 'Prevents passing admin roles to Lambda/EC2/Glue for code execution escalation.'
            })

        elif strategy == 'full_admin':
            actions.append({
                'action': 'Replace Wildcard with Least Privilege',
                'description': 'Replace "*" actions with specific required actions based on CloudTrail analysis.',
                'priority': 'CRITICAL',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": "*", "Resource": "*"},
                    "After": {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:PutObject",
                            "dynamodb:GetItem",
                            "dynamodb:PutItem"
                        ],
                        "Resource": [
                            "arn:aws:s3:::my-bucket/*",
                            "arn:aws:dynamodb:us-east-1:123456789012:table/my-table"
                        ]
                    }
                }, indent=2),
                'explanation': 'Full admin access violates least privilege. Use IAM Access Analyzer to generate policies from CloudTrail.'
            })

        elif strategy == 'service_wildcard':
            actions.append({
                'action': 'Replace Service Wildcard with Explicit Actions',
                'description': 'Enumerate the actions actually used for this service (via CloudTrail / IAM Access Analyzer) and list them explicitly instead of granting service:*.',
                'priority': 'HIGH',
                'code_example': json.dumps({
                    "Before": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                    "After": {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                        "Resource": ["arn:aws:s3:::my-app-bucket", "arn:aws:s3:::my-app-bucket/*"]
                    }
                }, indent=2),
                'explanation': 'A service wildcard silently grants every current and future action in that service, including newly released escalation paths.'
            })

        elif strategy == 'managed_policy_review':
            actions.append({
                'action': 'Review Attached Managed Policy',
                'description': 'Audit the attached managed policy for excessive permissions and replace with a scoped custom policy if needed.',
                'priority': 'MEDIUM',
                'code_example': json.dumps({
                    "Review": "aws iam get-policy-version --policy-arn <arn> --version-id <default>"
                }, indent=2),
                'explanation': 'Broad AWS-managed policies (e.g. PowerUserAccess) often exceed what the identity needs.'
            })

        if not actions:
            actions.append({
                'action': 'Review and Apply Least Privilege',
                'description': 'Analyze the specific permissions and remove unnecessary actions/resources.',
                'priority': severity,
                'code_example': json.dumps({
                    "Review": "Use IAM Access Analyzer to generate policy from CloudTrail logs"
                }, indent=2),
                'explanation': 'Generic remediation - analyze actual usage and restrict accordingly.'
            })

        return actions

    def _generate_hardened_policy(self, policy_doc: Dict, strategy: str) -> Dict:
        if not policy_doc:
            return {}

        statement = policy_doc.get('statement', policy_doc)
        if 'Statement' in policy_doc:
            statements = policy_doc['Statement']
        else:
            statements = [statement]

        hardened_statements = []
        for stmt in statements:
            if isinstance(stmt, dict):
                hardened = self._harden_statement(stmt, strategy)
                hardened_statements.append(hardened)

        if not hardened_statements:
            return {}

        return {
            "Version": "2012-10-17",
            "Statement": hardened_statements
        }

    def _harden_statement(self, statement: Dict, strategy: str) -> Dict:
        hardened = statement.copy()
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]

        if strategy in ('attach_policy', 'put_policy', 'policy_version'):
            hardened['Action'] = [a for a in actions if 'Attach' not in a and 'Put' not in a and 'PolicyVersion' not in a]
            if not hardened['Action']:
                hardened['Effect'] = 'Deny'
                hardened['Action'] = actions

        elif strategy == 'service_wildcard':
            # Keep the service prefix but drop the blanket wildcard.
            expanded = []
            for a in actions:
                if a.endswith(':*'):
                    service = a[:-2]
                    expanded.extend([f"{service}:Get*", f"{service}:List*", f"{service}:Describe*"])
                else:
                    expanded.append(a)
            hardened['Action'] = expanded

        elif strategy in ('access_key', 'login_profile'):
            if '*' in resources:
                hardened['Resource'] = ["arn:aws:iam::123456789012:user/${aws:username}"]

        elif strategy == 'assume_role':
            if '*' in resources:
                hardened['Resource'] = ["arn:aws:iam::123456789012:role/AllowedRole*"]
                hardened['Condition'] = {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                }

        elif strategy == 'pass_role':
            if '*' in resources:
                hardened['Resource'] = ["arn:aws:iam::123456789012:role/AppSpecificRole"]

        elif strategy == 'full_admin':
            hardened['Action'] = [
                "s3:GetObject", "s3:PutObject", "s3:ListBucket",
                "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query",
                "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"
            ]
            hardened['Resource'] = [
                "arn:aws:s3:::my-app-bucket/*",
                "arn:aws:dynamodb:us-east-1:123456789012:table/my-app-table",
                "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-function:*"
            ]

        # Add a region restriction as defense in depth (valid Condition form).
        condition = hardened.get('Condition')
        if not isinstance(condition, dict):
            condition = {}
        string_equals = condition.setdefault('StringEquals', {})
        if isinstance(string_equals, dict):
            string_equals.setdefault('aws:RequestedRegion', 'us-east-1')
        hardened['Condition'] = condition

        return hardened

    def _get_compliance_notes(self, strategy: str, severity: str) -> List[str]:
        notes = []

        if severity in ['CRITICAL', 'HIGH']:
            notes.append('CIS AWS Foundations 1.16 - Ensure IAM policies are attached only to groups or roles')
            notes.append('NIST 800-53 AC-6 - Least Privilege')
            notes.append('PCI-DSS 7.1 - Limit access to system components')

        if strategy in ('attach_policy', 'put_policy', 'policy_version', 'full_admin', 'service_wildcard'):
            notes.append('CIS 1.22 - Ensure IAM policies that allow "*" are not attached')

        if strategy == 'access_key':
            notes.append('CIS 1.13 - Ensure access keys are rotated every 90 days')
            notes.append('NIST 800-53 IA-5 - Authenticator Management')

        if strategy in ('assume_role', 'pass_role'):
            notes.append('CIS 1.17 - Ensure MFA is enabled for all IAM users')
            notes.append('NIST 800-53 AC-2 - Account Management')

        if not notes:
            notes.append('CIS AWS Foundations Benchmark')
            notes.append('NIST 800-53 Access Control Family')

        return notes
