import os
import json
import logging
import re
from typing import Dict, List, Any

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}

MITRE_TECHNIQUES = [
    'T1098.001', 'T1098.003', 'T1098.004', 'T1098.005',
    'T1550.001', 'T1484.002', 'T1611', 'T1078.004', 'T1530'
]

class AIDetector:
    """Optional AI second pass that finds privilege escalation paths the
    static rule engine (iam_analyzer) does not cover. Its findings are merged
    with the static findings and surfaced to the user as "AI Suggested"."""

    SYSTEM_PROMPT = """You are a senior AWS IAM security researcher specializing in privilege escalation.

You are given an AWS IAM configuration (Terraform plan JSON, raw IAM policy JSON, or iam-vulnerable output) and a list of vulnerabilities ALREADY detected by a deterministic rule engine.

Your job: find ADDITIONAL privilege escalation paths that the rule engine MISSED. Look for subtle misconfigurations such as:
- Dangerous permissions not in the known list (e.g. iam:TagUser/iam:TagRole abuse, iam:CreateLoginProfile, iam:SetDefaultPolicyVersion)
- Missing restrictive Condition keys on sensitive actions
- Overly broad Resource values combined with powerful actions
- Permissions boundaries that are missing or ineffective
- Service-linked role / trust-policy misconfigurations
- Cross-account role assumptions without ExternalId

RULES:
1. Do NOT repeat anything already detected (compare by title and action).
2. Only report REAL, credible escalation paths — never invent findings.
3. If nothing additional is found, return an empty list.
4. Output ONLY valid JSON, no markdown, no commentary."""

    PROMPT_TEMPLATE = """IAM Configuration:
{config}

Already detected by the rule engine (DO NOT repeat these):
{known}

Return additional findings as a JSON array with this exact structure:
[
  {{
    "title": "Short finding title",
    "description": "What the misconfiguration allows and why it is risky",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "resource_type": "aws_iam_policy|aws_iam_role|aws_iam_user|aws_iam_group",
    "resource_name": "The identity or policy name from the config",
    "action": "The problematic IAM action",
    "mitre_techniques": ["T1098.001"],
    "remediation_hint": "One sentence on how to fix it"
  }}
]

Return an empty array [] if there are no additional findings."""

    def __init__(self):
        self.client = None
        self.api_key = os.environ.get('ANTHROPIC_API_KEY')
        if self.api_key and ANTHROPIC_AVAILABLE:
            try:
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Failed to init Anthropic client: {e}")
                self.client = None
        else:
            logger.info("No ANTHROPIC_API_KEY set — AI detection pass skipped.")

    @property
    def enabled(self) -> bool:
        return self.client is not None

    def detect(self, iam_config: Any, static_findings: List[Dict]) -> List[Dict]:
        if not self.client:
            return []

        try:
            known = self._summarize_known(static_findings)
            prompt = self.PROMPT_TEMPLATE.format(
                config=json.dumps(iam_config, indent=2, default=str)[:12000],
                known=known
            )

            response = self.client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=3000,
                temperature=0.1,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )

            raw = response.content[0].text
            items = self._parse_json(raw)
            return self._normalize(items, iam_config)
        except Exception as e:
            logger.error(f"AI detection failed: {e}")
            return []

    def _summarize_known(self, static_findings: List[Dict]) -> str:
        lines = []
        for f in static_findings:
            lines.append(f"- {f.get('title', '')} (action: {self._first_action(f)})")
        if not lines:
            return "- (none)"
        return "\n".join(lines)

    def _first_action(self, finding: Dict) -> str:
        pd = finding.get('policy_document', {})
        action = pd.get('action')
        if isinstance(action, list):
            return ', '.join(action)
        stmt = pd.get('statement', {})
        if isinstance(stmt, dict):
            a = stmt.get('Action', '')
            if isinstance(a, list):
                return ', '.join(a)
            return str(a)
        return str(action or '')

    def _parse_json(self, raw: str) -> List[Dict]:
        raw = raw.strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            m = re.search(r'\[.*\]', raw, re.DOTALL)
            if not m:
                return []
            try:
                data = json.loads(m.group(0))
            except json.JSONDecodeError:
                return []
        if isinstance(data, dict):
            data = data.get('findings', data.get('vulnerabilities', []))
        if not isinstance(data, list):
            return []
        return [x for x in data if isinstance(x, dict)]

    def _normalize(self, items: List[Dict], iam_config: Any) -> List[Dict]:
        findings = []
        for i, item in enumerate(items):
            severity = str(item.get('severity', 'MEDIUM')).upper()
            if severity not in VALID_SEVERITIES:
                severity = 'MEDIUM'
            mitre = [t for t in item.get('mitre_techniques', []) if str(t) in MITRE_TECHNIQUES]
            if not mitre:
                mitre = ['T1098.001']

            findings.append({
                'id': f"AI-{i + 1:04d}",
                'title': str(item.get('title', 'Untitled AI finding')).strip(),
                'description': str(item.get('description', '')).strip(),
                'severity': severity,
                'resource_type': str(item.get('resource_type', 'aws_iam_policy')),
                'resource_name': str(item.get('resource_name', 'unknown')),
                'policy_document': {
                    'action': item.get('action', ''),
                    'statement': {},
                    'ai_source': True
                },
                'attack_path': [
                    f"Identity: {item.get('resource_name', 'unknown')}",
                    f"Action: {item.get('action', 'unknown')}"
                ],
                'mitre_techniques': mitre,
                'remediation_hint': str(item.get('remediation_hint', '')),
                'detection_source': 'ai'
            })
        return findings

    def dedupe(self, static_findings: List[Dict], ai_findings: List[Dict]) -> List[Dict]:
        """Drop AI findings that overlap with a static finding (same action)."""
        static_actions = set()
        for f in static_findings:
            pd = f.get('policy_document', {})
            for a in self._extract_actions(pd):
                static_actions.add(a.lower())

        kept = []
        for af in ai_findings:
            ai_action = str(af.get('policy_document', {}).get('action', '')).lower()
            if ai_action and ai_action in static_actions:
                continue
            kept.append(af)
        return kept

    def _extract_actions(self, pd: Dict) -> List[str]:
        actions = []
        a = pd.get('action')
        if isinstance(a, list):
            actions.extend(a)
        elif isinstance(a, str):
            actions.append(a)
        stmt = pd.get('statement', {})
        if isinstance(stmt, dict):
            sa = stmt.get('Action', [])
            if isinstance(sa, list):
                actions.extend(sa)
            elif isinstance(sa, str):
                actions.append(sa)
        return [str(x) for x in actions]
