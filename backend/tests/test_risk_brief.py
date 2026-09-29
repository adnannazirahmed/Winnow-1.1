"""Evidence grounding and explicit failure behavior for the AI risk brief."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from risk_brief import RiskBriefGenerator


class FakeProvider:
    def __init__(self, response=None, enabled=True):
        self.response = response
        self.enabled = enabled
        self.name = 'openai' if enabled else ''
        self.calls = 0
        self.last_prompt = ''
        self.last_max_tokens = 0

    def complete(self, system, prompt, max_tokens):
        self.calls += 1
        self.last_prompt = prompt
        self.last_max_tokens = max_tokens
        return self.response


SUMMARY = {
    'total_vulnerabilities': 2, 'critical': 1, 'high': 1, 'medium': 0, 'low': 0,
    'escalation_paths': 2, 'identity_count': 3, 'policy_count': 4,
    'source': 'live', 'account_id': '123456789012',
    'coverage': {'complete': True, 'warnings': []},
}
FINDINGS = [
    {'id': 'VULN-0001', 'title': 'Attach admin policy', 'severity': 'CRITICAL',
     'resource_name': 'alice', 'description': 'Can attach arbitrary managed policies.',
     'attack_path': ['alice', 'iam:AttachUserPolicy', 'admin'], 'mitre_techniques': ['T1098.001']},
    {'id': 'VULN-0002', 'title': 'Pass privileged role', 'severity': 'HIGH',
     'resource_name': 'builder', 'description': 'Can pass a privileged role.',
     'attack_path': ['builder', 'iam:PassRole'], 'mitre_techniques': ['T1098.003']},
]
REMEDIATIONS = [
    {'vulnerability': FINDINGS[0], 'remediation': {
        'vulnerability_id': 'VULN-0001', 'summary': 'Restrict policy attachment.',
        'actions': [{'action': 'Allow only approved policy ARNs', 'description': 'Scope the condition.', 'priority': 'CRITICAL'}],
        'validation_status': 'review_required', 'required_inputs': [],
    }},
    {'vulnerability': FINDINGS[1], 'remediation': {
        'vulnerability_id': 'VULN-0002', 'summary': 'Scope PassRole.',
        'actions': [{'action': 'Restrict iam:PassRole', 'description': 'Limit role ARNs.', 'priority': 'HIGH'}],
        'validation_status': 'review_required', 'required_inputs': [],
    }},
]
VISUALIZATION = {'resource_risk_map': {'resources': [
    {'name': 'alice', 'risk_score': 100, 'total': 1, 'critical': 1, 'high': 0},
    {'name': 'builder', 'risk_score': 75, 'total': 1, 'critical': 0, 'high': 1},
]}}


class TestRiskBrief(unittest.TestCase):
    def test_disabled_provider_returns_unavailable_without_a_report(self):
        brief = RiskBriefGenerator(FakeProvider(enabled=False)).generate(
            SUMMARY, FINDINGS, REMEDIATIONS, VISUALIZATION
        )
        self.assertEqual(brief['generated_by'], 'unavailable')
        self.assertEqual(brief['status'], 'unavailable')
        self.assertEqual(brief['metrics']['critical'], 1)
        self.assertEqual(brief['headline'], '')
        self.assertIsNone(brief['top_priority'])
        self.assertEqual(brief['key_risks'], [])

    def test_ai_prose_is_used_but_unknown_ids_and_actions_are_rejected(self):
        provider = FakeProvider('''{
          "headline": "Immediate administrator path",
          "assessment": "The account contains a direct escalation path.",
          "business_impact": "An attacker could gain administrator access.",
          "top_priority_id": "VULN-0001",
          "priority_reason": "Handle the direct policy attachment path first.",
          "next_action": "Delete every IAM user",
          "key_risk_ids": ["VULN-9999", "VULN-0002"],
          "confidence_note": "The supplied IAM inventory has complete supported coverage."
        }''')
        brief = RiskBriefGenerator(provider).generate(SUMMARY, FINDINGS, REMEDIATIONS, VISUALIZATION)
        self.assertEqual(brief['generated_by'], 'ai')
        self.assertEqual(brief['headline'], 'Immediate administrator path')
        self.assertEqual(brief['metrics']['critical'], 1)
        self.assertEqual(brief['top_priority']['finding_id'], 'VULN-0001')
        self.assertEqual(brief['top_priority']['next_action'], '')
        self.assertEqual([risk['finding_id'] for risk in brief['key_risks']], ['VULN-0002'])

    def test_unknown_top_priority_rejects_the_ai_report(self):
        provider = FakeProvider('''{
          "headline": "Immediate administrator path",
          "assessment": "The account contains a direct escalation path.",
          "business_impact": "An attacker could gain administrator access.",
          "top_priority_id": "VULN-9999",
          "priority_reason": "Handle this first.",
          "next_action": "Delete everything",
          "key_risk_ids": [],
          "confidence_note": "Complete supported coverage."
        }''')
        brief = RiskBriefGenerator(provider).generate(SUMMARY, FINDINGS, REMEDIATIONS, VISUALIZATION)
        self.assertEqual(brief['generated_by'], 'unavailable')
        self.assertIn('ungrounded', brief['error'])

    def test_reasoning_braces_before_final_object_are_ignored(self):
        raw = '''Reasoning example {not valid JSON} and {"example": true}.
        ```json
        {
          "headline":"Grounded", "assessment":"Grounded assessment.",
          "business_impact":"Grounded impact.", "top_priority_id":"VULN-0001",
          "priority_reason":"Highest risk.",
          "next_action":"Allow only approved policy ARNs",
          "key_risk_ids":["VULN-0001"], "confidence_note":"Complete coverage."
        }
        ```'''
        parsed = RiskBriefGenerator._parse_object(raw)
        self.assertEqual(parsed['headline'], 'Grounded')
        self.assertEqual(parsed['top_priority_id'], 'VULN-0001')

    def test_large_scan_prompt_is_bounded_to_highest_risk_findings(self):
        provider = FakeProvider('''{
          "headline":"Bounded", "assessment":"Grounded assessment.",
          "business_impact":"Grounded impact.", "top_priority_id":"VULN-0001",
          "priority_reason":"Highest risk.",
          "next_action":"Allow only approved policy ARNs",
          "key_risk_ids":["VULN-0001"], "confidence_note":"Complete coverage."
        }''')
        findings = FINDINGS + [
            {
                'id': f'VULN-{index:04d}', 'title': f'Finding {index}',
                'severity': 'LOW', 'resource_name': f'resource-{index}',
                'description': 'x' * 1000, 'attack_path': ['a'] * 20,
                'mitre_techniques': [],
            }
            for index in range(3, 103)
        ]
        summary = dict(SUMMARY, total_vulnerabilities=len(findings), low=100)
        brief = RiskBriefGenerator(provider).generate(
            summary, findings, REMEDIATIONS, VISUALIZATION
        )
        prompt_evidence = __import__('json').loads(
            provider.last_prompt.split('Complete Winnow analysis:\n', 1)[1]
        )
        self.assertEqual(brief['generated_by'], 'ai')
        self.assertEqual(
            len(prompt_evidence['findings']), RiskBriefGenerator.PROMPT_FINDING_LIMIT
        )
        self.assertEqual(prompt_evidence['findings'][0]['id'], 'VULN-0001')
        self.assertEqual(prompt_evidence['finding_selection']['total'], 102)
        self.assertEqual(provider.last_max_tokens, 2000)

    def test_identical_analysis_is_cached(self):
        provider = FakeProvider('''{
          "headline":"Cached", "assessment":"Grounded assessment.",
          "business_impact":"Grounded impact.", "top_priority_id":"VULN-0001",
          "priority_reason":"Highest risk.",
          "next_action":"Allow only approved policy ARNs",
          "key_risk_ids":["VULN-0001"], "confidence_note":"Complete coverage."
        }''')
        generator = RiskBriefGenerator(provider)
        generator.generate(SUMMARY, FINDINGS, REMEDIATIONS, VISUALIZATION)
        generator.generate(SUMMARY, FINDINGS, REMEDIATIONS, VISUALIZATION)
        self.assertEqual(provider.calls, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
