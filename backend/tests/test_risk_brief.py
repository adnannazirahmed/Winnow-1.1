"""Evidence grounding and fallback behavior for the AI risk brief."""
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

    def complete(self, system, prompt, max_tokens):
        self.calls += 1
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
    def test_fallback_preserves_deterministic_metrics_and_references(self):
        brief = RiskBriefGenerator(FakeProvider(enabled=False)).generate(
            SUMMARY, FINDINGS, REMEDIATIONS, VISUALIZATION
        )
        self.assertEqual(brief['generated_by'], 'rules')
        self.assertEqual(brief['metrics']['critical'], 1)
        self.assertEqual(brief['risk_score'], 100)
        self.assertEqual(brief['top_priority']['finding_id'], 'VULN-0001')
        self.assertEqual(brief['top_priority']['next_action'], 'Allow only approved policy ARNs')

    def test_ai_prose_is_used_but_unknown_ids_and_actions_are_rejected(self):
        provider = FakeProvider('''{
          "headline": "Immediate administrator path",
          "assessment": "The account contains a direct escalation path.",
          "business_impact": "An attacker could gain administrator access.",
          "top_priority_id": "VULN-9999",
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
        self.assertEqual(brief['top_priority']['next_action'], 'Allow only approved policy ARNs')
        self.assertEqual([risk['finding_id'] for risk in brief['key_risks']], ['VULN-0002'])

    def test_identical_analysis_is_cached(self):
        provider = FakeProvider('{"headline":"Cached","top_priority_id":"VULN-0001"}')
        generator = RiskBriefGenerator(provider)
        generator.generate(SUMMARY, FINDINGS, REMEDIATIONS, VISUALIZATION)
        generator.generate(SUMMARY, FINDINGS, REMEDIATIONS, VISUALIZATION)
        self.assertEqual(provider.calls, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
