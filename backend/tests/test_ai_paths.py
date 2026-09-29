"""Tests for the AI code paths, exercised with a stub Anthropic client so they
run without an API key (and without spending money)."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from iam_analyzer import IAMAnalyzer
from remediator import Remediator
from ai_detector import AIDetector


class FakeBlock:
    def __init__(self, text):
        self.text = text


class FakeResponse:
    def __init__(self, text):
        self.content = [FakeBlock(text)]


class FakeMessages:
    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        reply = self._replies[min(self.calls - 1, len(self._replies) - 1)]
        if isinstance(reply, Exception):
            raise reply
        return FakeResponse(reply)


class FakeClient:
    def __init__(self, replies):
        self.messages = FakeMessages(replies)


GOOD_REMEDIATION = '''Sure, here is the analysis:
```json
{"summary": "Risky", "risk_score": 88, "actions": [{"action": "Fix it", "description": "d",
 "priority": "CRITICAL", "code_example": "{}", "explanation": "e"}],
 "hardened_policy": {"Version": "2012-10-17", "Statement": [
   {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "arn:aws:iam::<ACCOUNT_ID>:user/<TARGET_USER_NAME>"}
 ]}, "compliance_notes": ["CIS 1.16"]}
```'''


class TestRemediatorAIPath(unittest.TestCase):
    def setUp(self):
        self.analyzer = IAMAnalyzer()
        self.vulns = [
            vuln for vuln in self.analyzer.analyze(
                self.analyzer.generate_dummy_data(), 'terraform'
            )
            if (vuln.get('policy_document') or {}).get('statement')
        ]

    def _remediator(self, replies, max_calls=5):
        with mock.patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key',
                                          'MAX_AI_REMEDIATIONS': str(max_calls)}):
            with mock.patch('remediator.ANTHROPIC_AVAILABLE', True), \
                 mock.patch('remediator.anthropic') as anth:
                anth.Anthropic.return_value = FakeClient(replies)
                return Remediator()

    def test_ai_response_with_prose_and_fences_is_used(self):
        rem = self._remediator([GOOD_REMEDIATION])
        result = rem.get_remediation(self.vulns[0])
        self.assertEqual(result['source'], 'ai')
        self.assertEqual(result['risk_score'], 88)
        self.assertEqual(result['actions'][0]['action'], 'Fix it')

    def test_unparseable_response_is_explicitly_unavailable(self):
        rem = self._remediator(['I cannot help with that.'])
        result = rem.get_remediation(self.vulns[0])
        self.assertEqual(result['source'], 'unavailable')
        self.assertEqual(result['actions'], [])
        self.assertEqual(result['validation']['status'], 'no_proposal')

    def test_api_exception_is_explicitly_unavailable(self):
        rem = self._remediator([RuntimeError('rate limited')])
        result = rem.get_remediation(self.vulns[0])
        self.assertEqual(result['source'], 'unavailable')
        self.assertEqual(result['actions'], [])
        self.assertIn('RuntimeError', result['error'])

    def test_ai_calls_are_capped_per_batch(self):
        """A large finding set must not trigger one call per finding."""
        rem = self._remediator([GOOD_REMEDIATION], max_calls=3)
        results = rem.batch_remediate(self.vulns)
        self.assertEqual(len(results), len(self.vulns))
        self.assertLessEqual(rem.client.messages.calls, 3,
                             "AI calls exceeded the configured per-batch cap")
        self.assertEqual(results[0]['source'], 'ai')
        limited = [r for r in results if 'call limit' in r.get('error', '')]
        self.assertTrue(limited)
        self.assertTrue(all(not r['actions'] for r in limited))

    def test_identical_findings_hit_cache_not_the_api(self):
        rem = self._remediator([GOOD_REMEDIATION], max_calls=50)
        vuln = self.vulns[0]
        rem.get_remediation(vuln)
        first_calls = rem.client.messages.calls
        for _ in range(5):
            rem.get_remediation(dict(vuln))
        self.assertEqual(rem.client.messages.calls, first_calls,
                         "Repeated identical findings should be served from cache")

    def test_policy_explainer_shape_is_normalized(self):
        response = '''{
          "summary": "The policy permits broad attachment.",
          "risk_score": 90,
          "risks": ["Arbitrary managed policies can be attached."],
          "recommendations": ["Restrict attachment to an approved user and policy."],
          "hardened_policy": {
            "Statement": {
              "Effect": "Allow",
              "Action": "iam:AttachUserPolicy",
              "Resource": "arn:aws:iam::<ACCOUNT_ID>:user/<TARGET_USER_NAME>"
            }
          }
        }'''
        rem = self._remediator([response])
        result = rem.get_remediation(self.vulns[0])
        self.assertEqual(result['source'], 'ai')
        self.assertEqual(len(result['hardened_policy']['Statement']), 1)
        self.assertEqual(result['risks'][0], 'Arbitrary managed policies can be attached.')
        self.assertEqual(len(result['actions']), 1)

    def test_invalid_first_policy_is_repaired_once(self):
        invalid = '''{
          "summary": "Assessment", "actions": [{"action": "Review"}],
          "hardened_policy": {"Version": "2012-10-17", "Statement": []}
        }'''
        rem = self._remediator([invalid, GOOD_REMEDIATION])
        result = rem.get_remediation(self.vulns[0])
        self.assertEqual(result['source'], 'ai')
        self.assertEqual(rem.client.messages.calls, 2)

    def test_policy_scope_validator_rejects_new_actions(self):
        original = {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Action': 'iam:GetUser', 'Resource': '*',
        }]}
        narrower = {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Action': 'iam:GetUser',
            'Resource': 'arn:aws:iam::123456789012:user/alice',
        }]}
        broader = {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Action': ['iam:GetUser', 'iam:DeleteUser'],
            'Resource': '*',
        }]}
        self.assertTrue(Remediator._does_not_broaden(original, narrower))
        self.assertFalse(Remediator._does_not_broaden(original, broader))

    def test_condition_keys_are_checked_against_actions(self):
        original = {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Action': 'iam:CreatePolicyVersion', 'Resource': '*',
        }]}
        wrong_key = {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Action': 'iam:CreatePolicyVersion', 'Resource': '*',
            'Condition': {'ArnEquals': {'iam:PolicyARN': 'arn:example'}},
        }]}
        pass_role = {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': '*',
            'Condition': {'StringEquals': {'iam:PassedToService': 'lambda.amazonaws.com'}},
        }]}
        self.assertEqual(
            Remediator._unsupported_added_condition_keys(original, wrong_key),
            ['iam:policyarn'],
        )
        self.assertEqual(
            Remediator._unsupported_added_condition_keys(
                {'Version': '2012-10-17', 'Statement': [{
                    'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': '*',
                }]},
                pass_role,
            ),
            [],
        )

    def test_timeout_is_configured(self):
        with mock.patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'k', 'ANTHROPIC_TIMEOUT_SECONDS': '12'}):
            with mock.patch('remediator.ANTHROPIC_AVAILABLE', True), \
                 mock.patch('remediator.anthropic') as anth:
                Remediator()
                kwargs = anth.Anthropic.call_args.kwargs
                self.assertEqual(kwargs['timeout'], 12.0)
                self.assertEqual(kwargs['max_retries'], 1)


class TestAIDetector(unittest.TestCase):
    def _detector(self, replies):
        with mock.patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
            with mock.patch('ai_detector.ANTHROPIC_AVAILABLE', True), \
                 mock.patch('ai_detector.anthropic') as anth:
                anth.Anthropic.return_value = FakeClient(replies)
                return AIDetector()

    def test_disabled_without_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(AIDetector().enabled)

    def test_findings_normalized_and_tagged(self):
        payload = '[{"title": "Tag abuse", "description": "d", "severity": "wat", ' \
                  '"resource_type": "aws_iam_user", "resource_name": "bob", ' \
                  '"action": "iam:TagUser", "mitre_techniques": ["BOGUS"], "remediation_hint": "h"}]'
        det = self._detector([payload])
        findings = det.detect({'x': 1}, [])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f['severity'], 'MEDIUM')       # invalid severity normalized
        self.assertEqual(f['mitre_techniques'], ['T1098.001'])  # bogus technique dropped
        self.assertEqual(f['detection_source'], 'ai')
        self.assertTrue(f['id'].startswith('AI-'))

    def test_malformed_response_yields_no_findings(self):
        det = self._detector(['not json at all'])
        self.assertEqual(det.detect({'x': 1}, []), [])

    def test_dedupe_drops_overlap_with_static(self):
        det = self._detector(['[]'])
        static = [{'policy_document': {'action': 'iam:PassRole'}}]
        ai = [
            {'policy_document': {'action': 'iam:PassRole'}, 'title': 'dup'},
            {'policy_document': {'action': 'iam:TagUser'}, 'title': 'new'},
        ]
        kept = det.dedupe(static, ai)
        self.assertEqual([k['title'] for k in kept], ['new'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
