"""Smoke tests for the IAM Remediation Assistant backend.

Run from the backend directory:  python -m pytest tests/ -q
or without pytest:               python tests/test_backend.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from iam_analyzer import IAMAnalyzer
from remediator import Remediator, PATTERN_STRATEGY
from visualizer import Visualizer


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = IAMAnalyzer()

    def test_dummy_data_detects_vulnerabilities(self):
        config = self.analyzer.generate_dummy_data()
        vulns = self.analyzer.analyze(config, 'terraform')
        self.assertGreater(len(vulns), 5)
        self.assertTrue(all(v['id'].startswith('VULN-') for v in vulns))
        self.assertTrue(all(v.get('pattern_id') for v in vulns))

    def test_ids_are_deterministic_across_calls(self):
        config = self.analyzer.generate_dummy_data()
        first = self.analyzer.analyze(config, 'terraform')
        second = self.analyzer.analyze(config, 'terraform')
        self.assertEqual([v['id'] for v in first], [v['id'] for v in second])
        self.assertEqual(first[0]['id'], 'VULN-0001')

    def test_wildcard_admin_detected(self):
        config = {'Policy': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}
        vulns = self.analyzer.analyze(config, 'json')
        # Exactly one finding: a bare "*" must not fan out across every pattern.
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]['pattern_id'], 'full_admin')
        self.assertEqual(vulns[0]['severity'], 'CRITICAL')

    def test_service_wildcard_summarized_once(self):
        config = {'Policy': {'Statement': [{'Effect': 'Allow', 'Action': 'iam:*', 'Resource': '*'}]}}
        vulns = self.analyzer.analyze(config, 'json')
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]['pattern_id'], 'service_wildcard')
        self.assertEqual(vulns[0]['severity'], 'CRITICAL')

    def test_prefix_wildcard_matches_patterns(self):
        config = {'Policy': {'Statement': [{'Effect': 'Allow', 'Action': 'iam:Attach*', 'Resource': '*'}]}}
        vulns = self.analyzer.analyze(config, 'json')
        patterns = {v['pattern_id'] for v in vulns}
        self.assertIn('iam:AttachUserPolicy', patterns)
        self.assertIn('iam:AttachRolePolicy', patterns)
        self.assertNotIn('iam:CreateAccessKey', patterns)

    def test_non_string_actions_ignored(self):
        config = {'Policy': {'Statement': [{'Effect': 'Allow', 'Action': [None, 42, 'iam:PassRole'], 'Resource': '*'}]}}
        vulns = self.analyzer.analyze(config, 'json')
        self.assertEqual([v['pattern_id'] for v in vulns], ['iam:PassRole'])

    def test_deny_statements_ignored(self):
        config = {'Policy': {'Statement': [{'Effect': 'Deny', 'Action': 'iam:AttachUserPolicy', 'Resource': '*'}]}}
        vulns = self.analyzer.analyze(config, 'json')
        self.assertEqual(vulns, [])


class TestRemediator(unittest.TestCase):
    def setUp(self):
        os.environ.pop('ANTHROPIC_API_KEY', None)
        self.remediator = Remediator()
        self.analyzer = IAMAnalyzer()

    def test_every_analyzer_pattern_has_a_strategy(self):
        """The analyzer <-> remediator contract: every static pattern the
        analyzer can emit must map to a remediation strategy."""
        for pattern in IAMAnalyzer.PRIVILEGE_ESCALATION_PATTERNS:
            self.assertIn(pattern, PATTERN_STRATEGY, f"No remediation strategy for {pattern}")
        self.assertIn('full_admin', PATTERN_STRATEGY)
        self.assertIn('attached_managed_policy', PATTERN_STRATEGY)

    def test_fallback_remediation_is_specific(self):
        config = self.analyzer.generate_dummy_data()
        vulns = self.analyzer.analyze(config, 'terraform')
        results = self.remediator.batch_remediate(vulns)
        self.assertEqual(len(results), len(vulns))
        for vuln, rem in zip(vulns, results):
            self.assertEqual(rem['vulnerability_id'], vuln['id'])
            self.assertTrue(rem['actions'])
        # Known patterns should not fall through to the generic action.
        attach_vuln = next(v for v in vulns if v['pattern_id'] == 'iam:AttachUserPolicy')
        rem = self.remediator.get_remediation(attach_vuln)
        self.assertIn('Attach', rem['actions'][0]['action'])

    def test_cache_rebinds_vulnerability_id(self):
        vuln_a = {'id': 'VULN-0001', 'pattern_id': 'iam:PassRole', 'title': 'Pass Role to Services',
                  'severity': 'HIGH', 'resource_name': 'r1', 'policy_document': {'action': 'iam:PassRole'}}
        vuln_b = dict(vuln_a, id='VULN-0099')
        rem_a = self.remediator.get_remediation(vuln_a)
        rem_b = self.remediator.get_remediation(vuln_b)
        self.assertEqual(rem_a['vulnerability_id'], 'VULN-0001')
        self.assertEqual(rem_b['vulnerability_id'], 'VULN-0099')

    def test_json_parsing_tolerates_prose_and_fences(self):
        parse = Remediator._parse_json_object
        self.assertEqual(parse('{"a": 1}'), {'a': 1})
        self.assertEqual(parse('Here you go:\n```json\n{"a": 1}\n```\nEnjoy!'), {'a': 1})
        self.assertEqual(parse('Some text {"a": 1} trailing'), {'a': 1})
        self.assertIsNone(parse('no json here'))
        self.assertIsNone(parse(''))

    def test_hardened_condition_is_valid_shape(self):
        vuln = {'id': 'VULN-0001', 'pattern_id': 'sts:AssumeRole', 'title': 'Role Assumption',
                'severity': 'HIGH', 'resource_name': 'r1',
                'policy_document': {'statement': {'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Resource': '*'}}}
        rem = self.remediator.get_remediation(vuln)
        stmt = rem['hardened_policy']['Statement'][0]
        cond = stmt.get('Condition', {})
        # Condition values must be nested under operators, not bare keys.
        for op, kv in cond.items():
            self.assertIsInstance(kv, dict, f"Condition operator {op} must map to a dict")


class TestVisualizer(unittest.TestCase):
    def setUp(self):
        self.visualizer = Visualizer()
        self.analyzer = IAMAnalyzer()
        os.environ.pop('ANTHROPIC_API_KEY', None)
        self.remediator = Remediator()

    def _results(self):
        config = self.analyzer.generate_dummy_data()
        vulns = self.analyzer.analyze(config, 'terraform')
        rems = self.remediator.batch_remediate(vulns)
        return [{'vulnerability': v, 'remediation': r} for v, r in zip(vulns, rems)]

    def test_generate_produces_all_sections(self):
        viz = self.visualizer.generate(self._results())
        for key in ('attack_graph', 'severity_distribution', 'resource_risk_map',
                    'remediation_timeline', 'mitre_heatmap',
                    'privilege_escalation_chains', 'summary_stats'):
            self.assertIn(key, viz)
        self.assertTrue(viz['attack_graph']['nodes'])
        self.assertTrue(viz['attack_graph']['edges'])

    def test_chain_max_severity_is_the_worst(self):
        results = self._results()
        chains = self.visualizer.generate(results)['privilege_escalation_chains']
        self.assertTrue(chains)
        rank = Visualizer.SEVERITY_RANK
        for chain in chains:
            worst_step = min(rank.get(s['severity'], 2) for s in chain['steps'])
            self.assertEqual(rank[chain['max_severity']], worst_step,
                             f"max_severity {chain['max_severity']} is not the worst in chain")

    def test_risk_map_sorted_by_risk_desc(self):
        resources = self.visualizer.generate(self._results())['resource_risk_map']['resources']
        scores = [r['risk_score'] for r in resources]
        self.assertEqual(scores, sorted(scores, reverse=True))


class TestApp(unittest.TestCase):
    def setUp(self):
        os.environ.pop('ANTHROPIC_API_KEY', None)
        import app as app_module
        self.app = app_module.app.test_client()

    def test_health(self):
        resp = self.app.get('/health')
        self.assertEqual(resp.status_code, 200)

    def test_analyze_requires_config(self):
        resp = self.app.post('/api/analyze', json={})
        self.assertEqual(resp.status_code, 400)

    def test_analyze_dummy_roundtrip(self):
        dummy = self.app.post('/api/generate-dummy').get_json()
        resp = self.app.post('/api/analyze', json={'iam_config': dummy['iam_config'], 'config_type': 'terraform'})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreater(data['summary']['total_vulnerabilities'], 5)
        self.assertEqual(len(data['vulnerabilities']), len(data['remediations']))

    def test_analyze_bad_body_no_error_leak(self):
        resp = self.app.post('/api/analyze', data='not json', content_type='application/json')
        self.assertEqual(resp.status_code, 400)

    def test_serves_frontend(self):
        resp = self.app.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'IAM Remediation', resp.data)


if __name__ == '__main__':
    unittest.main(verbosity=2)
