"""End-to-end merged pipeline, the /api/scan-account endpoint's offline behavior,
and the live AWS collector against a fake boto3 session."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

os.environ.pop('ANTHROPIC_API_KEY', None)

import iam_ingest
import aws_collector
from iam_analyzer import IAMAnalyzer

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return json.load(f)


class TestRunPipeline(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.run = app_module._run_pipeline

    def _result(self, source_name="static"):
        iam_data = iam_ingest.config_to_iamdata(IAMAnalyzer().generate_dummy_data(), 'terraform')
        return self.run(iam_data, source=source_name)

    def test_shape(self):
        r = self._result()
        self.assertIn('vulnerabilities', r)
        self.assertIn('remediations', r)
        self.assertEqual(len(r['vulnerabilities']), len(r['remediations']))
        for entry in r['remediations']:
            self.assertEqual(entry['remediation']['vulnerability_id'], entry['vulnerability']['id'])
        viz = r['visualization']
        for key in ('attack_graph', 'permission_graph', 'mitre_heatmap',
                    'resource_risk_map', 'remediation_timeline'):
            self.assertIn(key, viz)
        self.assertIn('nodes', viz['permission_graph'])
        self.assertGreater(r['summary']['total_vulnerabilities'], 5)

    def test_live_source_flag_and_account_id(self):
        iam_data = iam_ingest.parse_gaad(load_fixture("escalation_scenarios.json"), "424242424242")
        r = self.run(iam_data, source='live')
        self.assertEqual(r['summary']['source'], 'live')
        self.assertEqual(r['summary']['account_id'], "424242424242")
        self.assertGreater(r['summary']['graph_detected'], 0)

    def test_ids_deterministic(self):
        a = [v['id'] for v in self._result()['vulnerabilities']]
        b = [v['id'] for v in self._result()['vulnerabilities']]
        self.assertEqual(a, b)
        self.assertEqual(a[0], 'VULN-0001')

    def test_graph_finding_wins_over_rule_finding(self):
        # BadActor1's inline policy has iam:AttachUserPolicy: the graph engine
        # flags it as a reachable escalation, the rule scan flags the raw
        # permission. Only one survives per (identity, pattern_id).
        iam_data = iam_ingest.parse_gaad(load_fixture("escalation_scenarios.json"), "123")
        r = self.run(iam_data, source='static')
        pairs = [(v['resource_name'], v['pattern_id']) for v in r['vulnerabilities']]
        self.assertEqual(len(pairs), len(set(pairs)))


class TestScanAccountEndpoint(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.client = app_module.app.test_client()

    def test_no_boto3(self):
        with mock.patch.object(aws_collector, '_BOTO_OK', False):
            resp = self.client.post('/api/scan-account')
        self.assertEqual(resp.status_code, 501)
        self.assertIn('boto3', resp.get_json()['error'])

    def test_no_credentials(self):
        def boom():
            raise aws_collector.NoCredentials("nope")
        with mock.patch.object(aws_collector, 'collect_account_authorization_details', boom):
            resp = self.client.post('/api/scan-account')
        self.assertEqual(resp.status_code, 400)
        self.assertNotIn('Traceback', resp.get_data(as_text=True))

    def test_access_denied(self):
        def boom():
            raise aws_collector.AccessDenied("AccessDenied")
        with mock.patch.object(aws_collector, 'collect_account_authorization_details', boom):
            resp = self.client.post('/api/scan-account')
        self.assertEqual(resp.status_code, 403)

    def test_successful_scan_via_fake_collector(self):
        raw = load_fixture("escalation_scenarios.json")
        with mock.patch.object(aws_collector, 'collect_account_authorization_details',
                               lambda: (raw, "555555555555")):
            resp = self.client.post('/api/scan-account')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['summary']['source'], 'live')
        self.assertEqual(data['summary']['account_id'], "555555555555")
        self.assertGreater(data['summary']['total_vulnerabilities'], 0)


class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        yield from self._pages


class _FakeIam:
    def __init__(self, pages, error=None):
        self._pages = pages
        self._error = error

    def get_paginator(self, name):
        if self._error:
            raise self._error
        return _FakePaginator(self._pages)


class _FakeSts:
    def get_caller_identity(self):
        return {"Account": "999888777666"}


class _FakeSession:
    def __init__(self, pages, iam_error=None):
        self._pages = pages
        self._iam_error = iam_error

    def client(self, name):
        if name == "iam":
            return _FakeIam(self._pages, self._iam_error)
        if name == "sts":
            return _FakeSts()
        raise ValueError(name)


class TestAwsCollector(unittest.TestCase):
    def test_merges_pages_and_resolves_account(self):
        pages = [
            {"UserDetailList": [{"UserName": "a"}], "RoleDetailList": []},
            {"UserDetailList": [{"UserName": "b"}], "Policies": [{"PolicyName": "p"}]},
        ]
        with mock.patch.object(aws_collector, '_BOTO_OK', True), \
             mock.patch.object(aws_collector, '_session', lambda: _FakeSession(pages)):
            raw, account = aws_collector.collect_account_authorization_details()
        self.assertEqual([u["UserName"] for u in raw["UserDetailList"]], ["a", "b"])
        self.assertEqual(raw["Policies"], [{"PolicyName": "p"}])
        self.assertEqual(account, "999888777666")

    def test_access_denied_maps_to_typed_error(self):
        class FakeClientError(Exception):
            response = {"Error": {"Code": "AccessDenied"}}

        with mock.patch.object(aws_collector, '_BOTO_OK', True), \
             mock.patch.object(aws_collector, 'ClientError', FakeClientError), \
             mock.patch.object(aws_collector, '_session',
                               lambda: _FakeSession([], iam_error=FakeClientError())):
            with self.assertRaises(aws_collector.AccessDenied):
                aws_collector.collect_account_authorization_details()

    def test_boto3_absent(self):
        with mock.patch.object(aws_collector, '_BOTO_OK', False):
            with self.assertRaises(aws_collector.BotoNotInstalled):
                aws_collector.collect_account_authorization_details()


if __name__ == '__main__':
    unittest.main(verbosity=2)
