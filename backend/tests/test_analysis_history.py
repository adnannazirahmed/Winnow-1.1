"""Persistence and API tests for local completed-analysis history."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analysis_history import AnalysisHistoryStore
import app as app_module


def result(name='Pasted JSON', finding_id='VULN-0001'):
    finding = {
        'id': finding_id, 'title': 'Broad policy', 'severity': 'HIGH',
        'resource_name': 'RoleA', 'resource_type': 'aws_iam_role',
    }
    return {
        'vulnerabilities': [finding],
        'remediations': [{
            'vulnerability': finding,
            'remediation': {
                'vulnerability_id': finding_id, 'source': 'deterministic',
                'actions': [], 'hardened_policy': {},
            },
        }],
        'visualization': {'permission_graph': {'nodes': [], 'links': []}},
        'summary': {
            'source': 'upload', 'source_name': name, 'account_id': None,
            'identity_count': 2, 'escalation_paths': 3,
            'coverage': {'complete': True, 'warnings': []},
        },
    }


class TestAnalysisHistoryStore(unittest.TestCase):
    def setUp(self):
        self.database = Path(__file__).with_name('_analysis_history_test.db')
        self.database.unlink(missing_ok=True)

    def tearDown(self):
        self.database.unlink(missing_ok=True)

    def test_round_trip_list_and_delete(self):
        store = AnalysisHistoryStore(self.database, limit=3)
        metadata = store.save(result())
        self.assertEqual(metadata['finding_count'], 1)
        self.assertEqual(store.list()[0]['source_name'], 'Pasted JSON')
        restored = store.get(metadata['id'])
        self.assertEqual(restored['history']['id'], metadata['id'])
        self.assertEqual(restored['vulnerabilities'][0]['id'], 'VULN-0001')
        self.assertTrue(store.delete(metadata['id']))
        self.assertIsNone(store.latest())

    def test_history_is_bounded(self):
        store = AnalysisHistoryStore(self.database, limit=2)
        first = store.save(result('First'))
        store.save(result('Second'))
        store.save(result('Third'))
        self.assertEqual(len(store.list()), 2)
        self.assertIsNone(store.get(first['id']))

    def test_on_demand_remediation_updates_saved_result(self):
        store = AnalysisHistoryStore(self.database)
        metadata = store.save(result())
        ai = {
            'vulnerability_id': 'VULN-0001', 'source': 'ai',
            'summary': 'Scoped policy generated.', 'actions': [{'action': 'Scope'}],
        }
        self.assertTrue(store.update_remediation(metadata['id'], 'VULN-0001', ai))
        restored = store.get(metadata['id'])
        self.assertEqual(restored['remediations'][0]['remediation']['source'], 'ai')


class TestAnalysisHistoryRoutes(unittest.TestCase):
    def setUp(self):
        self.database = Path(__file__).with_name('_analysis_history_route_test.db')
        self.database.unlink(missing_ok=True)
        self.previous_store = app_module.analysis_store
        app_module.analysis_store = AnalysisHistoryStore(self.database)
        app_module.app.config['TESTING'] = True
        self.client = app_module.app.test_client()

    def tearDown(self):
        app_module.analysis_store = self.previous_store
        self.database.unlink(missing_ok=True)

    def test_latest_list_open_delete_and_clear(self):
        saved = result()
        saved['history'] = app_module.analysis_store.save(saved)
        run_id = saved['history']['id']

        listing = self.client.get('/api/history')
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.get_json()['runs'][0]['id'], run_id)

        latest = self.client.get('/api/history/latest').get_json()
        self.assertTrue(latest['available'])
        self.assertEqual(latest['analysis']['history']['id'], run_id)

        opened = self.client.get(f'/api/history/{run_id}').get_json()
        self.assertEqual(opened['analysis']['summary']['source_name'], 'Pasted JSON')

        deleted = self.client.delete(f'/api/history/{run_id}')
        self.assertEqual(deleted.status_code, 200)
        self.assertFalse(self.client.get('/api/history/latest').get_json()['available'])

        app_module.analysis_store.save(result('Another'))
        cleared = self.client.delete('/api/history').get_json()
        self.assertEqual(cleared['deleted'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
