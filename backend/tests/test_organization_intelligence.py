"""Organization inventory, anomaly evidence, and snapshot-history tests."""

import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import aws_collector
import iam_ingest
from organization_intelligence import (
    InventorySnapshotStore,
    build_account_inventory,
    build_organization_intelligence,
)


RAW = {
    'UserDetailList': [{
        'UserName': 'Alice', 'UserId': 'AIDA1',
        'Arn': 'arn:aws:iam::111111111111:user/Alice',
        'GroupList': [],
        'AttachedManagedPolicies': [{
            'PolicyName': 'AdministratorAccess',
            'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess',
        }],
        'UserPolicyList': [{
            'PolicyName': 'DirectData',
            'PolicyDocument': {'Version': '2012-10-17', 'Statement': [{
                'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*',
            }]},
        }],
    }],
    'GroupDetailList': [{
        'GroupName': 'Developers', 'GroupId': 'AGPA1',
        'Arn': 'arn:aws:iam::111111111111:group/Developers',
        'AttachedManagedPolicies': [], 'GroupPolicyList': [],
    }],
    'RoleDetailList': [{
        'RoleName': 'VendorRole', 'RoleId': 'AROA1',
        'Arn': 'arn:aws:iam::111111111111:role/VendorRole',
        'AttachedManagedPolicies': [], 'RolePolicyList': [],
        'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::222222222222:root'},
            'Action': 'sts:AssumeRole',
        }]},
    }],
    'Policies': [{
        'PolicyName': 'OldPolicy', 'PolicyId': 'ANPA1',
        'Arn': 'arn:aws:iam::111111111111:policy/OldPolicy',
        'AttachmentCount': 0, 'DefaultVersionId': 'v1',
        'PolicyVersionList': [{
            'VersionId': 'v1', 'IsDefaultVersion': True,
            'Document': {'Version': '2012-10-17', 'Statement': []},
        }],
    }],
}

CREDENTIALS = [{
    'user': '<root_account>', 'mfa_active': 'false',
}, {
    'user': 'Alice', 'password_enabled': 'true', 'mfa_active': 'false',
    'access_key_1_active': 'true',
    'access_key_1_last_rotated': '2023-01-01T00:00:00+00:00',
    'access_key_1_last_used_date': '2023-02-01T00:00:00+00:00',
    'access_key_2_active': 'false',
}]


class TestOrganizationIntelligence(unittest.TestCase):
    def setUp(self):
        self.iam_data = iam_ingest.parse_gaad(RAW, '111111111111')

    def test_inventory_maps_policies_membership_trust_and_credentials(self):
        inventory = build_account_inventory(
            self.iam_data,
            {'account_id': '111111111111', 'name': 'Security'},
            CREDENTIALS,
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        alice = next(item for item in inventory['identities'] if item['name'] == 'Alice')
        vendor = next(item for item in inventory['identities'] if item['name'] == 'VendorRole')
        self.assertTrue(alice['privileged'])
        self.assertIn('AdministratorAccess', alice['policies'])
        self.assertIn('console without MFA', alice['flags'])
        self.assertIn('stale access key', alice['flags'])
        self.assertEqual(vendor['trust_principals'], ['arn:aws:iam::222222222222:root'])
        categories = {item['category'] for item in inventory['anomalies']}
        self.assertTrue({
            'root_mfa', 'privileged_identity', 'direct_user_policy', 'missing_mfa',
            'stale_access_key', 'external_trust', 'unattached_policy',
        }.issubset(categories))

    def test_second_snapshot_flags_new_identity(self):
        first = build_organization_intelligence([{
            'account': {'account_id': '111111111111'},
            'iam_data': self.iam_data,
            'credential_rows': [],
        }])
        expanded_raw = dict(RAW)
        expanded_raw['UserDetailList'] = list(RAW['UserDetailList']) + [{
            'UserName': 'NewUser', 'UserId': 'AIDA2',
            'Arn': 'arn:aws:iam::111111111111:user/NewUser',
            'GroupList': [], 'AttachedManagedPolicies': [], 'UserPolicyList': [],
        }]
        second = build_organization_intelligence([{
            'account': {'account_id': '111111111111'},
            'iam_data': iam_ingest.parse_gaad(expanded_raw, '111111111111'),
            'credential_rows': [],
        }], previous=first)
        self.assertTrue(second['changes']['baseline_available'])
        self.assertEqual(len(second['changes']['new_identities']), 1)
        self.assertIn('new_identity', {item['category'] for item in second['anomalies']})

    def test_snapshot_store_round_trip(self):
        database = Path(__file__).with_name('_inventory_test.db')
        database.unlink(missing_ok=True)
        try:
            store = InventorySnapshotStore(database)
            payload = {'generated_at': '2026-01-01T00:00:00Z', 'identities': [{'id': 'one'}]}
            store.save('scope', payload)
            self.assertEqual(store.latest('scope'), payload)
            self.assertEqual(store.latest_any(), payload)
        finally:
            database.unlink(missing_ok=True)


class _FakeSts:
    def get_caller_identity(self):
        return {'Account': '111111111111', 'Arn': 'arn:aws:iam::111111111111:user/Admin'}


class _FakeSession:
    region_name = 'us-east-1'

    def client(self, name):
        if name == 'sts':
            return _FakeSts()
        raise AssertionError(name)


class TestOrganizationCollector(unittest.TestCase):
    def test_discovers_accounts_and_marks_members_unscanned_without_role(self):
        accounts = [
            {'Id': '111111111111', 'Name': 'Management', 'State': 'ACTIVE'},
            {'Id': '222222222222', 'Name': 'Workload', 'State': 'ACTIVE'},
        ]
        with mock.patch.object(aws_collector, '_BOTO_OK', True), \
                mock.patch.object(aws_collector, '_session', return_value=_FakeSession()), \
                mock.patch.object(aws_collector, '_organization_accounts', return_value=accounts), \
                mock.patch.object(aws_collector, '_collect_authorization_details', return_value=RAW), \
                mock.patch.object(aws_collector, '_credential_report', return_value=CREDENTIALS):
            result = aws_collector.collect_organization_inventory('', 100)
        self.assertEqual(len(result['accounts']), 2)
        self.assertEqual(len(result['scanned']), 1)
        member = next(item for item in result['accounts'] if item['account_id'] == '222222222222')
        self.assertFalse(member['scanned'])
        self.assertIn('role', member['error'].lower())


class TestOrganizationEndpoint(unittest.TestCase):
    def setUp(self):
        os.environ['AI_PROVIDER'] = 'disabled'
        import app as app_module
        self.app_module = app_module
        app_module.app.config['TESTING'] = True
        self.client = app_module.app.test_client()

    def test_scan_builds_and_saves_inventory(self):
        collected = {
            'scope_key': '111111111111',
            'accounts': [{
                'account_id': '111111111111', 'name': 'Management',
                'state': 'ACTIVE', 'scanned': True, 'error': '',
            }],
            'scanned': [{
                'account': {'account_id': '111111111111', 'name': 'Management'},
                'raw': RAW, 'credential_rows': CREDENTIALS,
            }],
            'warnings': [],
        }
        with mock.patch.object(aws_collector, 'collect_organization_inventory', return_value=collected), \
                mock.patch.object(self.app_module.inventory_store, 'latest', return_value=None), \
                mock.patch.object(self.app_module.inventory_store, 'save') as save:
            response = self.client.post('/api/organization/scan')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['overview']['accounts_scanned'], 1)
        self.assertGreater(payload['overview']['anomalies'], 0)
        save.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
