"""Regression checks for local data access and browser request boundaries."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import app as app_module


class TestSecurityGate(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.token_path = Path(self.directory.name) / 'access_token'
        self.file_patch = mock.patch.object(app_module, 'ACCESS_TOKEN_FILE', self.token_path)
        self.file_patch.start()
        self.env_patch = mock.patch.dict(os.environ, {'HOST': '127.0.0.1'}, clear=False)
        self.env_patch.start()
        os.environ.pop('WINNOW_ACCESS_TOKEN', None)
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.env_patch.stop()
        self.file_patch.stop()
        self.directory.cleanup()

    def test_local_api_works_without_token(self):
        response = self.client.get('/api/history')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertFalse(self.token_path.exists())

    def test_local_secret_files_are_not_static_assets(self):
        self.assertEqual(self.client.get('/.env').status_code, 404)
        self.assertEqual(self.client.get('/backend/.env').status_code, 404)

    def test_cross_origin_read_is_not_exposed(self):
        response = self.client.get('/api/history', headers={'Origin': 'https://attacker.example'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Access-Control-Allow-Origin', response.headers)

    def test_nonlocal_client_cannot_read_or_trigger_scans(self):
        remote = {'REMOTE_ADDR': '192.0.2.9'}
        for path in ('/api/history', '/api/history/latest', '/api/organization', '/api/settings'):
            self.assertEqual(self.client.get(path, environ_overrides=remote).status_code, 401)
        for path in ('/api/scan-account', '/api/organization/scan', '/api/analyze'):
            self.assertEqual(self.client.post(path, environ_overrides=remote).status_code, 401)
        self.assertEqual(self.client.get('/health', environ_overrides=remote).status_code, 200)

    def test_authentication_and_host_rebinding(self):
        remote = {'REMOTE_ADDR': '192.0.2.9'}
        self.assertEqual(self.client.get('/api/history', environ_overrides=remote).status_code, 401)
        token = self.token_path.read_text(encoding='ascii').strip()
        self.assertGreaterEqual(len(token), 32)
        response = self.client.get('/api/history', environ_overrides=remote,
                                   headers={'Authorization': 'Basic d2lubm93Ondyb25n'})
        self.assertEqual(response.status_code, 401)
        response = self.client.get('/api/history', environ_overrides=remote,
                                   auth=('winnow', token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get('/api/history', base_url='http://attacker.example').status_code, 403)
        self.assertEqual(self.client.get('/api/history', base_url='https://winnow.example',
                                         environ_overrides=remote).status_code, 401)
        self.assertEqual(self.client.get('/api/history', base_url='https://winnow.example',
                                         environ_overrides=remote, auth=('winnow', token)).status_code, 200)

    def test_cross_site_write_is_rejected_before_processing(self):
        with mock.patch.object(app_module.settings, 'remove_aws_credentials') as remove:
            response = self.client.delete('/api/settings/aws', headers={
                'Origin': 'https://attacker.example', 'Sec-Fetch-Site': 'cross-site',
            })
            self.assertEqual(response.status_code, 403)
            response = self.client.delete('/api/settings/aws', headers={
                'Origin': 'https://attacker.example',
            })
            self.assertEqual(response.status_code, 403)
            remove.assert_not_called()

    def test_public_bind_requires_auth_even_for_loopback_peer(self):
        with mock.patch.dict(os.environ, {'HOST': '0.0.0.0'}):
            response = self.client.get('/api/history')
        self.assertEqual(response.status_code, 401)

    def test_parser_error_does_not_echo_uploaded_secret(self):
        with mock.patch.object(app_module.iam_ingest, 'config_to_iamdata',
                               side_effect=ValueError('invalid value: private-token')):
            response = self.client.post('/api/analyze', json={'iam_config': {'bad': True}})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('private-token', response.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
