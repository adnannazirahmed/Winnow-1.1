"""Hosted auth and tenant boundaries."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import app as app_module
import public_auth
from supabase_history import SupabaseAnalysisStore
from io import BytesIO


USER_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
USER_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'


class PublicModeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.mode = mock.patch.object(app_module, 'PUBLIC_MODE', True)
        self.verifier = mock.patch.object(app_module, 'verified_user_id',
                                          side_effect=lambda token: {'a': USER_A, 'b': USER_B}.get(token))
        self.env = mock.patch.dict(os.environ, {'WINNOW_DATA_ROOT': self.directory.name,
                                                'SUPABASE_URL': 'https://example.supabase.co',
                                                'SUPABASE_ANON_KEY': 'publishable',
                                                'WINNOW_PUBLIC_ORIGIN': 'https://winnow.example'})
        self.storage = mock.patch('supabase_history.SupabaseAnalysisStore._request', return_value=[])
        self.mode.start()
        self.verifier.start()
        self.env.start()
        self.storage.start()
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.storage.stop()
        self.env.stop()
        self.verifier.stop()
        self.mode.stop()
        self.directory.cleanup()

    def test_api_requires_verified_bearer(self):
        self.assertEqual(self.client.get('/api/history').status_code, 401)
        self.assertEqual(self.client.get('/api/history', headers={'Authorization': 'Bearer fake'}).status_code, 401)
        self.assertEqual(self.client.get('/api/history', headers={'Authorization': 'Bearer a'}).status_code, 200)

    def test_history_is_isolated_by_user(self):
        def store_for(user_id, token):
            self.assertEqual(token, 'a' if user_id == USER_A else 'b')
            store = mock.Mock()
            store.list.return_value = [{'id': 1}] if user_id == USER_A else []
            store.get.return_value = {'history': {'id': 1}} if user_id == USER_A else None
            return store
        with mock.patch.object(app_module, 'SupabaseAnalysisStore', side_effect=store_for):
            a = self.client.get('/api/history', headers={'Authorization': 'Bearer a'}).json['runs']
            b = self.client.get('/api/history', headers={'Authorization': 'Bearer b'}).json['runs']
            self.assertEqual(a, [{'id': 1}])
            self.assertEqual(b, [])
            self.assertEqual(self.client.get('/api/history/1', headers={'Authorization': 'Bearer b'}).status_code, 404)

    def test_shared_settings_and_server_aws_scan_are_disabled(self):
        for path in ('/api/settings', '/api/settings/aws', '/api/settings/ai'):
            self.assertEqual(self.client.get(path, headers={'Authorization': 'Bearer a'}).status_code, 503)
        self.assertEqual(self.client.post('/api/scan-account', headers={'Authorization': 'Bearer a'}).status_code, 503)

    def test_cors_allows_only_the_site_origin(self):
        preflight = self.client.options('/api/analyze', headers={'Origin': 'https://winnow.example',
            'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization, content-type'})
        self.assertEqual(preflight.status_code, 204)
        self.assertEqual(preflight.headers['Access-Control-Allow-Origin'], 'https://winnow.example')
        denied = self.client.get('/api/history', headers={'Origin': 'https://attacker.example',
                                                          'Authorization': 'Bearer a'})
        self.assertEqual(denied.status_code, 403)
        self.assertNotIn('Access-Control-Allow-Origin', denied.headers)

    def test_public_site_and_workspace_routes(self):
        self.assertEqual(self.client.get('/').status_code, 302)
        self.assertEqual(self.client.get('/signup.html').status_code, 404)
        self.assertEqual(self.client.get('/app/').status_code, 302)
        self.assertEqual(self.client.get('/app/script.js').status_code, 404)


class TokenVerificationTests(unittest.TestCase):
    def test_validated_id_comes_from_auth_response(self):
        with mock.patch.dict(os.environ, {'SUPABASE_URL': 'https://example.supabase.co',
                                       'SUPABASE_ANON_KEY': 'publishable'}), \
             mock.patch.object(public_auth, 'urlopen', return_value=BytesIO(
                 ('{"id":"' + USER_A + '"}').encode('ascii'))) as send:
            self.assertEqual(public_auth.verified_user_id('access-token'), USER_A)
            self.assertEqual(send.call_args.args[0].get_header('Authorization'), 'Bearer access-token')

    def test_bad_user_id_and_missing_configuration_fail_closed(self):
        with mock.patch.dict(os.environ, {'SUPABASE_URL': 'https://example.supabase.co',
                                       'SUPABASE_ANON_KEY': 'publishable'}), \
             mock.patch.object(public_auth, 'urlopen', return_value=BytesIO(b'{"id":"not-a-uuid"}')):
            self.assertIsNone(public_auth.verified_user_id('access-token'))
        with mock.patch.dict(os.environ, {'SUPABASE_URL': '', 'SUPABASE_ANON_KEY': ''}):
            self.assertIsNone(public_auth.verified_user_id('access-token'))


class SupabaseHistoryTests(unittest.TestCase):
    def test_history_request_uses_user_bearer(self):
        with mock.patch.dict(os.environ, {'SUPABASE_URL': 'https://example.supabase.co',
                                       'SUPABASE_ANON_KEY': 'publishable'}), \
             mock.patch('supabase_history.urlopen', return_value=BytesIO(b'[]')) as send:
            store = SupabaseAnalysisStore(USER_A, 'user-access-token')
            self.assertEqual(store.list(), [])
            request = send.call_args.args[0]
            self.assertEqual(request.get_header('Authorization'), 'Bearer user-access-token')
            self.assertEqual(request.get_header('Apikey'), 'publishable')
            self.assertIn('/rest/v1/analysis_runs?', request.full_url)

    def test_insert_sets_owner_and_keeps_payload(self):
        with mock.patch.dict(os.environ, {'SUPABASE_URL': 'https://example.supabase.co',
                                       'SUPABASE_ANON_KEY': 'publishable'}):
            store = SupabaseAnalysisStore(USER_A, 'user-access-token')
            with mock.patch.object(store, '_request', return_value=[{'id': 9, 'source': 'upload'}]) as send:
                metadata = store.save({'summary': {'source': 'upload', 'source_name': 'Policy'},
                                       'vulnerabilities': []})
                self.assertEqual(metadata['id'], 9)
                record = send.call_args.kwargs['body']
                self.assertEqual(record['user_id'], USER_A)
                self.assertEqual(record['payload']['summary']['source_name'], 'Policy')
