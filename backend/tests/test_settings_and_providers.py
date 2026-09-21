"""Configuration and non-Anthropic provider contract tests."""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import settings
from ai_provider import AIConnectionError, AIProvider
import app as app_module


class FakeHTTPResponse:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


class TestSettings(unittest.TestCase):
    def setUp(self):
        self.old_env_file = settings.ENV_FILE
        self.test_env_file = Path(__file__).with_name('_settings_test.env')
        self.test_env_file.unlink(missing_ok=True)
        settings.ENV_FILE = self.test_env_file
        self.environ = mock.patch.dict(os.environ, {}, clear=True)
        self.environ.start()

    def tearDown(self):
        self.environ.stop()
        settings.ENV_FILE = self.old_env_file
        self.test_env_file.unlink(missing_ok=True)

    def test_aws_credentials_are_persisted_but_never_returned(self):
        settings.save_aws_credentials({
            'access_key_id': 'AKIA1234567890ABCDEF',
            'secret_access_key': 'a' * 40,
            'session_token': 'token-value',
            'region': 'us-east-1',
            'organization_role_name': 'WinnowAuditRole',
        })
        contents = settings.ENV_FILE.read_text(encoding='utf-8')
        self.assertIn('AWS_ACCESS_KEY_ID', contents)
        self.assertIn('AWS_SECRET_ACCESS_KEY', contents)
        public = settings.public_settings()['aws']
        self.assertTrue(public['configured'])
        self.assertEqual(public['access_key_hint'], '…CDEF')
        self.assertEqual(public['organization_role_name'], 'WinnowAuditRole')
        self.assertNotIn('a' * 40, str(public))
        settings.remove_aws_credentials()
        self.assertFalse(settings.public_settings()['aws']['configured'])
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', settings.ENV_FILE.read_text(encoding='utf-8'))

    def test_ai_switch_replaces_old_provider_key_and_remove_clears_keys(self):
        settings.save_ai_configuration({
            'provider': 'openai', 'api_key': 'openai-key', 'model': 'gpt-test',
            'base_url': 'https://openai.example/v1',
        })
        settings.save_ai_configuration({
            'provider': 'deepseek', 'api_key': 'deepseek-key', 'model': 'deepseek-test',
            'base_url': 'https://deepseek.example',
        })
        contents = settings.ENV_FILE.read_text(encoding='utf-8')
        self.assertNotIn('openai-key', contents)
        self.assertIn('deepseek-key', contents)
        self.assertIn('DEEPSEEK_BASE_URL', contents)
        public = settings.public_settings()['ai']
        self.assertEqual(public['provider'], 'deepseek')
        self.assertEqual(public['base_url'], 'https://deepseek.example')
        self.assertNotIn('deepseek-key', str(public))
        settings.remove_ai_configuration()
        self.assertNotIn('deepseek-key', settings.ENV_FILE.read_text(encoding='utf-8'))
        self.assertNotIn('DEEPSEEK_BASE_URL', settings.ENV_FILE.read_text(encoding='utf-8'))

    def test_ai_configuration_applies_provider_defaults_and_validates_url(self):
        config = settings.normalise_ai_configuration({
            'provider': 'openai', 'api_key': 'key', 'model': '', 'base_url': '',
        })
        self.assertEqual(config['model'], 'gpt-4o-mini')
        self.assertEqual(config['base_url'], 'https://api.openai.com/v1')
        with self.assertRaisesRegex(ValueError, 'complete http'):
            settings.normalise_ai_configuration({
                'provider': 'deepseek', 'api_key': 'key', 'base_url': 'api.deepseek.com',
            })


class TestCompatibleAIProviders(unittest.TestCase):
    def test_openai_compatible_chat_request(self):
        with mock.patch.dict(os.environ, {
            'AI_PROVIDER': 'openai', 'OPENAI_API_KEY': 'test-key',
            'AI_MODEL': 'model-a', 'OPENAI_BASE_URL': 'https://gateway.example/v1/',
        }, clear=True):
            with mock.patch('ai_provider.httpx.post', return_value=FakeHTTPResponse({'choices': [{'message': {'content': 'answer'}}]})) as post:
                provider = AIProvider()
                self.assertEqual(provider.complete('system', 'prompt', 120), 'answer')
                self.assertEqual(post.call_args.args[0], 'https://gateway.example/v1/chat/completions')
                self.assertEqual(post.call_args.kwargs['headers']['Authorization'], 'Bearer test-key')

    def test_ollama_uses_local_chat_api_without_a_key(self):
        with mock.patch.dict(os.environ, {'AI_PROVIDER': 'ollama', 'AI_MODEL': 'llama3.2'}, clear=True):
            with mock.patch('ai_provider.httpx.post', return_value=FakeHTTPResponse({'message': {'content': 'answer'}})) as post:
                provider = AIProvider()
                self.assertTrue(provider.enabled)
                self.assertEqual(provider.complete('system', 'prompt', 120), 'answer')
                self.assertEqual(post.call_args.args[0], 'http://127.0.0.1:11434/api/chat')

    def test_explicit_deepseek_configuration_uses_submitted_url(self):
        provider = AIProvider(
            provider='deepseek', api_key='submitted-key', model='deepseek-chat',
            base_url='https://gateway.example/deepseek/', timeout=5,
        )
        with mock.patch('ai_provider.httpx.post', return_value=FakeHTTPResponse({'choices': [{'message': {'content': 'ok'}}]})) as post:
            self.assertEqual(provider.complete('system', 'prompt', 8), 'ok')
        self.assertEqual(post.call_args.args[0], 'https://gateway.example/deepseek/chat/completions')
        self.assertEqual(post.call_args.kwargs['timeout'], 5.0)

    def test_connection_validation_maps_authentication_failure(self):
        class RejectedKey(Exception):
            status_code = 401

        provider = AIProvider(
            provider='openai', api_key='bad-key', model='gpt-test',
            base_url='https://api.openai.com/v1',
        )
        with mock.patch.object(provider, 'complete', side_effect=RejectedKey('secret response')):
            with self.assertRaisesRegex(AIConnectionError, 'rejected the API key') as caught:
                provider.validate_connection()
        self.assertNotIn('secret response', str(caught.exception))


class TestAISettingsRoute(unittest.TestCase):
    def setUp(self):
        app_module.app.config['TESTING'] = True
        self.client = app_module.app.test_client()
        self.payload = {
            'provider': 'openai', 'api_key': 'test-key', 'model': 'gpt-test',
            'base_url': 'https://api.openai.com/v1',
        }
        self.config = dict(self.payload)

    def test_route_verifies_before_saving(self):
        probe = mock.Mock()
        with mock.patch.object(app_module.settings, 'normalise_ai_configuration', return_value=self.config), \
                mock.patch.object(app_module, 'AIProvider', return_value=probe), \
                mock.patch.object(app_module.settings, 'save_ai_configuration') as save, \
                mock.patch.object(app_module.settings, 'public_settings', return_value={'ai': {'configured': True}}), \
                mock.patch.object(app_module, '_refresh_ai_components'):
            response = self.client.post('/api/settings/ai', json=self.payload)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['verified'])
        probe.validate_connection.assert_called_once_with()
        save.assert_called_once_with(self.payload)

    def test_route_does_not_save_when_verification_fails(self):
        probe = mock.Mock()
        probe.validate_connection.side_effect = AIConnectionError('The provider rejected the API key.')
        with mock.patch.object(app_module.settings, 'normalise_ai_configuration', return_value=self.config), \
                mock.patch.object(app_module, 'AIProvider', return_value=probe), \
                mock.patch.object(app_module.settings, 'save_ai_configuration') as save:
            response = self.client.post('/api/settings/ai', json=self.payload)
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.get_json()['error'], 'The provider rejected the API key.')
        save.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
