"""Configuration and non-Anthropic provider contract tests."""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import settings
from ai_provider import AIProvider


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
        })
        contents = settings.ENV_FILE.read_text(encoding='utf-8')
        self.assertIn('AWS_ACCESS_KEY_ID', contents)
        self.assertIn('AWS_SECRET_ACCESS_KEY', contents)
        public = settings.public_settings()['aws']
        self.assertTrue(public['configured'])
        self.assertEqual(public['access_key_hint'], '…CDEF')
        self.assertNotIn('a' * 40, str(public))
        settings.remove_aws_credentials()
        self.assertFalse(settings.public_settings()['aws']['configured'])
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', settings.ENV_FILE.read_text(encoding='utf-8'))

    def test_ai_switch_replaces_old_provider_key_and_remove_clears_keys(self):
        settings.save_ai_configuration({'provider': 'openai', 'api_key': 'openai-key', 'model': 'gpt-test'})
        settings.save_ai_configuration({'provider': 'deepseek', 'api_key': 'deepseek-key', 'model': 'deepseek-test'})
        contents = settings.ENV_FILE.read_text(encoding='utf-8')
        self.assertNotIn('openai-key', contents)
        self.assertIn('deepseek-key', contents)
        self.assertEqual(settings.public_settings()['ai']['provider'], 'deepseek')
        self.assertNotIn('deepseek-key', str(settings.public_settings()))
        settings.remove_ai_configuration()
        self.assertNotIn('deepseek-key', settings.ENV_FILE.read_text(encoding='utf-8'))


class TestCompatibleAIProviders(unittest.TestCase):
    def test_openai_compatible_chat_request(self):
        with mock.patch.dict(os.environ, {'AI_PROVIDER': 'openai', 'OPENAI_API_KEY': 'test-key', 'AI_MODEL': 'model-a'}, clear=True):
            with mock.patch('ai_provider.httpx.post', return_value=FakeHTTPResponse({'choices': [{'message': {'content': 'answer'}}]})) as post:
                provider = AIProvider()
                self.assertEqual(provider.complete('system', 'prompt', 120), 'answer')
                self.assertEqual(post.call_args.args[0], 'https://api.openai.com/v1/chat/completions')
                self.assertEqual(post.call_args.kwargs['headers']['Authorization'], 'Bearer test-key')

    def test_ollama_uses_local_chat_api_without_a_key(self):
        with mock.patch.dict(os.environ, {'AI_PROVIDER': 'ollama', 'AI_MODEL': 'llama3.2'}, clear=True):
            with mock.patch('ai_provider.httpx.post', return_value=FakeHTTPResponse({'message': {'content': 'answer'}})) as post:
                provider = AIProvider()
                self.assertTrue(provider.enabled)
                self.assertEqual(provider.complete('system', 'prompt', 120), 'answer')
                self.assertEqual(post.call_args.args[0], 'http://127.0.0.1:11434/api/chat')


if __name__ == '__main__':
    unittest.main(verbosity=2)
