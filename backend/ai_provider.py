"""Small provider adapter shared by AI detection and remediation.

Anthropic uses its installed SDK. OpenAI and DeepSeek both use their compatible
chat-completions API, and Ollama uses its local chat API through httpx.
"""

import logging
import os

import httpx

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:  # pragma: no cover - dependency is optional at runtime
    anthropic = None
    ANTHROPIC_AVAILABLE = False


logger = logging.getLogger(__name__)
DEFAULT_MODELS = {
    'anthropic': 'claude-3-haiku-20240307',
    'openai': 'gpt-4o-mini',
    'deepseek': 'deepseek-chat',
    'ollama': 'llama3.2',
}


class AIProvider:
    def __init__(self):
        provider = os.environ.get('AI_PROVIDER', '').strip().lower()
        if provider == 'claude':
            provider = 'anthropic'
        self.name = provider or ('anthropic' if os.environ.get('ANTHROPIC_API_KEY') else '')
        self.model = os.environ.get('AI_MODEL') or os.environ.get('REMEDIATOR_MODEL') or DEFAULT_MODELS.get(self.name, '')
        self.api_key = os.environ.get({
            'anthropic': 'ANTHROPIC_API_KEY', 'openai': 'OPENAI_API_KEY',
            'deepseek': 'DEEPSEEK_API_KEY', 'ollama': 'OLLAMA_API_KEY',
        }.get(self.name, ''), '')
        self.timeout = float(os.environ.get('AI_TIMEOUT_SECONDS', os.environ.get('ANTHROPIC_TIMEOUT_SECONDS', '30')))
        self.client = None
        if self.name == 'anthropic' and self.api_key and ANTHROPIC_AVAILABLE:
            self.client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout, max_retries=1)

    @property
    def enabled(self):
        if self.name == 'anthropic':
            return self.client is not None
        if self.name in ('openai', 'deepseek'):
            return bool(self.api_key and self.model)
        if self.name == 'ollama':
            return bool(self.model)
        return False

    def complete(self, system, prompt, max_tokens):
        if not self.enabled:
            raise RuntimeError('AI provider is not configured')
        if self.name == 'anthropic':
            response = self.client.messages.create(
                model=self.model, max_tokens=max_tokens, temperature=0.1,
                system=system, messages=[{'role': 'user', 'content': prompt}],
            )
            return response.content[0].text

        if self.name == 'ollama':
            url = os.environ.get('OLLAMA_BASE_URL', 'http://127.0.0.1:11434').rstrip('/') + '/api/chat'
            payload = {
                'model': self.model, 'stream': False, 'format': 'json',
                'options': {'temperature': 0.1},
                'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': prompt}],
            }
            headers = {'Authorization': 'Bearer ' + self.api_key} if self.api_key else {}
        else:
            root = 'https://api.openai.com/v1' if self.name == 'openai' else os.environ.get('DEEPSEEK_BASE_URL', 'https://api.deepseek.com').rstrip('/')
            url = root.rstrip('/') + '/chat/completions'
            payload = {
                'model': self.model, 'max_tokens': max_tokens, 'temperature': 0.1,
                'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': prompt}],
            }
            headers = {'Authorization': 'Bearer ' + self.api_key}

        response = httpx.post(url, json=payload, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        body = response.json()
        if self.name == 'ollama':
            return str(body.get('message', {}).get('content', ''))
        return str(body.get('choices', [{}])[0].get('message', {}).get('content', ''))
