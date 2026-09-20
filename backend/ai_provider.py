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
DEFAULT_URLS = {
    'anthropic': 'https://api.anthropic.com',
    'openai': 'https://api.openai.com/v1',
    'deepseek': 'https://api.deepseek.com',
    'ollama': 'http://127.0.0.1:11434',
}
URL_ENV_BY_PROVIDER = {
    'anthropic': 'ANTHROPIC_BASE_URL',
    'openai': 'OPENAI_BASE_URL',
    'deepseek': 'DEEPSEEK_BASE_URL',
    'ollama': 'OLLAMA_BASE_URL',
}


class AIConnectionError(RuntimeError):
    """A safe, user-facing error raised when provider verification fails."""


class AIProvider:
    def __init__(self, provider=None, api_key=None, model=None, base_url=None, timeout=None):
        provider = (provider if provider is not None else os.environ.get('AI_PROVIDER', '')).strip().lower()
        if provider == 'claude':
            provider = 'anthropic'
        self.name = provider or ('anthropic' if os.environ.get('ANTHROPIC_API_KEY') else '')
        self.model = model or os.environ.get('AI_MODEL') or os.environ.get('REMEDIATOR_MODEL') or DEFAULT_MODELS.get(self.name, '')
        env_api_key = os.environ.get({
            'anthropic': 'ANTHROPIC_API_KEY', 'openai': 'OPENAI_API_KEY',
            'deepseek': 'DEEPSEEK_API_KEY', 'ollama': 'OLLAMA_API_KEY',
        }.get(self.name, ''), '')
        self.api_key = api_key if api_key is not None else env_api_key
        env_url = os.environ.get(URL_ENV_BY_PROVIDER.get(self.name, ''), DEFAULT_URLS.get(self.name, ''))
        self.base_url = (base_url if base_url is not None else env_url).rstrip('/')
        self.timeout = float(timeout if timeout is not None else os.environ.get('AI_TIMEOUT_SECONDS', os.environ.get('ANTHROPIC_TIMEOUT_SECONDS', '30')))
        self.client = None
        if self.name == 'anthropic' and self.api_key and ANTHROPIC_AVAILABLE:
            self.client = anthropic.Anthropic(
                api_key=self.api_key, base_url=self.base_url,
                timeout=self.timeout, max_retries=1,
            )

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
            url = self.base_url + '/api/chat'
            payload = {
                'model': self.model, 'stream': False, 'format': 'json',
                'options': {'temperature': 0.1},
                'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': prompt}],
            }
            headers = {'Authorization': 'Bearer ' + self.api_key} if self.api_key else {}
        else:
            url = self.base_url + '/chat/completions'
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

    def validate_connection(self):
        """Authenticate against the configured URL and exercise the selected model."""
        if not self.enabled:
            raise AIConnectionError('The selected AI provider is not fully configured.')
        try:
            self.complete(
                'You are checking whether an AI provider connection works.',
                'Return only this JSON object: {"ok":true}',
                8,
            )
        except Exception as exc:
            status = getattr(exc, 'status_code', None)
            response = getattr(exc, 'response', None)
            status = status or getattr(response, 'status_code', None)
            name = type(exc).__name__.lower()
            if status in (401, 403) or 'authentication' in name or 'permission' in name:
                message = 'The provider rejected the API key.'
            elif status == 404:
                message = 'The provider URL or selected model was not found.'
            elif status == 429:
                message = 'The provider accepted the connection but its rate or credit limit was reached.'
            elif status is not None and 400 <= status < 500:
                message = 'The provider rejected the selected URL, key, or model.'
            elif isinstance(exc, (httpx.ConnectError, httpx.TimeoutException)) or 'connection' in name or 'timeout' in name:
                message = 'Winnow could not connect to the provider URL.'
            else:
                message = 'Winnow could not verify this provider. Check the URL, key, and model.'
            raise AIConnectionError(message) from None
        return True
