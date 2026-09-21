"""Local configuration helpers for the Winnow settings screen.

Secrets are written only to backend/.env and are never included in API
responses or log messages.  The API exposes only whether a setting exists.
"""

import os
import re
from pathlib import Path
from typing import Dict, Iterable
from urllib.parse import urlparse

from dotenv import dotenv_values, set_key, unset_key


ENV_FILE = Path(__file__).with_name('.env')
AWS_KEYS = ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
            'AWS_DEFAULT_REGION', 'AWS_PROFILE', 'AWS_ORGANIZATION_ROLE_NAME')
AI_KEY_BY_PROVIDER = {
    'anthropic': 'ANTHROPIC_API_KEY',
    'openai': 'OPENAI_API_KEY',
    'deepseek': 'DEEPSEEK_API_KEY',
    'ollama': 'OLLAMA_API_KEY',
}
AI_PROVIDERS = tuple(AI_KEY_BY_PROVIDER)
AI_URL_BY_PROVIDER = {
    'anthropic': 'ANTHROPIC_BASE_URL',
    'openai': 'OPENAI_BASE_URL',
    'deepseek': 'DEEPSEEK_BASE_URL',
    'ollama': 'OLLAMA_BASE_URL',
}
AI_DEFAULT_URLS = {
    'anthropic': 'https://api.anthropic.com',
    'openai': 'https://api.openai.com/v1',
    'deepseek': 'https://api.deepseek.com',
    'ollama': 'http://127.0.0.1:11434',
}
AI_DEFAULT_MODELS = {
    'anthropic': 'claude-3-haiku-20240307',
    'openai': 'gpt-4o-mini',
    'deepseek': 'deepseek-chat',
    'ollama': 'llama3.2',
}
_AWS_ACCESS_KEY = re.compile(r'^[A-Z0-9]{16,128}$')
_AWS_REGION = re.compile(r'^[a-z]{2}(?:-gov)?-[a-z0-9-]+-\d+$')
_AWS_ROLE_NAME = re.compile(r'^[A-Za-z0-9+=,.@_/-]{1,128}$')


def _env_file_values() -> Dict[str, str]:
    return {key: value for key, value in dotenv_values(ENV_FILE).items() if value is not None}


def _save(updates: Dict[str, str], removals: Iterable[str] = ()) -> None:
    ENV_FILE.touch(exist_ok=True)
    file_values = _env_file_values()
    for key in removals:
        if key in file_values:
            unset_key(str(ENV_FILE), key)
        os.environ.pop(key, None)
    for key, value in updates.items():
        set_key(str(ENV_FILE), key, value, quote_mode='auto')
        os.environ[key] = value


def _clean(value, field: str, maximum: int = 4096) -> str:
    if value is None:
        return ''
    if not isinstance(value, str):
        raise ValueError(f'{field} must be text')
    value = value.strip()
    if len(value) > maximum or '\n' in value or '\r' in value:
        raise ValueError(f'{field} is invalid')
    return value


def save_aws_credentials(data: Dict[str, object]) -> None:
    access_key_id = _clean(data.get('access_key_id'), 'AWS access key ID', 128)
    secret_access_key = _clean(data.get('secret_access_key'), 'AWS secret access key', 256)
    session_token = _clean(data.get('session_token'), 'AWS session token', 4096)
    region = _clean(data.get('region'), 'AWS region', 64) or 'us-east-1'
    organization_role_name = _clean(
        data.get('organization_role_name'), 'Organization audit role', 128
    )

    if not access_key_id or not secret_access_key:
        raise ValueError('Enter both an AWS access key ID and secret access key')
    if not _AWS_ACCESS_KEY.fullmatch(access_key_id):
        raise ValueError('AWS access key ID has an invalid format')
    if not _AWS_REGION.fullmatch(region):
        raise ValueError('AWS region has an invalid format')
    if organization_role_name and not _AWS_ROLE_NAME.fullmatch(organization_role_name):
        raise ValueError('Organization audit role has an invalid format')

    updates = {
        'AWS_ACCESS_KEY_ID': access_key_id,
        'AWS_SECRET_ACCESS_KEY': secret_access_key,
        'AWS_DEFAULT_REGION': region,
    }
    removals = ('AWS_PROFILE',)
    if session_token:
        updates['AWS_SESSION_TOKEN'] = session_token
    else:
        removals += ('AWS_SESSION_TOKEN',)
    if organization_role_name:
        updates['AWS_ORGANIZATION_ROLE_NAME'] = organization_role_name.lstrip('/')
    else:
        removals += ('AWS_ORGANIZATION_ROLE_NAME',)
    _save(updates, removals)


def remove_aws_credentials() -> None:
    _save({}, AWS_KEYS)


def normalise_ai_configuration(data: Dict[str, object]) -> Dict[str, str]:
    provider = _clean(data.get('provider'), 'AI provider', 32).lower()
    if provider == 'claude':
        provider = 'anthropic'
    if provider not in AI_PROVIDERS:
        raise ValueError('Choose Claude, Ollama, OpenAI, or DeepSeek')

    model = _clean(data.get('model'), 'AI model', 160) or AI_DEFAULT_MODELS[provider]
    api_key = _clean(data.get('api_key'), 'AI API key', 4096)
    base_url = _clean(data.get('base_url'), 'Provider URL', 512) or AI_DEFAULT_URLS[provider]
    if provider != 'ollama' and not api_key:
        raise ValueError('Enter an API key for the selected provider')
    parsed_url = urlparse(base_url)
    if parsed_url.scheme not in ('http', 'https') or not parsed_url.netloc:
        raise ValueError('Provider URL must be a complete http:// or https:// URL')
    return {
        'provider': provider,
        'model': model,
        'api_key': api_key,
        'base_url': base_url.rstrip('/'),
    }


def save_ai_configuration(data: Dict[str, object]) -> None:
    config = normalise_ai_configuration(data)
    provider = config['provider']

    updates = {
        'AI_PROVIDER': provider,
        'AI_MODEL': config['model'],
        AI_URL_BY_PROVIDER[provider]: config['base_url'],
    }
    # One active provider is intentionally stored at a time. Switching does
    # not leave an unused provider key behind in the local env file.
    removals = [key for name, key in AI_KEY_BY_PROVIDER.items() if name != provider]
    if config['api_key']:
        updates[AI_KEY_BY_PROVIDER[provider]] = config['api_key']
    elif provider == 'ollama':
        removals.append(AI_KEY_BY_PROVIDER[provider])
    _save(updates, removals)


def remove_ai_configuration() -> None:
    removals = ['AI_PROVIDER', 'AI_MODEL']
    removals.extend(AI_KEY_BY_PROVIDER.values())
    removals.extend(AI_URL_BY_PROVIDER.values())
    _save({}, removals)


def _active_provider() -> str:
    provider = os.environ.get('AI_PROVIDER', '').lower()
    if provider == 'claude':
        provider = 'anthropic'
    if provider in AI_PROVIDERS:
        return provider
    if os.environ.get('ANTHROPIC_API_KEY'):
        return 'anthropic'
    return ''


def public_settings() -> Dict[str, object]:
    file_values = _env_file_values()
    provider = _active_provider()
    aws_configured = bool(os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'))
    return {
        'aws': {
            'configured': aws_configured,
            'managed_by_winnow': bool(file_values.get('AWS_ACCESS_KEY_ID') and file_values.get('AWS_SECRET_ACCESS_KEY')),
            'region': os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'),
            'organization_role_name': os.environ.get('AWS_ORGANIZATION_ROLE_NAME', ''),
            'access_key_hint': ('…' + os.environ['AWS_ACCESS_KEY_ID'][-4:]) if aws_configured else '',
        },
        'ai': {
            'provider': provider or 'anthropic',
            'configured': bool(provider and os.environ.get(AI_KEY_BY_PROVIDER[provider], '') if provider != 'ollama' else provider),
            'model': os.environ.get('AI_MODEL', ''),
            'base_url': os.environ.get(
                AI_URL_BY_PROVIDER.get(provider or 'anthropic', 'ANTHROPIC_BASE_URL'),
                AI_DEFAULT_URLS.get(provider or 'anthropic', AI_DEFAULT_URLS['anthropic']),
            ),
        },
    }
