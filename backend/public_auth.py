"""Verify Supabase access tokens for the hosted Winnow API."""

import json
import os
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def verified_user_id(token):
    """Ask Supabase Auth to validate a bearer token; never trust client claims."""
    project_url = os.environ.get('SUPABASE_URL', '').rstrip('/')
    public_key = os.environ.get('SUPABASE_ANON_KEY', '')
    if not project_url.startswith('https://') or not public_key or not token:
        return None
    if len(token) > 8192:
        return None
    request = Request(
        project_url + '/auth/v1/user',
        headers={'apikey': public_key, 'Authorization': 'Bearer ' + token},
    )
    try:
        with urlopen(request, timeout=5) as response:
            user = json.load(response)
    except (HTTPError, URLError, TimeoutError, ValueError, OSError):
        return None
    try:
        return str(uuid.UUID(user['id']))
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
