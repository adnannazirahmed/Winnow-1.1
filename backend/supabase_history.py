"""User-scoped analysis history through Supabase PostgREST and RLS."""

import json
import os
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class SupabaseAnalysisStore:
    def __init__(self, user_id, access_token, limit=30):
        self.user_id = user_id
        self.access_token = access_token
        self.limit = max(1, min(int(limit), 500))
        self.base = os.environ['SUPABASE_URL'].rstrip('/') + '/rest/v1/analysis_runs'
        self.public_key = os.environ['SUPABASE_ANON_KEY']

    def _request(self, method='GET', query=None, body=None):
        url = self.base + ('?' + urlencode(query) if query else '')
        headers = {
            'apikey': self.public_key,
            'Authorization': 'Bearer ' + self.access_token,
            'Accept': 'application/json',
            'Prefer': 'return=representation',
        }
        data = None
        if body is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(body, separators=(',', ':'), default=str).encode('utf-8')
        with urlopen(Request(url, data=data, headers=headers, method=method), timeout=15) as response:
            raw = response.read()
        return json.loads(raw) if raw else []

    def claim_ai_allowance(self, daily_limit):
        """Atomically reserve one daily AI request for this authenticated user."""
        url = os.environ['SUPABASE_URL'].rstrip('/') + '/rest/v1/rpc/claim_ai_allowance'
        data = json.dumps({'daily_limit': daily_limit}).encode('utf-8')
        headers = {
            'apikey': self.public_key,
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json',
        }
        with urlopen(Request(url, data=data, headers=headers, method='POST'), timeout=5) as response:
            return json.load(response) is True

    def claim_scan_allowance(self):
        url = os.environ['SUPABASE_URL'].rstrip('/') + '/rest/v1/rpc/claim_scan_allowance'
        headers = {'apikey': self.public_key, 'Authorization': 'Bearer ' + self.access_token,
                   'Content-Type': 'application/json'}
        with urlopen(Request(url, data=b'{}', headers=headers, method='POST'), timeout=5) as response:
            return json.load(response) is True

    @staticmethod
    def _metadata(row):
        return {key: row.get(key) for key in (
            'id', 'created_at', 'source', 'source_name', 'account_id', 'status',
            'finding_count', 'identity_count', 'path_count')}

    @classmethod
    def _analysis(cls, row):
        payload = row.get('payload')
        if not isinstance(payload, dict):
            return None
        result = dict(payload)
        result['history'] = cls._metadata(row)
        return result

    def save(self, payload):
        summary = payload.get('summary') or {}
        coverage = summary.get('coverage') or {}
        record = {
            'user_id': self.user_id,
            'source': str(summary.get('source') or 'upload')[:32],
            'source_name': str(summary.get('source_name') or '')[:160] or None,
            'account_id': str(summary.get('account_id') or '')[:64] or None,
            'status': 'partial' if isinstance(coverage, dict) and not coverage.get('complete', True) else 'complete',
            'finding_count': len(payload.get('vulnerabilities') or []),
            'identity_count': max(0, int(summary.get('identity_count') or 0)),
            'path_count': max(0, int(summary.get('escalation_paths') or 0)),
            'payload': {key: value for key, value in payload.items() if key != 'history'},
        }
        rows = self._request('POST', body=record)
        return self._metadata(rows[0])

    def list(self, limit=None):
        count = max(1, min(int(limit or self.limit), self.limit))
        rows = self._request(query={'select': 'id,created_at,source,source_name,account_id,status,finding_count,identity_count,path_count',
                                    'order': 'id.desc', 'limit': count})
        return [self._metadata(row) for row in rows]

    def get(self, run_id):
        rows = self._request(query={'id': 'eq.' + str(int(run_id)), 'select': '*'})
        return self._analysis(rows[0]) if rows else None

    def latest(self):
        rows = self._request(query={'select': '*', 'order': 'id.desc', 'limit': 1})
        return self._analysis(rows[0]) if rows else None

    def delete(self, run_id):
        rows = self._request('DELETE', query={'id': 'eq.' + str(int(run_id)), 'select': 'id'})
        return bool(rows)

    def clear(self):
        rows = self._request('DELETE', query={'id': 'gte.0', 'select': 'id'})
        return len(rows)

    def update_remediation(self, run_id, finding_id, remediation):
        analysis = self.get(run_id)
        if not analysis or not finding_id or not isinstance(remediation, dict):
            return False
        analysis.pop('history', None)
        updated = False
        for entry in analysis.get('remediations') or []:
            vulnerability = entry.get('vulnerability') or {}
            current = entry.get('remediation') or {}
            if str(current.get('vulnerability_id') or vulnerability.get('id')) == str(finding_id):
                entry['remediation'] = remediation
                updated = True
                break
        if not updated:
            return False
        rows = self._request('PATCH', query={'id': 'eq.' + str(int(run_id)), 'select': 'id'},
                             body={'payload': analysis})
        return bool(rows)

