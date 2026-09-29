"""Bounded local persistence for completed Winnow analysis runs.

Only the processed analysis response is stored.  Uploaded source documents and
credentials are deliberately not copied into this database.
"""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_DB_PATH = Path(__file__).with_name('winnow_analysis.db')


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


class AnalysisHistoryStore:
    """Small SQLite store for reopening recent completed analyses."""

    def __init__(self, path: Optional[Path] = None, limit: Optional[int] = None):
        configured = os.environ.get('WINNOW_ANALYSIS_DB', '').strip()
        self.path = Path(path or configured or DEFAULT_DB_PATH)
        if limit is None:
            try:
                limit = int(os.environ.get('WINNOW_ANALYSIS_HISTORY_LIMIT', '30'))
            except ValueError:
                limit = 30
        self.limit = max(1, min(int(limit), 500))

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path), timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute(
            'CREATE TABLE IF NOT EXISTS analysis_runs ('
            'id INTEGER PRIMARY KEY AUTOINCREMENT, '
            'created_at TEXT NOT NULL, source TEXT NOT NULL, '
            'source_name TEXT, account_id TEXT, status TEXT NOT NULL, '
            'finding_count INTEGER NOT NULL, identity_count INTEGER NOT NULL, '
            'path_count INTEGER NOT NULL, payload TEXT NOT NULL)'
        )
        connection.execute(
            'CREATE INDEX IF NOT EXISTS idx_analysis_runs_created '
            'ON analysis_runs(id DESC)'
        )
        return connection

    @staticmethod
    def _metadata(row) -> Dict[str, Any]:
        return {
            'id': int(row['id']),
            'created_at': row['created_at'],
            'source': row['source'],
            'source_name': row['source_name'],
            'account_id': row['account_id'],
            'status': row['status'],
            'finding_count': int(row['finding_count']),
            'identity_count': int(row['identity_count']),
            'path_count': int(row['path_count']),
        }

    @classmethod
    def _analysis(cls, row) -> Optional[Dict[str, Any]]:
        try:
            payload = json.loads(row['payload'])
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        payload['history'] = cls._metadata(row)
        return payload

    def save(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError('Analysis history payload must be an object')
        summary = payload.get('summary') or {}
        if not isinstance(summary, dict):
            summary = {}
        coverage = summary.get('coverage') or {}
        status = 'partial' if isinstance(coverage, dict) and not coverage.get('complete', True) else 'complete'
        created_at = _utc_now()
        source = str(summary.get('source') or 'upload')[:32]
        source_name = str(summary.get('source_name') or '')[:160] or None
        account_id = str(summary.get('account_id') or '')[:64] or None
        finding_count = len(payload.get('vulnerabilities') or [])
        identity_count = max(0, int(summary.get('identity_count') or 0))
        path_count = max(0, int(summary.get('escalation_paths') or 0))
        stored_payload = dict(payload)
        stored_payload.pop('history', None)
        serialized = json.dumps(stored_payload, separators=(',', ':'), default=str)

        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    'INSERT INTO analysis_runs('
                    'created_at, source, source_name, account_id, status, '
                    'finding_count, identity_count, path_count, payload'
                    ') VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (created_at, source, source_name, account_id, status,
                     finding_count, identity_count, path_count, serialized),
                )
                run_id = int(cursor.lastrowid)
                connection.execute(
                    'DELETE FROM analysis_runs WHERE id NOT IN '
                    '(SELECT id FROM analysis_runs ORDER BY id DESC LIMIT ?)',
                    (self.limit,),
                )
        return {
            'id': run_id, 'created_at': created_at, 'source': source,
            'source_name': source_name, 'account_id': account_id, 'status': status,
            'finding_count': finding_count, 'identity_count': identity_count,
            'path_count': path_count,
        }

    def list(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        count = max(1, min(int(limit or self.limit), self.limit))
        with closing(self._connect()) as connection:
            rows = connection.execute(
                'SELECT id, created_at, source, source_name, account_id, status, '
                'finding_count, identity_count, path_count '
                'FROM analysis_runs ORDER BY id DESC LIMIT ?', (count,)
            ).fetchall()
        return [self._metadata(row) for row in rows]

    def get(self, run_id: int) -> Optional[Dict[str, Any]]:
        if not self.path.exists():
            return None
        with closing(self._connect()) as connection:
            row = connection.execute(
                'SELECT * FROM analysis_runs WHERE id = ?', (int(run_id),)
            ).fetchone()
        return self._analysis(row) if row else None

    def latest(self) -> Optional[Dict[str, Any]]:
        if not self.path.exists():
            return None
        with closing(self._connect()) as connection:
            row = connection.execute(
                'SELECT * FROM analysis_runs ORDER BY id DESC LIMIT 1'
            ).fetchone()
        return self._analysis(row) if row else None

    def delete(self, run_id: int) -> bool:
        if not self.path.exists():
            return False
        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    'DELETE FROM analysis_runs WHERE id = ?', (int(run_id),)
                )
        return bool(cursor.rowcount)

    def clear(self) -> int:
        if not self.path.exists():
            return 0
        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute('DELETE FROM analysis_runs')
        return max(0, int(cursor.rowcount))

    def update_remediation(self, run_id: int, finding_id: str,
                           remediation: Dict[str, Any]) -> bool:
        if not self.path.exists() or not finding_id or not isinstance(remediation, dict):
            return False
        with closing(self._connect()) as connection:
            with connection:
                row = connection.execute(
                    'SELECT payload FROM analysis_runs WHERE id = ?', (int(run_id),)
                ).fetchone()
                if not row:
                    return False
                try:
                    payload = json.loads(row['payload'])
                except (TypeError, json.JSONDecodeError):
                    return False
                entries = payload.get('remediations') or []
                updated = False
                for entry in entries:
                    vulnerability = entry.get('vulnerability') or {}
                    current = entry.get('remediation') or {}
                    current_id = current.get('vulnerability_id') or vulnerability.get('id')
                    if str(current_id) == str(finding_id):
                        entry['remediation'] = remediation
                        updated = True
                        break
                if not updated:
                    return False
                connection.execute(
                    'UPDATE analysis_runs SET payload = ? WHERE id = ?',
                    (json.dumps(payload, separators=(',', ':'), default=str), int(run_id)),
                )
        return True
