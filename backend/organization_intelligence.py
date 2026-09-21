"""Organization-wide IAM inventory, anomaly rules, and local scan history.

The analyzer deliberately separates facts from interpretation. AWS inventory and
credential reports supply the evidence; deterministic rules label review items.
No AI provider is required and no item is called shadow IT without a baseline.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from iam_model import IAMData, PolicyDocument, PolicyEffect


SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
DEFAULT_DB_PATH = Path(__file__).with_name('winnow_inventory.db')


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _truthy(value: Any) -> bool:
    return str(value or '').strip().lower() in ('true', '1', 'yes')


def _date_age_days(value: Any, now: Optional[datetime] = None) -> Optional[int]:
    text = str(value or '').strip()
    if not text or text.lower() in ('n/a', 'no_information', 'not_supported'):
        return None
    try:
        parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, int(((now or datetime.now(timezone.utc)) - parsed).total_seconds() // 86400))
    except (TypeError, ValueError):
        return None


def _document_grants_admin(document: PolicyDocument) -> bool:
    for statement in document.statements:
        if statement.effect != PolicyEffect.ALLOW:
            continue
        actions = {str(action).lower() for action in statement.actions}
        resources = {str(resource) for resource in statement.resources}
        if '*' in actions and ('*' in resources or not resources):
            return True
    return False


def _policy_names(entity: Any) -> List[str]:
    managed = [policy.policy_name for policy in entity.attached_managed_policies]
    inline = [policy.policy_name + ' (inline)' for policy in entity.inline_policies]
    return managed + inline


def _is_privileged(entity: Any, managed_policies: Optional[Dict[str, Any]] = None) -> bool:
    if any(policy.policy_name.lower() == 'administratoraccess'
           for policy in entity.attached_managed_policies):
        return True
    if any(_document_grants_admin(policy.document) for policy in entity.inline_policies):
        return True
    managed_policies = managed_policies or {}
    for attachment in entity.attached_managed_policies:
        policy = managed_policies.get(attachment.policy_arn) or managed_policies.get(attachment.policy_name)
        if policy and _document_grants_admin(policy.document):
            return True
    return False


def _resolved_account_id(iam_data: IAMData, configured: Any) -> str:
    account_id = str(configured or iam_data.account_id or '')
    if account_id and account_id != '000000000000':
        return account_id
    for entities in (iam_data.users, iam_data.groups, iam_data.roles, iam_data.policies):
        for entity in entities:
            arn = str(getattr(entity, 'arn', '') or '')
            parts = arn.split(':')
            if len(parts) > 4 and parts[4].isdigit() and len(parts[4]) == 12:
                return parts[4]
    return account_id or '000000000000'


def _stable_id(account_id: str, category: str, entity_id: str) -> str:
    value = f'{account_id}|{category}|{entity_id}'.encode('utf-8')
    return 'ANOM-' + hashlib.sha256(value).hexdigest()[:10].upper()


def _anomaly(account_id: str, severity: str, category: str, title: str,
             entity_id: str, entity_name: str, evidence: str,
             recommendation: str) -> Dict[str, Any]:
    return {
        'id': _stable_id(account_id, category, entity_id),
        'account_id': account_id,
        'severity': severity,
        'category': category,
        'title': title,
        'entity_id': entity_id,
        'entity_name': entity_name,
        'evidence': evidence,
        'recommendation': recommendation,
    }


def _credential_by_user(rows: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {str(row.get('user', '')): row for row in rows if row.get('user')}


def build_account_inventory(iam_data: IAMData, account: Optional[Dict[str, Any]] = None,
                            credential_rows: Optional[List[Dict[str, Any]]] = None,
                            now: Optional[datetime] = None) -> Dict[str, Any]:
    """Build a serializable identity inventory and evidence-backed review queue."""
    account = account or {}
    account_id = _resolved_account_id(iam_data, account.get('account_id'))
    credentials = _credential_by_user(credential_rows or [])
    identities: List[Dict[str, Any]] = []
    policies: List[Dict[str, Any]] = []
    anomalies: List[Dict[str, Any]] = []
    managed_policies: Dict[str, Any] = {}
    actual_attachments: Dict[str, int] = {}
    for policy in iam_data.policies:
        managed_policies[policy.arn] = policy
        managed_policies[policy.policy_name] = policy
    for entities in (iam_data.users, iam_data.groups, iam_data.roles):
        for entity in entities:
            for attachment in entity.attached_managed_policies:
                for key in (attachment.policy_arn, attachment.policy_name):
                    actual_attachments[key] = actual_attachments.get(key, 0) + 1

    group_members: Dict[str, List[str]] = {}
    for user in iam_data.users:
        for group_name in user.group_list:
            group_members.setdefault(group_name, []).append(user.user_name)

    root = credentials.get('<root_account>')
    if root and not _truthy(root.get('mfa_active')):
        anomalies.append(_anomaly(
            account_id, 'CRITICAL', 'root_mfa', 'Root account does not have MFA enabled',
            account_id + ':root', 'Root account',
            'The IAM credential report lists mfa_active=false for the root account.',
            'Enable hardware or phishing-resistant MFA for the root account.',
        ))

    for user in iam_data.users:
        entity_id = f'{account_id}:user:{user.user_name}'
        flags: List[str] = []
        privileged = _is_privileged(user, managed_policies)
        if privileged:
            flags.append('administrator access')
            anomalies.append(_anomaly(
                account_id, 'CRITICAL', 'privileged_identity',
                'IAM user has administrator-level permissions', entity_id, user.user_name,
                'AdministratorAccess or an inline Allow * on * policy is attached directly to this user.',
                'Move human access to a controlled role or group and replace broad permissions with least privilege.',
            ))
        if user.inline_policies:
            flags.append('direct inline policy')
            anomalies.append(_anomaly(
                account_id, 'MEDIUM', 'direct_user_policy',
                'IAM user has a direct inline policy', entity_id, user.user_name,
                f'{len(user.inline_policies)} inline policy or policies are embedded directly on the user.',
                'Prefer centrally managed policies attached through an approved group or role.',
            ))
        if not user.group_list:
            flags.append('outside groups')
            anomalies.append(_anomaly(
                account_id, 'LOW', 'ungrouped_user',
                'IAM user is not assigned to a group', entity_id, user.user_name,
                'The authorization snapshot lists no group memberships for this user.',
                'Confirm ownership and move repeatable permissions into an approved group or federated role.',
            ))

        credential = credentials.get(user.user_name, {})
        password_enabled = _truthy(credential.get('password_enabled'))
        mfa_active = _truthy(credential.get('mfa_active'))
        if password_enabled and not mfa_active:
            flags.append('console without MFA')
            anomalies.append(_anomaly(
                account_id, 'HIGH', 'missing_mfa',
                'Console-enabled IAM user has no MFA', entity_id, user.user_name,
                'The credential report lists password_enabled=true and mfa_active=false.',
                'Require MFA or migrate interactive access to IAM Identity Center.',
            ))

        active_keys = 0
        stale_keys = 0
        for index in (1, 2):
            if not _truthy(credential.get(f'access_key_{index}_active')):
                continue
            active_keys += 1
            rotated_age = _date_age_days(credential.get(f'access_key_{index}_last_rotated'), now)
            used_age = _date_age_days(credential.get(f'access_key_{index}_last_used_date'), now)
            if (rotated_age is not None and rotated_age > 90) or (used_age is not None and used_age > 90):
                stale_keys += 1
        if stale_keys:
            flags.append('stale access key')
            anomalies.append(_anomaly(
                account_id, 'HIGH', 'stale_access_key',
                'IAM user has an old or inactive access key', entity_id, user.user_name,
                f'{stale_keys} active access key or keys are older than 90 days or have not been used in 90 days.',
                'Confirm the workload owner, rotate active keys, and remove credentials that are no longer required.',
            ))

        identities.append({
            'id': entity_id, 'account_id': account_id, 'type': 'user',
            'name': user.user_name, 'arn': user.arn, 'path': user.path,
            'groups': list(user.group_list), 'members': [],
            'policies': _policy_names(user), 'managed_policy_count': len(user.attached_managed_policies),
            'inline_policy_count': len(user.inline_policies), 'trust_principals': [],
            'privileged': privileged, 'active_access_keys': active_keys,
            'mfa_active': mfa_active if password_enabled else None,
            'flags': flags,
        })

    for group in iam_data.groups:
        entity_id = f'{account_id}:group:{group.group_name}'
        privileged = _is_privileged(group, managed_policies)
        flags = ['administrator access'] if privileged else []
        if privileged:
            anomalies.append(_anomaly(
                account_id, 'CRITICAL', 'privileged_group',
                'IAM group grants administrator-level permissions', entity_id, group.group_name,
                'AdministratorAccess or an inline Allow * on * policy is attached to the group.',
                'Review every member and replace broad group permissions with job-specific access.',
            ))
        identities.append({
            'id': entity_id, 'account_id': account_id, 'type': 'group',
            'name': group.group_name, 'arn': group.arn, 'path': group.path,
            'groups': [], 'members': sorted(group_members.get(group.group_name, [])),
            'policies': _policy_names(group), 'managed_policy_count': len(group.attached_managed_policies),
            'inline_policy_count': len(group.inline_policies), 'trust_principals': [],
            'privileged': privileged, 'active_access_keys': 0, 'mfa_active': None,
            'flags': flags,
        })

    for role in iam_data.roles:
        entity_id = f'{account_id}:role:{role.role_name}'
        privileged = _is_privileged(role, managed_policies)
        principals = sorted({principal for statement in role.assume_role_policy_document.statements
                             for principal in statement.principals})
        flags = ['administrator access'] if privileged else []
        if privileged:
            anomalies.append(_anomaly(
                account_id, 'CRITICAL', 'privileged_role',
                'IAM role grants administrator-level permissions', entity_id, role.role_name,
                'AdministratorAccess or an inline Allow * on * policy is attached to the role.',
                'Restrict the role to the permissions required by its workload and review who can assume it.',
            ))
        external = []
        wildcard = False
        for principal in principals:
            if principal == '*':
                wildcard = True
            elif principal.startswith('arn:') and ':iam::' in principal:
                principal_account = principal.split(':')[4]
                if principal_account and principal_account != account_id:
                    external.append(principal)
        if wildcard:
            flags.append('public trust')
            anomalies.append(_anomaly(
                account_id, 'CRITICAL', 'wildcard_trust',
                'Role trust policy allows any principal', entity_id, role.role_name,
                'The role trust policy contains Principal "*".',
                'Replace wildcard trust with explicitly approved principals and protective conditions.',
            ))
        elif external:
            flags.append('cross-account trust')
            anomalies.append(_anomaly(
                account_id, 'HIGH', 'external_trust',
                'Role trusts a principal outside this account', entity_id, role.role_name,
                'Trusted principal: ' + ', '.join(external[:3]),
                'Confirm each external account is approved and require an external ID or organization condition where appropriate.',
            ))
        identities.append({
            'id': entity_id, 'account_id': account_id, 'type': 'role',
            'name': role.role_name, 'arn': role.arn, 'path': role.path,
            'groups': [], 'members': [], 'policies': _policy_names(role),
            'managed_policy_count': len(role.attached_managed_policies),
            'inline_policy_count': len(role.inline_policies),
            'trust_principals': principals, 'privileged': privileged,
            'active_access_keys': 0, 'mfa_active': None, 'flags': flags,
        })

    for policy in iam_data.policies:
        policy_id = f'{account_id}:policy:{policy.arn or policy.policy_name}'
        privileged = _document_grants_admin(policy.document)
        attachment_count = max(
            int(policy.attachment_count or 0),
            actual_attachments.get(policy.arn, 0),
            actual_attachments.get(policy.policy_name, 0),
        )
        policies.append({
            'id': policy_id, 'account_id': account_id, 'name': policy.policy_name,
            'arn': policy.arn, 'attachment_count': attachment_count,
            'privileged': privileged, 'path': policy.path,
        })
        if attachment_count == 0:
            anomalies.append(_anomaly(
                account_id, 'LOW', 'unattached_policy',
                'Customer-managed policy is not attached', policy_id, policy.policy_name,
                'The authorization snapshot reports an attachment count of zero.',
                'Confirm the policy is still required, then archive or delete it through the normal change process.',
            ))

    anomalies.sort(key=lambda item: (
        SEVERITY_ORDER.get(item['severity'], 9), item['account_id'],
        item['entity_name'].lower(), item['category'],
    ))
    identities.sort(key=lambda item: (item['account_id'], item['type'], item['name'].lower()))
    policies.sort(key=lambda item: (item['account_id'], item['name'].lower()))
    return {
        'account': {
            'account_id': account_id,
            'name': str(account.get('name') or ''),
            'email': str(account.get('email') or ''),
            'state': str(account.get('state') or 'ACTIVE'),
            'scanned': True,
            'error': '',
        },
        'identities': identities,
        'policies': policies,
        'anomalies': anomalies,
        'credential_report_available': bool(credential_rows),
    }


def build_organization_intelligence(scanned_accounts: List[Dict[str, Any]],
                                    discovered_accounts: Optional[List[Dict[str, Any]]] = None,
                                    warnings: Optional[List[str]] = None,
                                    previous: Optional[Dict[str, Any]] = None,
                                    source: str = 'live') -> Dict[str, Any]:
    identities: List[Dict[str, Any]] = []
    policies: List[Dict[str, Any]] = []
    anomalies: List[Dict[str, Any]] = []
    accounts: List[Dict[str, Any]] = []
    scanned_by_id = {}
    credential_reports = 0

    for item in scanned_accounts:
        if item.get('iam_data') is None:
            continue
        built = build_account_inventory(
            item['iam_data'], item.get('account'), item.get('credential_rows') or []
        )
        account_id = built['account']['account_id']
        scanned_by_id[account_id] = built['account']
        identities.extend(built['identities'])
        policies.extend(built['policies'])
        anomalies.extend(built['anomalies'])
        credential_reports += int(built['credential_report_available'])

    for account in discovered_accounts or []:
        account_id = str(account.get('account_id') or account.get('Id') or '')
        if account_id == '000000000000' and len(scanned_by_id) == 1:
            account_id = next(iter(scanned_by_id))
        normalized = scanned_by_id.get(account_id, {
            'account_id': account_id,
            'name': str(account.get('name') or account.get('Name') or ''),
            'email': str(account.get('email') or account.get('Email') or ''),
            'state': str(account.get('state') or account.get('State') or account.get('Status') or ''),
            'scanned': bool(account.get('scanned')),
            'error': str(account.get('error') or ''),
        })
        if account.get('error'):
            normalized['error'] = str(account['error'])
        accounts.append(normalized)
    known_account_ids = {item.get('account_id') for item in accounts}
    for account_id, account in scanned_by_id.items():
        if account_id not in known_account_ids:
            accounts.append(account)
    if not accounts:
        accounts = list(scanned_by_id.values())

    previous = previous or {}
    previous_ids = {item.get('id') for item in previous.get('identities', [])}
    current_ids = {item['id'] for item in identities}
    previous_policy_ids = {item.get('id') for item in previous.get('policies', [])}
    current_policy_ids = {item['id'] for item in policies}
    previous_account_ids = {item.get('account_id') for item in previous.get('accounts', [])}
    current_account_ids = {item.get('account_id') for item in accounts}
    has_baseline = bool(previous.get('generated_at'))

    changes = {
        'baseline_available': has_baseline,
        'new_identities': sorted(current_ids - previous_ids) if has_baseline else [],
        'removed_identities': sorted(previous_ids - current_ids) if has_baseline else [],
        'new_policies': sorted(current_policy_ids - previous_policy_ids) if has_baseline else [],
        'removed_policies': sorted(previous_policy_ids - current_policy_ids) if has_baseline else [],
        'new_accounts': sorted(current_account_ids - previous_account_ids) if has_baseline else [],
        'removed_accounts': sorted(previous_account_ids - current_account_ids) if has_baseline else [],
    }
    identity_by_id = {item['id']: item for item in identities}
    for identity_id in changes['new_identities']:
        identity = identity_by_id[identity_id]
        severity = 'HIGH' if identity.get('privileged') else 'MEDIUM'
        anomalies.append(_anomaly(
            identity['account_id'], severity, 'new_identity',
            'New IAM identity appeared since the previous scan', identity_id, identity['name'],
            f"A new {identity['type']} was not present in the previous saved organization snapshot.",
            'Confirm the owner, purpose, approval record, and expected lifetime of this identity.',
        ))
    for account_id in changes['new_accounts']:
        anomalies.append(_anomaly(
            account_id, 'HIGH', 'new_account',
            'New AWS account appeared since the previous scan', account_id + ':account', account_id,
            'This account ID was not present in the previous saved organization snapshot.',
            'Confirm that the account has an approved owner, organizational unit, logging, and security baseline.',
        ))

    anomalies.sort(key=lambda item: (
        SEVERITY_ORDER.get(item['severity'], 9), item['account_id'],
        item['entity_name'].lower(), item['category'],
    ))
    overview = {
        'accounts_discovered': len(accounts),
        'accounts_scanned': len(scanned_by_id),
        'users': sum(1 for item in identities if item['type'] == 'user'),
        'groups': sum(1 for item in identities if item['type'] == 'group'),
        'roles': sum(1 for item in identities if item['type'] == 'role'),
        'policies': len(policies),
        'anomalies': len(anomalies),
        'critical': sum(1 for item in anomalies if item['severity'] == 'CRITICAL'),
        'high': sum(1 for item in anomalies if item['severity'] == 'HIGH'),
        'credential_reports': credential_reports,
    }
    result = {
        'generated_at': _utc_now(),
        'source': source,
        'overview': overview,
        'accounts': sorted(accounts, key=lambda item: (item.get('name', '').lower(), item.get('account_id', ''))),
        'identities': identities,
        'policies': policies,
        'anomalies': anomalies,
        'changes': changes,
        'coverage': {
            'complete': len(scanned_by_id) == len(accounts) and not warnings,
            'warnings': list(warnings or []),
            'credential_reports': credential_reports,
            'definition': 'Unmanaged items become change anomalies only after a prior Winnow snapshot exists.',
        },
    }
    return result


class InventorySnapshotStore:
    """Small local SQLite history used only to compare organization scans."""

    def __init__(self, path: Optional[Path] = None):
        configured = os.environ.get('WINNOW_INVENTORY_DB', '').strip()
        self.path = Path(path or configured or DEFAULT_DB_PATH)

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path), timeout=5)
        connection.execute(
            'CREATE TABLE IF NOT EXISTS organization_snapshots ('
            'id INTEGER PRIMARY KEY AUTOINCREMENT, '
            'scope_key TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)'
        )
        connection.execute(
            'CREATE INDEX IF NOT EXISTS idx_org_snapshot_scope '
            'ON organization_snapshots(scope_key, id DESC)'
        )
        return connection

    def latest(self, scope_key: str) -> Optional[Dict[str, Any]]:
        if not self.path.exists():
            return None
        with closing(self._connect()) as connection:
            row = connection.execute(
                'SELECT payload FROM organization_snapshots '
                'WHERE scope_key = ? ORDER BY id DESC LIMIT 1', (scope_key,)
            ).fetchone()
        if not row:
            return None
        try:
            payload = json.loads(row[0])
            return payload if isinstance(payload, dict) else None
        except (TypeError, json.JSONDecodeError):
            return None

    def save(self, scope_key: str, payload: Dict[str, Any]) -> None:
        serialized = json.dumps(payload, separators=(',', ':'), sort_keys=True, default=str)
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    'INSERT INTO organization_snapshots(scope_key, created_at, payload) VALUES (?, ?, ?)',
                    (scope_key, payload.get('generated_at') or _utc_now(), serialized),
                )
                # Keep a bounded local history per scope.
                connection.execute(
                    'DELETE FROM organization_snapshots WHERE scope_key = ? AND id NOT IN '
                    '(SELECT id FROM organization_snapshots WHERE scope_key = ? ORDER BY id DESC LIMIT 30)',
                    (scope_key, scope_key),
                )

    def latest_any(self) -> Optional[Dict[str, Any]]:
        if not self.path.exists():
            return None
        with closing(self._connect()) as connection:
            row = connection.execute(
                'SELECT payload FROM organization_snapshots ORDER BY id DESC LIMIT 1'
            ).fetchone()
        if not row:
            return None
        try:
            payload = json.loads(row[0])
            return payload if isinstance(payload, dict) else None
        except (TypeError, json.JSONDecodeError):
            return None
