"""Live AWS IAM collection — read-only.

Ported from adnannazirahmed/IAM-Visualizer (backend/src/aws_exporter.py) and
extended with optional AWS Organizations, cross-account, and credential-report
collection. Typed exceptions let the API layer return clean HTTP responses.

Exactly two AWS API calls, both read-only:
  * iam:GetAccountAuthorizationDetails  (paginated — every user/role/group/policy)
  * sts:GetCallerIdentity               (just the account id)

The separate organization inventory can also call organizations:ListAccounts,
sts:AssumeRole, iam:GenerateCredentialReport, and iam:GetCredentialReport. It
never creates, updates, or deletes IAM access.

Credentials come from the standard boto3 chain: AWS_PROFILE, or AWS_ACCESS_KEY_ID
/ AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN, or ~/.aws/*, or an instance/container
role. Nothing here ever calls a mutating IAM API.
"""

import logging
import os
import random
import time
import csv
import io
import base64
from typing import Any, Dict, Tuple

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError, ProfileNotFound
    _BOTO_OK = True
except ImportError:  # pragma: no cover - exercised only where boto3 is absent
    boto3 = None
    _BOTO_OK = False

    class ClientError(Exception): ...
    class BotoCoreError(Exception): ...
    class NoCredentialsError(Exception): ...
    class ProfileNotFound(Exception): ...


class CollectorError(Exception):
    """Base for everything the API layer maps to an HTTP status."""


class BotoNotInstalled(CollectorError): ...
class NoCredentials(CollectorError): ...
class AccessDenied(CollectorError): ...
class Throttled(CollectorError): ...


_THROTTLE_CODES = {"Throttling", "ThrottlingException", "RequestLimitExceeded", "RateExceeded"}
_MAX_RETRIES = 5
_BASE_DELAY = 1.0
_MAX_DELAY = 30.0


def _session():
    profile = os.environ.get("AWS_PROFILE")
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def _call_with_backoff(operation, **kwargs):
    retries = 0
    while True:
        try:
            return operation(**kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in _THROTTLE_CODES:
                if retries >= _MAX_RETRIES:
                    raise Throttled(f"throttled after {retries} retries")
                delay = min(_MAX_DELAY, _BASE_DELAY * (2 ** retries))
                time.sleep(delay + random.uniform(0, delay * 0.1))
                retries += 1
                continue
            raise


def _collect_authorization_details(session) -> Dict[str, Any]:
    iam = session.client("iam")
    raw: Dict[str, Any] = {
        "UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": [],
    }
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate():
        for key in raw:
            raw[key].extend(page.get(key, []))
    return raw


def _credential_report(session):
    """Return parsed credential-report rows, or [] when the permission is absent."""
    iam = session.client("iam")
    try:
        state = _call_with_backoff(iam.generate_credential_report).get('State', '')
        for _ in range(4):
            if state == 'COMPLETE':
                break
            time.sleep(0.25)
            state = _call_with_backoff(iam.generate_credential_report).get('State', '')
        if state != 'COMPLETE':
            return []
        content = _call_with_backoff(iam.get_credential_report).get('Content', b'')
        if isinstance(content, str):
            try:
                content = base64.b64decode(content)
            except Exception:
                content = content.encode('utf-8')
        text = bytes(content).decode('utf-8-sig', errors='replace')
        return list(csv.DictReader(io.StringIO(text)))
    except (ClientError, BotoCoreError):
        return []


def _organization_accounts(session):
    organizations = session.client('organizations')
    accounts = []
    paginator = organizations.get_paginator('list_accounts')
    for page in paginator.paginate():
        accounts.extend(page.get('Accounts', []))
    return accounts


def _assume_account_session(session, account_id: str, role_name: str, partition: str):
    sts = session.client('sts')
    response = _call_with_backoff(
        sts.assume_role,
        RoleArn=f'arn:{partition}:iam::{account_id}:role/{role_name.lstrip("/")}',
        RoleSessionName='WinnowOrganizationInventory',
        DurationSeconds=3600,
    )
    credentials = response['Credentials']
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=getattr(session, 'region_name', None),
    )


def collect_account_authorization_details() -> Tuple[Dict[str, Any], str]:
    """Return (merged raw GAAD dict, account_id). Raises a CollectorError subclass
    the API layer maps to an HTTP status."""
    if not _BOTO_OK:
        raise BotoNotInstalled("boto3 is not installed")

    session = _session()
    try:
        raw = _collect_authorization_details(session)
    except (NoCredentialsError, ProfileNotFound) as e:
        raise NoCredentials(str(e))
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            raise AccessDenied(code)
        if code in ("InvalidClientTokenId", "SignatureDoesNotMatch", "AuthFailure",
                    "ExpiredToken", "ExpiredTokenException", "InvalidAccessKeyId"):
            raise NoCredentials(code)
        if code in _THROTTLE_CODES:
            raise Throttled(code)
        logger.error("get_account_authorization_details failed: %s", code or e)
        raise CollectorError(code or "AWS error")
    except BotoCoreError as e:
        raise CollectorError(str(e))

    account_id = "000000000000"
    try:
        sts = session.client("sts")
        account_id = _call_with_backoff(sts.get_caller_identity).get("Account", account_id)
    except (NoCredentialsError, ProfileNotFound):
        raise NoCredentials("no AWS credentials for sts:GetCallerIdentity")
    except Exception as e:  # non-fatal — the account id is cosmetic
        logger.warning("Could not resolve AWS account id: %s", e)

    return raw, account_id


def collect_organization_inventory(role_name: str = '', max_accounts: int = 100) -> Dict[str, Any]:
    """Discover AWS Organization accounts and collect read-only IAM inventories.

    The caller's account is always scanned. Other active accounts are scanned only
    when role_name is configured and assumable in those accounts. Partial failures
    are returned as coverage warnings rather than discarding successful accounts.
    """
    if not _BOTO_OK:
        raise BotoNotInstalled("boto3 is not installed")
    session = _session()
    try:
        caller = _call_with_backoff(session.client('sts').get_caller_identity)
    except (NoCredentialsError, ProfileNotFound) as exc:
        raise NoCredentials(str(exc))
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code', '')
        if code in ("InvalidClientTokenId", "SignatureDoesNotMatch", "AuthFailure",
                    "ExpiredToken", "ExpiredTokenException", "InvalidAccessKeyId"):
            raise NoCredentials(code)
        raise CollectorError(code or 'STS error')

    current_id = str(caller.get('Account') or '')
    arn = str(caller.get('Arn') or 'arn:aws:')
    partition = arn.split(':', 2)[1] if arn.startswith('arn:') else 'aws'
    warnings = []
    try:
        discovered = _organization_accounts(session)
    except (ClientError, BotoCoreError) as exc:
        discovered = [{'Id': current_id, 'Name': 'Connected account', 'State': 'ACTIVE'}]
        warnings.append(
            'AWS Organizations account discovery is unavailable; showing the connected account only. '
            'Grant organizations:ListAccounts from a management or delegated administrator account.'
        )

    if not any(str(item.get('Id')) == current_id for item in discovered):
        discovered.append({'Id': current_id, 'Name': 'Connected account', 'State': 'ACTIVE'})
    active_all = [item for item in discovered
                  if str(item.get('State') or item.get('Status') or 'ACTIVE') == 'ACTIVE']
    active_all.sort(key=lambda item: 0 if str(item.get('Id')) == current_id else 1)
    active = list(active_all)
    limited = []
    if max_accounts > 0 and len(active_all) > max_accounts:
        warnings.append(
            f'Organization scan was limited to {max_accounts} active accounts. '
            'Increase MAX_ORGANIZATION_ACCOUNTS to extend coverage.'
        )
        active = active_all[:max_accounts]
        limited = active_all[max_accounts:]

    scanned = []
    account_status = [{
        'account_id': str(item.get('Id') or ''),
        'name': str(item.get('Name') or ''),
        'email': str(item.get('Email') or ''),
        'state': str(item.get('State') or item.get('Status') or ''),
        'scanned': False,
        'error': 'Account is not active',
    } for item in discovered if item not in active_all]
    account_status.extend({
        'account_id': str(item.get('Id') or ''),
        'name': str(item.get('Name') or ''),
        'email': str(item.get('Email') or ''),
        'state': str(item.get('State') or item.get('Status') or 'ACTIVE'),
        'scanned': False,
        'error': 'Outside the configured scan limit',
    } for item in limited)
    for item in active:
        account_id = str(item.get('Id') or '')
        metadata = {
            'account_id': account_id,
            'name': str(item.get('Name') or ''),
            'email': str(item.get('Email') or ''),
            'state': str(item.get('State') or item.get('Status') or 'ACTIVE'),
        }
        target_session = session
        if account_id != current_id:
            if not role_name:
                metadata.update({
                    'scanned': False,
                    'error': 'Cross-account role not configured',
                })
                account_status.append(metadata)
                continue
            try:
                target_session = _assume_account_session(
                    session, account_id, role_name, partition
                )
            except Exception as exc:
                metadata.update({
                    'scanned': False,
                    'error': 'Could not assume the configured read-only role',
                })
                account_status.append(metadata)
                logger.info('Organization inventory could not assume role in %s: %s',
                            account_id, type(exc).__name__)
                continue
        try:
            raw = _collect_authorization_details(target_session)
            credentials = _credential_report(target_session)
            metadata.update({'scanned': True, 'error': ''})
            account_status.append(metadata)
            scanned.append({
                'account': metadata,
                'raw': raw,
                'credential_rows': credentials,
            })
        except ClientError as exc:
            metadata.update({
                'scanned': False,
                'error': 'Read-only IAM inventory permission was denied',
            })
            account_status.append(metadata)
            logger.info('Organization IAM inventory denied in %s: %s',
                        account_id, exc.response.get('Error', {}).get('Code', 'ClientError'))
        except (NoCredentialsError, ProfileNotFound):
            metadata.update({'scanned': False, 'error': 'Credentials were unavailable'})
            account_status.append(metadata)
        except BotoCoreError as exc:
            metadata.update({'scanned': False, 'error': 'AWS inventory request failed'})
            account_status.append(metadata)
            logger.info('Organization IAM inventory failed in %s: %s', account_id, type(exc).__name__)

    unscanned = [item for item in account_status if not item.get('scanned')]
    if unscanned:
        warnings.append(
            f'{len(unscanned)} discovered account(s) were not scanned. Review each account status '
            'and configure the cross-account role shown in Settings where applicable.'
        )
    return {
        'scope_key': current_id,
        'current_account_id': current_id,
        'accounts': account_status,
        'scanned': scanned,
        'warnings': warnings,
    }
