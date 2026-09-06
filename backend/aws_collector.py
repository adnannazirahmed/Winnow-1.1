"""Live AWS IAM collection — read-only.

Ported from adnannazirahmed/IAM-Visualizer (backend/src/aws_exporter.py), trimmed
to the two calls Winnow needs and given typed exceptions the API layer can turn
into clean HTTP responses.

Exactly two AWS API calls, both read-only:
  * iam:GetAccountAuthorizationDetails  (paginated — every user/role/group/policy)
  * sts:GetCallerIdentity               (just the account id)

Credentials come from the standard boto3 chain: AWS_PROFILE, or AWS_ACCESS_KEY_ID
/ AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN, or ~/.aws/*, or an instance/container
role. Nothing here ever calls a mutating IAM API.
"""

import logging
import os
import random
import time
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


def collect_account_authorization_details() -> Tuple[Dict[str, Any], str]:
    """Return (merged raw GAAD dict, account_id). Raises a CollectorError subclass
    the API layer maps to an HTTP status."""
    if not _BOTO_OK:
        raise BotoNotInstalled("boto3 is not installed")

    session = _session()
    iam = session.client("iam")

    raw: Dict[str, Any] = {
        "UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": [],
    }
    try:
        paginator = iam.get_paginator("get_account_authorization_details")
        for page in paginator.paginate():
            for key in raw:
                raw[key].extend(page.get(key, []))
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
