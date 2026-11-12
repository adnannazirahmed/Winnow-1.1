import os
import json
import logging
import hmac
import secrets
import time
import re
import hashlib
from pathlib import Path
from urllib.parse import urlsplit
from flask import Flask, request, jsonify, send_from_directory, g, Response, redirect, abort
from dotenv import load_dotenv

from iam_analyzer import IAMAnalyzer
from ai_detector import AIDetector
from remediator import Remediator
from visualizer import Visualizer
import iam_ingest
import iam_graph
from graph_to_findings import graph_to_findings
from risk_brief import RiskBriefGenerator
from ai_provider import AIConnectionError, AIProvider
from analysis_history import AnalysisHistoryStore
from organization_intelligence import (
    InventorySnapshotStore,
    build_organization_intelligence,
)
import settings
from public_auth import verified_user_id
from supabase_history import SupabaseAnalysisStore

load_dotenv(dotenv_path=settings.ENV_FILE)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Resolve the frontend directory relative to this file, not the CWD,
# so the app works no matter where it is launched from.
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
PUBLIC_MODE = os.environ.get('WINNOW_PUBLIC_MODE') == '1'
if PUBLIC_MODE:
    for required in ('SUPABASE_URL', 'SUPABASE_ANON_KEY', 'WINNOW_PUBLIC_ORIGIN'):
        if not os.environ.get(required):
            raise RuntimeError(f'{required} is required in hosted mode')

MAX_CONFIG_BYTES = int(os.environ.get('MAX_CONFIG_BYTES', str(1024 * 1024)))  # 1 MB default

app = Flask(__name__, static_folder=FRONTEND_DIR)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONFIG_BYTES

ACCESS_TOKEN_FILE = Path(os.environ.get('WINNOW_ACCESS_TOKEN_FILE') or Path(__file__).with_name('.access_token'))

analyzer = IAMAnalyzer()
ai_detector = AIDetector()
remediator = Remediator()
visualizer = Visualizer()
risk_brief_generator = RiskBriefGenerator()
inventory_store = InventorySnapshotStore()
analysis_store = AnalysisHistoryStore()


def _user_store_path(filename):
    root = Path(os.environ.get('WINNOW_DATA_ROOT', '/data'))
    user_hash = hashlib.sha256(g.user_id.encode('ascii')).hexdigest()
    return root / 'users' / user_hash / filename


def _analysis_store():
    if PUBLIC_MODE:
        if not hasattr(g, 'analysis_store'):
            g.analysis_store = SupabaseAnalysisStore(g.user_id, g.access_token)
        return g.analysis_store
    return analysis_store


def _inventory_store():
    if PUBLIC_MODE:
        if not hasattr(g, 'inventory_store'):
            g.inventory_store = InventorySnapshotStore(_user_store_path('inventory.db'))
        return g.inventory_store
    return inventory_store

_SEVERITY_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def _refresh_ai_components():
    """Apply a settings change without requiring the user to restart Flask."""
    global ai_detector, remediator, risk_brief_generator
    ai_detector = AIDetector()
    remediator = Remediator()
    risk_brief_generator = RiskBriefGenerator()


def _access_token():
    """Share one strong token across workers and restarts without logging it."""
    configured = os.environ.get('WINNOW_ACCESS_TOKEN', '')
    if configured:
        if len(configured) < 32:
            raise RuntimeError('WINNOW_ACCESS_TOKEN must be at least 32 characters')
        return configured
    ACCESS_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    if ACCESS_TOKEN_FILE.is_symlink():
        raise RuntimeError('Winnow access token file must not be a symlink')
    try:
        fd = os.open(str(ACCESS_TOKEN_FILE), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, 'w', encoding='ascii') as output:
            output.write(secrets.token_urlsafe(48) + '\n')
    if ACCESS_TOKEN_FILE.is_symlink():
        raise RuntimeError('Winnow access token file must not be a symlink')
    if os.name != 'nt':
        ACCESS_TOKEN_FILE.chmod(0o600)
    for _ in range(20):
        token = ACCESS_TOKEN_FILE.read_text(encoding='ascii').strip()
        if token:
            return token
        time.sleep(0.05)
    raise RuntimeError('Winnow access token could not be initialized')


def _request_hostname():
    try:
        return (urlsplit('//' + request.host).hostname or '').lower()
    except ValueError:
        return ''


def _local_request():
    return (os.environ.get('HOST', '127.0.0.1') in ('127.0.0.1', 'localhost', '::1')
            and request.remote_addr in ('127.0.0.1', '::1')
            and _request_hostname() in ('localhost', '127.0.0.1', '::1'))


@app.before_request
def protect_local_data():
    if request.path == '/health':
        return None
    if PUBLIC_MODE:
        if request.path.startswith('/api/'):
            origin = request.headers.get('Origin')
            allowed_origin = os.environ.get('WINNOW_PUBLIC_ORIGIN', '')
            if origin and origin != allowed_origin:
                return jsonify({'error': 'Request origin is not allowed.'}), 403
            if request.method == 'OPTIONS':
                return Response(status=204)
            if request.path.startswith(('/api/settings', '/api/scan-account',
                                        '/api/organization/scan', '/api/generate-dummy')):
                return jsonify({'error': 'This feature is not available for hosted accounts yet.'}), 503
            authorization = request.headers.get('Authorization', '')
            if not authorization.startswith('Bearer '):
                return jsonify({'error': 'Sign in to continue.'}), 401
            g.access_token = authorization[7:]
            g.user_id = verified_user_id(g.access_token)
            if not g.user_id:
                return jsonify({'error': 'Your session has expired. Sign in again.'}), 401
        return None
    if not _local_request():
        hostname = _request_hostname()
        if (hostname not in ('localhost', '127.0.0.1', '::1')
                and not request.is_secure):
            return jsonify({'error': 'HTTPS is required for remote access.'}), 403
        auth = request.authorization
        supplied = auth.password if auth and auth.type == 'basic' and auth.username == 'winnow' else ''
        expected = _access_token()
        if not supplied or not hmac.compare_digest(supplied, expected):
            response = jsonify({'error': 'Authentication required.'})
            response.status_code = 401
            response.headers['WWW-Authenticate'] = 'Basic realm="Winnow"'
            return response
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        origin = request.headers.get('Origin')
        if request.headers.get('Sec-Fetch-Site') == 'cross-site':
            return jsonify({'error': 'Cross-site requests are not allowed.'}), 403
        if origin:
            expected = os.environ.get('WINNOW_PUBLIC_ORIGIN') or request.host_url.rstrip('/')
            if origin != expected:
                return jsonify({'error': 'Request origin is not allowed.'}), 403
    return None


@app.after_request
def public_cors(response):
    if PUBLIC_MODE and request.path.startswith('/api/'):
        origin = request.headers.get('Origin')
        if origin and origin == os.environ.get('WINNOW_PUBLIC_ORIGIN', ''):
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Vary'] = 'Origin'
            response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, DELETE, OPTIONS'
        response.headers['Cache-Control'] = 'no-store'
    return response


def _remember_analysis(payload):
    """Persist a completed result without making history a scan dependency."""
    if app.config.get('TESTING'):
        return payload
    try:
        payload['history'] = _analysis_store().save(payload)
    except Exception as exc:
        logger.error('Could not save completed analysis history: %s', type(exc).__name__)
    return payload


def _safe_input_error(error):
    """Retain parser location without echoing source text or field values."""
    message = str(error)
    match = re.match(r'^Invalid (Terraform syntax|JSON) at line (\d+), column (\d+)', message)
    if match:
        return f'Invalid {match.group(1)} at line {match.group(2)}, column {match.group(3)}.'
    if message.startswith('Invalid Terraform configuration JSON:'):
        return 'Invalid Terraform configuration JSON: blocks must contain objects.'
    return 'Invalid IAM configuration format'


@app.after_request
def set_security_headers(response):
    """Defense in depth: even if a rendering bug slipped through, CSP blocks
    inline event handlers and unknown script origins."""
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response


# ──────────────────────────────────────────────
#  Shared analysis pipeline
# ──────────────────────────────────────────────

def _merge_findings(graph_findings, rule_findings):
    """Graph findings (reachability-aware escalation paths) take precedence over a
    rule finding for the same (identity, pattern). Policy-scoped rule findings and
    identity-scoped graph findings almost never collide, so both mostly survive."""
    seen = {(f['resource_name'], f['pattern_id']) for f in graph_findings}
    merged = list(graph_findings)
    for f in rule_findings:
        key = (f['resource_name'], f['pattern_id'])
        if key in seen:
            continue
        seen.add(key)
        merged.append(f)
    return merged


def _run_pipeline(iam_data, source='static', source_name=None):
    """IAMData -> permission graph -> merged findings -> AI pass -> remediation ->
    visualization. Returns the JSON body shared by /api/analyze and /api/scan-account."""
    graph_output = iam_graph.process_iam_data(iam_data)
    graph_output.metadata.source = source
    graph_output.metadata.account_id = iam_data.account_id

    static_vulnerabilities = _merge_findings(
        graph_to_findings(graph_output),
        analyzer.scan_iamdata(iam_data),
    )

    ai_vulnerabilities = []
    if ai_detector.enabled:
        ai_vulnerabilities = ai_detector.dedupe(
            static_vulnerabilities,
            ai_detector.detect(iam_data.model_dump(mode='json'), static_vulnerabilities),
        )

    vulnerabilities = static_vulnerabilities + ai_vulnerabilities
    # Deterministic IDs: same input -> same IDs across processes / workers.
    vulnerabilities.sort(key=lambda v: (
        _SEVERITY_RANK.get(v.get('severity'), 4),
        v.get('resource_name', ''), v.get('pattern_id', ''), v.get('title', ''),
    ))
    for i, vuln in enumerate(vulnerabilities, start=1):
        vuln['id'] = f"VULN-{i:04d}"
        vuln['account_id'] = iam_data.account_id

    remediations = remediator.batch_remediate(vulnerabilities)
    remediation_results = [
        {'vulnerability': vuln, 'remediation': remediation}
        for vuln, remediation in zip(vulnerabilities, remediations)
    ]
    visualization_data = visualizer.generate(remediation_results, graph_output)

    def _count(sev):
        return len([v for v in vulnerabilities if v.get('severity') == sev])

    summary = {
        'total_vulnerabilities': len(vulnerabilities),
        'critical': _count('CRITICAL'),
        'high': _count('HIGH'),
        'medium': _count('MEDIUM'),
        'low': _count('LOW'),
        'ai_suggested': len([v for v in vulnerabilities if v.get('detection_source') == 'ai']),
        'graph_detected': len([v for v in vulnerabilities if v.get('detection_source') == 'graph']),
        'escalation_paths': graph_output.metadata.escalation_count,
        'source': graph_output.metadata.source,
        'source_name': source_name,
        'account_id': iam_data.account_id,
        'identity_count': len(iam_data.users) + len(iam_data.roles) + len(iam_data.groups),
        'policy_count': len(iam_data.policies) + sum(
            len(entity.inline_policies)
            for entities in (iam_data.users, iam_data.roles, iam_data.groups)
            for entity in entities
        ),
        'coverage': iam_data.coverage.model_dump(mode='json'),
        'ai_status': 'enabled' if ai_detector.enabled else 'disabled',
    }
    risk_brief = risk_brief_generator.generate(
        summary, vulnerabilities, remediation_results, visualization_data
    )
    organization = build_organization_intelligence(
        [{
            'account': {
                'account_id': iam_data.account_id,
                'name': source_name or ('Connected account' if source == 'live' else 'Current analysis'),
                'state': 'ACTIVE',
            },
            'iam_data': iam_data,
            'credential_rows': [],
        }],
        discovered_accounts=[{
            'account_id': iam_data.account_id,
            'name': source_name or ('Connected account' if source == 'live' else 'Current analysis'),
            'state': 'ACTIVE',
            'scanned': True,
        }],
        warnings=([] if source == 'live' else [
            'This inventory reflects the current analysis input, not an AWS Organizations scan.'
        ]),
        source=source,
    )

    return {
        'vulnerabilities': vulnerabilities,
        'remediations': remediation_results,
        'visualization': visualization_data,
        'summary': summary,
        'risk_brief': risk_brief,
        'organization_intelligence': organization,
    }


# ──────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────

@app.route('/')
def index():
    if PUBLIC_MODE:
        return redirect('https://adnannazirahmed.github.io/Winnow-1.1/', code=302)
    return send_from_directory(FRONTEND_DIR, 'index.html')


@app.route('/app/')
def workspace():
    if PUBLIC_MODE:
        return redirect('https://adnannazirahmed.github.io/Winnow-1.1/app/', code=302)
    return send_from_directory(FRONTEND_DIR, 'index.html')


@app.route('/app/<path:path>')
def workspace_asset(path):
    if PUBLIC_MODE:
        abort(404)
    return send_from_directory(FRONTEND_DIR, path)


@app.route('/supabase-config.js')
def supabase_browser_config():
    if not PUBLIC_MODE:
        return Response('window.WINNOW_PUBLIC_MODE = false;', mimetype='application/javascript')
    config = {
        'url': os.environ.get('SUPABASE_URL', ''),
        'anonKey': os.environ.get('SUPABASE_ANON_KEY', ''),
    }
    source = ('window.WINNOW_PUBLIC_MODE = true;\nwindow.WINNOW_SUPABASE = '
              + json.dumps(config) + ';\n')
    response = Response(source, mimetype='application/javascript')
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/<path:path>')
def serve_static(path):
    if PUBLIC_MODE:
        abort(404)
    return send_from_directory(FRONTEND_DIR, path)


@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or 'iam_config' not in data:
            return jsonify({'error': 'Missing iam_config in request'}), 400

        iam_config = data['iam_config']
        config_type = data.get('config_type', 'terraform')
        source = data.get('source', 'upload')
        if source not in ('upload', 'demo', 'static'):
            source = 'upload'
        source_name = str(data.get('source_name') or '')[:160] or None

        iam_data = iam_ingest.config_to_iamdata(iam_config, config_type)
        result = _run_pipeline(iam_data, source=source, source_name=source_name)
        return jsonify(_remember_analysis(result))
    except ValueError as e:
        logger.warning('Invalid analyze request: %s', type(e).__name__)
        return jsonify({'error': _safe_input_error(e)}), 400
    except Exception as e:
        logger.error('Analysis error: %s', type(e).__name__)
        return jsonify({'error': 'Internal server error during analysis'}), 500


@app.route('/api/scan-account', methods=['POST'])
def scan_account():
    """Scan the caller's live AWS account (read-only). Credentials come from the
    standard boto3 chain (AWS_PROFILE or AWS_* env vars). Never returns a stack
    trace; never logs or echoes credentials."""
    try:
        import aws_collector
    except Exception:
        logger.warning("scan-account requested but aws_collector import failed")
        return jsonify({'error': 'AWS scanning unavailable: boto3 is not installed'}), 501

    try:
        raw, account_id = aws_collector.collect_account_authorization_details()
    except aws_collector.BotoNotInstalled:
        return jsonify({'error': 'AWS scanning unavailable: boto3 is not installed'}), 501
    except aws_collector.NoCredentials:
        return jsonify({'error': 'No AWS credentials found. Set AWS_PROFILE or the standard AWS_* environment variables.'}), 400
    except aws_collector.AccessDenied:
        return jsonify({'error': 'The AWS credentials lack iam:GetAccountAuthorizationDetails.'}), 403
    except aws_collector.Throttled:
        return jsonify({'error': 'AWS throttled the request after retries. Try again shortly.'}), 429
    except Exception as exc:
        logger.error('AWS scan error: %s', type(exc).__name__)
        return jsonify({'error': 'AWS scan failed. Check the server logs.'}), 502

    try:
        iam_data = iam_ingest.parse_gaad(raw, account_id)
        return jsonify(_remember_analysis(_run_pipeline(iam_data, source='live')))
    except Exception as exc:
        logger.error('Analysis error after AWS scan: %s', type(exc).__name__)
        return jsonify({'error': 'Internal server error during analysis'}), 500


@app.route('/api/generate-dummy', methods=['POST'])
def generate_dummy():
    try:
        dummy_config = analyzer.generate_dummy_data()
        return jsonify({'iam_config': dummy_config})
    except Exception as exc:
        logger.error('Dummy generation error: %s', type(exc).__name__)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/history', methods=['GET', 'DELETE'])
def analysis_history():
    """List recent local analyses or remove the complete local history."""
    try:
        if request.method == 'DELETE':
            return jsonify({'deleted': _analysis_store().clear(), 'runs': []})
        return jsonify({'runs': _analysis_store().list()})
    except Exception as exc:
        logger.error('Could not access analysis history: %s', type(exc).__name__)
        return jsonify({'error': 'Saved analysis history is unavailable.'}), 500


@app.route('/api/history/latest', methods=['GET'])
def latest_analysis():
    try:
        analysis = _analysis_store().latest()
        return jsonify({'available': bool(analysis), 'analysis': analysis})
    except Exception as exc:
        logger.error('Could not restore the latest analysis: %s', type(exc).__name__)
        return jsonify({'error': 'The latest saved analysis is unavailable.'}), 500


@app.route('/api/history/<int:run_id>', methods=['GET', 'DELETE'])
def saved_analysis(run_id):
    try:
        if request.method == 'DELETE':
            deleted = _analysis_store().delete(run_id)
            if not deleted:
                return jsonify({'error': 'Saved analysis was not found.'}), 404
            return jsonify({'deleted': True, 'id': run_id})
        analysis = _analysis_store().get(run_id)
        if not analysis:
            return jsonify({'error': 'Saved analysis was not found.'}), 404
        return jsonify({'analysis': analysis})
    except Exception as exc:
        logger.error('Could not access saved analysis %s: %s', run_id, type(exc).__name__)
        return jsonify({'error': 'Saved analysis is unavailable.'}), 500


@app.route('/api/remediate', methods=['POST'])
def generate_remediation():
    """Generate and cache an AI assessment for one selected finding.

    Batch analysis is intentionally capped to control latency and cost. This
    route lets the policy workbench request any remaining finding on demand.
    """
    data = request.get_json(silent=True)
    finding = data.get('finding') if isinstance(data, dict) else None
    if not isinstance(finding, dict):
        return jsonify({'error': 'Send one finding as JSON.'}), 400
    try:
        if len(str(finding)) > 32000:
            raise ValueError('Finding is too large to remediate')
        policy_document = finding.get('policy_document') or {}
        if not isinstance(policy_document, dict):
            raise ValueError('Finding policy_document must be an object')
        attack_path = finding.get('attack_path') or []
        if not isinstance(attack_path, list):
            raise ValueError('Finding attack_path must be a list')
        mitre = finding.get('mitre_techniques') or []
        if not isinstance(mitre, list):
            raise ValueError('Finding mitre_techniques must be a list')
        severity = str(finding.get('severity') or 'MEDIUM').upper()
        if severity not in _SEVERITY_RANK:
            severity = 'MEDIUM'
        clean_finding = {
            'id': str(finding.get('id') or '')[:64],
            'pattern_id': str(finding.get('pattern_id') or '')[:160],
            'title': str(finding.get('title') or 'Unnamed finding')[:240],
            'description': str(finding.get('description') or '')[:4000],
            'severity': severity,
            'resource_type': str(finding.get('resource_type') or 'unknown')[:160],
            'resource_name': str(finding.get('resource_name') or 'unknown')[:512],
            'account_id': str(finding.get('account_id') or '')[:64],
            'policy_document': policy_document,
            'attack_path': [str(step)[:512] for step in attack_path[:24]],
            'mitre_techniques': [str(item)[:64] for item in mitre[:24]],
            'remediation_hint': str(finding.get('remediation_hint') or '')[:1000],
            'detection_source': str(finding.get('detection_source') or 'rule')[:32],
        }
        if not clean_finding['id']:
            raise ValueError('Finding id is required')
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    remediation = remediator.get_remediation(clean_finding)
    history_saved = False
    history_id = data.get('history_id') if isinstance(data, dict) else None
    if history_id is not None:
        try:
            history_saved = _analysis_store().update_remediation(
                int(history_id), clean_finding['id'], remediation
            )
        except (TypeError, ValueError):
            history_saved = False
        except Exception as exc:
            logger.error('Could not update remediation in saved analysis: %s', type(exc).__name__)
    return jsonify({
        'remediation': remediation,
        'generated': remediation.get('source') == 'ai',
        'history_saved': history_saved,
    })


@app.route('/api/organization', methods=['GET'])
def latest_organization_inventory():
    if PUBLIC_MODE:
        return jsonify({'available': False, 'inventory': None})
    try:
        latest = _inventory_store().latest_any()
    except Exception as exc:
        logger.error('Could not read the saved organization inventory: %s', type(exc).__name__)
        return jsonify({'available': False, 'error': 'Saved organization inventory is unavailable.'}), 500
    return jsonify({'available': bool(latest), 'inventory': latest})


@app.route('/api/organization/scan', methods=['POST'])
def scan_organization():
    """Build a read-only identity inventory across discoverable AWS accounts."""
    try:
        import aws_collector
    except Exception:
        return jsonify({'error': 'AWS organization scanning unavailable: boto3 is not installed'}), 501

    role_name = os.environ.get('AWS_ORGANIZATION_ROLE_NAME', '').strip()
    try:
        maximum = max(1, int(os.environ.get('MAX_ORGANIZATION_ACCOUNTS', '100')))
    except ValueError:
        maximum = 100
    try:
        collected = aws_collector.collect_organization_inventory(role_name, maximum)
    except aws_collector.BotoNotInstalled:
        return jsonify({'error': 'AWS organization scanning unavailable: boto3 is not installed'}), 501
    except aws_collector.NoCredentials:
        return jsonify({'error': 'No valid AWS credentials are connected.'}), 400
    except aws_collector.Throttled:
        return jsonify({'error': 'AWS throttled the organization scan. Try again shortly.'}), 429
    except aws_collector.CollectorError:
        return jsonify({'error': 'AWS organization discovery failed for the connected credentials.'}), 502
    except Exception as exc:
        logger.error('AWS organization collection failed: %s', type(exc).__name__)
        return jsonify({'error': 'AWS organization collection failed. Check the server logs.'}), 502

    scanned_accounts = []
    parse_warnings = []
    for item in collected.get('scanned', []):
        account = item.get('account') or {}
        account_id = str(account.get('account_id') or '000000000000')
        try:
            scanned_accounts.append({
                'account': account,
                'iam_data': iam_ingest.parse_gaad(item.get('raw') or {}, account_id),
                'credential_rows': item.get('credential_rows') or [],
            })
        except Exception:
            parse_warnings.append(
                f'Winnow could not parse the IAM inventory for account {account_id}.'
            )

    scope_key = str(collected.get('scope_key') or 'connected-account')
    warnings = list(collected.get('warnings') or []) + parse_warnings
    try:
        previous = _inventory_store().latest(scope_key)
    except Exception:
        previous = None
        warnings.append('The previous local snapshot could not be read, so change detection is unavailable.')
    inventory = build_organization_intelligence(
        scanned_accounts,
        discovered_accounts=collected.get('accounts') or [],
        warnings=warnings,
        previous=previous,
        source='aws-organization',
    )
    try:
        _inventory_store().save(scope_key, inventory)
    except Exception as exc:
        logger.error('Could not save organization inventory snapshot: %s', type(exc).__name__)
        inventory['coverage']['warnings'].append(
            'This scan succeeded but its local comparison snapshot could not be saved.'
        )
        inventory['coverage']['complete'] = False
    return jsonify(inventory)


# ──────────────────────────────────────────────
#  Local integration settings
# ──────────────────────────────────────────────

@app.route('/api/settings', methods=['GET'])
def get_settings():
    return jsonify(settings.public_settings())


@app.route('/api/settings/aws', methods=['POST', 'DELETE'])
def aws_settings():
    if request.method == 'DELETE':
        settings.remove_aws_credentials()
        return jsonify({'settings': settings.public_settings()})

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Send AWS credentials as JSON.'}), 400
    try:
        settings.save_aws_credentials(data)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    # Confirm the submitted credentials through Winnow's existing read-only
    # inventory call. The returned result saves a duplicate scan request.
    try:
        import aws_collector
        raw, account_id = aws_collector.collect_account_authorization_details()
        iam_data = iam_ingest.parse_gaad(raw, account_id)
        return jsonify({
            'settings': settings.public_settings(),
            'analysis': _remember_analysis(_run_pipeline(iam_data, source='live')),
        })
    except Exception as e:
        logger.info('Saved AWS settings could not be verified: %s', type(e).__name__)
        return jsonify({
            'error': 'Credentials were saved but could not be verified. Check the key, region, and IAM read permissions.',
            'settings': settings.public_settings(),
        }), 422


@app.route('/api/settings/ai', methods=['POST', 'DELETE'])
def ai_settings():
    if request.method == 'DELETE':
        settings.remove_ai_configuration()
        _refresh_ai_components()
        return jsonify({'settings': settings.public_settings()})

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Send AI settings as JSON.'}), 400
    try:
        config = settings.normalise_ai_configuration(data)
        probe = AIProvider(
            provider=config['provider'], api_key=config['api_key'],
            model=config['model'], base_url=config['base_url'],
            timeout=float(os.environ.get('AI_VALIDATION_TIMEOUT_SECONDS', '15')),
        )
        probe.validate_connection()
        settings.save_ai_configuration(data)
        _refresh_ai_components()
        return jsonify({'settings': settings.public_settings(), 'verified': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except AIConnectionError as e:
        return jsonify({'error': str(e)}), 422


@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    # Bind to localhost by default; set HOST=0.0.0.0 explicitly for containers.
    host = os.environ.get('HOST', '127.0.0.1')
    app.run(host=host, port=port, debug=debug)
