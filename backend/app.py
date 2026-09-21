import os
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
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
from organization_intelligence import (
    InventorySnapshotStore,
    build_organization_intelligence,
)
import settings

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Resolve the frontend directory relative to this file, not the CWD,
# so the app works no matter where it is launched from.
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))

MAX_CONFIG_BYTES = int(os.environ.get('MAX_CONFIG_BYTES', str(1024 * 1024)))  # 1 MB default

app = Flask(__name__, static_folder=FRONTEND_DIR)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONFIG_BYTES

# CORS: same-origin by default. Set CORS_ORIGINS to a comma-separated list
# only if the frontend is served from a different origin.
cors_origins = os.environ.get('CORS_ORIGINS')
if cors_origins:
    CORS(app, resources={r"/api/*": {"origins": [o.strip() for o in cors_origins.split(',')]}})

analyzer = IAMAnalyzer()
ai_detector = AIDetector()
remediator = Remediator()
visualizer = Visualizer()
risk_brief_generator = RiskBriefGenerator()
inventory_store = InventorySnapshotStore()

_SEVERITY_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def _refresh_ai_components():
    """Apply a settings change without requiring the user to restart Flask."""
    global ai_detector, remediator, risk_brief_generator
    ai_detector = AIDetector()
    remediator = Remediator()
    risk_brief_generator = RiskBriefGenerator()


def _settings_write_allowed():
    """Secrets may be entered through the UI only from this machine by default.
    An operator deploying the app remotely can opt in deliberately."""
    if os.environ.get('ALLOW_REMOTE_SETTINGS') == '1':
        return True
    return request.remote_addr in ('127.0.0.1', '::1', None)


def _settings_write_guard():
    if not _settings_write_allowed():
        return jsonify({'error': 'Settings changes are available only from the server machine.'}), 403
    return None


@app.after_request
def set_security_headers(response):
    """Defense in depth: even if a rendering bug slipped through, CSP blocks
    inline event handlers and unknown script origins."""
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://d3js.org https://cdnjs.cloudflare.com; "
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
    return send_from_directory(FRONTEND_DIR, 'index.html')


@app.route('/<path:path>')
def serve_static(path):
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
        return jsonify(_run_pipeline(iam_data, source=source, source_name=source_name))
    except ValueError as e:
        logger.warning(f"Invalid analyze request: {e}")
        return jsonify({'error': str(e)[:240] or 'Invalid IAM configuration format'}), 400
    except Exception:
        logger.exception("Analysis error")
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
    except Exception:
        logger.exception("AWS scan error")
        return jsonify({'error': 'AWS scan failed. Check the server logs.'}), 502

    try:
        iam_data = iam_ingest.parse_gaad(raw, account_id)
        return jsonify(_run_pipeline(iam_data, source='live'))
    except Exception:
        logger.exception("Analysis error after AWS scan")
        return jsonify({'error': 'Internal server error during analysis'}), 500


@app.route('/api/generate-dummy', methods=['POST'])
def generate_dummy():
    try:
        dummy_config = analyzer.generate_dummy_data()
        return jsonify({'iam_config': dummy_config})
    except Exception:
        logger.exception("Dummy generation error")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/organization', methods=['GET'])
def latest_organization_inventory():
    try:
        latest = inventory_store.latest_any()
    except Exception:
        logger.exception('Could not read the saved organization inventory')
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
    except Exception:
        logger.exception('AWS organization collection failed')
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
        previous = inventory_store.latest(scope_key)
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
        inventory_store.save(scope_key, inventory)
    except Exception:
        logger.exception('Could not save organization inventory snapshot')
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
    guard = _settings_write_guard()
    if guard:
        return guard
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
            'analysis': _run_pipeline(iam_data, source='live'),
        })
    except Exception as e:
        logger.info('Saved AWS settings could not be verified: %s', type(e).__name__)
        return jsonify({
            'error': 'Credentials were saved but could not be verified. Check the key, region, and IAM read permissions.',
            'settings': settings.public_settings(),
        }), 422


@app.route('/api/settings/ai', methods=['POST', 'DELETE'])
def ai_settings():
    guard = _settings_write_guard()
    if guard:
        return guard
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
