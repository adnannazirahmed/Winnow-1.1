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

_SEVERITY_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


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


def _run_pipeline(iam_data, source='static'):
    """IAMData -> permission graph -> merged findings -> AI pass -> remediation ->
    visualization. Returns the JSON body shared by /api/analyze and /api/scan-account."""
    graph_output = iam_graph.process_iam_data(iam_data)
    graph_output.metadata.source = 'live' if source == 'live' else 'static'
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

    return {
        'vulnerabilities': vulnerabilities,
        'remediations': remediation_results,
        'visualization': visualization_data,
        'summary': {
            'total_vulnerabilities': len(vulnerabilities),
            'critical': _count('CRITICAL'),
            'high': _count('HIGH'),
            'medium': _count('MEDIUM'),
            'low': _count('LOW'),
            'ai_suggested': len([v for v in vulnerabilities if v.get('detection_source') == 'ai']),
            'graph_detected': len([v for v in vulnerabilities if v.get('detection_source') == 'graph']),
            'escalation_paths': graph_output.metadata.escalation_count,
            'source': graph_output.metadata.source,
            'account_id': iam_data.account_id,
        },
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
        if not data or 'iam_config' not in data:
            return jsonify({'error': 'Missing iam_config in request'}), 400

        iam_config = data['iam_config']
        config_type = data.get('config_type', 'terraform')

        iam_data = iam_ingest.config_to_iamdata(iam_config, config_type)
        return jsonify(_run_pipeline(iam_data, source='static'))
    except ValueError as e:
        logger.warning(f"Invalid analyze request: {e}")
        return jsonify({'error': 'Invalid IAM configuration format'}), 400
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


@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    # Bind to localhost by default; set HOST=0.0.0.0 explicitly for containers.
    host = os.environ.get('HOST', '127.0.0.1')
    app.run(host=host, port=port, debug=debug)
