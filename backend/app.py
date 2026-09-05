import os
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

from iam_analyzer import IAMAnalyzer
from ai_detector import AIDetector
from remediator import Remediator
from visualizer import Visualizer

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

        static_vulnerabilities = analyzer.analyze(iam_config, config_type)

        ai_vulnerabilities = []
        if ai_detector.enabled:
            ai_vulnerabilities = ai_detector.dedupe(
                static_vulnerabilities,
                ai_detector.detect(iam_config, static_vulnerabilities)
            )

        vulnerabilities = static_vulnerabilities + ai_vulnerabilities

        remediations = remediator.batch_remediate(vulnerabilities)
        remediation_results = [
            {'vulnerability': vuln, 'remediation': remediation}
            for vuln, remediation in zip(vulnerabilities, remediations)
        ]

        visualization_data = visualizer.generate(remediation_results)

        return jsonify({
            'vulnerabilities': vulnerabilities,
            'remediations': remediation_results,
            'visualization': visualization_data,
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'critical': len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL']),
                'high': len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
                'medium': len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM']),
                'low': len([v for v in vulnerabilities if v.get('severity') == 'LOW']),
                'ai_suggested': len([v for v in vulnerabilities if v.get('detection_source') == 'ai'])
            }
        })
    except ValueError as e:
        # Bad input (e.g. malformed JSON strings inside the config)
        logger.warning(f"Invalid analyze request: {e}")
        return jsonify({'error': 'Invalid IAM configuration format'}), 400
    except Exception:
        logger.exception("Analysis error")
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
