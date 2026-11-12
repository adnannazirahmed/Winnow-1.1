"""Package the static GitHub Pages site and the real workbench."""

import json
import os
import shutil
import hashlib
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'site-dist'


def required_origin(name):
    value = os.environ.get(name, '').rstrip('/')
    parsed = urlparse(value)
    if parsed.scheme != 'https' or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
        raise SystemExit(f'{name} must be a complete HTTPS origin')
    return value


def build():
    api_origin = required_origin('WINNOW_API_ORIGIN')
    supabase_url = required_origin('SUPABASE_URL')
    public_key = os.environ.get('SUPABASE_ANON_KEY', '')
    if not public_key.startswith(('sb_publishable_', 'eyJ')):
        raise SystemExit('SUPABASE_ANON_KEY must be a public publishable or anon key')
    if OUTPUT.resolve().parent != ROOT.resolve():
        raise SystemExit('Output must stay inside the project root')
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    shutil.copytree(ROOT / 'website', OUTPUT)
    shutil.copytree(ROOT / 'frontend', OUTPUT / 'app')
    app_page = OUTPUT / 'app' / 'index.html'
    app_html = app_page.read_text(encoding='utf-8')
    for asset, attribute in (('style.css', 'href'), ('public-app.js', 'src')):
        original = f'{attribute}="{asset}"'
        if app_html.count(original) != 1:
            raise SystemExit(f'Expected one {asset} reference in the app page')
        digest = hashlib.sha256((OUTPUT / 'app' / asset).read_bytes()).hexdigest()[:12]
        app_html = app_html.replace(original, f'{attribute}="{asset}?v={digest}"')
    app_page.write_text(app_html, encoding='utf-8')
    config = (
        'window.WINNOW_PUBLIC_MODE = true;\n'
        'window.WINNOW_API_ORIGIN = ' + json.dumps(api_origin) + ';\n'
        'window.WINNOW_SUPABASE = ' + json.dumps({
            'url': supabase_url, 'anonKey': public_key}) + ';\n'
    )
    (OUTPUT / 'supabase-config.js').write_text(config, encoding='utf-8')
    print(f'Built {OUTPUT}')


if __name__ == '__main__':
    build()
