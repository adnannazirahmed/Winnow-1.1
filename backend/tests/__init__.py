"""Keep local integration secrets out of the offline test suite."""

import os

# app.py loads backend/.env during import. Explicit empty values prevent that
# file from enabling real provider calls while tests use mock credentials.
os.environ['AI_PROVIDER'] = 'disabled'
for key in ('ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'DEEPSEEK_API_KEY', 'OLLAMA_API_KEY'):
    os.environ[key] = ''
