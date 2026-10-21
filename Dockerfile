FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=5000 \
    FLASK_DEBUG=0 \
    WINNOW_SETTINGS_FILE=/data/settings.env \
    WINNOW_ANALYSIS_DB=/data/winnow_analysis.db \
    WINNOW_INVENTORY_DB=/data/winnow_inventory.db

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt \
    && groupadd --system --gid 10001 winnow \
    && useradd --system --uid 10001 --gid winnow --no-create-home winnow

COPY backend/ /app/backend/
COPY frontend/ /app/frontend/

RUN mkdir -p /data && chown winnow:winnow /data
WORKDIR /app/backend
USER 10001:10001

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)" || exit 1

CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
