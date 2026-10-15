# ============================================================================
# CipherGuard AI — ML Service Dockerfile
# ============================================================================
#
# IMPORTANT: The trained model artifact (models/ember_rf.joblib, ~107 MiB) is
# NOT baked into this image. It must be provided at runtime via a bind mount:
#
#   docker run --rm \
#     -v "$(pwd)/models:/app/models:ro" \
#     -p 8000:8000 \
#     cipherguard-ml
#
# This keeps the image lean and avoids committing a large binary artifact to
# the container image layer. See README.md for the full workflow.
#
# EMBER training data is never included in the runtime image.
# ============================================================================

# --- Stage 1: dependency builder ----------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools needed for lief and pefile native extensions.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install into a prefix so we can copy just the site-packages in stage 2.
RUN pip install --upgrade pip && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt


# --- Stage 2: runtime image ---------------------------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="CipherGuard AI ML Service"
LABEL org.opencontainers.image.description="Static PE malware assessment — EMBER 2018 + Random Forest"

# Copy installed packages from the builder stage.
COPY --from=builder /install /usr/local

# Create a non-root user for runtime security.
RUN groupadd --gid 10001 mlservice && \
    useradd --uid 10001 --gid mlservice --no-create-home --shell /sbin/nologin mlservice

WORKDIR /app

# Copy application source only (see .dockerignore for exclusions).
COPY app/       ./app/
COPY pytest.ini .
# requirements.txt is copied for reference / auditing only.
COPY requirements.txt .

# models/ directory must exist so the bind-mount target resolves correctly.
# The actual .joblib artifact is NOT baked in — supply it at runtime.
RUN mkdir -p /app/models && chown -R mlservice:mlservice /app

# Switch to non-root user.
USER mlservice

# Default environment — override in docker run or docker-compose.
ENV ML_ENVIRONMENT=production \
    ML_MODEL_PATH=/app/models/ember_rf.joblib \
    ML_HOST=0.0.0.0 \
    ML_PORT=8000 \
    ML_MAX_FILE_SIZE_BYTES=52428800 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Health check — polls /health every 30 s, allows 60 s for cold-start model load.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c \
        "import urllib.request, sys; \
         r = urllib.request.urlopen('http://localhost:8000/health', timeout=5); \
         import json; body = json.loads(r.read()); \
         sys.exit(0 if body.get('model_ready') else 1)"

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--log-level", "info"]
