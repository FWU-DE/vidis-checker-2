FROM python:3.12-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

# Chromium in exactly the build the locked playwright package expects, plus its system libraries.
# The bundled node driver needs libatomic before it can install anything.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libatomic1 \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

COPY src ./src
RUN uv sync --frozen --no-dev \
    && useradd --create-home --uid 1000 vidis \
    && mkdir -p /data/results /data/inputs \
    && chown -R vidis:vidis /data

ENV VIDIS_RESULTS_DIR=/data/results \
    VIDIS_ALLOWED_PATH_ROOTS=/data/inputs \
    VIDIS_HOST=0.0.0.0 \
    VIDIS_PORT=8645 \
    VIDIS_JOB_WORKERS=2

USER vidis
VOLUME ["/data/results"]
EXPOSE 8645

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8645/health', timeout=4).status == 200 else 1)"

CMD ["vidis", "serve"]
