# syntax=docker/dockerfile:1.7
FROM python:3.14.7-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv

RUN python -m venv "${VIRTUAL_ENV}"
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --upgrade pip \
    && python -m pip install .

FROM python:3.14.7-slim-bookworm AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10001 aegis \
    && useradd --system --uid 10001 --gid aegis --no-create-home aegis

COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 LICENSE /licenses/Aegis-Agent-Platform-LICENSE

USER 10001:10001
WORKDIR /app
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; port = os.environ.get('AEGIS_PORT', '8080'); urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=2)"]

ENTRYPOINT ["python", "-m", "aegis_agent_platform.control_plane"]
