# syntax=docker/dockerfile:1.7
FROM python:3.14.7-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv

RUN python -m venv "${VIRTUAL_ENV}"
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR /build
COPY pyproject.toml requirements.lock README.md LICENSE ./
COPY src ./src
RUN python -m pip install --require-hashes --no-deps -r requirements.lock \
    && python -m pip install --no-build-isolation --no-deps . \
    && python -m pip uninstall --yes \
      hatchling pathspec pluggy tomlkit trove-classifiers \
    && python -m pip uninstall --yes pip setuptools

FROM python:3.14.7-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52 AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get upgrade --yes \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 aegis \
    && useradd --system --uid 10001 --gid aegis --no-create-home aegis \
    && install -d -m 0755 /opt/aegis/trust

ADD --checksum=sha256:e5bb2084ccf45087bda1c9bffdea0eb15ee67f0b91646106e466714f9de3c7e3 \
    https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
    /opt/aegis/trust/rds-global-bundle.pem
RUN chmod 0444 /opt/aegis/trust/rds-global-bundle.pem

COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 LICENSE /licenses/Aegis-Agent-Platform-LICENSE
COPY --chown=10001:10001 migrations /opt/aegis/migrations
COPY --chown=10001:10001 scripts/migrate.py /opt/aegis/scripts/migrate.py
COPY --chown=10001:10001 scripts/bootstrap_local_compose.py /opt/aegis/scripts/bootstrap_local_compose.py

USER 10001:10001
WORKDIR /app
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; port = os.environ.get('AEGIS_PORT', '8080'); urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=2)"]

ENTRYPOINT ["python", "-m", "aegis_agent_platform.control_plane"]
