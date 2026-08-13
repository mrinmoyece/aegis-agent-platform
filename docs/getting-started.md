# Getting started with Layer 1

Layer 1 teaches a less visible part of agent engineering: deciding where
durability, security, and vendor boundaries live before writing orchestration
logic. The code is intentionally small. The contracts and checks are the lesson.

## What you will inspect

- `domain` owns immutable, provider-neutral event data.
- `event_store` and `queueing` define persistence ports without adapters.
- `control_plane` exposes liveness and configuration readiness only.
- subsystem packages reserve explicit architecture boundaries.
- `compose.yaml` describes the local dependencies later layers will integrate.
- architecture tests prevent infrastructure from leaking into the pure domain.

No agent runs in this layer.

## Run the fast checks

Install Python 3.12+, then:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
make check
```

The checks cover formatting, linting, strict typing, tests with coverage,
documentation links, and repository manifests. They do not require network
services.

## Inspect the local stack

Docker Compose substitutes local-only values from `.env.example`:

```bash
cp .env.example .env
make compose-config
docker compose up --build
```

After startup:

| Surface | URL | Purpose |
| --- | --- | --- |
| Aegis health | <http://localhost:8080/healthz> | Process liveness |
| Aegis readiness | <http://localhost:8080/readyz> | Configuration readiness |
| Keycloak | <http://localhost:8081> | Local identity provider |
| Prometheus | <http://localhost:9090> | Metrics inspection |
| Grafana | <http://localhost:3000> | Local dashboards |

The imported Keycloak realm has no users. The API does not yet authenticate
requests. PostgreSQL and Redis are present but the Layer 1 API does not connect
to them.

Stop and remove containers with `docker compose down`. Add `--volumes` only when
you intentionally want to delete local data.

## Read next

Read `architecture.md`, then the ADRs in numerical order. Compare the future
acceptance gates in `roadmap.md` with the status table in
`enterprise-checklist.md`.
