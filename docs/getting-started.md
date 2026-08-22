# Getting started with Layers 1–5

This repository teaches the less visible part of agent engineering: deciding
where durability, security, and vendor boundaries live before writing
orchestration logic. Layer 1 built the package contracts and local
infrastructure. Layer 2 adds identity, tenancy, and governance. Layer 3 adds a
durable PostgreSQL ledger, inbox/outbox, projections, and production repositories.
Layer 4 adds Redis Streams delivery and fenced worker execution. Layer 5 adds
the model gateway, provider adapters, and cost governance, but not agent
reasoning.

## What you will inspect

- `domain` owns immutable, provider-neutral event data.
- `event_store` defines ports plus the PostgreSQL ledger, inbox/outbox, and
  projection adapters; `queueing` and `runtime` implement delivery and workers.
- `identity` verifies bearer JWTs and resolves authoritative, tenant-scoped
  principals; `identity.authorization` makes deny-by-default access decisions.
- `tenancy` carries validated tenant context through every tenant-scoped port.
- `policy` evaluates tenant governance policy, risk, and quotas as a pure
  function.
- `audit` records redacted, additive, append-only security events.
- `secrets_boundary` carries secret references and opaque values, never raw
  material, through general application code.
- `control_plane` composes the above behind an authenticated `/v1/*` API plus
  liveness/readiness routes.
- migrations `0001`–`0003` define governance, ledger, work state, leases, DLQ,
  roles, grants, triggers, forced RLS, inbox/outbox, and projections.
- `compose.yaml` describes the local dependencies later layers will integrate.
- architecture tests prevent infrastructure from leaking into the pure domain.

The durable store and Redis worker substrate are implemented. Layer 5 now also
includes an executable `ModelGateway` plus fake and live provider adapters, so
real model calls can run when those adapters are configured. The local quick
checks and most integration paths still rely on deterministic fixtures or
scripted providers rather than live external model, Dynatrace, or GitHub calls.

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
documentation links, repository manifests, and (from Layer 2) ordered SQL
migration validation. They do not require network services or a running
identity provider — JWT verification is exercised against deterministic
fixtures, not a live Keycloak realm.

Run the live PostgreSQL/Redis suite against disposable services:

```bash
AEGIS_TEST_DATABASE_URL=postgresql://... \
AEGIS_TEST_REDIS_URL=redis://... \
  python -m pytest tests/integration
```

The fixture resets that database's `public` schema. Never point it at shared or
production data.

## Try the identity, tenancy, and governance slice

The [identity and tenancy tutorial](identity-tenancy.md) walks through
building a deterministic signed JWT, verifying it, resolving it to a
principal, making a deny-by-default authorization decision, evaluating a
tenant policy and quotas, and inspecting the resulting redacted audit trail —
all without any external service. Read it after this page for a hands-on tour
of the newest code.

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
| Aegis liveness | <http://localhost:8080/healthz> or `/health/live` | Process liveness |
| Aegis readiness | <http://localhost:8080/readyz> or `/health/ready` | Configuration readiness |
| Aegis authenticated API | <http://localhost:8080/v1/me> | Requires a valid bearer token; see below |
| Keycloak | <http://localhost:8081> | Local identity provider |
| Prometheus | <http://localhost:9090> | Metrics inspection |
| Grafana | <http://localhost:3000> | Local dashboards |

The imported Keycloak realm has no users and self-registration disabled, so it
demonstrates the expected configuration shape (issuer, JWKS URL, audience) for
`RemoteJwksProvider` rather than a ready-to-use login flow. Calling `/v1/me`
on the module-level demo application returns `503 authentication_not_configured`;
obtaining a real token and wiring an authentication service through
`RemoteJwksProvider` is a deployment exercise, not something the fast local
checks assume works. PostgreSQL initializes all forward migrations. Production
composition must explicitly inject the PostgreSQL repositories and event store;
the module-level demo application remains fail-closed and does not invent
development identities.

Stop and remove containers with `docker compose down`. Add `--volumes` only when
you intentionally want to delete local data.

## Read next

Read `durable-execution.md`, `worker-runtime.md`, ADR 0010/0011,
`failure-modes.md`, and `runbook.md`, then
compare roadmap gates with `enterprise-checklist.md`.
