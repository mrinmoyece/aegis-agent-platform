# Getting started with Layers 1–2

This repository teaches the less visible part of agent engineering: deciding
where durability, security, and vendor boundaries live before writing
orchestration logic. Layer 1 built the package contracts and local
infrastructure. Layer 2 adds a small, real control-plane vertical slice for
identity, tenancy, and governance. The code stays intentionally small; the
contracts, tests, and checks are the lesson.

## What you will inspect

- `domain` owns immutable, provider-neutral event data.
- `event_store` and `queueing` define persistence ports without adapters.
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
- `migrations/0001_identity_governance.sql` defines the Postgres schema and
  row-level security these boundaries are designed to persist against.
- `compose.yaml` describes the local dependencies later layers will integrate.
- architecture tests prevent infrastructure from leaking into the pure domain.

No durable runtime, event store, queue worker, or live Dynatrace/GitHub
connector runs yet — see `limitations.md` for the complete gap list.

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
without a bearer token returns `401 missing_token`; obtaining a real token
against this realm and wiring it through `RemoteJwksProvider` is a deployment
exercise, not something the fast local checks assume works. PostgreSQL now
initializes with the identity/governance migration
(`migrations/0001_identity_governance.sql`), but the control plane's default
repositories remain in-memory — no adapter connects them to Postgres yet, so
nothing you do through the API survives a restart.

Stop and remove containers with `docker compose down`. Add `--volumes` only when
you intentionally want to delete local data.

## Read next

Read `architecture.md`, then the ADRs in numerical order (especially ADR 0004
and ADR 0009). Compare the acceptance gates in `roadmap.md` with the status
table in `enterprise-checklist.md`, and read `threat-model.md`'s Layer 2
residual-risk section for exactly what is and is not proven so far.
