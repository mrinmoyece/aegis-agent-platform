# Dashboard guide

Grafana provisions ten dashboards from `deploy/grafana/dashboards`: executive
health, runtime/queue, model cost/budgets, evidence/connectors, specialist
investigations, approvals/actions, sandbox, memory/RAG, evaluation quality, and
platform dependencies.

Variables contain bounded environment, component, role, provider, connector, or
backend families. They never enumerate tenants, users, incidents, runs, targets,
or artifacts. Operators begin with the executive dashboard, follow an alert to
the domain dashboard, then use the authenticated timeline or replay API for an
authorized aggregate. Dashboards are derived and must never be used to infer or
repair authoritative state.

Panels use seconds, bytes, USD, counts, or ratios and provide thresholds where a
reviewed objective exists. Empty panels mean **no telemetry evidence**, not
healthy. Check collector health, Prometheus targets, exporter drops, and then
use ledger replay. Dashboard JSON, UIDs, provisioning, variables, and required
panel fields are validated by `make observability-check`.
