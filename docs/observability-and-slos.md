# Observability and SLO architecture

Layer 12 adds a provider-neutral, bounded observability adapter around every
implemented layer. It does not change domain folds or authoritative state.
Validated context flows API -> ledger/outbox -> Redis -> worker and through
provider, connector, specialist, action, sandbox, memory, and evaluation paths.
Async retries, redelivery, fan-out, and fan-in use links rather than pretending
to be one synchronous parent chain.

Structured logs, metrics, traces, dashboards, alert state, health caches,
support reports, and projection comparisons are derived. Export failure is
bounded, counted, and non-blocking. Correctness-critical DB/queue/sandbox policy
dependencies can fail readiness; optional telemetry reports degraded without
making the service unready.

Local Compose provisions an OTLP collector, Prometheus rules, and Grafana
dashboards. The collector applies memory limiting, resource normalization,
attribute deletion/redaction, and batching in that order. Trace/log export uses
a bounded ephemeral queue. Production requires authenticated TLS, persistent
buffering if needed, external managed storage qualification, and a documented
retention/access policy. No sensitive debug exporter is enabled.

See [semantic conventions](telemetry-semantic-conventions.md),
[SLO catalog](slo-catalog.md), [dashboard guide](dashboard-guide.md),
[on-call runbook](on-call-observability.md), and
[replay tutorial](replay-debugger.md).
