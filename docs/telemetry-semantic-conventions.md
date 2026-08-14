# Telemetry semantic conventions

Layer 12 defines `aegis.telemetry.v1`. The executable catalog is
`aegis_agent_platform.observability.semantic`; this document explains its
operational contract. Telemetry is disposable derived evidence. The append-only
event ledger remains the sole source of operational truth.

## Stable dimensions and taxonomy

Operations use bounded dotted names: `api.request`, `ledger.append`,
`ledger.replay`, `outbox.publish`, `queue.consume`, `work.*`, `model.*`,
`connector.query`, `evidence.*`, `specialist.execute`,
`coordinator.aggregate`, `approval.decide`, `action.*`, `sandbox.*`,
`memory.*`, `eval.*`, `observability.*`, `replay.*`, and `projection.rebuild`.
Log events append a lifecycle and schema suffix, for example
`work.execute.failed.v1`.

Lifecycle values are `started`, `succeeded`, `failed`, `denied`, `cancelled`,
`timed_out`, `degraded`, `partial`, `ambiguous`, `quarantined`, and
`abstained`. Error classes are validation, authentication, authorization,
policy, conflict, fencing, rate limit, budget, timeout, dependency, provider,
corruption, and internal. Retryability is `retryable`, `permanent`, `unknown`,
or `not_applicable`. Effect ambiguity and recovery outcomes are separate
dimensions.

Allowed metric labels are fixed service, environment, component, operation,
status, error class, retryability, risk class, provider family, connector
family, backend family, queue/work state, and specialist role. **Tenant, user,
principal, run, incident, investigation, artifact, approval, action, sandbox,
memory, target, correlation, trace, span, message, prompt, evidence, URL,
exception, and free-text values are forbidden metric labels.**

Correlation identifiers may appear only in access-controlled traces and logs.
They are omitted where possible and otherwise HMAC-SHA256 pseudonymized with a
rotating deployment key. The executable implementation emits 96 bits of the
digest; the random collision boundary is therefore 2^-96. Rotate the key and
version together. Never reuse a production hash key in support or local
environments.

## Propagation

W3C `traceparent` and `tracestate` are validated before use. Version `ff`,
all-zero identifiers, unsupported flags, duplicate headers, oversized state,
or baggage outside the allowlist are rejected. The baggage allowlist contains
only component, environment, risk class, role, and service classes.

API parent context is continued synchronously. Durable intent events may record
validated W3C context as diagnostic metadata. Outbox and queue envelopes carry
only validated propagation headers. Retries and redelivery create links to the
prior attempt; fan-out links children to the coordinator and fan-in links the
aggregation span to completed children. Sampling is a deterministic hash of
deployment seed plus trace ID, so crashes and replay do not change the decision.
Provider-specific OTel SDK types stop at the instrumentation adapter.

## Safety, bounds, and counting

Attributes are scalar-only, allowlisted, and bounded to 32 keys, 64-byte names,
256-byte values, and an 8 KiB structured event. Secret, JWT, key, credential,
prompt, evidence, memory, URL-query, header, and common PII patterns are
redacted or dropped. Model, connector, tool, and backend errors are untrusted;
only reviewed error classes/codes are emitted.

Business outcome counters require a durable outcome key. Retries, redelivery,
replay, and projection rebuild do not increment them again. Attempt counters
may count attempts and are named accordingly. Histograms have explicit buckets
and units. Label values are limited to 32 and series to 256 per metric in the
in-process guard. Drop, rejection, exporter failure, and circuit state are
self-observed without including rejected content.

Exporter calls are never on the correctness path. A bounded in-memory queue,
timeout, retry policy, and circuit contain outages; overflow is dropped and
counted. This local queue is ephemeral. Even complete telemetry loss must not
alter run results: investigation falls back to the event ledger and replay
debugger.
