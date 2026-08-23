"""Deterministic semantic, safety, propagation, metrics, logs, and health tests."""

from __future__ import annotations

import asyncio
import io
import logging
from datetime import UTC, datetime

import pytest

from aegis_agent_platform.observability import (
    ALLOWED_METRIC_LABELS,
    METRICS,
    AttributeSanitizer,
    BoundedExportBuffer,
    BoundedMetrics,
    ComponentProbe,
    DependencyCriticality,
    ErrorClass,
    HealthRegistry,
    HealthStatus,
    JsonEventFormatter,
    ProbeResult,
    SafeLogger,
    TelemetryStatus,
    TraceContextError,
    TraceLinkKind,
    deterministic_sample,
    extract_context,
    hash_identifier,
    inject_context,
    linked_contexts,
    redact_text,
    sanitize_url,
)
from aegis_agent_platform.observability.context import (
    PropagationContext,
    _parse_tracestate,
    durable_trace_context,
)
from aegis_agent_platform.observability.logging import configure_json_logging
from aegis_agent_platform.observability.safety import (
    bounded_event_size,
    sanitize_headers,
)
from aegis_agent_platform.observability.semantic import (
    FORBIDDEN_METRIC_LABEL_FRAGMENTS,
    MetricKind,
)

TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def test_semantic_metric_catalog_has_units_buckets_ownership_and_safe_labels() -> None:
    assert len(METRICS) >= 35
    for definition in METRICS.values():
        assert definition.owner
        assert definition.unit
        assert set(definition.labels) <= ALLOWED_METRIC_LABELS
        assert not any(
            fragment in label
            for label in definition.labels
            for fragment in FORBIDDEN_METRIC_LABEL_FRAGMENTS
        )
        assert bool(definition.buckets) is (definition.kind is MetricKind.HISTOGRAM)


def test_context_rejects_hostile_headers_and_allows_only_reviewed_baggage() -> None:
    context = extract_context(
        {
            "traceparent": TRACEPARENT,
            "tracestate": "vendor=value",
            "baggage": "aegis.component=worker,aegis.environment=test",
        }
    )

    assert context is not None
    assert context.sampled is True
    assert inject_context(context)["baggage"] == (
        "aegis.component=worker,aegis.environment=test"
    )
    with pytest.raises(TraceContextError):
        extract_context({"traceparent": "00-not-valid"})
    with pytest.raises(TraceContextError):
        extract_context(
            {
                "traceparent": TRACEPARENT,
                "baggage": "tenant_id=tenant-secret",
            }
        )
    with pytest.raises(TraceContextError):
        extract_context({"baggage": "aegis.component=worker"})


def test_sampling_and_async_links_are_deterministic() -> None:
    context = extract_context({"traceparent": TRACEPARENT})
    assert context is not None

    first = deterministic_sample(
        context.trace_id,
        rate=0.25,
        deployment_seed="test",
    )
    second = deterministic_sample(
        context.trace_id,
        rate=0.25,
        deployment_seed="test",
    )
    links = linked_contexts((context, context), TraceLinkKind.REDELIVERY)

    assert first is second
    assert len(links) == 1
    assert links[0].kind is TraceLinkKind.REDELIVERY


def test_sanitizer_redacts_secret_pii_urls_and_rotates_identifier_hashes() -> None:
    sanitizer = AttributeSanitizer(
        allowed=frozenset({"aegis.component", "aegis.status"})
    )
    attributes = sanitizer.sanitize(
        {
            "aegis.component": "worker",
            "aegis.status": "Bearer secret-token",
            "tenant_id": "tenant-a",
            "exception": "password=hunter2",
        }
    )

    assert attributes == {
        "aegis.component": "worker",
        "aegis.status": "[REDACTED]",
    }
    assert sanitizer.stats().dropped == 2
    assert "alice@example.com" not in redact_text("contact alice@example.com")
    assert sanitize_url("https://user:pass@example.test/path?q=secret#fragment") == (
        "https://example.test/path"
    )
    key = b"a" * 32
    assert hash_identifier("run-1", key=key, key_version="v1") != hash_identifier(
        "run-1",
        key=b"b" * 32,
        key_version="v2",
    )


def test_metrics_bound_cardinality_and_do_not_double_count_business_outcomes() -> None:
    metrics = BoundedMetrics(max_label_values=2, max_series=2)

    assert metrics.add(
        "aegis_api_requests_total",
        labels={"aegis.status": "succeeded"},
        outcome_key="event-1",
    )
    assert not metrics.add(
        "aegis_api_requests_total",
        labels={"aegis.status": "succeeded"},
        outcome_key="event-1",
    )
    assert metrics.add(
        "aegis_api_requests_total",
        labels={"aegis.status": "failed"},
        outcome_key="event-2",
    )
    assert not metrics.add(
        "aegis_api_requests_total",
        labels={"aegis.status": "denied"},
        outcome_key="event-3",
    )
    snapshot = metrics.snapshot()

    assert sum(point.value for point in snapshot.points) == 2
    assert snapshot.duplicate_business_outcomes == 1
    assert snapshot.dropped == 1


def test_exporter_outage_is_contained_and_opens_bounded_circuit() -> None:
    capped_gauges = BoundedMetrics(max_label_values=1)
    assert capped_gauges.set_gauge(
        "aegis_queue_pending_messages",
        1,
        labels={"aegis.queue.state": "ready"},
    )
    assert not capped_gauges.set_gauge(
        "aegis_queue_pending_messages",
        2,
        labels={"aegis.queue.state": "queued"},
    )
    assert capped_gauges.snapshot().dropped == 1
    bounded_outcomes = BoundedMetrics()
    with pytest.raises(ValueError, match="outcome key"):
        bounded_outcomes.add(
            "aegis_api_requests_total",
            labels={"aegis.status": "succeeded"},
            outcome_key="x" * 257,
        )

    buffer = BoundedExportBuffer(capacity=2)
    assert buffer.offer({"event": "one"})
    assert buffer.offer({"event": "two"})
    assert not buffer.offer({"event": "three"})

    def unavailable(_batch: object) -> None:
        raise TimeoutError

    assert buffer.drain(unavailable) == 0
    assert buffer.drain(unavailable) == 0
    assert buffer.drain(unavailable) == 0
    assert buffer.status["circuit_open"] is True
    assert buffer.status["buffered"] == 2
    buffer.reset_circuit()
    exported: list[object] = []
    assert buffer.drain(lambda batch: exported.extend(batch), limit=1) == 1
    assert buffer.status["buffered"] == 1


def test_observability_bounds_reject_invalid_configuration_and_values() -> None:
    with pytest.raises(ValueError, match="max_label_values"):
        BoundedMetrics(max_label_values=0)
    with pytest.raises(ValueError, match="max_series"):
        BoundedMetrics(max_series=257)
    metrics = BoundedMetrics()
    with pytest.raises(ValueError, match="unregistered"):
        metrics.add("unknown")
    with pytest.raises(ValueError, match="gauges"):
        metrics.add(
            "aegis_queue_pending_messages",
            labels={"aegis.queue.state": "ready"},
        )
    with pytest.raises(ValueError, match="negative"):
        metrics.add(
            "aegis_api_requests_total",
            -1,
            labels={"aegis.status": "failed"},
            outcome_key="one",
        )
    with pytest.raises(ValueError, match="outcome key"):
        metrics.add(
            "aegis_api_requests_total",
            labels={"aegis.status": "succeeded"},
        )
    with pytest.raises(ValueError, match="labels"):
        metrics.add("aegis_api_requests_total", labels={})
    with pytest.raises(ValueError, match="bounded identifier"):
        metrics.add(
            "aegis_api_requests_total",
            labels={"aegis.status": "not valid"},
            outcome_key="two",
        )
    with pytest.raises(ValueError, match="only gauges"):
        metrics.set_gauge(
            "aegis_api_requests_total",
            1,
            labels={"aegis.status": "succeeded"},
        )
    with pytest.raises(ValueError, match="negative"):
        metrics.set_gauge(
            "aegis_queue_pending_messages",
            -1,
            labels={"aegis.queue.state": "ready"},
        )
    assert metrics.set_gauge(
        "aegis_queue_pending_messages",
        2,
        labels={"aegis.queue.state": "ready"},
    )
    assert (
        metrics.distinct_label_values(
            "aegis_queue_pending_messages",
            "aegis.queue.state",
        )
        == 1
    )
    with pytest.raises(ValueError, match="capacity"):
        BoundedExportBuffer(capacity=0)
    with pytest.raises(ValueError, match="drain limit"):
        BoundedExportBuffer().drain(lambda _batch: None, limit=0)


def test_context_and_safety_bounds_cover_hostile_edge_cases() -> None:
    assert extract_context({}) is None
    assert durable_trace_context(None) is None
    context = extract_context({"traceparent": TRACEPARENT})
    assert context is not None
    assert durable_trace_context(context) is not None
    assert deterministic_sample(context.trace_id, rate=1, deployment_seed="x")
    assert deterministic_sample(
        context.trace_id,
        rate=0,
        deployment_seed="x",
        force=True,
    )
    with pytest.raises(ValueError, match="sampling rate"):
        deterministic_sample(context.trace_id, rate=2, deployment_seed="x")
    with pytest.raises(ValueError, match="sampling seed"):
        deterministic_sample(context.trace_id, rate=1, deployment_seed="")
    with pytest.raises(TraceContextError):
        PropagationContext(
            context.trace_id,
            context.parent_span_id,
            True,
            TRACEPARENT,
            schema_version=2,
        )
    for headers in (
        {"TraceParent": TRACEPARENT, "traceparent": TRACEPARENT},
        {"traceparent": "ff-" + TRACEPARENT[3:]},
        {"traceparent": "00-" + "0" * 32 + TRACEPARENT[35:]},
        {"traceparent": TRACEPARENT[:-2] + "03"},
        {"traceparent": TRACEPARENT, "tracestate": ""},
        {"traceparent": TRACEPARENT, "tracestate": "invalid"},
        {"traceparent": TRACEPARENT, "baggage": "aegis.component=bad value"},
    ):
        with pytest.raises(TraceContextError):
            extract_context(headers)

    sanitizer = AttributeSanitizer(
        allowed=frozenset({"aegis.component", "aegis.status"}),
        max_attributes=1,
    )
    assert sanitizer.sanitize(
        {"aegis.component": True, "aegis.status": ["invalid"]}
    ) == {"aegis.component": True}
    with pytest.raises(ValueError, match="max_attributes"):
        AttributeSanitizer(max_attributes=0)
    assert sanitize_headers(
        {
            "Content-Type": "application/json",
            "Authorization": "Bearer abc",
            "X-Unknown": "value",
        }
    ) == {"content-type": "application/json"}
    with pytest.raises(ValueError, match="at least 32"):
        hash_identifier("id", key=b"short", key_version="v1")
    with pytest.raises(ValueError, match="version"):
        hash_identifier("id", key=b"x" * 32, key_version="")
    assert bounded_event_size({"items": ["x", {"value": 1}]})
    assert not bounded_event_size({"value": "x" * 9_000})


def test_structured_logging_redacts_and_suppresses_duplicates() -> None:
    stream = io.StringIO()
    logger = logging.getLogger("aegis-test-structured")
    logger.handlers.clear()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonEventFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    safe = SafeLogger(logger, suppression_seconds=10)
    now = datetime(2026, 1, 1, tzinfo=UTC)

    assert safe.emit(
        "api.request.failed.v1",
        TelemetryStatus.FAILED,
        occurred_at=now,
        monotonic_time=1,
        error_class=ErrorClass.DEPENDENCY,
        error_code="storage_unavailable",
        attributes={
            "aegis.component": "api",
            "aegis.lifecycle.status": "Bearer should-not-leak",
        },
    )
    assert not safe.emit(
        "api.request.failed.v1",
        TelemetryStatus.FAILED,
        occurred_at=now,
        monotonic_time=2,
        error_class=ErrorClass.DEPENDENCY,
        error_code="storage_unavailable",
    )

    rendered = stream.getvalue()
    assert "should-not-leak" not in rendered
    assert "storage_unavailable" in rendered
    assert '"exception"' not in rendered


def test_structured_logging_validation_audit_and_fallback_format() -> None:
    logger = logging.getLogger("aegis-test-validation")
    logger.handlers.clear()
    safe = SafeLogger(logger, minimum_level="WARNING", suppression_seconds=0)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert not safe.emit(
        "api.request.failed.v1",
        TelemetryStatus.FAILED,
        occurred_at=now,
        monotonic_time=0,
        level="INFO",
    )
    with pytest.raises(ValueError, match="unregistered"):
        safe.emit(
            "unknown",
            TelemetryStatus.FAILED,
            occurred_at=now,
            monotonic_time=0,
        )
    with pytest.raises(ValueError, match="timezone"):
        safe.emit(
            "api.request.failed.v1",
            TelemetryStatus.FAILED,
            occurred_at=datetime(2026, 1, 1),
            monotonic_time=0,
            level="WARNING",
        )
    with pytest.raises(ValueError, match="error_code"):
        safe.emit(
            "api.request.failed.v1",
            TelemetryStatus.FAILED,
            occurred_at=now,
            monotonic_time=0,
            level="WARNING",
            error_code="not-valid",
        )
    with pytest.raises(ValueError, match="minimum_level"):
        SafeLogger(logger, minimum_level="INVALID")
    with pytest.raises(ValueError, match="suppression_seconds"):
        SafeLogger(logger, suppression_seconds=301)
    operational, audit = configure_json_logging(
        level="ERROR",
        logger_name="aegis-test-configured",
    )
    assert isinstance(operational, SafeLogger)
    assert isinstance(audit, SafeLogger)
    with pytest.raises(ValueError, match="log level"):
        configure_json_logging(level="INVALID")
    record = logging.LogRecord("test", logging.INFO, "", 0, "plain", (), None)
    assert "logging.invalid_record.failed.v1" in JsonEventFormatter().format(record)


def test_health_registry_degrades_optional_and_gates_correctness_dependencies() -> None:
    storage_status = HealthStatus.HEALTHY
    telemetry_status = HealthStatus.UNAVAILABLE

    async def storage() -> ProbeResult:
        return ProbeResult(storage_status, "storage_probe")

    async def telemetry() -> ProbeResult:
        return ProbeResult(telemetry_status, "exporter_probe")

    registry = HealthRegistry(
        (
            ComponentProbe(
                "postgres",
                DependencyCriticality.CORRECTNESS,
                storage,
            ),
            ComponentProbe(
                "telemetry",
                DependencyCriticality.OPTIONAL,
                telemetry,
            ),
        ),
        cache_seconds=0,
        transition_threshold=2,
    )

    first = __import__("asyncio").run(registry.report(monotonic_time=1))
    assert first.ready is True
    assert first.status is HealthStatus.DEGRADED

    storage_status = HealthStatus.UNAVAILABLE
    transitional = __import__("asyncio").run(registry.report(monotonic_time=2))
    unavailable = __import__("asyncio").run(registry.report(monotonic_time=3))
    assert transitional.ready is True
    assert unavailable.ready is False


def test_health_registry_validates_inputs_converts_failures_and_caches() -> None:
    with pytest.raises(ValueError, match="reason_code"):
        ProbeResult(HealthStatus.HEALTHY, "not valid!")
    with pytest.raises(ValueError, match="component"):
        ComponentProbe(
            "not valid!",
            DependencyCriticality.CORRECTNESS,
            lambda: asyncio.sleep(0),
        )
    with pytest.raises(ValueError, match="cache_seconds"):
        HealthRegistry((), cache_seconds=61)
    with pytest.raises(ValueError, match="transition_threshold"):
        HealthRegistry((), transition_threshold=0)
    with pytest.raises(ValueError, match="probe_timeout_seconds"):
        HealthRegistry((), probe_timeout_seconds=0.01)
    calls = {"cached": 0}

    async def cached_probe() -> ProbeResult:
        calls["cached"] += 1
        return ProbeResult(HealthStatus.HEALTHY, "cached_ok")

    with pytest.raises(ValueError, match="unique"):
        HealthRegistry(
            (
                ComponentProbe("dup", DependencyCriticality.OPTIONAL, cached_probe),
                ComponentProbe("dup", DependencyCriticality.CORRECTNESS, cached_probe),
            )
        )

    async def timeout_probe() -> ProbeResult:
        await asyncio.sleep(0.05)
        return ProbeResult(HealthStatus.HEALTHY, "slow")

    async def connection_probe() -> ProbeResult:
        raise ConnectionError

    async def os_probe() -> ProbeResult:
        raise OSError

    async def failed_probe() -> ProbeResult:
        raise RuntimeError

    registry = HealthRegistry(
        (
            ComponentProbe(
                "cached",
                DependencyCriticality.OPTIONAL,
                cached_probe,
            ),
            ComponentProbe(
                "timeout",
                DependencyCriticality.CORRECTNESS,
                timeout_probe,
            ),
            ComponentProbe(
                "connection",
                DependencyCriticality.OPTIONAL,
                connection_probe,
            ),
            ComponentProbe("os", DependencyCriticality.OPTIONAL, os_probe),
            ComponentProbe(
                "failed",
                DependencyCriticality.OPTIONAL,
                failed_probe,
            ),
        ),
        cache_seconds=5,
        transition_threshold=1,
        probe_timeout_seconds=0.05,
    )

    report = asyncio.run(registry.report(monotonic_time=1))
    cached = asyncio.run(registry.report(monotonic_time=2))

    assert report.ready is False
    assert report.components["timeout"].reason_code == "probe_timeout"
    assert report.components["connection"].reason_code == "dependency_unavailable"
    assert report.components["os"].reason_code == "dependency_unavailable"
    assert report.components["failed"].reason_code == "probe_failed"
    assert cached.components["cached"].reason_code == "cached_ok"
    assert calls["cached"] == 1


def test_metrics_track_histograms_non_finite_values_and_export_locking() -> None:
    metrics = BoundedMetrics()
    assert metrics.add(
        "aegis_memory_retrieval_duration_seconds",
        0.5,
        labels={"aegis.status": "succeeded"},
    )
    point = next(
        item
        for item in metrics.snapshot().points
        if item.name == "aegis_memory_retrieval_duration_seconds"
    )
    assert point.count == 1
    assert point.buckets
    with pytest.raises(ValueError, match="finite"):
        metrics.add(
            "aegis_api_requests_total",
            float("nan"),
            labels={"aegis.status": "failed"},
            outcome_key="nan",
        )
    with pytest.raises(ValueError, match="finite"):
        metrics.set_gauge(
            "aegis_queue_pending_messages",
            float("inf"),
            labels={"aegis.queue.state": "ready"},
        )

    dedup = BoundedMetrics()
    for index in range(10_001):
        assert dedup.add(
            "aegis_api_requests_total",
            labels={"aegis.status": "succeeded"},
            outcome_key=f"event-{index}",
        )
    assert dedup.add(
        "aegis_api_requests_total",
        labels={"aegis.status": "succeeded"},
        outcome_key="event-0",
    )

    capped_gauges = BoundedMetrics(max_label_values=1)
    assert capped_gauges.set_gauge(
        "aegis_queue_pending_messages",
        1,
        labels={"aegis.queue.state": "ready"},
    )
    assert not capped_gauges.set_gauge(
        "aegis_queue_pending_messages",
        2,
        labels={"aegis.queue.state": "queued"},
    )
    assert capped_gauges.snapshot().dropped == 1
    bounded_outcomes = BoundedMetrics()
    with pytest.raises(ValueError, match="outcome key"):
        bounded_outcomes.add(
            "aegis_api_requests_total",
            labels={"aegis.status": "succeeded"},
            outcome_key="x" * 257,
        )

    buffer = BoundedExportBuffer(capacity=2)
    assert buffer.offer({"event": "one"})
    assert buffer.offer({"event": "two"})
    assert buffer._drain_lock.acquire(blocking=False)
    try:
        assert buffer.drain(lambda _batch: None) == 0
    finally:
        buffer._drain_lock.release()
    assert BoundedExportBuffer().drain(lambda _batch: None) == 0
    assert buffer.drain(lambda batch: None, limit=1) == 1
    assert buffer.status["buffered"] == 1


def test_context_and_event_size_handle_strict_tracestate_and_json_escaping() -> None:
    valid = extract_context(
        {"traceparent": TRACEPARENT, "tracestate": "a=b,tenant@sys=value"}
    )
    assert valid is not None
    for tracestate in (
        "a=b,a=c",
        "=b",
        "a =b",
        "a=" + ("x" * 300),
        ",".join(f"k{i}=v" for i in range(33)),
    ):
        with pytest.raises(TraceContextError):
            extract_context({"traceparent": TRACEPARENT, "tracestate": tracestate})
    with pytest.raises(TraceContextError):
        extract_context({"traceparent": TRACEPARENT + "-extra"})
    with pytest.raises(TraceContextError):
        _parse_tracestate("a=b" * 200)
    with pytest.raises(TraceContextError):
        _parse_tracestate("a=value ")
    with pytest.raises(TraceContextError):
        extract_context(
            {"traceparent": TRACEPARENT, "baggage": "aegis.component=x" * 1000}
        )
    with pytest.raises(TraceContextError):
        extract_context(
            {
                "traceparent": TRACEPARENT,
                "baggage": ",".join(f"aegis.component=v{i}" for i in range(17)),
            }
        )
    sanitizer = AttributeSanitizer(allowed=frozenset({"safe"}), max_attributes=2)
    sanitized = sanitizer.sanitize({"safe": object(), "other": "value"})
    assert sanitized == {}
    assert AttributeSanitizer(allowed=frozenset({"safe"})).sanitize({"safe": 1.5}) == {
        "safe": 1.5
    }
    truncated = sanitizer.sanitize({"safe": "x" * 300, "safe_float": 1.5})
    assert truncated["safe"] == "x" * 256
    assert sanitize_url("https://user:pass@example.test:8443/path?q=1#frag") == (
        "https://example.test:8443/path"
    )
    assert not bounded_event_size({"value": '"' * 5000})
