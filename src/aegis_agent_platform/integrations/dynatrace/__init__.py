"""Production Dynatrace evidence adapter over current HTTP APIs."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import cast
from urllib.parse import urlencode

from aegis_agent_platform.domain import (
    EvidenceKind,
    EvidenceReference,
    EvidenceSeverity,
    EvidenceSourceKind,
    JsonValue,
    PartialResult,
    ServiceIdentity,
    SpanReference,
    TraceReference,
    TrustStatus,
)
from aegis_agent_platform.evidence import (
    CancellationSignal,
    ConnectorCapability,
    ConnectorError,
    ConnectorErrorClass,
    ConnectorPage,
    EvidenceQuery,
    HttpRequest,
    HttpTransport,
    RawEvidence,
)
from aegis_agent_platform.integrations._http import json_mapping
from aegis_agent_platform.integrations._pagination import decode_cursor, encode_cursor
from aegis_agent_platform.integrations.config import DynatraceConnectorConfig
from aegis_agent_platform.secrets_boundary import SecretProvider
from aegis_agent_platform.tenancy import TenantContext

_SELECTOR = re.compile(r"^[A-Za-z0-9_.:/-]{1,256}$")
_SUPPORTED = (
    EvidenceKind.LOG,
    EvidenceKind.METRIC,
    EvidenceKind.TRACE,
    EvidenceKind.SPAN,
    EvidenceKind.PROBLEM,
    EvidenceKind.EVENT,
    EvidenceKind.ENTITY,
    EvidenceKind.TOPOLOGY,
    EvidenceKind.CHANGE,
    EvidenceKind.DEPLOYMENT,
)


class DynatraceAdapter:
    """Read-only adapter using OAuth2 client credentials and bounded queries."""

    source = EvidenceSourceKind.DYNATRACE

    def __init__(
        self,
        context: TenantContext,
        config: DynatraceConnectorConfig,
        secrets: SecretProvider,
        transport: HttpTransport,
    ) -> None:
        if context.tenant_id != config.tenant_id:
            raise PermissionError("cross_tenant_connector_config")
        if not config.enabled:
            raise ValueError("Dynatrace connector is disabled")
        self._context = context
        self._config = config
        self._secrets = secrets
        self._transport = transport

    async def capability(self) -> ConnectorCapability:
        return ConnectorCapability(
            self.source,
            _SUPPORTED,
            "environment-v2+grail-v1",
            True,
            "ok",
        )

    async def query(
        self,
        query: EvidenceQuery,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> ConnectorPage:
        self._validate(query, cancellation)
        token = await self._token()
        records: list[RawEvidence] = []
        reasons: list[str] = []
        cursor_state = decode_cursor(
            query.cursor,
            allowed_keys=tuple(kind.value for kind in query.kinds),
        )
        next_cursors: dict[str, str] = {}
        active_kinds = (
            query.kinds
            if cursor_state is None
            else tuple(kind for kind in query.kinds if kind.value in cursor_state)
        )
        for kind in active_kinds:
            if cancellation is not None and cancellation.cancelled:
                raise ConnectorError(
                    ConnectorErrorClass.CANCELLED,
                    "query_cancelled",
                    retryable=False,
                    partial=bool(records),
                )
            response = await self._transport.send(
                self._request(
                    query,
                    kind,
                    token,
                    cursor_state.get(kind.value) if cursor_state else None,
                )
            )
            payload = json_mapping(response)
            if (
                kind in {EvidenceKind.LOG, EvidenceKind.TRACE, EvidenceKind.SPAN}
                and not _has_collection(payload)
                and isinstance(payload.get("requestToken"), str)
            ):
                payload = await self._poll_grail(
                    str(payload["requestToken"]),
                    token,
                    cancellation,
                    partial=bool(records),
                )
            items, cursor = _items(payload)
            if kind is EvidenceKind.METRIC:
                items = _metric_items(items)
            elif kind is EvidenceKind.TRACE:
                items = _trace_items(items)
            page_truncated = False
            for item in items:
                if len(records) >= min(query.limit, self._config.limits.max_records):
                    reasons.append("record_cap")
                    page_truncated = True
                    break
                records.append(
                    _normalize(item, kind, query, self._config.environment_url)
                )
            if (
                cursor is not None
                and not page_truncated
                and kind
                not in {
                    EvidenceKind.LOG,
                    EvidenceKind.TRACE,
                    EvidenceKind.SPAN,
                }
            ):
                next_cursors[kind.value] = cursor
                reasons.append(f"upstream_pagination:{kind.value}")
        partial = bool(reasons)
        return ConnectorPage(
            records,
            encode_cursor(next_cursors),
            PartialResult(
                partial,
                "record_cap" in reasons,
                tuple(sorted(set(reasons))),
            ),
        )

    async def _poll_grail(
        self,
        request_token: str,
        access_token: str,
        cancellation: CancellationSignal | None,
        *,
        partial: bool,
    ) -> Mapping[str, JsonValue]:
        base = self._config.environment_url.rstrip("/")
        for _ in range(self._config.limits.max_pages):
            if cancellation is not None and cancellation.cancelled:
                raise ConnectorError(
                    ConnectorErrorClass.CANCELLED,
                    "query_cancelled",
                    retryable=False,
                    partial=partial,
                )
            response = await self._transport.send(
                HttpRequest(
                    "GET",
                    (
                        base
                        + "/platform/storage/query/v1/query:poll?"
                        + urlencode({"request-token": request_token})
                    ),
                    {
                        "authorization": f"Bearer {access_token}",
                        "accept": "application/json",
                    },
                    self._config.limits.timeout_seconds,
                    self._config.limits.max_response_bytes,
                )
            )
            payload = json_mapping(response)
            if _has_collection(payload):
                return payload
            state = str(payload.get("state", payload.get("queryState", ""))).upper()
            if state in {"FAILED", "CANCELLED"}:
                raise ConnectorError(
                    ConnectorErrorClass.UNAVAILABLE,
                    "dynatrace_query_failed",
                    retryable=state == "FAILED",
                    partial=partial,
                )
        raise ConnectorError(
            ConnectorErrorClass.TIMEOUT,
            "dynatrace_query_poll_exhausted",
            retryable=True,
            partial=partial,
        )

    async def _token(self) -> str:
        client_id = self._secrets.resolve(
            self._context, self._config.client_id
        ).reveal()
        secret = self._secrets.resolve(
            self._context, self._config.client_secret
        ).reveal()
        body = urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": client_id.decode(),
                "client_secret": secret.decode(),
                "scope": " ".join(self._config.oauth_scopes),
            }
        ).encode()
        response = await self._transport.send(
            HttpRequest(
                "POST",
                self._config.account_url.rstrip("/") + "/sso/connect/token",
                {"content-type": "application/x-www-form-urlencoded"},
                self._config.limits.timeout_seconds,
                64_000,
                body,
            )
        )
        payload = json_mapping(response)
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "dynatrace_access_token_missing",
                retryable=False,
            )
        return token

    def _request(
        self,
        query: EvidenceQuery,
        kind: EvidenceKind,
        token: str,
        cursor: str | None,
    ) -> HttpRequest:
        base = self._config.environment_url.rstrip("/")
        headers = {"authorization": f"Bearer {token}", "accept": "application/json"}
        parameters = {
            "from": query.window.start.astimezone(UTC).isoformat(),
            "to": query.window.end.astimezone(UTC).isoformat(),
            "pageSize": str(min(query.limit, self._config.limits.max_records)),
        }
        if kind in {EvidenceKind.LOG, EvidenceKind.TRACE, EvidenceKind.SPAN}:
            if cursor is not None:
                raise ConnectorError(
                    ConnectorErrorClass.INVALID_QUERY,
                    "dynatrace_grail_cursor_unsupported",
                    retryable=False,
                )
            query_text = _grail_query(kind, query.selectors)
            return HttpRequest(
                "POST",
                base + "/platform/storage/query/v1/query:execute",
                {**headers, "content-type": "application/json"},
                self._config.limits.timeout_seconds,
                self._config.limits.max_response_bytes,
                json.dumps(
                    {
                        "query": query_text,
                        "defaultTimeframeStart": parameters["from"],
                        "defaultTimeframeEnd": parameters["to"],
                        "maxResultRecords": parameters["pageSize"],
                    },
                    separators=(",", ":"),
                ).encode(),
            )
        paths = {
            EvidenceKind.METRIC: "/api/v2/metrics/query",
            EvidenceKind.PROBLEM: "/api/v2/problems",
            EvidenceKind.EVENT: "/api/v2/events",
            EvidenceKind.CHANGE: "/api/v2/events",
            EvidenceKind.DEPLOYMENT: "/api/v2/events",
            EvidenceKind.ENTITY: "/api/v2/entities",
            EvidenceKind.TOPOLOGY: "/api/v2/entities",
        }
        if kind is EvidenceKind.METRIC:
            parameters["metricSelector"] = "builtin:service.errors.total"
        if kind in {EvidenceKind.ENTITY, EvidenceKind.TOPOLOGY}:
            parameters["entitySelector"] = "type(SERVICE)"
        if kind in {EvidenceKind.CHANGE, EvidenceKind.DEPLOYMENT}:
            parameters["eventSelector"] = 'eventType("CUSTOM_DEPLOYMENT")'
        if cursor is not None:
            parameters = {"nextPageKey": cursor}
        return HttpRequest(
            "GET",
            base + paths[kind] + "?" + urlencode(parameters),
            headers,
            self._config.limits.timeout_seconds,
            self._config.limits.max_response_bytes,
        )

    def _validate(
        self,
        query: EvidenceQuery,
        cancellation: CancellationSignal | None,
    ) -> None:
        if query.tenant_id != str(self._context.tenant_id):
            raise PermissionError("cross_tenant_query")
        if query.environment.name != self._config.environment:
            raise PermissionError("environment_not_allowed")
        if query.window.end - query.window.start > _seconds(
            self._config.limits.max_window_seconds
        ):
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "query_window_too_large",
                retryable=False,
            )
        if any(kind not in _SUPPORTED for kind in query.kinds):
            raise ConnectorError(
                ConnectorErrorClass.CAPABILITY,
                "unsupported_evidence_kind",
                retryable=False,
            )
        if len(query.kinds) != 1:
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "dynatrace_single_kind_required",
                retryable=False,
            )
        if any(not _SELECTOR.fullmatch(value) for value in query.selectors.values()):
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "unsafe_selector",
                retryable=False,
            )
        if cancellation is not None and cancellation.cancelled:
            raise ConnectorError(
                ConnectorErrorClass.CANCELLED,
                "query_cancelled",
                retryable=False,
            )


def _grail_query(kind: EvidenceKind, selectors: Mapping[str, str]) -> str:
    dataset = "logs" if kind is EvidenceKind.LOG else "spans"
    clauses = [f"fetch {dataset}"]
    service = selectors.get("service")
    if service is not None:
        clauses.append(f'filter service.name == "{service}"')
    if kind is EvidenceKind.TRACE:
        clauses.append("fields start_time, trace.id, service.name, duration, status")
    elif kind is EvidenceKind.SPAN:
        clauses.append(
            "fields start_time, trace.id, span.id, service.name, duration, status"
        )
    else:
        clauses.append("fields timestamp, content, loglevel, trace.id, span.id")
    return " | ".join(clauses)


def _items(
    payload: Mapping[str, object],
) -> tuple[tuple[Mapping[str, object], ...], str | None]:
    collection_keys = (
        "records",
        "items",
        "result",
        "problems",
        "events",
        "entities",
    )
    key = next((name for name in collection_keys if name in payload), None)
    if key is None:
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "dynatrace_collection_missing",
            retryable=False,
        )
    candidates = payload[key]
    if isinstance(candidates, dict):
        candidates = candidates.get("records", [])
    if not isinstance(candidates, list) or not all(
        isinstance(item, dict) for item in candidates
    ):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "dynatrace_records_invalid",
            retryable=False,
        )
    cursor = payload.get("nextPageKey")
    return tuple(candidates), cursor if isinstance(cursor, str) else None


def _has_collection(payload: Mapping[str, object]) -> bool:
    return any(
        key in payload
        for key in ("records", "items", "result", "problems", "events", "entities")
    )


def _metric_items(
    items: tuple[Mapping[str, object], ...],
) -> tuple[Mapping[str, object], ...]:
    records: list[Mapping[str, object]] = []
    for metric in items:
        metric_id = metric.get("metricId")
        series = metric.get("data")
        if not isinstance(metric_id, str) or not isinstance(series, list):
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "dynatrace_metric_series_invalid",
                retryable=False,
            )
        for series_index, datum in enumerate(series):
            if not isinstance(datum, Mapping):
                raise ConnectorError(
                    ConnectorErrorClass.MALFORMED_RESPONSE,
                    "dynatrace_metric_series_invalid",
                    retryable=False,
                )
            timestamps = datum.get("timestamps")
            values = datum.get("values")
            if not isinstance(timestamps, list) or not isinstance(values, list):
                raise ConnectorError(
                    ConnectorErrorClass.MALFORMED_RESPONSE,
                    "dynatrace_metric_points_invalid",
                    retryable=False,
                )
            for point_index, (timestamp, value) in enumerate(
                zip(timestamps, values, strict=False)
            ):
                if value is None:
                    continue
                records.append(
                    {
                        "id": (f"{metric_id}:{series_index}:{point_index}:{timestamp}"),
                        "timestamp": timestamp,
                        "displayName": metric_id,
                        "metricId": metric_id,
                        "value": value,
                    }
                )
    return tuple(records)


def _trace_items(
    items: tuple[Mapping[str, object], ...],
) -> tuple[Mapping[str, object], ...]:
    grouped: dict[str, list[Mapping[str, object]]] = {}
    for item in items:
        trace_id = item.get("trace.id")
        if not isinstance(trace_id, str) or not trace_id:
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "dynatrace_trace_id_missing",
                retryable=False,
            )
        grouped.setdefault(trace_id, []).append(item)
    traces: list[Mapping[str, object]] = []
    for trace_id, spans in sorted(grouped.items()):
        ordered = sorted(
            spans,
            key=lambda item: _timestamp(item.get("start_time", item.get("timestamp"))),
        )
        services = sorted(
            {
                str(item["service.name"])
                for item in ordered
                if isinstance(item.get("service.name"), str)
            }
        )
        statuses = sorted(
            {str(item["status"]) for item in ordered if item.get("status") is not None}
        )
        trace: dict[str, object] = {
            "id": trace_id,
            "trace.id": trace_id,
            "start_time": _timestamp(
                ordered[0].get("start_time", ordered[0].get("timestamp"))
            ).isoformat(),
            "displayName": f"trace {trace_id}",
            "span_count": len(ordered),
            "statuses": statuses,
        }
        if len(services) == 1:
            trace["service.name"] = services[0]
        elif services:
            trace["services"] = services
        traces.append(trace)
    return tuple(traces)


def _normalize(
    item: Mapping[str, object],
    kind: EvidenceKind,
    query: EvidenceQuery,
    base_url: str,
) -> RawEvidence:
    record_id = str(
        item.get(
            "id",
            item.get(
                "eventId",
                item.get(
                    "problemId",
                    item.get(
                        "entityId",
                        item.get(
                            "span.id",
                            item.get("trace.id", item.get("timestamp", "")),
                        ),
                    ),
                ),
            ),
        )
    )
    if not record_id:
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "dynatrace_record_id_missing",
            retryable=False,
        )
    observed = _timestamp(
        item.get(
            "timestamp",
            item.get(
                "startTime",
                item.get(
                    "start_time",
                    item.get("startTimeUnixNano", item.get("lastSeenTms")),
                ),
            ),
        )
    )
    summary = str(
        item.get(
            "displayName",
            item.get("title", item.get("content", kind.value)),
        )
    )
    trace_id = item.get("trace.id")
    span_id = item.get("span.id")
    references: tuple[EvidenceReference, ...] = ()
    if isinstance(trace_id, str) and trace_id:
        references = (
            (SpanReference(trace_id, span_id),)
            if isinstance(span_id, str) and span_id
            else (TraceReference(trace_id),)
        )
    return RawEvidence(
        record_id,
        kind,
        observed,
        summary[:4096],
        _json_fields(item),
        f"{base_url.rstrip('/')}/ui/record/{record_id}",
        service=(
            ServiceIdentity(str(item["service.name"]))
            if isinstance(item.get("service.name"), str)
            else None
        ),
        severity=_severity(item.get("severityLevel", item.get("loglevel"))),
        references=references,
        trust=TrustStatus.VERIFIED,
    )


def _json_fields(item: Mapping[str, object]) -> Mapping[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in sorted(item.items())[:200]:
        sanitized = _json_value(value, depth=0)
        if sanitized is not _OMIT:
            result[key] = cast(JsonValue, sanitized)
    return result


_OMIT = object()


def _json_value(value: object, *, depth: int) -> JsonValue | object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if depth >= 4:
        return _OMIT
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, item in list(value.items())[:100]:
            if not isinstance(key, str):
                continue
            sanitized = _json_value(item, depth=depth + 1)
            if sanitized is not _OMIT:
                result[key] = cast(JsonValue, sanitized)
        return result
    if isinstance(value, list | tuple):
        result_items: list[JsonValue] = []
        for item in value[:100]:
            sanitized = _json_value(item, depth=depth + 1)
            if sanitized is not _OMIT:
                result_items.append(cast(JsonValue, sanitized))
        return tuple(result_items)
    return _OMIT


def _timestamp(value: object) -> datetime:
    if isinstance(value, (int, float)):
        divisor = 1_000_000_000 if value > 10**17 else 1000
        return datetime.fromtimestamp(value / divisor, UTC)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            pass
    raise ConnectorError(
        ConnectorErrorClass.MALFORMED_RESPONSE,
        "dynatrace_timestamp_invalid",
        retryable=False,
    )


def _severity(value: object) -> EvidenceSeverity:
    text = str(value).lower()
    return next(
        (severity for severity in EvidenceSeverity if severity.value in text),
        EvidenceSeverity.UNKNOWN,
    )


def _seconds(value: int) -> timedelta:
    return timedelta(seconds=value)


__all__ = ["DynatraceAdapter"]
