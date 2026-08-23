"""Structured JSON logging with fixed schemas and duplicate suppression."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from threading import Lock

from opentelemetry import trace

from aegis_agent_platform.observability.safety import (
    AttributeSanitizer,
    bounded_event_size,
)
from aegis_agent_platform.observability.semantic import (
    LOG_EVENTS,
    SEMANTIC_SCHEMA_VERSION,
    ErrorClass,
    TelemetryStatus,
)

_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


@dataclass(frozen=True, slots=True)
class LogSuppression:
    """Bounded suppression state for one stable event class."""

    last_emitted: float
    suppressed: int


class JsonEventFormatter(logging.Formatter):
    """Serialize only the reviewed event mapping attached by ``SafeLogger``."""

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "aegis_event", None)
        if not isinstance(event, Mapping):
            event = {
                "schema_version": SEMANTIC_SCHEMA_VERSION,
                "event_name": "logging.invalid_record.failed.v1",
                "status": TelemetryStatus.FAILED.value,
                "error_class": ErrorClass.INTERNAL.value,
            }
        return json.dumps(event, separators=(",", ":"), sort_keys=True)


class SafeLogger:
    """Emit bounded structured records without exception or business content."""

    def __init__(
        self,
        logger: logging.Logger,
        *,
        sanitizer: AttributeSanitizer | None = None,
        minimum_level: str = "INFO",
        suppression_seconds: float = 10,
        audit: bool = False,
    ) -> None:
        if minimum_level not in _LEVELS:
            raise ValueError("minimum_level is not recognized")
        if not 0 <= suppression_seconds <= 300:
            raise ValueError("suppression_seconds must be between 0 and 300")
        self._logger = logger
        self._sanitizer = sanitizer or AttributeSanitizer()
        self._minimum_level = _LEVELS[minimum_level]
        self._suppression_seconds = suppression_seconds
        self._audit = audit
        self._suppression: dict[tuple[str, str], LogSuppression] = {}
        self._lock = Lock()

    def emit(
        self,
        event_name: str,
        status: TelemetryStatus,
        *,
        occurred_at: datetime,
        monotonic_time: float,
        level: str = "INFO",
        error_class: ErrorClass = ErrorClass.NONE,
        error_code: str | None = None,
        attributes: Mapping[str, object] | None = None,
    ) -> bool:
        """Emit one safe event and return false when suppressed or oversized."""
        if event_name not in LOG_EVENTS:
            raise ValueError("unregistered structured log event")
        if occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        if level not in _LEVELS:
            raise ValueError("log level is not recognized")
        numeric_level = _LEVELS[level]
        if numeric_level < self._minimum_level:
            return False
        if error_code is not None and (
            not error_code
            or len(error_code) > 64
            or not error_code.replace("_", "").isalnum()
        ):
            raise ValueError("error_code must be a bounded identifier")
        key = (event_name, error_code or "none")
        with self._lock:
            previous = self._suppression.get(key)
            if (
                not self._audit
                and previous is not None
                and monotonic_time - previous.last_emitted < self._suppression_seconds
            ):
                self._suppression[key] = LogSuppression(
                    previous.last_emitted,
                    previous.suppressed + 1,
                )
                return False
            suppressed = previous.suppressed if previous is not None else 0
            self._suppression[key] = LogSuppression(monotonic_time, 0)
        span_context = trace.get_current_span().get_span_context()
        event: dict[str, object] = {
            "schema_version": SEMANTIC_SCHEMA_VERSION,
            "event_name": event_name,
            "occurred_at": occurred_at.isoformat(),
            "status": status.value,
            "error_class": error_class.value,
            "audit": self._audit,
            "suppressed_duplicates": suppressed,
        }
        if error_code is not None:
            event["error_code"] = error_code
        if span_context.is_valid:
            event["trace_id"] = f"{span_context.trace_id:032x}"
            event["span_id"] = f"{span_context.span_id:016x}"
        event.update(self._sanitizer.sanitize(attributes or {}))
        if not bounded_event_size(event):
            return False
        self._logger.log(
            numeric_level,
            event_name,
            extra={"aegis_event": event},
        )
        return True


def configure_json_logging(
    *,
    level: str,
    logger_name: str = "aegis",
) -> tuple[SafeLogger, SafeLogger]:
    """Configure separate operational and audit logger namespaces."""
    if level not in _LEVELS:
        raise ValueError("log level is not recognized")
    formatter = JsonEventFormatter()
    operational = logging.getLogger(logger_name)
    audit = logging.getLogger(f"{logger_name}.audit")
    for logger in (operational, audit):
        logger.handlers.clear()
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(_LEVELS[level])
        logger.propagate = False
    return (
        SafeLogger(operational, minimum_level=level),
        SafeLogger(audit, minimum_level=level, suppression_seconds=0, audit=True),
    )


__all__ = [
    "JsonEventFormatter",
    "LogSuppression",
    "SafeLogger",
    "configure_json_logging",
]
