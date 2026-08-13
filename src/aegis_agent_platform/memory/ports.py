"""Provider-neutral memory, embedding, summarization, and scanning ports."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from aegis_agent_platform.domain import (
    EmbeddingRequest,
    EmbeddingResponse,
    SummarizationRequest,
    SummarizationResponse,
    SummaryClaim,
    canonical_text,
)

_SECRET = re.compile(
    r"(?i)(authorization:\s*bearer\s+[^\s]{6,}|"
    r"(api[_-]?key|client[_-]?secret|password)\s*[:=]\s*[^\s]{6,})"
)
_PII = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_INJECTION = re.compile(
    r"(?i)(ignore (all |any )?(previous|system) instructions|"
    r"grant (me )?(admin|tool|approval)|system prompt|developer message|"
    r"execute (this|the) command|bypass (policy|approval))"
)


class MemoryProviderErrorClass(StrEnum):
    INVALID_REQUEST = "invalid_request"
    DIMENSION_MISMATCH = "dimension_mismatch"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    TRANSIENT = "transient"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    MALFORMED_RESPONSE = "malformed_response"
    PROVIDER_BUG = "provider_bug"


class MemoryProviderError(RuntimeError):
    """Secret-safe classified provider failure."""

    def __init__(
        self,
        error_class: MemoryProviderErrorClass,
        code: str,
        *,
        retryable: bool,
        result_ambiguous: bool = False,
    ) -> None:
        super().__init__(code)
        if not code:
            raise ValueError("memory provider error code is required")
        self.error_class = error_class
        self.code = code
        self.retryable = retryable
        self.result_ambiguous = result_ambiguous


class MemoryScanError(RuntimeError):
    """Secret-safe scanner failure that may be durably classified."""

    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        if not code:
            raise ValueError("memory scan error code is required")
        self.code = code
        self.retryable = retryable


class ScanDisposition(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    QUARANTINE = "quarantine"


@dataclass(frozen=True, slots=True)
class ScanResult:
    disposition: ScanDisposition
    redacted_text: str
    rule_ids: tuple[str, ...]
    prompt_injection_marked: bool
    poisoning_suspected: bool

    def __post_init__(self) -> None:
        if not self.redacted_text:
            raise ValueError("scanner output cannot be empty")
        rules = tuple(sorted(set(self.rule_ids)))
        if self.disposition is ScanDisposition.ALLOW and rules:
            raise ValueError("allowed scanner output cannot claim redaction rules")
        if self.disposition is not ScanDisposition.ALLOW and not rules:
            raise ValueError("scanner decision requires bounded rule identifiers")
        object.__setattr__(self, "rule_ids", rules)


class EmbeddingProvider(Protocol):
    provider_name: str

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse: ...


class SummarizationProvider(Protocol):
    provider_name: str

    async def summarize(
        self,
        request: SummarizationRequest,
    ) -> SummarizationResponse: ...


class MemoryScanner(Protocol):
    async def scan(self, text: str) -> ScanResult: ...


class DeterministicEmbeddingProvider:
    """Hash-based normalized embeddings for tests and demos; no network."""

    provider_name = "deterministic"

    async def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        vectors: list[tuple[float, ...]] = []
        for text in request.texts:
            values = [0.0] * request.dimension
            tokens = canonical_text(text).casefold().split()
            if not tokens:
                raise MemoryProviderError(
                    MemoryProviderErrorClass.INVALID_REQUEST,
                    "empty_embedding_input",
                    retryable=False,
                )
            for token in tokens:
                digest = hashlib.sha256(token.encode()).digest()
                bucket = int.from_bytes(digest[:4], "big") % request.dimension
                sign = -1.0 if digest[4] & 1 else 1.0
                values[bucket] += sign * (1.0 + digest[5] / 255.0)
            norm = math.sqrt(sum(value * value for value in values))
            if norm == 0:
                values[0] = 1.0
                norm = 1.0
            vectors.append(tuple(value / norm for value in values))
        return EmbeddingResponse(
            request_id=request.request_id,
            model=request.model,
            model_version=request.model_version,
            dimension=request.dimension,
            vectors=tuple(vectors),
            provider_request_id=f"fake-{request.input_digest[:16]}",
        )


class DeterministicSummarizationProvider:
    """Citation-preserving extractive summarizer for tests and demos."""

    provider_name = "deterministic"

    async def summarize(
        self,
        request: SummarizationRequest,
    ) -> SummarizationResponse:
        selected = tuple(
            sorted(
                request.source_items,
                key=lambda item: (-item.priority, item.occurred_at, item.reference_id),
            )
        )
        max_bytes = request.max_output_tokens * 4
        claims: list[SummaryClaim] = []
        rendered: list[str] = []
        covered: list[str] = []
        used = 0
        for item in selected:
            citation_ids = tuple(citation.source_id for citation in item.citations)
            line = f"{item.text} [{' '.join(citation_ids)}]"
            encoded = line.encode()
            if rendered and used + len(encoded) > max_bytes:
                continue
            if len(encoded) > max_bytes:
                line = encoded[:max_bytes].decode("utf-8", errors="ignore").rstrip()
            rendered.append(line)
            claims.append(SummaryClaim(item.text, citation_ids))
            covered.append(item.reference_id)
            used += len(line.encode())
        if not rendered:
            raise MemoryProviderError(
                MemoryProviderErrorClass.INVALID_REQUEST,
                "summary_budget_too_small",
                retryable=False,
            )
        return SummarizationResponse(
            request_id=request.request_id,
            summary="\n".join(rendered),
            claims=tuple(claims),
            covered_reference_ids=tuple(covered),
            model=request.model,
            model_version=request.model_version,
        )


class RegexMemoryScanner:
    """Deterministic baseline hook for secrets, PII, and prompt injection."""

    async def scan(self, text: str) -> ScanResult:
        value = canonical_text(text)
        rules: set[str] = set()
        if _SECRET.search(value):
            value = _SECRET.sub("[REDACTED-SECRET]", value)
            rules.add("secret-pattern-v1")
        if _PII.search(value):
            value = _PII.sub("[REDACTED-EMAIL]", value)
            rules.add("email-pattern-v1")
        injection = bool(_INJECTION.search(value))
        if injection:
            rules.add("prompt-injection-v1")
        disposition = (
            ScanDisposition.QUARANTINE
            if injection
            else ScanDisposition.REDACT
            if rules
            else ScanDisposition.ALLOW
        )
        return ScanResult(
            disposition,
            value,
            tuple(rules),
            prompt_injection_marked=injection,
            poisoning_suspected=injection,
        )


def validate_embedding_response(
    request: EmbeddingRequest,
    response: EmbeddingResponse,
) -> None:
    """Reject provider bugs without coercing a success-shaped result."""
    if response.request_id != request.request_id:
        raise MemoryProviderError(
            MemoryProviderErrorClass.MALFORMED_RESPONSE,
            "embedding_request_id_mismatch",
            retryable=False,
            result_ambiguous=True,
        )
    if (
        response.model != request.model
        or response.model_version != request.model_version
        or response.dimension != request.dimension
    ):
        raise MemoryProviderError(
            MemoryProviderErrorClass.DIMENSION_MISMATCH,
            "embedding_model_or_dimension_mismatch",
            retryable=False,
            result_ambiguous=True,
        )
    if len(response.vectors) != len(request.texts):
        raise MemoryProviderError(
            MemoryProviderErrorClass.MALFORMED_RESPONSE,
            "embedding_vector_count_mismatch",
            retryable=False,
            result_ambiguous=True,
        )


__all__ = [
    "DeterministicEmbeddingProvider",
    "DeterministicSummarizationProvider",
    "EmbeddingProvider",
    "MemoryProviderError",
    "MemoryProviderErrorClass",
    "MemoryScanError",
    "MemoryScanner",
    "RegexMemoryScanner",
    "ScanDisposition",
    "ScanResult",
    "SummarizationProvider",
    "validate_embedding_response",
]
