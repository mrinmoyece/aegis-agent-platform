# ADR 0006: Keep provider SDKs behind adapters

- Status: Accepted
- Date: 2026-08-13

## Context

Model providers differ in request formats, streaming, usage, errors, safety
metadata, and idempotency. Vendor types in core logic create lock-in and
inconsistent durability.

## Decision

Core code uses small provider-neutral request, response, usage, and error types.
Adapters translate vendor SDK objects at the edge. Provider-specific options
must be explicit extensions rather than untyped dictionaries that leak inward.

## Consequences

The common contract will not expose every vendor feature. Adding a feature
requires a deliberate portable contract or a clearly isolated extension.
Contract tests must run against each adapter.

## Implementation evidence

Layer 5 implements the neutral contracts in `domain.model`, the provider
protocol and deterministic fake, and isolated official-SDK adapters for OpenAI
and Anthropic. Mocked transport tests cover messages, tools, structured output,
refusals, usage classes, request IDs, timeout/cancellation, malformed returns,
error classification, and SDK-bug containment. See ADR 0012 for fenced budgets.
