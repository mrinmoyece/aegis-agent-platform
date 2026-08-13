# ADR 0001: Use a typed Python monorepo

- Status: Accepted
- Date: 2026-08-13

## Context

The learning path crosses API, runtime, domain, adapters, evaluation, and
operations. Separate repositories would obscure contract changes and make early
layers expensive to review.

## Decision

Use Python 3.12 with a `src` layout in one repository. Keep subsystem package
boundaries explicit, enforce strict typing and architecture tests, and split
deployable processes at entry points rather than repositories.

## Consequences

Atomic contract changes and one fast check suite improve learning and review.
The repository must resist accidental coupling; a future split requires stable
ports and an ADR.
