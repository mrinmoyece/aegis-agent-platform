# ADR 0007: Treat evaluation as versioned release evidence

- Status: Accepted
- Date: 2026-08-13

## Context

Agent quality is probabilistic and multidimensional. Unit tests alone cannot
detect task-quality, safety, latency, or cost regressions.

## Decision

Maintain versioned evaluation datasets with provenance, deterministic graders
where possible, calibrated model graders where necessary, and stored results
tied to code, prompt, policy, provider, and model versions. Use offline gates
before release and bounded online evaluation after release.

## Consequences

Scores require confidence ranges and segmentation, not a single vanity metric.
Sensitive datasets need tenant and retention controls. Model graders never
replace deterministic security assertions.
