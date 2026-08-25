## Purpose

<!-- State the bounded problem and roadmap layer. -->

## Implemented

<!-- Describe only behavior present in this pull request. -->

## Not implemented

<!-- Make deferred capabilities and limitations explicit. -->

## Invariants and threats

<!-- Reference AGENTS.md, ADRs, and threat-model rows affected by this change. -->

## Evidence

- [ ] `make check`
- [ ] `make compose-config` when configuration changed
- [ ] `make container-check` when the image changed
- [ ] Cross-tenant and failure-path tests where applicable
- [ ] Enterprise checklist status updated where applicable
- [ ] `make qualification` when a cross-layer contract, readiness claim, risk, or release gate changed
- [ ] Live/environment evidence is separated from local/configuration evidence
- [ ] Residual risks name an owner, evidence, mitigation, trigger, and target date
- [ ] No secrets, sensitive prompts, or tenant data included
