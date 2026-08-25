# Compliance-ready engineering control map

The canonical machine-readable map is
[`qualification/compliance-map.json`](../qualification/compliance-map.json).
It maps control concepts to code, tests, and evidence while listing missing live
or organizational proof. It is not a SOC 2, ISO 27001, privacy, or AI-governance
certification and does not define legal scope.

## Coverage

- SOC 2-like security: identity, tenant authorization, RLS, least privilege,
  secure change, vulnerability handling, audit, and incident evidence.
- SOC 2-like availability: durable work, recovery, capacity, SLO hypotheses,
  alerting, backup, restore, and failover.
- SOC 2-like confidentiality: classification, minimization, redaction, secret
  references, support evidence, retention, and deletion.
- ISO 27001-like organizational, people, physical, and technological domains.
- Privacy lifecycle: purpose, ACL, retention, legal hold, tombstone, derived
  purge, erasable blobs, export gaps, and backup expiry gaps.
- AI governance/model risk: inventory concepts, provider-neutral routing,
  budgets, provenance/citations, human approval, deterministic safety/evals,
  live drift/calibration gaps, and change evidence.

## Evidence absent from code

The repository cannot prove management-approved scope and policy, asset/vendor
inventories, employment controls/training, joiner-mover-leaver records,
periodic access review, legal basis and notices, contracts and cross-border
assessment, physical controls, key custody ceremonies, live incident/change/
backup records, 24/7 on-call performance, independent testing, or auditor
opinion. Those remain named go-live inputs rather than success-shaped defaults.
