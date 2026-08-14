# Replay debugger

`aegis-replay` is a read-only ledger debugger. It loads a tenant plus aggregate
and bounded sequence/time range, validates sequence, positions, schema versions,
source cursor shape, optional event hashes/hash chain, and computes a canonical
stream digest. It can fold at event N, compare two points, explain causation and
blocked/failed reason codes, compare a disposable projection, and create a
bounded pseudonymized support report.

```bash
python -m aegis_agent_platform.observability \
  --input support/events.ndjson \
  --tenant tenant-a \
  --aggregate run-a \
  --at-sequence 42 \
  --compare-sequence 21 \
  --support-report
```

Use a tenant-scoped non-superuser export. The debugger has no model, connector,
tool, sandbox, or effect adapter and its write methods reject use. It never
repairs the event ledger. `facts` are committed envelope facts;
`interpretations` are explicitly derived hints. Projection differences report
`ledger_fold` beside `derived_projection`; the ledger fold wins.

## Corruption

Stop projection consumers when sequence, position, tenant, aggregate, version,
or hash validation fails. Preserve the immutable evidence, page storage
ownership, and do not edit history. A missing optional event hash is reported
as `null`, not success. Rebuild only disposable projections after ledger
integrity is established.

Support reports are capped at 1 MiB, contain pseudonymous tenant/aggregate
references, facts and causal sequence links, and have a SHA-256 content digest.
Optional HMAC signing requires an explicit 32-byte key and signer. The local CLI
key is conspicuously demo-only and must not be used for production support.
