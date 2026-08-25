# Security policy

## Supported versions

Aegis is pre-release learning/reference software and is not certified or
supported for production deployment. Security fixes are applied to the default
branch only.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. Include the
affected commit, impact, reproduction steps, and any suggested mitigation. Do
not include secrets, tenant data, or exploit traffic from systems you do not
own.

If private reporting is unavailable, contact the repository owner privately
through their published GitHub profile. Do not create a public issue before a
coordinated disclosure plan exists.

We aim to acknowledge complete reports within seven days. Timelines for fixes
and disclosure depend on severity and project maturity.

## Scope warning

Layer 16 locally qualifies implemented authorization, tenant isolation, durable
execution, provider/evidence/agent/remediation/sandbox/memory/protocol
boundaries, replay, and deployment configuration. It does not prove live
identity, cloud/cluster/sandbox/egress enforcement, provider/partner behavior,
managed recovery, production SLOs/capacity, 24/7 operations, independent
penetration testing, or compliance. The local credentials in `.env.example` and
all deterministic fakes are intentionally unsafe outside an isolated
workstation.

See `docs/security-assessment.md` and
`qualification/residual-risks.json` for the current executable assessment and
open gates.
