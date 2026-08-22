# Security policy

## Supported versions

Aegis is pre-release learning software and is not supported for production
deployment. Security fixes are applied to the default branch only.

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

Layer 1 provides architecture and local-development scaffolding. It does not
implement authorization, tenant isolation, sandboxing, audit retention, or
durable execution. The local credentials in `.env.example` are intentionally
unsafe outside an isolated workstation.
