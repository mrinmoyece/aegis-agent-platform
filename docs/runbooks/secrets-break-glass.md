# Secrets bootstrap, rotation, revocation, and break glass

1. Bootstrap Secrets Manager/KMS and External Secrets controller with a separately
   reviewed administrator; commit only secret references and workload identity.
2. Give the External Secrets controller the only approved secret-read role. Bind API and
   workers separately to minimum object/key actions; give the migrator no AWS role.
   Runtime identities never retrieve the RDS master secret. Tenant-bound references
   cannot be selected from mutable payload data.
3. Rotate by creating a provider version, validating in staging, refreshing the
   ExternalSecret, draining processes, and verifying auth/key readiness. Revoke old
   versions and sessions after overlap.
4. On compromise, disable IAM association and secret policy first, fence effects,
   revoke provider/OIDC credentials, rotate encryption/signing material as designed,
   restart affected workloads, reconcile ambiguous operations, and audit access.
5. Break glass requires two-person time-bounded approval, dedicated identity, narrow
   action/environment, no secret disclosure in tickets/logs, session recording or
   equivalent audit, immediate revocation, and post-incident review.

Missing identity, key, or schema dependencies must fail readiness; never substitute a
plaintext Kubernetes Secret or permissive fallback.
