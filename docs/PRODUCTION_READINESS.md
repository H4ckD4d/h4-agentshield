# H4 AgentShield — v0.2 security baseline
**Creator: Chris Cruz — @h4ckd4d**
Implemented: tenant-scoped API, viewer/editor/admin permissions, high-entropy API key SHA-256 digest configuration, revoked-key handling, paginated audit logs, agent inventory and negative authorization tests.

Generate a high-entropy secret locally and store only its SHA-256 digest in the H4_TENANTS JSON configuration under `key_sha256` (with `tenant_id`, `actor_id`, `role`). Legacy plaintext `key` remains for local demo backward compatibility only.

Production blockers: enterprise OIDC, tenant membership, RBAC for each domain action, robust revocation, migrations, PostgreSQL row-level policies, secret vault, distributed quotas, queues, idempotency, observability, backup/restore drills, customer SLAs, billing and load/security reviews.

Demo only: not production-ready; no validated security certification or scale guarantees.
