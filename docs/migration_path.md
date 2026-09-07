# Unified Identity Architecture – Migration Path

This document describes the incremental migration path from the current split identity systems
to the unified Camunda Security Library described in
[`docs/architecture/`](architecture/README.md).

## 1. Current state summary

Before describing the migration, the following table summarizes the components being replaced per
deployment context — split by authentication and authorization, since the two migrate on different
timelines; see [rollout status](architecture/02-current-state.md#21-rollout-status-at-a-glance) for
what has shipped and what remains outstanding.

| Deployment | Component | AuthN | AuthZ | Storage |
|---|---|---|---|---|
| SaaS | Auth0 (Camunda-managed) | On CSL — CSL fronts Auth0 as the OIDC provider for Console and Web Modeler; Management Identity no longer serves the SaaS web apps | Not enforced by Auth0 itself, but its org-membership claims feed CSL's authorization input | Auth0 tenant |
| SaaS | OC Identity | Migrated to CSL — Operate, Tasklist, OC APIs | Read/check path migrated to CSL (one evaluator via `AuthorizationCheckPort`); write/authoring path not yet implemented on CSL (engine-side processors remain in `zeebe/engine`) | Zeebe primary (RocksDB) + secondary (ES/OS/RDBMS) |
| Self-Managed | Management Identity | Migrated to CSL — Console, Web Modeler, and Optimize authentication | Still Management Identity — not yet migrated | Keycloak DB + Management Identity PostgreSQL |
| Self-Managed | OC Identity | Migrated to CSL — Operate, Tasklist, OC APIs | Read/check path migrated to CSL (one evaluator via `AuthorizationCheckPort`); write/authoring path not yet implemented on CSL (engine-side processors remain in `zeebe/engine`) | Zeebe primary (RocksDB) + secondary (ES/OS/RDBMS) |

**What does not change:** all enterprise IdP integrations remain standard OIDC/SAML. The customer's
IdP (Keycloak, Entra, Okta, etc.) is never replaced — only the components consuming and enforcing
identity decisions change.

WIP
