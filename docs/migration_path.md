# Unified Identity Architecture – Migration Path

This document describes the incremental migration path from the current split identity systems
to the unified Camunda Security Library described in
[`docs/architecture/`](architecture/README.md).

## 1. Current state summary

The current state — which component owns authentication and authorization per deployment context,
and which parts have shipped — is maintained in the architecture documentation rather than
duplicated here: see [rollout status](architecture/02-current-state.md#21-rollout-status-at-a-glance)
for what has shipped and what remains outstanding, and
[§2.4 Pre-CSL baseline](architecture/02-current-state.md#24-pre-csl-baseline-historical)
for the components and storage being replaced.

**What does not change:** all enterprise IdP integrations remain standard OIDC/SAML. The customer's
IdP (Keycloak, Entra, Okta, etc.) is never replaced — only the components consuming and enforcing
identity decisions change.

WIP
