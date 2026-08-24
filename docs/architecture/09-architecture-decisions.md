## 9. Architecture Decision Records

This unified architecture builds on existing identity arc42 docs and ADRs for OC Identity and Management Identity; those ADRs remain the canonical source for detailed trade-offs. The main new decisions here are:

- Use a shared hexagonal Camunda Security Library with SPIs for persistence, propagation, IdP, OC commands, and (optionally) engine-level integration.
- Use Hub as policy SoT whenever present; OC-only deployments are treated as documented first-class modes, not afterthoughts.
- Ship a single shared Admin UI package, feature-gated by configuration for Hub vs OC, standalone vs Hub-managed.
- Make logical-tenant and Physical-Tenant support explicit in the core model and diagrams, not side effects.

### 9.1 Detailed ADRs

This section contains detailed Architectural Decision Records (ADRs) for the Camunda Security Library. Each ADR documents a specific decision, the context, alternatives considered, and consequences.

> When adding a new ADR file to `docs/adr/`, add a corresponding entry to this list.

- [ADR-0001: PolicyVersion commits with full-policy propagation (iteration one)](../adr/0001-policy-version-change-sets.md)
- [ADR-0002: Placement of the Camunda Security Library (embedded vs standalone service)](../adr/0002-placement-of-the-security-gateway-framework.md)
- [ADR-0003: Push vs Pull Policy Propagation (Hub ↔ Orchestration Clusters)](../adr/0003-push-vs-pull-policy-propagation.md)
- [ADR-0004: Identity data persistence in the Orchestration Cluster](../adr/0004-oc-identity-data-persistence-and-engine-command-scope.md)
- [ADR-0005: Frontend integration approach for Hub and Orchestration Cluster Admin UI](../adr/0005-frontend-integration-for-hub-and-oc.md)
- [ADR-0008: Security configuration: chain catalog and explicit host activation](../adr/0008-no-spring-boot-auto-configuration.md)
- [ADR-0010: Admin-user setup SPIs (`AdminUserPresencePort`, `AdminUserMissingHandlerPort`)](../adr/0010-admin-user-setup-spis.md)
- [ADR-0011: Lazy-load membership fields on `CamundaAuthentication`](../adr/0011-lazy-load-authentication-memberships.md)
- [ADR-0013: Additive multi-IdP OIDC configuration with an issuer-aware `JwtDecoder`](../adr/0013-multi-idp-oidc-configuration.md)
- [ADR-0014: OIDC UserInfo — the login-time `userInfoEnabled` toggle and request-time claim augmentation](../adr/0014-oidc-user-info-enabled-toggle.md)
- [ADR-0016: CSL authz enums as the canonical source for Service, Search, Exporter, and Persistence layers](../adr/0016-authz-enum-ownership-and-layered-usage.md)
- [ADR-0017: Own the web-session lifecycle behind `SessionStorePort`, with one session filter per surface and one OIDC logout handler per chain](../adr/0017-session-store-port-and-web-session-ownership.md)
- [ADR-0021: User-resolution ports — `CamundaUserPort` (user view) and `BasicAuthUserDetailsPort` (basic-auth credentials)](../adr/0021-user-details-port.md)
- [ADR-0023: OIDC bearer-token validation lives on the API chain only](../adr/0023-oidc-bearer-tokens-on-api-chain-only.md)
- [ADR-0024: Dedicated `validation` module for entity validators](../adr/0024-validation-module.md)
- [ADR-0025: `CamundaSecurityScopeProvider` SPI for host-contributed path-scoped API and webapp chains](../adr/0025-camunda-security-scope-provider-spi.md)
- [ADR-0028: Unify authorization checking in CSL `core` behind `AuthorizationCheckPort`](../adr/0028-unified-authz-framework-in-core.md)
- [ADR-0033: Reject Microsoft Entra v1 tokens at the token-claims conversion layer](../adr/0033-reject-entra-v1-tokens.md)
- [ADR-0034: Host customization hooks for security filter chains](../adr/0034-cors-and-https-redirect-host-hooks.md)
- [ADR-0035: JVM-local, session-ID-keyed guard for authentication refresh dedup](../adr/0035-jvm-local-session-refresh-guard.md)
- [ADR-0038: Optimize reuses the stateful OIDC webapp chain and the JWT-cookie chain is retired](../adr/0038-optimize-reuses-stateful-oidc-webapp-chain.md)
- [ADR-0041: `core`-owned assembly factories and native latency instrumentation for `AuthorizationCheckPort`](../adr/0041-authorization-check-latency-metric.md)
- [ADR-0042: Configurable session idle timeout driven by client activity, not request traffic](../adr/0042-configurable-activity-driven-session-idle-timeout.md)
- [ADR-0043: Hand-author spring-configuration-metadata.json for camunda.security.* properties](../adr/0043-hand-authored-spring-configuration-metadata.md)

---

