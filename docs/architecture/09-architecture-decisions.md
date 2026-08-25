## 9. Architecture Decision Records

This unified architecture builds on existing identity arc42 docs and ADRs for OC Identity and Management Identity; those ADRs remain the canonical source for detailed trade-offs. The main new decisions here are:

- Use a shared hexagonal Camunda Security Library with SPIs for persistence, propagation, IdP, OC commands, and (optionally) engine-level integration.
- Use Hub as policy SoT whenever present; OC-only deployments are treated as documented first-class modes, not afterthoughts.
- Ship a single shared Admin UI package, feature-gated by configuration for Hub vs OC, standalone vs Hub-managed.
- Make logical-tenant and Physical-Tenant support explicit in the core model and diagrams, not side effects.

### 9.1 Detailed ADRs

This section contains detailed Architectural Decision Records (ADRs) for the Camunda Security Library. Each ADR documents a specific decision, the context, alternatives considered, and consequences.

> When adding a new ADR file to `docs/adr/`, add a corresponding entry to this list.

- [ADR-0001: Placement of the Camunda Security Library (embedded vs standalone service)](../adr/0001-placement-of-the-security-gateway-framework.md)
- [ADR-0002: Frontend integration approach for Hub and Orchestration Cluster Admin UI](../adr/0002-frontend-integration-for-hub-and-oc.md)
- [ADR-0003: Security configuration: chain catalog and explicit host activation](../adr/0003-no-spring-boot-auto-configuration.md)
- [ADR-0004: Admin-user setup SPIs (`AdminUserPresencePort`, `AdminUserMissingHandlerPort`)](../adr/0004-admin-user-setup-spis.md)
- [ADR-0005: Lazy-load membership fields on `CamundaAuthentication`](../adr/0005-lazy-load-authentication-memberships.md)
- [ADR-0006: Additive multi-IdP OIDC configuration with an issuer-aware `JwtDecoder`](../adr/0006-multi-idp-oidc-configuration.md)
- [ADR-0007: OIDC UserInfo — the login-time `userInfoEnabled` toggle and request-time claim augmentation](../adr/0007-oidc-user-info-enabled-toggle.md)
- [ADR-0008: CSL authz enums as the canonical source for Service, Search, Exporter, and Persistence layers](../adr/0008-authz-enum-ownership-and-layered-usage.md)
- [ADR-0009: Own the web-session lifecycle behind `SessionStorePort`, with one session filter per surface and one OIDC logout handler per chain](../adr/0009-session-store-port-and-web-session-ownership.md)
- [ADR-0010: User-resolution ports — `CamundaUserPort` (user view) and `BasicAuthUserDetailsPort` (basic-auth credentials)](../adr/0010-user-details-port.md)
- [ADR-0011: OIDC bearer-token validation lives on the API chain only](../adr/0011-oidc-bearer-tokens-on-api-chain-only.md)
- [ADR-0012: Dedicated `validation` module for entity validators](../adr/0012-validation-module.md)
- [ADR-0013: `CamundaSecurityScopeProvider` SPI for host-contributed path-scoped API and webapp chains](../adr/0013-camunda-security-scope-provider-spi.md)
- [ADR-0014: Unify authorization checking in CSL `core` behind `AuthorizationCheckPort`](../adr/0014-unified-authz-framework-in-core.md)
- [ADR-0015: Reject Microsoft Entra v1 tokens at the token-claims conversion layer](../adr/0015-reject-entra-v1-tokens.md)
- [ADR-0016: Host customization hooks for security filter chains](../adr/0016-cors-and-https-redirect-host-hooks.md)
- [ADR-0017: JVM-local, session-ID-keyed guard for authentication refresh dedup](../adr/0017-jvm-local-session-refresh-guard.md)
- [ADR-0018: Optimize reuses the stateful OIDC webapp chain and the JWT-cookie chain is retired](../adr/0018-optimize-reuses-stateful-oidc-webapp-chain.md)
- [ADR-0019: `core`-owned assembly factories and native latency instrumentation for `AuthorizationCheckPort`](../adr/0019-authorization-check-latency-metric.md)
- [ADR-0020: Configurable session idle timeout driven by client activity, not request traffic](../adr/0020-configurable-activity-driven-session-idle-timeout.md)
- [ADR-0021: Hand-author spring-configuration-metadata.json for camunda.security.* properties](../adr/0021-hand-authored-spring-configuration-metadata.md)

### 9.2 Vision documents (proposed, not yet decided)

These documents describe designs for capabilities that are not yet implemented — targeted for
Camunda 8.11. They are not accepted ADRs; each will be promoted into `docs/adr/` as a new,
sequentially-numbered ADR once work on the topic actually begins.

- [PolicyVersion commits with full-policy propagation (iteration one)](../vision/policy-version-change-sets.md)
- [Push vs Pull Policy Propagation (Hub ↔ Orchestration Clusters)](../vision/push-vs-pull-policy-propagation.md)
- [Identity data persistence in the Orchestration Cluster](../vision/oc-identity-data-persistence-and-engine-command-scope.md)

---

