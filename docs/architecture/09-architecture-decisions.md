## 9. Architecture Decision Records

This unified architecture builds on existing identity arc42 docs and ADRs for OC Identity and Management Identity; those ADRs remain the canonical source for detailed trade-offs. The main new decisions here are:

- Use a shared hexagonal Camunda Security Library with SPIs for persistence, propagation, IdP, OC commands, and (optionally) engine-level integration.
- Use Hub as policy SoT whenever present; OC-only deployments are treated as documented first-class modes, not afterthoughts.
- Ship a single shared Admin UI package, feature-gated by configuration for Hub vs OC, standalone vs Hub-managed.
- Make logical-tenant and Physical-Tenant support explicit in the core model and diagrams, not side effects.

### 9.1 Detailed ADRs

This section contains detailed Architectural Decision Records (ADRs) for the Camunda Security Library. Each ADR documents a specific decision, the context, alternatives considered, and consequences.

> When adding a new ADR file to `docs/adr/`, add a corresponding entry to this list.

- [ADR-0001: PolicyVersion commits and full-policy propagation](../adr/0001-policy-version-change-sets.md)
- [ADR-0002: Placement of the Camunda Security Library (embedded vs standalone service)](../adr/0002-placement-of-the-security-gateway-framework.md)
- [ADR-0003: Push vs Pull Policy Propagation (Hub ↔ Orchestration Clusters)](../adr/0003-push-vs-pull-policy-propagation.md)
- [ADR-0004: Identity data persistence in the Orchestration Cluster (Open)](../adr/0004-oc-identity-data-persistence-and-engine-command-scope.md)
- [ADR-0005: Frontend integration approach for Hub and Orchestration Cluster Admin UI](../adr/0005-frontend-integration-for-hub-and-oc.md)
- [ADR-0006: Central Spring Security filter chains](../adr/0006-central-security-filter-chains.md)
- [ADR-0007: Two-port authorization surface (`ResourcePermissionPort` and `AuthorizationRepositoryPort`)](../adr/0007-resource-permission-port-and-authorization-repository.md)
- [ADR-0008: No Spring Boot auto-configuration — hosts explicitly import configurations](../adr/0008-no-spring-boot-auto-configuration.md)
- [ADR-0009: Web-app authorization SPIs](../adr/0009-web-app-authorization-spis.md)
- [ADR-0010: Admin-user setup SPIs](../adr/0010-admin-user-setup-spis.md)
- [ADR-0011a: Admin user check filter — Basic auth only](../adr/0011-admin-user-check-filter-basic-auth-only.md)
- [ADR-0011b: Lazy-load authentication memberships](../adr/0011-lazy-load-authentication-memberships.md)
- [ADR-0012: OIDC logout success handler](../adr/0012-oidc-logout-success-handler.md)
- [ADR-0013: Multi-IdP OIDC configuration](../adr/0013-multi-idp-oidc-configuration.md)
- [ADR-0014: OIDC UserInfo enabled toggle](../adr/0014-oidc-user-info-enabled-toggle.md)
- [ADR-0015: Additional JWK Set URIs — composite decoder](../adr/0015-additional-jwk-set-uris-composite-decoder.md)
- [ADR-0016: Authorization enum ownership and layered usage](../adr/0016-authz-enum-ownership-and-layered-usage.md)
- [ADR-0017: Session store port and web-session ownership](../adr/0017-session-store-port-and-web-session-ownership.md)
- [ADR-0018: CamundaUserPort — user resolution port](../adr/0018-camunda-user-port.md)
- [ADR-0019: Authorization runtime check migration and no Jackson in domain](../adr/0019-authorization-runtime-check-migration-and-no-jackson-in-domain.md)
- [ADR-0020a: Issuer-aware JWT decoder](../adr/0020-issuer-aware-jwt-decoder.md)
- [ADR-0020b: SecurityContext and condition types migration](../adr/0020-security-context-and-condition-types-migration.md)
- [ADR-0021: User details port](../adr/0021-user-details-port.md)
- [ADR-0022: Resource access control framework ownership](../adr/0022-resource-access-control-framework-ownership.md)
- [ADR-0023a: Hand-authored Spring configuration metadata](../adr/0023-hand-authored-spring-configuration-metadata.md)
- [ADR-0023b: OIDC bearer tokens on API chain only](../adr/0023-oidc-bearer-tokens-on-api-chain-only.md)
- [ADR-0024: Validation module](../adr/0024-validation-module.md)
- [ADR-0025: `CamundaSecurityScopeProvider` SPI](../adr/0025-camunda-security-scope-provider-spi.md)
- [ADR-0026: UserInfo claim augmentation](../adr/0026-userinfo-claim-augmentation.md)
- [ADR-0027: Scoped webapp security chains and per-scope sessions](../adr/0027-scoped-webapp-security-chains-and-per-scope-sessions.md)
- [ADR-0028: Extend CSL authorization model to serve both search-layer and zeebe engine](../adr/0028-unified-authz-framework-in-core.md)
- [ADR-0029: Per-scope session store ownership for durable web sessions](../adr/0029-per-scope-session-store-ownership.md)

---

