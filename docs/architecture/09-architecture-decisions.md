## 9. Architecture decisions and open points

This unified architecture builds on existing identity arc42 docs and ADRs for OC Identity and Management Identity; those ADRs remain the canonical source for detailed trade-offs. The main new decisions here are:

- Use a shared hexagonal Camunda Security Library with SPIs for persistence, propagation, IdP, OC commands, and (optionally) engine-level integration.
- Use Hub as policy SoT whenever present; OC-only deployments are treated as documented first-class modes, not afterthoughts.
- Ship a single shared Admin UI package, feature-gated by configuration for Hub vs OC, standalone vs Hub-managed.
- Make logical-tenant and Physical-Tenant support explicit in the core model and diagrams, not side effects.

### 9.1 Open High Level points (to be refined in separate ADRs):

- Exact SPI boundaries for OC/engine command creation.
- Migration path from current Auth0-based SaaS setup to “Enterprise IdP as SoT” while keeping Auth0 as a private implementation detail.
- If the endpoints to apply policy changes are public, Hub will not be aware of what a customer applies to OC and will run out of sync.
- How can we apply a snapshot multiple times? How could we reset the projections in primary and secondary storage?

### 9.2 Detailed ADRs

This section contains detailed Architectural Decision Records (ADRs) for the Camunda Security Library. Each ADR documents a specific decision, the context, alternatives considered, and consequences.

- [ADR-0001: PolicyVersion commits and full-policy propagation](adr/0001-policy-version-change-sets.md)
- [ADR-0002: Placement of the Camunda Security Library (embedded vs standalone service)](adr/0002-placement-of-the-security-gateway-framework.md)
- [ADR-0003: Push vs Pull Policy Propagation (Hub ↔ Orchestration Clusters)](adr/0003-push-vs-pull-policy-propagation.md)
- [ADR-0004: Identity data persistence in the Orchestration Cluster (Open)](adr/0004-oc-identity-data-persistence-and-engine-command-scope.md)
- [ADR-0005: Frontend integration approach for Hub and Orchestration Cluster Admin UI](adr/0005-frontend-integration-for-hub-and-oc.md)
- [ADR-0006: Central Spring Security filter chains as Spring Boot auto-configuration](adr/0006-central-security-filter-chains.md)
- [ADR-0007: Two-port authorization surface (`ResourcePermissionPort` and `AuthorizationRepositoryPort`)](adr/0007-resource-permission-port-and-authorization-repository.md)
- [ADR-0008: No Spring Boot auto-configuration — hosts explicitly import configurations](adr/0008-no-spring-boot-auto-configuration.md)

---

