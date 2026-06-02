---
status: Accepted
---

# ADR-0018: CamundaUserPort contract migration to CSL

**Deciders**: @p-wunderlich

## Status

Accepted

## Context

OC currently owns the `CamundaUserService` interface (and its
`OidcCamundaUserService` / `BasicCamundaUserService` implementations) and the
`CamundaUserDTO` record that power the `CamundaAuthentication` view returned
by `GET /v2/authentication/me` and `/v2/authentication/me/token`.

Increment 13 (#243) is part of the M1 epic (#95) that migrates common
authentication classes from OC into CSL with OC integration. The migration must
let other adopters (Hub, future OCs) reuse the user-view contract without
dragging in OC's secondary-storage stack.

Two structural constraints shape the decision:

1. **The OC implementations are not portable as-is.**
   `OidcCamundaUserService` and `BasicCamundaUserService` depend on
   `UserServices`, `TenantServices`, and OAuth2 host wiring — all OC-only.
   Lifting them as CSL defaults would either pull those services into CSL
   (large surface, conflicts with Inc-14/Inc-15 boundaries) or invent shim
   ports (premature port design with no concrete adopter).
2. **`CamundaUserDTO` references OC's `search.entities.TenantEntity`**
   directly for tenants (while groups and roles are already plain string IDs).
   Moving the record into CSL means decoupling it from search-domain entities
   at the boundary.

**Membership migration is explicitly out of scope.** `MembershipPort` already
lives in CSL (`core/port/out/`); its OC implementations (`DefaultMembershipService`,
`NoDBMembershipService`) stay in OC. A CSL-side default for `MembershipPort` is
deferred — there is no concrete second adopter today, and `NoDBMembershipService`
already depends on CSL types (`OidcGroupsExtractor`, `OidcConfiguration`), so the
OC host can keep the no-DB variant without it costing reusability.

`IdpClientPort` is still an empty marker in CSL and is left untouched — it is
outbound (library → IdP) and belongs with a concrete IdP-client adapter, not
with the inbound user contract.

## Decision

**CSL owns the user-view contract.** A new inbound port `CamundaUserPort` lives
in `core/src/main/java/io/camunda/security/core/port/in/`. It exposes:

```java
CamundaUserDTO getCurrentUser();
String getUserToken();
```

mirroring the OC interface so consumers (`AuthenticationController`,
`SaaSTokenController`) port straight across.

**`CamundaUserDTO` moves to the public `api` module** at
`io.camunda.security.api.model.user.CamundaUserDTO`. Tenant, role, and group
fields are typed as `List<String>` (just IDs). Groups and roles were already
`List<String>` in OC; tenants drop the `TenantEntity` wrapper so the DTO carries
no host search-domain dependency. The tenant display name is no longer surfaced
through the CSL DTO — adopters that need it look it up host-side (in OC,
`AuthenticationController` resolves `TenantEntity` instances from the IDs and
passes them to the response mapper). `c8Links` is typed as `Map<String, String>`
(lower-cased app identifier → URL) because the OC `ClusterMetadata.AppName`
enum is host-specific; hosts populate the map with the same string keys the
existing endpoint already emits.

**`UserConfiguration` (host-imported via the umbrella) provides a CSL-default
`OidcCamundaUserService`.** It assembles the DTO from the active
`CamundaAuthentication` (username, tenant/group/role IDs) and the OIDC
principal carried in the Spring Security context (full name + email), and
returns the access/id token via `OAuth2AuthorizedClientRepository`. It is
guarded by `@ConditionalOnAuthenticationMethod(OIDC)` and
`@ConditionalOnMissingBean(CamundaUserPort.class)`, so OC's
`@Service`-registered `OidcCamundaUserService` (which still resolves authorized
components via `ResourceAccessProvider`) wins the bean.

**No CSL-side default ships for basic auth.** `BasicCamundaUserService` stays
in OC. It reads secondary-storage user data (`UserServices.getUser`) which CSL
has no contract for, and basic auth without secondary storage is already an
unsupported combination that OC fails fast on (see
`BasicAuthenticationNoDbConfiguration`).

**Membership stays in OC unchanged.** Both `DefaultMembershipService` and
`NoDBMembershipService` continue to provide `MembershipPort` from OC. CSL adds
no membership adapter in this increment.

## Options Considered

### `CamundaUserDTO` shape: all `List<String>` (chosen) vs introduce CSL ref records

The OC DTO carries `List<TenantEntity>` for tenants alongside `List<String>`
for groups and roles, and `Map<ClusterMetadata.AppName, String>` for
`c8Links`. Migrating `TenantEntity` and `AppName` into CSL is out of scope.

- **Chosen:** simplify all three membership fields to `List<String>` of IDs;
  keep `c8Links` as `Map<String, String>` keyed by the existing lowercase
  app-name strings. OC's `OidcCamundaUserService` already populates groups and
  roles from string IDs; only the tenant field needs a small adapter
  (`List<TenantEntity>` → `List<String>` of tenant IDs) and tenant-name
  enrichment moves from the service to `AuthenticationController`.
- **Pro:** CSL stays framework- and host-free with the minimum surface; no
  new model records.
- **Con:** the user service no longer returns tenant names. Adopters that
  need them resolve them host-side, as OC does today.

### Membership migration: defer (chosen) vs migrate `NoDBMembershipService` as a CSL default

`NoDBMembershipService` already depends only on CSL types
(`OidcGroupsExtractor`, `OidcConfiguration`, `MembershipPort`), so it could
move to CSL as a default `MembershipPort` implementation.

- **Chosen:** leave `NoDBMembershipService` in OC. No new CSL adapter, no new
  CSL configuration class for membership.
- **Pro:** minimum CSL surface for this increment; no risk of bean-wiring
  surprises with OC's existing `@Primary DefaultMembershipService` selection;
  no concrete second adopter today.
- **Con:** another adopter that wants a no-DB membership default will need
  the migration done later. Cheap to revisit when the adopter exists.

### Scope of CSL defaults in this increment

The migration could ship the port only and leave every implementation in OC.

- **Chosen for the merged commit:** ship the port + DTO + ADR (commit 1) and
  a host-imported, exploratory `OidcCamundaUserService` default in
  spring-boot-starter (commit 2).
- **Pro:** the second commit demonstrates the contract is implementable
  inside CSL using only CSL-visible types and gives future adopters a working
  starting point.
- **Con:** the default is intentionally minimal — no tenant-name resolution,
  no authorized-components, no SaaS metadata. If OC's override is universal
  in practice (today it is), commit 2 carries little weight and can be dropped
  before merge.

## Consequences

**Positive:**

- The user-view contract becomes reusable behind a clean inbound port; the
  public `api/model/user` package exposes a host-free DTO.
- `core/` remains framework-free (enforced by `DomainArchTest`); the new port
  imports only `api/` types.
- Membership scope is left for a later increment, keeping this PR focused.

**Negative / ongoing obligations:**

- The `/v2/authentication/me` JSON shape is preserved by re-enriching tenant
  names in `AuthenticationController` from `TenantServices` before calling the
  response mapper. The mapper signature changes to take both the DTO and the
  enriched tenant list.
- The umbrella `@Import` list and `CamundaSecurityAutoConfigurationTest` gain
  one entry (`UserConfiguration`) — kept in sync per the convention.

## Risks and follow-ups

**CSL-default `OidcCamundaUserService` weight.** The default in commit 2 only
populates what CSL can see. If every supported deployment registers a richer
OC implementation, the default is dead code; drop commit 2 before merge in
that case.

**`IdpClientPort` design deferred.** When a concrete IdP-client adapter
materialises (token exchange, userinfo fetching, refresh), the empty marker
should be turned into a real contract. Out of scope here.

**Membership-port default deferred.** When a concrete CSL adopter needs a
no-DB membership default, lift `NoDBMembershipService` from OC. Today the OC
host is the only adopter, so the lift adds no value.
