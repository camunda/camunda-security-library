---
status: Accepted
---

# ADR-0021: User-resolution ports — `CamundaUserPort` (user view) and `BasicAuthUserDetailsPort` (basic-auth credentials)

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

OC owns two related, but distinct, user-resolution concerns that CSL needs to take over so other adopters (Hub, future OCs) can reuse them without dragging in OC's secondary-storage stack:

1. **The user-view contract.** OC's `CamundaUserService` interface (with `OidcCamundaUserService` / `BasicCamundaUserService` implementations) and its `CamundaUserDTO` record power the `CamundaAuthentication` view returned by `GET /v2/authentication/me` and `/v2/authentication/me/token`. `OidcCamundaUserService` and `BasicCamundaUserService` depend on `UserServices`, `TenantServices`, `ResourceAccessProvider`, and OAuth2 host wiring — all OC-only — so lifting either wholesale would either pull those services into CSL or require narrowly-scoped outbound ports so a CSL default can ask the host for the parts it cannot see itself. `CamundaUserDTO` also references OC's `search.entities.TenantEntity` directly for tenants (while groups and roles are already plain string IDs), which couples the record to a host search-domain entity at the CSL/OC boundary.
2. **Basic-auth credential resolution.** The CSL basic-auth filter chains (`BasicAuthApiSecurityConfiguration`, `BasicAuthWebappSecurityConfiguration`) wire `.httpBasic(...)` / `.formLogin(...)` but ship no user resolution. The host supplies a hand-rolled `CamundaUserDetailsService` (in `camunda/camunda` `dist/.../identity/`) that Spring Boot picks up globally to back the chains. That service hard-codes the tenant (`userServices("default")`) with a `// TODO use the contextual physicalTenantId`, and it duplicates Spring Security plumbing every basic-auth adopter would otherwise have to reproduce.

These two concerns are resolved by the same record because the second is a gap the first's original migration explicitly left open: `BasicCamundaUserService` reads secondary-storage user data CSL had no contract for, so basic-auth user resolution stayed in OC when the user-view contract moved. Closing that gap needs its own narrow outbound contract for the credential-verification path — "is this username/password valid" — which is a different question from "what does the authenticated user's `/me` view look like".

The gap closes in a shape that also unblocks per-physical-tenant API chains (parent camunda/camunda#54728, companion CSL #369): a single host adapter resolves the tenant/scope internally from request context, so the credential-resolution port carries no scope parameter.

Two concerns stay explicitly out of scope for both contracts and remain so today. Membership resolution already lives behind CSL's `MembershipPort` (`core/port/out/`); its implementations (`DefaultMembershipService`, `NoDBMembershipService`) stay in OC — there is no CSL-side default, and none is added here. `IdpClientPort` is still an untouched empty marker in CSL; it is outbound (library → IdP) and belongs with a concrete IdP-client adapter, not with either user-resolution contract.

The core question this ADR answers: what contract shape lets CSL own the user-view read path (`CamundaUserPort`) and the basic-auth credential-verification path (`BasicAuthUserDetailsPort`) as two separate, host-pluggable outbound seams, each free of OC's secondary-storage and tenant-model specifics?

## Decision

### `CamundaUserPort` — the user-view contract

**CSL owns the user-view contract.** A new inbound port `CamundaUserPort` lives in `core/port/in/`. It exposes:

```java
CamundaUserDTO getCurrentUser();
String getUserToken();
```

mirroring the OC interface so consumers (`AuthenticationController`, `SaaSTokenController`) port straight across.

**`CamundaUserDTO` moves to the public `api` module** at `io.camunda.security.api.model.user.CamundaUserDTO`. Tenant, role, and group fields are typed as `List<String>` (just IDs) — groups and roles were already `List<String>` in OC; tenants drop the `TenantEntity` wrapper so the DTO carries no host search-domain dependency. The tenant display name is no longer surfaced through the CSL DTO — adopters that need it look it up host-side. `c8Links` is typed as `Map<String, String>` (lower-cased app identifier → URL) because OC's `ClusterMetadata.AppName` enum is host-specific; hosts populate the map with the same string keys the existing endpoint already emits.

**`UserConfiguration` (host-imported via the umbrella) provides the OIDC default `CamundaUserPort` implementation, `OidcCamundaUserService`.** This is the production implementation for OIDC deployments, not a placeholder: it assembles the DTO from the active `CamundaAuthentication` (username, tenant/group/role IDs) and the OIDC principal carried in the Spring Security context (full name + email), and returns the access/id token via `OAuth2AuthorizedClientRepository`. It is guarded by `@ConditionalOnAuthenticationMethod(OIDC)`, `@ConditionalOnMissingBean(CamundaUserPort.class)`, and `@ConditionalOnBean(OAuth2AuthorizedClientRepository.class)` — the last because resolving the current user's authorized client needs the session-scoped OAuth2 client infrastructure that only exists when the webapp chain is enabled; a bearer-only OIDC host that disables the webapp chain gets no default `CamundaUserPort` from CSL and must supply its own.

Authorized components — the one piece of data the CSL-side default cannot resolve on its own — flow in via a new outbound `AuthorizedComponentsPort` (`resolve(CamundaAuthentication)`). OC contributes the adapter that delegates to its `ResourceAccessProvider`; when no adapter is registered, `UserConfiguration` falls back to a default bean that returns an empty list.

**No CSL-side default ships for basic auth.** `BasicCamundaUserService` — the user-view implementation for `/v2/authentication/me` under basic auth — stays host-side. It reads secondary-storage user data (`UserServices.getUser`) which CSL has no contract for, and basic auth without secondary storage is already an unsupported combination that OC fails fast on. This is a separate concern from `BasicAuthUserDetailsPort` below: that port covers *credential verification* ("is this username/password valid"), not the user-view DTO. A basic-auth deployment that wants a `GET /v2/authentication/me` response must still register its own `CamundaUserPort`, exactly as OC does today.

**`/v2/authentication/me/token` is preserved byte-identically.** `getUserToken()` returns the access (or id) token as a JSON string literal (escaped + surrounded by quotes), matching OC's pre-migration `Json.createValue(token).toString()` output. The endpoint declares `application/json`, so the body remains a valid JSON value rather than raw text; this double-encoding is a known, deliberately out-of-scope oddity carried forward unchanged, not a bug being fixed here.

### `BasicAuthUserDetailsPort` — basic-auth credential resolution

**A new outbound port `BasicAuthUserDetailsPort` lives in `core/port/out/`.** It is framework-free (no Spring/Jakarta/Jackson — enforced by `DomainArchTest`) and host-must-provide (no CSL default), like `SecurityPathPort` and `MembershipPort`. It is a `@FunctionalInterface` with a single method:

```java
CamundaUserDetails loadUser(String username);
```

The host resolves any tenant/scope internally (e.g. from request context); CSL passes no scope. The method returns `null` when no such user exists. A nested framework-free record, `BasicAuthUserDetailsPort.CamundaUserDetails(String username, String password)`, carries the result.

**CSL owns the Spring Security plumbing.** `spring-boot-starter` adds `CamundaUserDetailsService` (`final`, implements Spring's `UserDetailsService`), which delegates to `BasicAuthUserDetailsPort`, throws `UsernameNotFoundException` when the username is blank or the port returns `null` or an incomplete record (blank username/password), and otherwise maps the record onto Spring `User.withUsername(...).password(...)` (whose status flags default to active). Authorities are empty — CSL performs authorization separately.

`UserConfiguration` registers two beans, both basic-auth only:

```java
@Bean @ConditionalOnMissingBean(UserDetailsService.class)
      @ConditionalOnBean(BasicAuthUserDetailsPort.class)
      @ConditionalOnAuthenticationMethod(BASIC)
UserDetailsService camundaUserDetailsService(BasicAuthUserDetailsPort port) { ... }

@Bean @ConditionalOnMissingBean(PasswordEncoder.class)
      @ConditionalOnAuthenticationMethod(BASIC)
PasswordEncoder passwordEncoder() {
  return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```

The `UserDetailsService` only activates when the host provides a `BasicAuthUserDetailsPort` bean (`@ConditionalOnBean`); `@ConditionalOnMissingBean(UserDetailsService.class)` means hosts that already register their own single `UserDetailsService` are unchanged. CSL also ships a default delegating `PasswordEncoder` for basic-auth; a host that already registers one (OC's cluster-wide encoder) wins via `@ConditionalOnMissingBean`.

**The basic-auth chain config classes need no change.** Spring Boot's `InitializeUserDetailsBeanManagerConfigurer` assembles the global `AuthenticationManager` from the single `UserDetailsService` + `PasswordEncoder` beans, which the existing `.httpBasic(...)` chains consume as-is — including the per-scope chains `ScopedWebappSecurityChainBuilder` assembles, which do not resolve or override `UserDetailsService` themselves. An `AuthenticationManager`/`DaoAuthenticationProvider`-level integration test confirms valid credentials authenticate and a wrong password / unknown user are rejected.

This **replaces OC's hand-rolled `CamundaUserDetailsService`**: OC contributes a thin `UserDetailsAdapter` implementing the port and deletes the duplicated service, its bean, and the `// TODO use the contextual physicalTenantId`, retaining only the thin adapter as the structural home for future per-physical-tenant scope resolution.

### Why these particular boundaries

- **`CamundaUserDTO` fields simplified to `List<String>` of IDs, not ported OC reference types.** The alternative — migrating `TenantEntity`/`ClusterMetadata.AppName` into CSL alongside the DTO — was rejected: it would keep CSL coupled to OC's search-domain and cluster-metadata types for no behavioural gain. Only the tenant field needed a small adapter (`List<TenantEntity>` → `List<String>` of tenant IDs); tenant-name enrichment moved to the host's response-mapping layer instead.
- **`BasicAuthUserDetailsPort` carries no scope/tenant parameter.** The current OC service hard-codes a `"default"` tenant; surfacing scope as a port parameter was considered and rejected in favour of letting the host resolve scope internally from request context. This keeps the contract dead-simple and stable, lets hosts evolve per-physical-tenant scope resolution (#54729/#54730) without a CSL signature change ever touching every adapter, and mirrors how `SecurityPathPort` and `MembershipPort` already resolve host-specific concerns entirely host-side. The cost is that the contract does not document scope at the type level — correct scope resolution is the host adapter's responsibility.
- **A framework-free `CamundaUserDetails` record, not Spring's `UserDetails` returned directly from the port.** Returning `UserDetails` would work, but it would put a Spring Security type on a `core/port/out/` signature, which `DomainArchTest` forbids. The one mapping step CSL performs in the starter (record → Spring `User`) is trivial and well-tested; the port itself stays reusable by any adopter regardless of its security stack.
- **`null` means "no such user", not `Optional`.** Keeps the functional contract minimal and matches the OC behaviour the port's default consumer is lifted from; the only caller (CSL's `CamundaUserDetailsService`) documents and handles the `null` case in one place.
- **CSL ships a default delegating `PasswordEncoder`, gated `@ConditionalOnMissingBean` and basic-auth only,** so a basic-auth adopter gets a sensible, standard encoder out of the box while a host encoder (OC's cluster-wide one) still wins when present.
- **No CSL default for basic-auth `CamundaUserPort`, mirroring the OIDC/basic-auth split already established for `BasicAuthUserDetailsPort`.** Both gaps trace back to the same root cause — OC's secondary-storage user data has no CSL contract — and basic auth without secondary storage is already an unsupported OC deployment shape, so this is not a new constraint the migration introduces.

### Default implementations and override boundaries

| Contract | Default | Override use case |
|---|---|---|
| `CamundaUserPort` (OIDC) | `OidcCamundaUserService` | Host needs tenant display names, SaaS metadata, `c8Links`, or a different membership resolution strategy |
| `CamundaUserPort` (basic auth) | None — host must register | Always (matches the existing unsupported "basic auth without secondary storage" constraint) |
| `AuthorizedComponentsPort` | Empty-list fallback | Host adapter delegating to its own resource-access model (in OC, `ResourceAccessProvider`) |
| `BasicAuthUserDetailsPort` | None — host must register | Always; the `UserDetailsService` bean does not activate without it |
| `UserDetailsService` (basic auth) | `CamundaUserDetailsService`, delegating to `BasicAuthUserDetailsPort` | Host registers its own single `UserDetailsService` |
| `PasswordEncoder` (basic auth) | `DelegatingPasswordEncoder` | Host registers its own (e.g. OC's cluster-wide encoder) |
| `MembershipPort` | None — host must register | Always; unchanged and out of scope for this ADR |
| `IdpClientPort` | Untouched empty marker | Out of scope for this ADR; awaits a concrete IdP-client adapter |

## Consequences

**Positive**

- The user-view contract becomes reusable behind a clean inbound port; the public `api/model/user` package exposes a host-free DTO, and `core/` stays framework-free (enforced by `DomainArchTest`) since the new ports import only `api/`/JDK types.
- Basic-auth user resolution becomes a shared, reviewable CSL implementation; every basic-auth adopter inherits the Spring Security plumbing and a default `PasswordEncoder` instead of reproducing it.
- OC drops both its hand-rolled `CamundaUserDetailsService` (and the `// TODO use the contextual physicalTenantId` it carried) and its own `OidcCamundaUserService`, retaining only thin adapters (`UserDetailsAdapter`, `AuthorizedComponentsAdapter`) — the structural home for future per-physical-tenant scope resolution.
- OIDC user resolution becomes a shared, reviewable implementation every OIDC host inherits, with the one remaining host-specific piece (authorized components) isolated behind a named outbound port.

**Negative / accepted trade-offs**

- Basic-auth deployments must register their own `BasicAuthUserDetailsPort`, or the basic-auth chains have no user resolution — the `UserDetailsService` bean does not activate without it.
- Basic-auth deployments that want a `GET /v2/authentication/me` response must separately register their own `CamundaUserPort`; the CSL default is OIDC-only. This matches the existing "basic auth without secondary storage is unsupported" constraint surface, so it is not a new gap.
- `/v2/authentication/me/token`'s JSON-string-literal body format is carried forward unchanged. Whether the double-encoding is itself worth fixing on the API contract is intentionally out of scope here; it would need a separate change with API-consumer sign-off.
- `IdpClientPort` design remains deferred: when a concrete IdP-client adapter materialises (token exchange, userinfo fetching, refresh), the empty marker should be turned into a real contract. Out of scope here.
- `MembershipPort` gets no CSL-side default in this ADR: both `DefaultMembershipService` and `NoDBMembershipService` continue to provide it from OC. There is no concrete second adopter today, so the cost of leaving this deferred is low and cheap to revisit once one exists.
- The umbrella `@Import` list already carries `UserConfiguration`; the four new beans it now hosts must stay gated (`@ConditionalOnMissingBean`) so hosts can override any of them individually.

## Alternatives Considered

- **Surface a scope/tenant parameter on `BasicAuthUserDetailsPort`, instead of letting the host resolve it internally.** Rejected — would document scope at the type level today at the cost of forcing every future scope-resolution strategy (notably per-physical-tenant, #54729/#54730) through a CSL signature change and every existing adapter. Mirrors why `SecurityPathPort` and `MembershipPort` resolve host-specific concerns entirely host-side.
- **Keep `CamundaUserDTO`'s tenant field as OC's `List<TenantEntity>` (or introduce an equivalent CSL reference record), instead of collapsing all membership fields to `List<String>` IDs.** Rejected — migrating `TenantEntity` into CSL just to carry a display name would reintroduce the exact host search-domain coupling the migration exists to remove, for a field adopters can already resolve host-side the way OC does today.

Consolidates records previously numbered 0018 (see git history).
