---
status: Accepted
---

# ADR-0021: BasicAuthUserDetailsPort for basic-auth user resolution

**Deciders**: Sebastian Bathke (megglos)

## Status

Accepted

## Context

The CSL basic-auth filter chains (`BasicAuthApiSecurityConfiguration`,
`BasicAuthWebappSecurityConfiguration`) wire `.httpBasic(...)` / `.formLogin(...)`
but ship **no** user resolution. The host (Orchestration Cluster) supplies a
hand-rolled `CamundaUserDetailsService` (in `camunda/camunda`
`dist/.../identity/`) that Spring Boot picks up globally to back the chains.
That service hard-codes the tenant (`userServices("default")`) with a
`// TODO use the contextual physicalTenantId`, and it duplicates Spring Security
plumbing every basic-auth adopter would otherwise have to reproduce.

ADR-0018 deliberately left basic-auth user resolution in OC: `BasicCamundaUserService`
reads secondary-storage user data that CSL had no contract for. This ADR closes
that gap for the credential-verification path by introducing a narrow outbound
contract, so CSL can own the Spring Security plumbing once and the host only
provides a scope-agnostic lookup.

This unblocks per-physical-tenant API chains (parent camunda/camunda#54728,
companion CSL #369): a single host adapter resolves the tenant/scope internally
from request context, so the port carries **no scope parameter**.

The question this ADR answers: what contract lets a host supply basic-auth user
resolution so CSL owns the Spring Security plumbing once, without the port
knowing about tenant or scope?

## Decision

**A new outbound port `BasicAuthUserDetailsPort` lives in `core/port/out/`.** It is
framework-free (no Spring/Jakarta/Jackson — enforced by `DomainArchTest`) and
host-must-provide (no CSL default), like `SecurityPathPort` and `MembershipPort`.
It is a `@FunctionalInterface` with a single method:

```java
CamundaUserDetails loadUser(String username);
```

The host resolves any tenant/scope internally (e.g. from request context); CSL
passes no scope. The method returns `null` when no such user exists.

A nested framework-free record carries the result:

```java
record CamundaUserDetails(String username, String password) {}
```

**CSL owns the Spring Security plumbing.** `spring-boot-starter` adds
`CamundaUserDetailsService` (`final`, implements Spring's `UserDetailsService`),
which delegates to `BasicAuthUserDetailsPort`, throws `UsernameNotFoundException` on a
blank username or a `null` port result, and otherwise maps the record onto Spring
`User.withUsername(...).password(...)` (whose status flags default to active).
Authorities are empty — CSL performs authorization separately.

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

The `UserDetailsService` only activates when the host provides a `BasicAuthUserDetailsPort`
bean (`@ConditionalOnBean`); `@ConditionalOnMissingBean(UserDetailsService.class)`
means hosts that already register their own single `UserDetailsService` are
unchanged. CSL also ships a default delegating `PasswordEncoder` for basic-auth;
a host that already registers one (OC's cluster-wide encoder) wins via
`@ConditionalOnMissingBean`.

**The basic-auth chain config classes need no change.** Spring Boot's
`InitializeUserDetailsBeanManagerConfigurer` assembles the global
`AuthenticationManager` from the single `UserDetailsService` + `PasswordEncoder`
beans, which the existing `.httpBasic(...)` chains consume. An
`AuthenticationManager`/`DaoAuthenticationProvider`-level integration test
confirms valid credentials authenticate and a wrong password / unknown user are
rejected.

This **replaces OC's hand-rolled `CamundaUserDetailsService`**: OC contributes a
thin `UserDetailsAdapter` implementing the port (companion camunda/camunda PR)
and deletes the duplicated service and its bean.

## Consequences

**Positive**

- Basic-auth user resolution becomes a shared, reviewable CSL implementation;
  every basic-auth adopter inherits the Spring Security plumbing and a default
  `PasswordEncoder`.
- `core/` stays framework-free; the new port imports only JDK types.
- OC drops its hand-rolled `CamundaUserDetailsService` and the
  `// TODO use the contextual physicalTenantId`, retaining only a thin adapter —
  the structural home for future per-physical-tenant scope resolution.

**Negative / accepted trade-offs**

- Basic-auth deployments must register a `BasicAuthUserDetailsPort` bean, or the
  basic-auth chains have no user resolution (the service bean does not activate
  without the port).
- The umbrella `@Import` list already carries `UserConfiguration`; no umbrella
  change was needed. The two new beans must stay gated (`@ConditionalOnMissingBean`)
  so hosts can override them.

## Alternatives Considered

### Outbound port with no scope parameter (chosen) vs scope-carrying port

The current OC service hard-codes a `"default"` tenant. We could surface scope
(physical-tenant) as a parameter on the port.

- **Chosen:** no scope parameter; the host resolves scope internally from
  request context.
- **Pro:** keeps the contract dead-simple and stable; lets hosts evolve scope
  resolution (per-physical-tenant, #54729/#54730) without changing the CSL
  signature or every adapter. Mirrors how other host-specific concerns
  (`SecurityPathPort`, `MembershipPort`) are resolved entirely host-side.
- **Con:** the contract does not document scope at the type level; correct scope
  resolution is the host adapter's responsibility.

### Framework-free record (chosen) vs returning Spring `UserDetails` from the port

The port could return Spring Security's `UserDetails` directly.

- **Chosen:** a framework-free `CamundaUserDetails` record in `core/`; CSL maps
  it to Spring `User` in the starter.
- **Pro:** `core/` stays free of Spring (enforced by `DomainArchTest`); the port
  is reusable by any adopter regardless of its security stack.
- **Con:** one mapping step in the starter. Trivial and well-tested.

### CSL ships a default `PasswordEncoder` (chosen) vs host always provides one

- **Chosen:** CSL ships a default `DelegatingPasswordEncoder`
  (`@ConditionalOnMissingBean`, basic-auth only); a host encoder still wins.
- **Pro:** a basic-auth adopter gets a sensible, standard encoder out of the box;
  OC's cluster-wide encoder continues to win.
- **Con:** one more default bean to keep gated and overridable.

### `null`-means-not-found (chosen) vs `Optional`

- **Chosen:** the port returns `null` for "no such user"; CSL maps it to
  `UsernameNotFoundException`.
- **Pro:** keeps the functional contract minimal and matches the current OC
  behaviour the adapter is lifted from.
- **Con:** `null` returns; the contract is documented and the only caller (CSL)
  handles it in one place.
