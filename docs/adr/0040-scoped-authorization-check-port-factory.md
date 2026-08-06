---
status: Accepted
---

# ADR-0040: A scoped `AuthorizationCheckPort` factory for hosts with several scope repositories

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

[camunda-security-library#596](https://github.com/camunda/camunda-security-library/issues/596)
tracks a monorepo (OC) request: OC hand-rolls per-physical-tenant fan-out around CSL's
authorization graph in two `dist/` call sites, naming `AuthorizationChecker`/`AuthorizationService`
— `core`-internal implementation classes — directly instead of depending only on
`AuthorizationCheckPort`:

1. `TenantAwareAuthorizationCheckPort` resolves the current physical tenant's
   `AuthorizationChecker` via an OC-owned `AuthorizationCheckerProvider`, then builds a **new
   `AuthorizationService` on every single check call**.
2. `ResourceAccessControllerConfiguration` loops over physical tenants calling an in-repo
   `AuthorizationCheckerFactory.forPhysicalTenant(...)` to get an `AuthorizationChecker` directly.

Investigation during implementation found that only consumer 1 is actually reachable from `core`:
consumer 2 constructs `io.camunda.search.clients.auth.DefaultResourceAccessProvider`, a
**monorepo-owned** class (`search/search-client-query-transformer`), which CSL cannot build. That
consumer's fix is a static factory added to `DefaultResourceAccessProvider` itself, entirely on the
monorepo side, out of `core`'s reach. This ADR therefore covers only consumer 1: a per-scope
`AuthorizationCheckPort` assembly for hosts (typically Spring) that already own several
`AuthorizationScopeRepositoryPort` instances — one per scope, an opaque key `core` attaches no
meaning to (a host may map it to, for example, a physical tenant; `core` types for this kind of
per-scope host surface are conventionally named `Scoped*`, e.g.
`ScopedSessionStorePortProvider`/`ScopedWebSessionRepositoryFactory`, ADR-0029).

`AuthorizationPortsFactory` (ADR-0028) already assembles this graph for a single scope, but only
for non-Spring consumers, and it builds its own `LazyTokenClaimsConverter` from a `MembershipPort`.
Neither fits consumer 1 directly: OC needs one `AuthorizationCheckPort` per scope with a fail-hard
lookup (mirroring the OC-owned `AuthorizationCheckerProvider.withPhysicalTenant` it replaces), and
it must reuse its *existing* `LazyTokenClaimsConverter`/`TokenClaimsAuthenticationResolver` bean —
not have a factory build a second one — because that bean is shared with the rest of the host's
authentication pipeline (claims-to-authentication conversion for OIDC token processing).

## Decision

### 1. Widen `AuthorizationService`'s claims-resolver dependency to the `TokenClaimsAuthenticationResolver` port

`AuthorizationService`'s constructor and field held the concrete `LazyTokenClaimsConverter`
(`core`-internal) purely so its one internal call site could invoke `convert(Map)`. That method's
behaviour is already exposed on the `api`-level `TokenClaimsAuthenticationResolver` port as
`resolve(Map)` (ADR-0028 §5). Widening the parameter/field type to
`TokenClaimsAuthenticationResolver` and switching the call site to `resolve(...)` is behaviourally
a no-op — `LazyTokenClaimsConverter.resolve` delegates to `convert` — but it is what makes "bring
your own resolver" expressible in decision 2 without adding a new public parameter of a
`core`-internal type. No other call site needs to change: both `AuthorizationPortsFactory.create`
and the `spring-boot-starter`'s `AuthorizationConfiguration` bean already pass a concrete
`LazyTokenClaimsConverter`, which satisfies the widened interface parameter.

### 2. `ScopedAuthorizationCheckPortFactory` — a new, separate entry point

A new class, `core/authz/ScopedAuthorizationCheckPortFactory`, with one static method:

```java
public static ScopedAuthorizationCheckPorts create(
    Map<String, AuthorizationScopeRepositoryPort> scopeRepositoriesByScope,
    TokenClaimsAuthenticationResolver claimsResolver,
    List<PropertyAuthorizationEvaluator<?>> propertyEvaluators,
    boolean authorizationEnabled,
    boolean multiTenancyChecksEnabled)
```

It builds one `AuthorizationChecker` + one `AuthorizationService` per map entry, all sharing the
*given* `claimsResolver`, and returns a `ScopedAuthorizationCheckPorts` holder whose only public
method, `forScope(String)`, throws `IllegalStateException` on an unknown scope — no fallback to
another scope's port, mirroring the isolation guarantee `AuthorizationCheckerProvider
.withPhysicalTenant` already provides in OC. The holder is a plain final class wrapping a private
map, not a `record` exposing it: a caller reading the map directly would get a silent `null` on a
missing key instead of the fail-hard behaviour `forScope` guarantees.

`authorizationEnabled`/`multiTenancyChecksEnabled` are **global scalars, not per-scope**. This
matches consumer 1's existing behaviour — it has always read both flags from one global
configuration object and applied them to every tenant — and is a deliberate scope boundary: a
per-scope flag would be a behaviour change, not part of this issue.

This is a **separate class from `AuthorizationPortsFactory`**, not an overload on it:
`AuthorizationPortsFactory`'s own Javadoc states it is "the entry point for non-Spring consumers
only" with a deliberately sole public method; consumer 1 is a Spring host. Keeping them separate
also keeps `AuthorizationPortsFactory`'s single-scope, no-Spring contract legible.

Takes an eager `Map`, not a new `Scoped*Provider` SPI (the shape ADR-0029 used for
`ScopedSessionStorePortProvider`): that SPI exists because a scope's session store must be resolved
lazily, discovered per Spring Session commit. Here, the host (OC) knows every scope's
`AuthorizationScopeRepositoryPort` at application-context wiring time — there is no laziness or
decoupling need an SPI would serve, only a straightforward map-in, map-out assembly.

### 3. Why this is not ADR-0028 §6's rejected alternative

ADR-0028 §6 rejected "route the Spring `authorizationService` bean through `create(...)`" because
the factory would build its own checker/converter and silently discard host bean overrides. Decision
2 above is not that: it takes the host's *existing* `TokenClaimsAuthenticationResolver`, it does not
build one, so there is no divergent second converter instance. It also does not compete with a
single overridable `@ConditionalOnMissingBean` bean the way the starter's `authorizationService`
bean does — OC's multi-tenant fan-out was never expressible as a single bean to begin with; its
`TenantAwareAuthorizationCheckPort` already wins the bean-definition race against CSL's
single-tenant default for exactly that reason. ADR-0028 §6 also rejected "granular `new*` methods"
because they would put `AuthorizationChecker`/`AuthorizationService`/`LazyTokenClaimsConverter` back
on the public surface. `ScopedAuthorizationCheckPortFactory.create`'s parameters
(`AuthorizationScopeRepositoryPort`, `TokenClaimsAuthenticationResolver`) and return
(`AuthorizationCheckPort`, via the holder) are already host-facing port types — nothing
`core`-internal is exposed.

### 4. `AGENTS.md`: document the `Scoped*` / no-physical-tenant convention

`core` has no notion of a physical tenant, only an opaque scope key. Per-scope host-facing types
are conventionally named `Scoped*` (`ScopedSessionStorePortProvider`,
`ScopedWebSessionRepositoryFactory`, and now `ScopedAuthorizationCheckPortFactory`). This was
implicit in the existing code; `AGENTS.md` now states it explicitly so it isn't reinvented or
contradicted (e.g. by tenant-flavored naming in `core`) in future work.

## Consequences

**Positive**

- OC's consumer 1 (`TenantAwareAuthorizationCheckPort`) can depend only on
  `AuthorizationCheckPort` and drop its own `AuthorizationChecker`/`AuthorizationService`/per-call
  construction plumbing.
- The claims-resolver widening (decision 1) is a pure interface-narrowing with no behaviour change,
  verified by the existing `AuthorizationServiceTest`/`AuthorizationPortsFactoryTest` suites passing
  unmodified.
- The `Scoped*` naming convention is now written down, not just implicit in existing code.

**Negative / accepted trade-offs**

- A second per-scope assembly entry point exists alongside `AuthorizationPortsFactory`'s
  single-scope one; the two overlap in what they build internally (an `AuthorizationChecker` +
  `AuthorizationService` per scope) but intentionally differ in Spring-vs-non-Spring shape and in
  claims-resolver ownership (build-your-own vs. bring-your-own). Not merged into one class for the
  reasons in decision 2.
- This issue's second named consumer (`ResourceAccessControllerConfiguration`) turned out to be
  outside `core`'s reach entirely (it builds a monorepo-owned class) and is not addressed here;
  the equivalent fix lives in the monorepo's `search` module.

## Alternatives Considered

- **Add a multi-tenant overload directly on `AuthorizationPortsFactory`.** Rejected — that class's
  Javadoc states a deliberately sole, non-Spring entry point; a Spring-host overload there would
  contradict its own contract.
- **Have the factory build its own `LazyTokenClaimsConverter` from a shared `MembershipPort`,
  mirroring `AuthorizationPortsFactory.create`.** Rejected — would build a second converter
  instance diverging from the host's existing one, reintroducing exactly the concern ADR-0028 §6
  raised about routing Spring wiring through a factory.
- **A `Scoped*Provider` SPI, mirroring `ScopedSessionStorePortProvider` (ADR-0029).** Rejected —
  that SPI's laziness serves a specific Spring-Session-commit-timing constraint that does not exist
  here; an eager `Map` is simpler and sufficient since the host knows every scope upfront.
- **Widen `DefaultResourceAccessProvider` (the monorepo's search-plane consumer) via a CSL change.**
  Rejected outright — that class is monorepo-owned; CSL cannot construct it.
