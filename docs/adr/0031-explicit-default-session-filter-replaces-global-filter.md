---
status: Accepted
---

# ADR-0031: Replace the global Spring Session filter with an explicit default-scope session filter

**Deciders**: Patrick Wunderlich (p-wunderlich), Sebastian Bathke (megglos), Joaquin Felici (joaquinfelici)

## Status

Accepted

Revises [ADR-0017](0017-session-store-port-and-web-session-ownership.md)'s `@EnableSpringHttpSession`
mechanism and the filter-installation aspect of [ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md)
§3 (which installed an explicit `SessionRepositoryFilter` per scope but left the default/unprefixed
surface on the global filter). Both ADRs' other decisions — `SessionStorePort`, `PersistentSession`,
per-scope chain assembly, cookie isolation — stand unchanged. Supersedes [camunda-security-library#477](https://github.com/camunda/camunda-security-library/pull/477)'s
`ScopeAwareSessionCookieSerializer` mechanism, which this ADR removes.

## Context

[ADR-0017](0017-session-store-port-and-web-session-ownership.md) wired CSL's persistent web-session
lifecycle onto Spring Session via `@EnableSpringHttpSession` on `WebSessionConfiguration`. That
annotation auto-registers a single, global `SessionRepositoryFilter` — a plain servlet filter,
outside Spring Security's `FilterChainProxy` — that transparently replaces the servlet container's
native `HttpSession` for **every** request. This was the correct, idiomatic choice at the time: CSL
had exactly one webapp surface, so "swap the whole app's session backing" was the simplest possible
mechanism, with zero manual filter wiring.

[ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md) later added
physical-tenant-scoped webapp/API chains. Scopes could not reuse the global mechanism — a single
global filter can only be bound to one `SessionRepository` — so ADR-0027 introduced a **second,
independent** mechanism: an explicitly-constructed `SessionRepositoryFilter` per scope, hand-inserted
into that scope's `SecurityFilterChain` via `http.addFilterBefore(sessionRepositoryFilter,
SecurityContextHolderFilter.class)`. The default/unprefixed surface was left on the original global
filter, since nothing forced it to change.

[camunda-security-library#477](https://github.com/camunda/camunda-security-library/pull/477) later
found that the global filter's default (unscoped) cookie broke per-scope isolation: a PT-scoped
request still carried the global filter's unscoped `camunda-session` cookie at `Path=/`, leaking
across scopes. Its fix made the global filter's cookie resolver **scope-aware**
(`ScopeAwareSessionCookieSerializer`), so it recognises and reads/writes the same scoped cookie name
the in-chain filter uses for a given basePath.

That fix introduced a new, more serious defect (found by the end-to-end tests for
[camunda#55852](https://github.com/camunda/camunda/issues/55852)): a PT-scoped request now has
**two** `SessionRepositoryFilter` instances resolving the *same* cookie against **different**
`SessionRepository`s (the global filter against the default store, the in-chain filter against the
tenant's own store, per [ADR-0029](0029-per-scope-session-store-ownership.md)). Spring Session caches
a negative lookup via a request attribute, `SessionRepositoryFilter.INVALID_SESSION_ID_ATTR`, that is
shared between filters (`HttpServletRequestWrapper.setAttribute`/`getAttribute` delegate to the same
underlying raw request). Confirmed by decompiling `spring-session-core`:

```java
S requestedSession = getRequestedSession();
if (requestedSession != null) {
  if (getAttribute(INVALID_SESSION_ID_ATTR) == null) {   // shared request attribute
    ... return the valid, wrapped session ...
  }
  // falls through to "treat as absent" if the flag is already set
} else {
  setAttribute(INVALID_SESSION_ID_ATTR, "true");          // poisons the raw request
}
```

Sequence on a PT-scoped request: the global filter (outermost, runs first) resolves the scoped cookie
(thanks to #477), looks it up in the **default** store, misses, and sets `INVALID_SESSION_ID_ATTR`.
The in-chain filter then runs, looks up the *same* id in the tenant's **own** store — where it
genuinely exists — but sees the flag already set and discards its own correct result. The session
that was correctly written at commit is then invisible on the very next request; a PT-scoped user is
effectively logged out after one click. Confirmed end-to-end: writing a session under a tenant lands
in that tenant's table; the immediately following read hits the default tenant's table instead.

This could not happen before ADR-0029, because the global and in-chain filters shared one store — any
lookup by either always produced the same answer, so there was nothing for the shared flag to poison.
It is the *combination* of #477 (global filter becomes cookie-aware for scoped paths) and ADR-0029
(scoped filter gets its own, different store) that exposes an assumption Spring Session's own caching
makes: exactly one `SessionRepositoryFilter` is authoritative per request. Nesting two that disagree
breaks that assumption, regardless of how carefully their cookie names are kept in sync.

The question this ADR answers: how does the default surface get correct, isolated session handling
without relying on a global filter that Spring Session's internals were never designed to nest with
per-scope filters?

## Decision

**Remove the global filter. Give the default surface its own explicit `SessionRepositoryFilter`,
built and installed exactly the way a physical-tenant scope's is.** There is no longer a distinction
in kind between "the default surface" and "a scope" from the session filter's point of view — both
are one dedicated `SessionRepositoryFilter` instance, installed into the specific chain(s) that serve
that surface, resolving its own `SessionRepository`. No two filters ever see the same request, so
there is no shared-attribute interaction left to have. This symmetry is about filter *behavior*, not
about Spring wiring: the default surface still gets its own `DefaultWebSessionFilterConfiguration`
rather than going through `ScopedSecurityChainRegistrar`, because it is a single, fixed instance
wired at compile-time through the primary `@Configuration` classes, whereas scopes are an
open-ended, host-defined list discovered at runtime from `CamundaSecurityScopeProvider`.

### 1. `@EnableSpringHttpSession` is removed from `WebSessionConfiguration`

The global, auto-registered filter and its dependency on Spring Boot's generic filter-bean
registration go away entirely. `WebSessionConfiguration` keeps everything else it already owned
(`WebSessionRepository`, `WebSessionMapper`, `WebSessionAttributeConverter`, the expiry-sweep
scheduler) — those beans are session-store plumbing, not filter registration, and CSL still needs the
durable `WebSessionRepository` bean to hand to the new default filter builder.

### 2. A default `SessionRepositoryFilter`, built like a scope's

A new component (mirroring `ScopedWebSessionComponentsFactory`) builds one `SessionRepositoryFilter`
for the default surface: a `DefaultCookieSerializer` with the cookie name resolved from
`server.servlet.session.cookie.name` (falling back to `CamundaSecurityFilterChainConstants.SESSION_COOKIE`,
`"camunda-session"` — the exact property `#477`'s `defaultClusterCookieSerializer` already read, and
the exact fallback the previous global filter's Spring Boot auto-configuration used), and **no**
`ContextPathScopedCookieSerializer` wrapper — the default surface has no basePath, so
`DefaultCookieSerializer`'s own context-path-aware `Path` computation is exactly what the global
filter's auto-configuration already did.

The backing `SessionRepository` is resolved with the **same preference order** `ScopedSecurityChainRegistrar.resolveSessionRepository`
already uses for scopes: (1) the durable `WebSessionRepository` bean when persistent sessions are
enabled, (2) a `MapSessionRepository` fallback otherwise. This is a new, deliberate behaviour change
in dev/test mode (`camunda.security.session.persistent.enabled=false`): the default surface now goes
through a Spring-Session-backed in-memory repository instead of the servlet container's native
`HttpSession`, exactly matching how a physical-tenant scope already behaves with persistence off.
Built once and cached (a `SecurityFilterChain`-scoped singleton), the same way a scope's filter is
shared across its webapp and API chains.

### 3. Installed into the primary chains, not registered globally

`ScopedWebappSecurityChainBuilder.buildOidcWebappChain`/`buildBasicWebappChain` and
`ScopedApiSecurityChainBuilder`'s primary-chain overloads of `buildBasicApiChain`/`buildOidcApiChain`
— today the only call paths that build a chain with **no** session filter — take the new default
filter and install it the same way the scoped internal methods already do:

```java
http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);
```

`BasicAuthWebappSecurityConfiguration`, `OidcWebappSecurityConfiguration`,
`BasicAuthApiSecurityConfiguration`, and `OidcApiSecurityConfiguration` inject the default filter bean
and pass it through. This also completes [ADR-0023](0023-oidc-bearer-tokens-on-api-chain-only.md)'s
"the session is honoured on the API chain" property for the default surface *deliberately* — today it
only worked as an accidental side effect of the global filter wrapping the request ahead of
`FilterChainProxy`.

### 4. `#477`'s scope-aware global resolver is removed

`ScopeAwareSessionCookieSerializer` and `ScopedSecurityChainRegistrar.registerGlobalScopedSessionCookieResolver`
/ `buildGlobalScopedSessionCookieResolver` / `defaultClusterCookieSerializer` only existed to patch
the global filter's cookie behaviour for scoped paths. With no global filter left to patch, there is
no runtime path-based cookie routing left to do — each chain's own filter has its own hard-wired
cookie serializer, and Spring Security's `securityMatcher` already picks the right chain (hence the
right filter) structurally. The property-reading logic in `defaultClusterCookieSerializer`
(`server.servlet.session.cookie.name`, default `SESSION_COOKIE`) is carried forward into the new
default filter builder (§2), not lost. `ScopeAwareSessionCookieSerializerTest` and
`ScopedGlobalSessionCookieResolverTest` are removed with their subject.

### Why these particular boundaries

- **Symmetry over reconciliation.** Rejects "keep both mechanisms and make them coordinate" (e.g.
  having the global filter skip PT-scoped paths) in favour of removing the asymmetry that caused the
  bug in the first place. A coordination fix only closes this one interaction; a future change to
  either mechanism could reopen the same class of bug as long as two independently-configured
  `SessionRepositoryFilter`s can still see the same request.
- **No shared Spring Session internals across filters.** Every chain owns exactly one
  `SessionRepositoryFilter`, and Spring Security's chain matching guarantees a request is handled by
  exactly one chain — so `INVALID_SESSION_ID_ATTR` (and any other Spring-Session-internal, request-attribute-based
  state) is scoped to a single filter's view of the request by construction, not by careful
  coordination.
- **Reuse, don't reinvent.** The default filter is built with the same components
  (`DefaultCookieSerializer`, `CookieHttpSessionIdResolver`, `SessionRepositoryFilter`) and the same
  repository-resolution preference order the scope mechanism already uses and CSL's tests already
  exercise — this is completing the ADR-0027 pattern, not inventing a third one.

## Consequences

**Positive**

- Removes the entire bug class: no two `SessionRepositoryFilter`s ever process the same request, so
  Spring Session's shared-attribute caching can no longer disagree with itself.
- One filter-installation mechanism instead of two; the default surface and every scope are now
  instances of the same concept, not special-cased relative to each other.
- Completes ADR-0023's "session honoured on the API chain" property for the default surface
  deliberately instead of as a side effect of filter-registration order.
- Deletes more code than it adds: `ScopeAwareSessionCookieSerializer` and the global-resolver
  registration logic (and their tests) are removed outright.

**Negative / accepted trade-offs**

- Behaviour change in non-persistent mode: the default surface now uses an in-memory
  `MapSessionRepository`-backed Spring Session instead of the servlet container's native `HttpSession`.
  Functionally equivalent for standard use (both are ephemeral, per-JVM), but it is a genuine change
  in what backs `HttpSession` when persistence is off, worth explicit test coverage.
- `ScopedWebappSecurityChainBuilder`/`ScopedApiSecurityChainBuilder`'s primary-chain methods gain a
  required parameter; every call site must supply the new default filter bean.
- `@EnableSpringHttpSession`'s auto-configuration also wired session-lifecycle event publishing
  (`SessionEventHttpSessionListenerAdapter`, translating Spring Session events into standard
  `HttpSessionListener` callbacks). No CSL or known host code currently depends on this, but it is
  removed as a side effect and is not being explicitly reproduced.

## Alternatives Considered

- **Make the global filter skip itself for `/physical-tenants/**` paths (a raw path check before
  Spring Security or `PhysicalTenantContext` resolution).** Rejected as the primary fix — it stops
  this one interaction but leaves two independently-configured session mechanisms in place, and the
  next change to either side could reintroduce the same class of bug. Considered a smaller, faster
  patch than this ADR's approach, not a durable one.
- **Reset `SessionRepositoryFilter.INVALID_SESSION_ID_ATTR` (and related internal attributes) between
  the global and in-chain filters** (e.g. in `PhysicalTenantFilter`, before dispatching into the
  chain). Rejected — depends on Spring Session internal field names and caching behaviour that are not
  part of its public contract and could change or shift meaning in a future version; papers over the
  interaction rather than removing it.
- **Keep `#477`'s scope-aware global resolver and additionally make it store-aware, not just
  cookie-name-aware.** Rejected — this would require the global filter to somehow proxy to whichever
  scope's store matches the request, which is exactly what a scope's own in-chain filter already does;
  duplicating that logic in the global filter is more complex than removing the global filter.
