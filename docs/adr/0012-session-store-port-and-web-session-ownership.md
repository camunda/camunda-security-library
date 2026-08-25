---
status: Accepted
---

# ADR-0012: Own the web-session lifecycle behind `SessionStorePort`, with one session filter per surface and one OIDC logout handler per chain

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

OC (the `camunda` monorepo) runs persistent server-side web sessions: a Spring Session
`SessionRepository` backed by either a search index (Elasticsearch/OpenSearch) or RDBMS. Before this
decision the session classes lived entirely in OC's `authentication` module and bound directly to OC
search types — `PersistentWebSessionClient`, `PersistentWebSessionEntity`, `SearchQueryResult`, and
`CamundaSearchException`. That coupling kept the session *lifecycle* logic (expiry rules, change
tracking, polling, the deletion scan) inside a host and prevented other adopters (Hub, future OCs)
from reusing it. CSL already declared an empty outbound port `SessionStorePort`, signalling that
session *storage* was always intended to be a CSL contract satisfied by a host-provided backend.

Three further forces shaped the decision after the initial inversion landed:

1. **Multiple webapp surfaces in one browser.** [ADR-0016](0016-camunda-security-scope-provider-spi.md)
   lets a host contribute path-scoped chains — the motivating case is an Orchestration Cluster
   running *physical tenants*, many isolated tenants behind per-tenant URL prefixes. A webapp chain
   mints a session (`oauth2Login` needs one to hold the `SecurityContext` and the
   authorization-request state), so several scopes coexisting in one browser need session and cookie
   isolation. A single cookie at `Path = /` cannot provide it: tenant A's session would be sent to
   tenant B.
2. **Durable storage must route per scope.** When each scope is a tenant with an isolated
   secondary-storage schema, a scope's session bytes must land in that scope's schema — including on
   the context-free background expiry sweep. An earlier design routed this from an ambient
   request-scoped tenant context read inside the host adapter. That design is **factually broken**:
   Spring Session's `SessionRepositoryFilter` reads and writes the store in `commitSession`, invoked
   from a `finally` block *after* `DispatcherServlet` has torn down the request scope, so the
   context resolves to nothing and the write falls back to the default store. Symptoms were a hard
   500 at commit on non-PT/SaaS deployments
   ([camunda#55849](https://github.com/camunda/camunda/issues/55849)) and, on multi-tenant
   deployments, a session written to the default store and read back from the tenant's store on the
   next request, so the user could never stay logged in
   ([camunda#55852](https://github.com/camunda/camunda/issues/55852)).
3. **Two nested session filters cannot coexist.** Wiring Spring Session via
   `@EnableSpringHttpSession` auto-registers a single **global** `SessionRepositoryFilter` outside
   Spring Security's `FilterChainProxy` that replaces the container's native `HttpSession` for every
   request. Once scopes got their own in-chain filters over their own stores, a scoped request was
   handled by *two* independently-configured `SessionRepositoryFilter`s resolving the same cookie
   against different repositories. Spring Session caches a negative lookup in the shared request
   attribute `SessionRepositoryFilter.INVALID_SESSION_ID_ATTR`:

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

   The outermost global filter missed in the default store and set the flag; the in-chain filter
   then found the session in the scope's own store but discarded its own correct result. A
   scope-scoped user was effectively logged out after one click — confirmed end to end. Spring
   Session assumes exactly one authoritative `SessionRepositoryFilter` per request; nesting two that
   disagree breaks that assumption regardless of how carefully their cookie names are kept in sync.

A fourth, adjacent concern is **OIDC RP-initiated logout**. Logout is done by a
`LogoutSuccessHandler` that resolves the `end_session_endpoint` and `client_id` from the
authenticated user's `ClientRegistration` and sends the IdP a `post_logout_redirect_uri`. CSL
originally shipped this as a single host-overridable `@ConditionalOnMissingBean` bean built from the
cluster `ClientRegistrationRepository`. A singleton cannot serve scoped chains: it holds the wrong
repository (a scoped chain builds its own per-scope `InMemoryClientRegistrationRepository` from the
descriptor's providers only, so a scoped user's registration never resolves and IdP logout never
runs), and `OidcClientInitiatedLogoutSuccessHandler` expands `{baseUrl}` to scheme/host/port plus
the servlet context path only — a CSL `basePath` is an application path, not a context path, so it
is dropped from the redirect URI.

The question this ADR answers: who owns the web-session lifecycle, how is a session isolated,
persisted and filtered per surface without depending on ambient request context or a global filter,
and how does OIDC logout stay correct on every chain?

## Decision

### 1. CSL owns the session lifecycle classes

`WebSession`, `WebSessionRepository`, `WebSessionMapper` (+ `SpringBasedWebSessionAttributeConverter`),
`WebSessionAttributeConverter`, and `WebSessionDeletionTask` live in `spring-boot-starter/` under
`io.camunda.security.spring.session`. They use Spring Session (`org.springframework.session.*`) and
servlet types, so they belong in the starter, not `core/`. CSL gains one dependency,
`spring-session-core` (version managed by the Spring Boot BOM), in `spring-boot-starter/`.

### 2. `SessionStorePort` and `PersistentSession` define the storage contract

`SessionStorePort` lives in `core/port/out/` with four operations that speak only framework-free
types:

```java
PersistentSession get(String sessionId);   // null when absent
void upsert(PersistentSession session);
void delete(String sessionId);
List<PersistentSession> getAll();
```

A framework-free `PersistentSession` record crosses the boundary, placed in the public `api` module
at `io.camunda.security.api.model.session`: `(String id, Long creationTime, Long lastAccessedTime,
Long maxInactiveIntervalInSeconds, Map<String, byte[]> attributes)`. It is part of the adopter-facing
surface — hosts implementing `SessionStorePort` map their storage entity to and from it — so it
belongs with the other public model records rather than buried in `core`. `core` depends on `api`, so
the port can reference it directly.

**No default `SessionStorePort` implementation ships in CSL.** The host supplies the adapter. OC's
adapter delegates to its existing `PersistentWebSessionClient` and maps `PersistentSession` ↔
`PersistentWebSessionEntity`, keeping its resilience4j upsert retry host-side: the retry inspects
`CamundaSearchException` reasons to decide what is transient, and moving it into CSL would either
need a CSL-side marker exception or degrade to "retry any `RuntimeException`", while pulling a
resilience4j dependency into the library. Resilience policy is genuinely a property of the storage
backend.

**Bean wiring lives in CSL's `WebSessionConfiguration`** (`spring-boot-starter`, gated by
`@ConditionalOnPersistentWebSessionEnabled`), which exposes `WebSessionRepository`,
`WebSessionMapper`, `WebSessionAttributeConverter`, the per-scope repository factory and the
expiry-sweep scheduler — each `@ConditionalOnMissingBean`. It is deliberately **left out of the
`CamundaSecurityAutoConfiguration` umbrella** (an intentional exception to the "add new configs to
the umbrella" convention, see [ADR-0006](0006-no-spring-boot-auto-configuration.md)): the host must
`@Import` it behind its own web/gateway gate, because activation is tied to the OC-only
`@ConditionalOnRestGatewayEnabled` which CSL cannot reference. The deletion scheduler's
`Thread.UncaughtExceptionHandler` is an overridable `@ConditionalOnMissingBean` bean so the host can
plug in its own fatal-error handling.

Enablement uses the canonical CSL property `camunda.security.session.persistent.enabled` (bound via
`SessionConfiguration` and checked by `@ConditionalOnPersistentWebSessionEnabled`). Hosts that still
use legacy enable-keys bridge them onto this property — OC bridges
`camunda.persistent.sessions.enabled` plus its `camunda.operate.*` / `camunda.tasklist.*` variants
via an `EnvironmentPostProcessor` — so the canonical key is the single source of truth and CSL never
references host-specific keys.

**OC retains only host-specific pieces:** the secondary-storage backend clients + index descriptor,
the `SessionStorePort` adapters (incl. retry), the `@ConditionalOnRestGatewayEnabled` gate, the
`FatalErrorHandler`-backed uncaught-exception-handler override, and the legacy-property bridge.

### 3. Per-scope session and cookie components, shared across a scope's chains

Isolation is built on Spring Session rather than the container's own session, because the container
owns `JSESSIONID` and neither its name nor its `Path` can be scoped per chain — so sibling scopes
could never be isolated in one browser that way. For each `ScopedSecurityDescriptor` CSL therefore
builds **once** a set of per-scope session components (`ScopedWebSessionComponentsFactory`) and
injects them into *both* that scope's webapp and API chains:

- a `SessionRepositoryFilter` bound to the scope, over the repository resolved in §4;
- a `DefaultCookieSerializer` with `Path = basePath`, wrapped in `ContextPathScopedCookieSerializer`
  so the scope prefix rather than the servlet context path determines the cookie `Path`, and a
  cookie name **derived deterministically from `basePath`**;
- a session-reading `SecurityContextRepository`;
- the CSRF cookie scoped to the same prefix, with its own derived name.

**Cookie-name derivation.** `basePath` is a URL path and may contain characters (notably `/`) that
are not valid in an RFC 6265 cookie name, so the name cannot be `basePath` verbatim. The session
cookie name is `camunda-session-` + **sanitize(`basePath`)** and the CSRF cookie name is
`X-CSRF-TOKEN-` + the same suffix, where `sanitize` is `ScopedSecurityChainRegistrar.sanitizeBasePath`:
strip the leading `/`, collapse each run of non-alphanumeric characters (`[^A-Za-z0-9]+`) to a single
`-`, and trim leading/trailing `-` (e.g. `/physical-tenants/tenanta` →
`camunda-session-physical-tenants-tenanta`; `/api/` → `camunda-session-api`). Reusing the registrar's
own helper guarantees the cookie name matches what CSL derives elsewhere for the same scope.

A scope-distinct **name** — not merely a distinct `Path` — is required: the primary unprefixed chain
keeps `camunda-session` at `Path = /`, which the browser sends *alongside* a scoped cookie on a
nested path, leaving two same-named cookies. Browsers do order them (RFC 6265 sends longer-`Path`
cookies first), but server-side cookie parsers resolve duplicate names inconsistently, so a distinct
per-scope name removes the ambiguity.

To keep the `basePath → name` mapping injective without an opaque hash suffix, the registrar's
duplicate-`basePath` rejection ([ADR-0016](0016-camunda-security-scope-provider-spi.md)) is extended
with **startup fail-fast checks** rather than a runtime ambiguity: reject any two scopes whose
sanitized cookie names collide, reject a scope whose sanitized suffix is empty (a `basePath` with no
alphanumerics maps to `""`, which would yield the non-distinct `camunda-session-`), and reject a
derived name longer than `MAX_COOKIE_NAME_LENGTH = 200` characters. Cookie *names* have no length cap
of their own in RFC 6265; the relevant budget is the ~4096-byte per-cookie (`name=value`) size RFC
6265 asks user agents to support at minimum (real per-cookie and per-domain limits vary by browser),
which a session-id value never threatens even for a long sanitized name — the 200-character cap
simply fails fast instead of silently emitting an over-budget cookie.

Isolation is therefore **structural**, the webapp analogue of ADR-0016's per-scope decoder: because
the session cookie is `Path`-scoped with a scope-distinct name, the browser only ever sends a scope's
session cookie to that scope's prefix — never to a sibling scope, and never colliding with the
primary chain's `camunda-session` at `Path = /`.

### 4. Durable per-scope storage routes structurally, via `ScopedSessionStorePortProvider`

Routing is decided by *which filter handles the request* (object identity), not by ambient context
read at commit time. An optional outbound contract in `core/port/out/`:

```java
public interface ScopedSessionStorePortProvider {
  /** The session store bound to the given scope's storage (one physical tenant). */
  SessionStorePort forBasePath(String basePath);
}
```

It is keyed by **`basePath`** — the scope identity CSL already owns — so `core` never learns what a
scope *means*; the host maps `basePath` → tenant internally. `SessionStorePort` itself is
**unchanged**: no tenant parameter, and each returned port is bound to exactly one store.

When a `ScopedSessionStorePortProvider` bean is present, `ScopedSecurityChainRegistrar` builds a
**per-scope** `WebSessionRepository` over `provider.forBasePath(basePath)` (via
`ScopedWebSessionRepositoryFactory`, which owns the mapper and request-proxy wiring) and injects it
into that scope's `SessionRepositoryFilter`. Because the filter holds its own repository,
`commitSession` → `findById`/`save` route to the scope's store by construction. Resolution order,
preserving backward compatibility:

1. per-scope factory available → per-scope `SessionStorePort`-backed `WebSessionRepository`;
2. else the shared singleton `WebSessionRepository` bean → today's shared behaviour;
3. else → a per-scope in-memory `MapSessionRepository` (dev/test), separate instances giving
   store-level isolation on top of the cookie `Path` isolation.

No in-memory `SessionStorePort` implementation is added — "no default `SessionStorePort` in CSL"
(§2) stands.

Every `SessionStorePort` instance is bound to **exactly one** store; none performs a cross-store
`getAll`/`delete`. The context-free background **expiry sweep** (`WebSessionDeletionTask`) therefore
**iterates the per-scope repositories** plus the default-surface one, running the expiry check
against each store in turn. The all-tenants concern lives there, explicitly, rather than hidden
behind a fan-out `getAll`/`delete` on a shared adapter.

Host-side wiring:

- a **single-store** `SessionStorePort` adapter bound to one `PersistentWebSessionClient` resolved
  through the host's existing `PhysicalTenantScoped<PersistentWebSessionClient>.withPhysicalTenant(id)`
  provider (no bespoke client map — the data layer already standardises per-tenant resolution there,
  the same abstraction behind `SearchClientReadersFactory` and the `ServiceRegistry`). This is the
  **only** `SessionStorePort` shape;
- a `ScopedSessionStorePortProvider` implementation: `forBasePath("/physical-tenants/<id>")` → strip
  the prefix → single-store adapter for `<id>` (`default` included, as the default alias);
- **the host must return the *same* `SessionStorePort` instance for the default surface and the
  `default` scope.** The expiry sweep deduplicates repositories by backing-store *identity*
  (`WebSessionConfiguration#distinctByStore`, an `IdentityHashMap` keyed on the `SessionStorePort`
  instance), so sharing the instance is what actually collapses the default store's otherwise
  duplicate sweep. Distinct instances backing the same store would each be swept.

Consequently no request- or thread-scoped tenant context is consulted anywhere in the session-storage
path.

### 5. One explicit `SessionRepositoryFilter` per surface — no global filter

`@EnableSpringHttpSession` is **removed** from `WebSessionConfiguration`. The global, auto-registered
filter and its dependency on Spring Boot's generic filter-bean registration go away entirely;
`WebSessionConfiguration` keeps everything else it owns (§2), because those beans are session-store
plumbing, not filter registration.

The default surface gets its own explicit `SessionRepositoryFilter`, built and installed exactly the
way a scope's is. There is no longer a distinction *in kind* between "the default surface" and "a
scope" from the session filter's point of view — both are one dedicated filter instance installed
into the specific chain(s) that serve that surface, resolving its own `SessionRepository`. No two
filters ever see the same request, so there is no shared-attribute interaction left to have.

- **`DefaultWebSessionFilterConfiguration`** (in the `CamundaSecurityAutoConfiguration` umbrella,
  always active — the primary chains always need a session filter) exposes
  `defaultSessionRepositoryFilter` via `DefaultWebSessionComponentsFactory`: a
  `DefaultCookieSerializer` with the cookie name read from `server.servlet.session.cookie.name`,
  falling back to `CamundaSecurityFilterChainConstants.SESSION_COOKIE` (`"camunda-session"`), and
  **no** `ContextPathScopedCookieSerializer` wrapper — the default surface has no `basePath`, so
  `DefaultCookieSerializer`'s own context-path-aware `Path` computation is exactly right. The
  backing repository uses the same preference order a scope's does: the durable
  `WebSessionRepository` bean when persistent sessions are enabled, a `MapSessionRepository`
  otherwise. It is built once and cached, the same way a scope's filter is shared across its webapp
  and API chains.
- The configuration also registers `defaultSessionRepositoryFilterRegistration` with
  `setEnabled(false)`. That is the mechanism that keeps the filter out of the servlet container's
  global filter list: Spring Boot would otherwise auto-register any `Filter` bean container-wide,
  reintroducing exactly the nested-filter interference described in Context.
- The filter is installed into the primary chains the same way the scoped internal methods do it:

  ```java
  http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);
  ```

  `ScopedWebappSecurityChainBuilder`'s and `ScopedApiSecurityChainBuilder`'s primary-chain methods
  take the default filter and install it, and
  `BasicAuthWebappSecurityConfiguration`/`OidcWebappSecurityConfiguration`/
  `BasicAuthApiSecurityConfiguration`/`OidcApiSecurityConfiguration`/
  `UnprotectedApiSecurityConfiguration` inject it and pass it through.

The scope-aware *global* cookie resolver that previously patched the global filter's cookie behaviour
for scoped paths is removed with it. With no global filter left to patch there is no runtime
path-based cookie routing to do: each chain's own filter has its own hard-wired cookie serializer,
and Spring Security's `securityMatcher` already picks the right chain — hence the right filter —
structurally. The property-reading logic (`server.servlet.session.cookie.name`, default
`SESSION_COOKIE`) is carried forward into the default filter builder, not lost.

This symmetry is about filter *behaviour*, not Spring wiring: the default surface still gets its own
`DefaultWebSessionFilterConfiguration` rather than going through `ScopedSecurityChainRegistrar`,
because it is a single fixed instance wired at compile time through the primary `@Configuration`
classes, whereas scopes are an open-ended, host-defined list discovered at runtime from
`CamundaSecurityScopeProvider`.

### 6. The scoped API chain honours the per-scope session

The scoped API chain ([ADR-0016](0016-camunda-security-scope-provider-spi.md)) installs the **same**
per-scope session components and keeps `SessionCreationPolicy.NEVER` (read, never create). A request
to `basePath + /v2/**` — nested under `basePath`, so the browser sends the scope's session cookie —
is authenticated by **either** the per-scope session (SPA XHR) **or** a bearer token (machine
client). This extends [ADR-0014](0014-oidc-bearer-tokens-on-api-chain-only.md)'s "the session is
honoured on the API chain" property to per-scope sessions without contradicting it: bearer validation
remains API-chain-only and the webapp chain remains login/session-only. For the default surface the
same property is now achieved *deliberately* (§5) instead of as an accidental side effect of the
global filter wrapping the request ahead of `FilterChainProxy`.

This relies on the scope's API surface being **nested inside `basePath`** (the host's tenant-first
routing, e.g. `/physical-tenants/<id>/v2/**`). An API surface routed *outside* the cookie's `Path`
cannot carry the session and is bearer-only — acceptable, and a host routing choice, not a CSL one.

### 7. OIDC logout: one handler per chain, route declared on `SecurityPathPort`

CSL builds the logout success handler for every OIDC webapp chain. There is **no**
`LogoutSuccessHandler` bean seam: the handler is constructed per chain from that chain's own
`ClientRegistrationRepository` and its own prefix, which is exactly what a shared singleton cannot
carry.

**The route comes from `SecurityPathPort`**, the outbound port the host already implements to declare
its security-relevant paths, as an optional method with a default:

```java
default Optional<String> postLogoutRedirectPath() {
  return Optional.empty();
}
```

The method must **never return `null`**; a host that wants no `post_logout_redirect_uri` returns
`Optional.empty()` and lets the IdP apply its own default. The caller enforces this with
`Objects.requireNonNull(pathPort.postLogoutRedirectPath(), "…must not return null; return
Optional.empty() to send no post_logout_redirect_uri")`. The route must start with `/` when present,
the same convention the port's other path methods use. The default keeps the change backward
compatible: existing implementers send no `post_logout_redirect_uri`, the pre-existing behaviour.

**`ScopedWebappSecurityChainBuilder.oidcLogoutSuccessHandler(repo, prefix)`** is a private helper
called once for the primary chain (`prefix = ""`) and once per scoped chain (`prefix = basePath`),
each time constructing a fresh `CamundaOidcLogoutSuccessHandler` bound to that chain's repository.
The redirect-URI template is built by `postLogoutRedirectUri(prefix, route)` as
`{baseUrl}<prefix><route>`, returning `""` (send no URI) when the route is absent or blank.
`{baseUrl}` supplies scheme, host and port; the literal prefix adds back the CSL base path that
`{baseUrl}` drops. The prefix is the normalized base path (`BasePaths.normalize`, trailing slash
stripped), so the join produces exactly one slash and the redirect URI stays stable for IdP
allow-listing. The `ScopedSecurityDescriptor` does not change — no webapp fields are added to the
host contract.

**`CamundaOidcLogoutSuccessHandler`** (`io.camunda.security.spring.security`) is `final` and extends
Spring Security's `OidcClientInitiatedLogoutSuccessHandler`, adding two customisations on top of
vanilla RP-initiated logout:

- **Post-logout redirect URI from the `Referer` header.** The validated `Referer` is stored on the
  HTTP session so the host application can navigate back to the originating page once IdP logout
  completes. Validation is a same-origin check that compares scheme, host (both case-insensitive)
  and effective port (default ports normalised) on parsed `URI` values rather than a `startsWith`
  prefix match — prefix matching is vulnerable to host-confusion bypasses such as
  `https://app.example.com.evil.com/` and `https://app.example.com@evil.com/`. CR/LF-injection,
  relative URLs, and unparseable URIs are rejected. The check is inlined, not promoted to a port:
  it is six lines, security-critical, and an SPI would invite host divergence on a check that should
  be uniform.
- **`login_hint` → `logout_hint` propagation.** When the OIDC user carries a `login_hint` claim it is
  forwarded as a `logout_hint` query parameter to the IdP's end-session endpoint, so the IdP
  terminates the right session for users with several active identities at the same provider.

Two public constants, `POST_LOGOUT_REDIRECT_ATTRIBUTE` and `REDIRECT_MESSAGE_ATTRIBUTE`, are the
host-facing contract for reading those values. Both attributes are written to the HTTP session — not
the request — so they survive the redirect the handler issues and are readable by the post-logout
page on the subsequent request. Hosts reference the constants instead of hard-coding the strings.
Auth-context validation runs *before* the end-session diagnostic: Spring's `super.determineTargetUrl`
returns `getDefaultTargetUrl()` for *any* non-OIDC authentication context (non-`OAuth2AuthenticationToken`,
non-`OidcUser` principal, unknown `registrationId`), not only when the IdP publishes no
`end_session_endpoint`, so the handler confirms a valid OIDC session first and only then sets
`REDIRECT_MESSAGE_ATTRIBUTE`. Because the handler looks up `ClientRegistration` by the principal's
`authorizedClientRegistrationId`, RP-initiated logout works across every configured provider with no
additional wiring.

### Why these particular boundaries

- **Structural over ambient, everywhere.** Both the storage routing (§4) and the filter installation
  (§5) are decided by object identity at wiring time rather than by context read at request time.
  That is immune to request-scope teardown, async/error dispatch and pooled-thread leakage — it
  removes the entire "context gone at commit" failure class rather than papering over one trigger of
  it, and it needs no extra dispatch-type registrations.
- **Keyed by `basePath`, not by tenant.** Keeps `core` scope-agnostic; the tenant mapping stays
  host-side, matching ADR-0016.
- **Symmetry over reconciliation.** "Keep both filter mechanisms and make them coordinate" — have the
  global filter skip scoped paths, or reset `INVALID_SESSION_ID_ATTR` between the two filters — only
  closes one interaction, and the reset variant additionally depends on Spring Session internal field
  names and caching behaviour that are not part of its public contract. Removing the asymmetry
  removes the bug class instead: Spring Security's chain matching guarantees a request is handled by
  exactly one chain, so `INVALID_SESSION_ID_ATTR` and any other Spring-Session-internal
  request-attribute state is scoped to a single filter's view of the request by construction.
- **One adapter shape, one store each.** No `SessionStorePort` instance is silently cross-store; the
  only place that spans stores is the expiry sweep, which iterates them explicitly. The isolation
  boundary stays uniform.
- **Logout route on `SecurityPathPort`, not a config property or a new bean.** The post-logout route
  is a host decision, not end-user configuration (in OC it is fixed and the end user does not choose
  it). A user-facing property would put it in the wrong layer; a dedicated bean would add a type and
  wiring for no gain, since `SecurityPathPort` exists for exactly this purpose and is already
  injected into the builder.
- **Reuse, don't reinvent.** The default filter is built from the same components
  (`DefaultCookieSerializer`, `CookieHttpSessionIdResolver`, `SessionRepositoryFilter`) and the same
  repository-resolution preference order the scope mechanism already uses and CSL's tests already
  exercise.
- **Boundary return type `List<PersistentSession>`, not the host's `SearchQueryResult`.** OC's client
  returns `SearchQueryResult<PersistentWebSessionEntity>` but the repository only ever read
  `.items()`. Returning a plain `java.util.List` keeps `core/` free of `io.camunda.search.*`; the OC
  adapter unwraps.

### Default implementations and override boundaries

| Concern | Provided by | Default / absent behaviour |
|---|---|---|
| `SessionStorePort` | Host | No CSL default; persistent sessions require a host adapter. One instance per store |
| `ScopedSessionStorePortProvider` | Host (optional) | Absent → shared singleton `WebSessionRepository`, else per-scope `MapSessionRepository` |
| `WebSessionAttributeConverter` | CSL (`SpringBasedWebSessionAttributeConverter`) | `@ConditionalOnMissingBean` — host may swap the serialization format |
| Deletion-task uncaught-exception handler | CSL | `@ConditionalOnMissingBean` — host may plug in its own fatal-error handling |
| Default-surface session filter | CSL (`DefaultWebSessionFilterConfiguration`) | `@ConditionalOnMissingBean`; registered with `setEnabled(false)` so it is never global |
| Expiry sweep | CSL | Iterates the per-scope repositories plus the default, deduplicated by store identity |
| Post-logout route | Host via `SecurityPathPort#postLogoutRedirectPath()` | `Optional.empty()` → no `post_logout_redirect_uri` |
| OIDC `LogoutSuccessHandler` | CSL, per chain | No bean seam; not host-replaceable |

## Consequences

**Positive**

- The session lifecycle (expiry rules, change tracking, polling, deletion scan) is a reusable library
  concern behind a clean port; any adopter can plug in its own storage. `core/` stays framework-free
  (enforced by `DomainArchTest`) — the port and DTO use only `java.util`.
- A scope's durable session is written to and read from that scope's store at commit
  ([camunda#55852](https://github.com/camunda/camunda/issues/55852) resolved), with no dependency on
  ambient tenant context anywhere in the storage path.
- The entire nested-filter bug class is gone: no two `SessionRepositoryFilter`s ever process the same
  request, so Spring Session's shared-attribute caching cannot disagree with itself. One
  filter-installation mechanism instead of two, and the removal deletes more code than it adds.
- Session isolation is structural and derived from `basePath`: no scope's browser session is usable on
  a sibling scope or collides with the primary chain's cookie, and the per-scope session is valid on
  the scope's API chain so an SPA's XHR works exactly as on the unprefixed surface.
- Primary and scoped OIDC chains use one logout code path with the prefix as the only difference;
  every chain's handler carries its own `ClientRegistrationRepository`, so `end_session_endpoint` and
  `client_id` resolve on both surfaces and scoped post-logout redirects land under the scope's
  `basePath`.
- Additive and backward-compatible throughout: the `SessionStorePort`, `CamundaSecurityScopeProvider`
  and `ScopedSecurityDescriptor` contracts are unchanged, and primary-only or non-scoped hosts are
  unaffected.

**Negative / accepted trade-offs**

- A second trivial mapping appears at the boundary (`WebSession` ↔ `PersistentSession` in CSL, then
  `PersistentSession` ↔ the host entity in the adapter). This is the cost of the dependency
  inversion; both records carry identical fields. Changing the `SessionStorePort` signature requires
  updating every adapter that satisfies it.
- Library and host share responsibility for the feature, and the split must be kept clear (documented
  in `docs/adopters/ports.md` and `docs/adopters/persistent-web-sessions.md`).
- `WebSessionConfiguration` is intentionally excluded from the `CamundaSecurityAutoConfiguration`
  umbrella, deviating from the "register every config in the umbrella" convention, because activation
  must be wrapped by the host's OC-only gateway gate.
- **Behaviour change in non-persistent mode:** the default surface now uses an in-memory
  `MapSessionRepository`-backed Spring Session instead of the servlet container's native
  `HttpSession`. Functionally equivalent for standard use (both ephemeral, per-JVM), but a genuine
  change in what backs `HttpSession` when persistence is off, and worth explicit test coverage.
- **Removing `@EnableSpringHttpSession` silently dropped `SessionEventHttpSessionListenerAdapter`**,
  which translated Spring Session lifecycle events into standard `HttpSessionListener` callbacks. No
  CSL or known host code depends on it today, but it is gone and is **not** reproduced. Accepted as a
  deliberate trade-off, not an oversight — a host that needs it must wire it itself.
- A new host-facing SPI (`ScopedSessionStorePortProvider`) plus one `WebSessionRepository` instance
  per scope in addition to each scope's filter and cookie serializer. Negligible for small N; very
  large N is not a known use case. The expiry sweep must enumerate the per-scope repositories rather
  than relying on a single fan-out adapter — a little extra wiring in exchange for every adapter
  staying single-store.
- The scoped API chain reading a session means it is no longer purely stateless; intended
  ([ADR-0014](0014-oidc-bearer-tokens-on-api-chain-only.md)), but a behavioural addition relative to
  the API-only scoped chains of ADR-0016. Honouring the session there requires the API surface to be
  nested under `basePath`.
- A host can no longer replace the OIDC logout handler with its own `LogoutSuccessHandler`. The only
  known customisation is the route and the port now carries it; wider per-host logout behaviour is
  out of scope (YAGNI). If it is ever needed it comes back as **one** uniform mechanism that works
  the same for primary and scoped chains, not as a shared singleton.
- `postLogoutRedirectPath()` returns one route for all chains. That holds for the physical-tenant
  model, where every chain uses the same route under its own prefix; a per-scope route is a
  follow-up.
- **Each per-scope `post_logout_redirect_uri` must be allow-listed at the IdP.** Multi-tenant
  deployments need a wildcard or pattern registration. This is a deployment concern, but an
  operationally important one — logout fails at the IdP if it is missed.
- Hosts must not return `null` from `postLogoutRedirectPath()`; the contract is `Optional.empty()`.
  A `null` return fails fast with a `NullPointerException` at chain build time rather than silently
  sending no URI.

## Risks and follow-ups

**Default attribute converter uses Java native serialization.** `SpringBasedWebSessionAttributeConverter`
— the default `WebSessionAttributeConverter` bean wired by `WebSessionConfiguration` — uses
`SerializingConverter`/`DeserializingConverter` (Java native serialization) to translate session
attribute values to and from bytes. This preserves the behaviour migrated from OC unchanged. Two
known drawbacks come with it:

- **Deserialization risk.** Reading attacker-controllable bytes back through Java native
  deserialization can be exploited via gadget chains. The session storage is server-side and written
  exclusively through `SessionStorePort`, so the threat model is "storage tampering" rather than
  direct user input — but a hardened production deployment should still avoid Java native
  deserialization as the default.
- **Upgrade brittleness.** Class renames, package moves, or `serialVersionUID` changes in attribute
  types break previously-persisted sessions.

The `WebSessionAttributeConverter` bean is `@ConditionalOnMissingBean`, so hosts can register their
own — for example a JSON converter with explicit DTOs, or a `DeserializingConverter` configured with
an `ObjectInputFilter` allowlist. Adopter guidance is in `docs/adopters/ports.md` under
[`SessionStorePort`](../adopters/ports.md#sessionstoreport). Switching the CSL default away from Java
native serialization is deferred — that would change persisted-session compatibility for every
existing adopter and is out of scope for the behaviour-preserving migration.

**Session-ID rotation does not delete the previous record.** When `changeSessionId()` (or
`setId(...)`) rotates a session's ID, `WebSessionRepository.save(...)` writes the new ID through
`SessionStorePort.upsert(...)` but does **not** delete the previous ID. The old record then remains
valid in the backing store until natural expiry — a potential session-fixation / parallel-valid-IDs
hazard and a minor storage leak. This too matches the pre-CSL OC behaviour and is preserved by the
migration. It is tracked as a follow-up against `WebSessionRepository`; there is no linked issue yet.

## Alternatives Considered

- **Propagate the tenant onto the request thread across commit** (an outer filter binds a
  thread-local tenant context, cleared in `finally`). Prototyped, then rejected — it works but keeps
  routing *ambient*: it depends on the propagating filter running on the commit thread (async/error
  dispatch), on strict thread-local hygiene to avoid cross-tenant leakage on pooled threads, and it
  does not cleanly cover an outermost global session filter. Structural routing removes all three
  dependencies.
- **Keep a single shared, host-overridable `LogoutSuccessHandler` bean and fix only scoped chains.**
  Rejected — the shared singleton *is* the root cause: the correct target depends on the chain's own
  repository and prefix, which a singleton cannot carry. A scoped-only fix keeps two code paths and
  leaves the primary fallback on the wrong repository. Letting the host supply the scoped handler
  through a factory or per-`basePath` registry cannot work either: the scope's
  `ClientRegistrationRepository` is built inside CSL, so a host-built handler carries the wrong repo,
  and handing the scoped repo out would leak CSL internals and bring back host-side chain assembly.

Consolidates records previously numbered 0012, 0027 (session sections only), 0029, 0031, 0032 (see git history).
