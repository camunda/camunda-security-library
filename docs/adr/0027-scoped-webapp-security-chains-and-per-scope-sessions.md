---
status: Proposed
---

# ADR-0027: Scoped webapp security chains and per-scope web sessions

**Deciders**: Ben Sheppard (Ben-Sheppard), Patrick Wunderlich (p-wunderlich), Sebastian Bathke (megglos), Joaquin Felici (joaquinfelici)

## Status

Proposed

## Context

[ADR-0025](0025-camunda-security-scope-provider-spi.md) added the `CamundaSecurityScopeProvider`
SPI and the `ScopedSecurityDescriptor` (`basePath` + `AuthenticationConfiguration`), letting a host
contribute path-scoped **API** chains that CSL assembles from its own reusable builders. The
descriptor was deliberately made **surface-agnostic**: ADR-0025 notes that "if a future webapp
surface is needed for the same scope, the descriptor is reused unchanged and CSL assembles a
different chain type from it." This ADR is that follow-up.

Some host deployments (the motivating case is the Camunda 8 Orchestration Cluster running
*physical tenants* — many isolated tenants behind per-tenant URL prefixes) need, **per scope**, not
just an API chain but an interactive **webapp** chain: OAuth2 authorization-code login
(`oauth2Login`), the multi-IdP login picker, logout, and a browser session — plus, in BASIC mode,
form-login. CSL already ships exactly such chains for the *primary* surface
(`OidcWebappSecurityConfiguration`, `BasicAuthWebappSecurityConfiguration`,
[ADR-0006](0006-central-security-filter-chains.md)). What is missing is the **scoped** equivalent,
and the **session isolation** that makes multiple webapp scopes coexist in one browser and one
backend.

Two properties make the webapp surface materially harder than the API surface:

1. **A webapp chain mints a session.** Unlike the API chain (`SessionCreationPolicy.NEVER`, bearer
   tokens), `oauth2Login` requires an HTTP session to hold the `SecurityContext` and the
   authorization-request state. CSL's primary webapp chain relies on the default servlet
   `HttpSession` with a single session cookie (`camunda-session`, `Path = /`). With multiple
   scopes in one browser, a single cookie at `Path = /` cannot isolate scopes: tenant A's session
   would be sent to tenant B.
2. **The session must be honoured on the API chain.** [ADR-0023](0023-oidc-bearer-tokens-on-api-chain-only.md)
   established that a logged-in browser calls the API off its session — the API chain reads (but
   never creates) the session established by the webapp chain. On the unprefixed surface this works
   *implicitly* because both chains share one servlet session at one cookie path. For scoped
   surfaces it must be made **explicit**: the scoped API chain has to read the scope's own session,
   which no longer lives in the default servlet session.

A third concern is **durable storage**: CSL owns the web-session lifecycle and depends on the
host's `SessionStorePort` ([ADR-0017](0017-session-store-port-and-web-session-ownership.md)). When
each scope is a tenant with an isolated secondary-storage schema, the host's adapter must route a
scope's sessions to that scope's schema — including on the context-free background deletion sweep.

The hard constraint from ADR-0025 holds: **CSL must remain scope-agnostic.** It must not learn what
a scope means, and the `ScopedSecurityDescriptor` / `CamundaSecurityScopeProvider` contract must not
change. The question this ADR answers: how does CSL assemble a per-scope **webapp** chain with
isolated sessions and cookies, keep that session valid on the scope's API chain, and let the host
persist per-scope sessions to isolated storage — all without changing the host contract?

## Decision

### 1. `ScopedWebappSecurityChainBuilder` — the webapp sibling of the API builder

A new reusable builder in `spring-boot-starter`, symmetric to `ScopedApiSecurityChainBuilder`
(ADR-0025), is the single source of truth for the CSL webapp chain shape. Given a
`ScopedSecurityDescriptor` it derives the chain's security matchers by prefixing each entry from
`SecurityPathPort.webappPaths()` with `basePath`, and assembles, by `authentication.getMethod()`:

- **OIDC** — `oauth2Login` with the scope's `ClientRegistration`s (built from the descriptor's
  merged `AuthenticationConfiguration` via the existing `ScopedClientRegistrationFactory`, i.e. the
  scope's assigned providers only); the multi-IdP login picker at `basePath + /login`
  (the `DefaultLoginPageGeneratingFilter` installed for [#269](https://github.com/camunda/camunda-security-library/issues/269));
  the OAuth2 redirect URI at `basePath + /sso-callback`; logout at `basePath + /logout`; and the
  delegating `AuthenticationEntryPoint` (bearer → 401, browser → IdP/login) retained per ADR-0023.
- **BASIC** — form-login at `basePath + /login` backed by the host's `BasicAuthUserDetailsPort`
  ([ADR-0021](0021-user-details-port.md)), whose adapter resolves the scope from request context.

CSL's own `OidcWebappSecurityConfiguration` and `BasicAuthWebappSecurityConfiguration` are re-based
on this builder, so any change to the webapp chain shape propagates to both the primary and every
scoped chain — the same single-source-of-truth guarantee ADR-0025 gave the API chains.

All webapp-specific endpoints are **derived from `basePath`**; none is added to the descriptor.

### 2. Prefix-aware `OAuth2AuthorizationRequestResolver`

Spring Security's default authorization-request resolver does not reliably match a multi-segment
prefix such as `basePath + /oauth2/authorization/<id>`. The scoped webapp chain installs a
prefix-aware resolver so the authorization request and the `basePath + /sso-callback` redirect
resolve correctly. This composes with the resolver lifted into CSL in the
2026-05-20 OIDC-authorization-request-resolver design (RFC 8707 `resource`, additional params).

### 3. Per-scope session + cookie components, shared across a scope's chains

For each descriptor CSL builds **once** a set of per-scope session components and injects them into
*both* that scope's webapp and API chains:

- a `SessionRepositoryFilter` bound to the scope, over the existing Spring-Session
  `SessionRepository` (in-memory by default; the `SessionStorePort`-backed `WebSessionRepository`
  of ADR-0017 when persistent sessions are enabled);
- a `DefaultCookieSerializer` with `Path = basePath` and a cookie name **derived deterministically
  from `basePath`** (see below);
- a session-reading `SecurityContextRepository`;
- the CSRF cookie scoped to `Path = basePath`.

**Cookie-name derivation.** `basePath` is a URL path and may contain characters (notably `/`) that
are not valid in an RFC 6265 cookie name, so the name cannot be `basePath` verbatim. The name is
`camunda-session-` + **sanitize(`basePath`)**, where `sanitize` strips the leading `/` and replaces
each run of characters outside `[A-Za-z0-9-]` with a single `-` (e.g. `/physical-tenants/tenanta` →
`camunda-session-physical-tenants-tenanta`). A scope-distinct *name* — not merely a distinct `Path`
— is required: the primary unprefixed chain keeps `camunda-session` at `Path = /`, which the browser
would send *alongside* a scoped cookie on a nested path, leaving two same-named cookies whose
resolution order is undefined. To keep the `basePath → name` mapping injective without an opaque
hash suffix, the registrar's existing duplicate-`basePath` rejection (ADR-0025) is extended to also
reject any two scopes whose sanitized cookie names collide — a fail-fast startup check rather than a
runtime ambiguity.

Cookie *names* have no length cap of their own in RFC 6265; the only hard budget is the ~4096-byte
per-cookie (`name=value`) limit browsers enforce, which the short session-id value never threatens
even for a long sanitized name, and `Path`-scoping keeps each request's `Cookie` header to the
matching scope. The same startup validation that rejects colliding names also caps the derived name
length, failing fast rather than silently emitting an over-budget cookie — no hash suffix needed.

Isolation is **structural**, the webapp analogue of ADR-0025's per-scope decoder: because the
session cookie is `Path = basePath` with a scope-distinct name, the browser only ever sends a
scope's session cookie to that scope's prefix — never to a sibling scope, and never colliding with
the primary chain's `camunda-session` at `Path = /`.

### 4. The scoped API chain honours the per-scope session

The scoped API chain (ADR-0025) is extended to install the **same** per-scope session components and
keep `SessionCreationPolicy.NEVER` (read-but-never-create). A request to `basePath + /v2/**` —
nested under `basePath`, so the browser sends the scope's session cookie — is then authenticated by
**either** the per-scope session (SPA XHR) **or** a bearer token (machine client). This extends
ADR-0023's "session honoured on the API chain" property to per-scope sessions; it does not
contradict ADR-0023 — bearer validation remains API-chain-only and the webapp chain remains
login/session-only.

This relies on the scope's API surface being **nested inside `basePath`** (the host's tenant-first
routing, e.g. `/physical-tenants/<id>/v2/**`). An API surface *outside* the cookie's `Path` cannot
carry the session and would be bearer-only — acceptable, and a host routing choice, not a CSL one.

### 5. Registrar builds both chains per descriptor

The collector/registrar of ADR-0025 (`ScopedApiChainRegistrar`, a static
`BeanDefinitionRegistryPostProcessor`) is extended to register, per descriptor, **both** an API and
a webapp chain (method-driven; the cluster is single-mode). Both reuse the order `ORDER_WEBAPP_API`
(`1`), which sorts **ahead of** the `ORDER_UNHANDLED` (`2`) catch-all deny chain so contributed
requests can match; base paths are structurally disjoint, so a request matches at most
one chain (ADR-0025's ordering rationale is unchanged). When no provider bean is present the
post-processor is a no-op — primary-only hosts (Hub, single-scope OC) are unaffected.

### 6. Host-side: durable per-scope sessions route in the `SessionStorePort` adapter

`SessionStorePort` (ADR-0017) is **unchanged** — no tenant parameter. The host's adapter (OC's
`SessionStoreAdapter`) becomes scope-aware:

- it holds a `Map<scope, PersistentWebSessionClient>`, each client bound to that scope's isolated
  secondary-storage schema, built from the host's existing per-scope config resolution;
- request-scoped `get` / `upsert` / `delete` resolve the scope from request context (the cookie's
  `Path` already pinned the request to a scope) — mirroring the `BasicAuthUserDetailsPort` adapter pattern;
- the **background deletion sweep** (`getAll` → `delete`, run with no request context by ADR-0017's
  `WebSessionDeletionTask`) **fans out** across all per-scope clients.

The per-scope `PersistentWebSessionClient` instances and the `search-client` / `db-rdbms` modules
stay tenant-agnostic ("one client = one store"). The alternative — pushing scope-awareness *into*
`PersistentWebSessionClient` — is rejected below.

### 7. Host-side: serving the SPA under the prefix

Rewriting the served SPA so it bootstraps under `basePath` (base-href / context-path, asset and
cluster-endpoint URL mapping, `client-config.js`, webapp-controller routing) is a pure host
webapp-serving concern. **CSL does not serve the SPA and never learns the prefix scheme.** This work
stays in the host (OC).

## Consequences

**Positive**

- The webapp surface gets the same single-source-of-truth chain assembly the API surface got in
  ADR-0025; webapp-chain hardening propagates to primary and scoped chains alike.
- Session isolation is structural and derived from `basePath`: cookies are `Path`-scoped per scope,
  so no scope's browser session is usable on a sibling scope or collides with the primary chain.
- The per-scope session is valid on the scope's API chain, so the SPA's XHR works exactly as on the
  unprefixed surface — without a contract change and consistent with ADR-0023.
- The `ScopedSecurityDescriptor` / `CamundaSecurityScopeProvider` contract and the `SessionStorePort`
  contract are **both unchanged**. Additive and backward-compatible: primary-only hosts are
  unaffected.
- Durable per-scope sessions are isolated at rest; storage clients stay tenant-agnostic; the host's
  PT-context resolution is concentrated in the one adapter built for it.

**Negative / accepted trade-offs**

- More moving parts per descriptor: each scope now contributes two chains plus a per-scope session
  filter and cookie serializer. For small N negligible; very large N is not a known use case
  (same caveat as ADR-0025).
- The scoped API chain reading a session means it is no longer purely stateless; this is intended
  (ADR-0023) but is a behavioural addition to the scoped API chain relative to ADR-0025.
- Honouring the session on the API chain requires the API surface to be nested under `basePath`. A
  host that routes its scoped API outside the prefix gets bearer-only on that surface.
- The host adapter gains a scope→client map and request-context resolution. Routing the id-only
  `get`/`delete` on background threads needs either PT-encoded session ids or fan-out (resolved in
  the implementation plan).

## Alternatives Considered

- **Grow the descriptor with webapp fields (cookie name/path, redirect URI, login URL).** Rejected —
  all are derivable from `basePath`; adding them leaks surface concerns into the host contract and
  breaks the surface-agnostic property ADR-0025 established.

- **Isolate sessions via the servlet `HttpSession`.** Rejected — the container owns `JSESSIONID`;
  its name and `Path` cannot be scoped per chain, so sibling scopes could not be isolated in one
  browser.

- **Have the host build and contribute the per-scope session components / webapp chains.** Rejected —
  it would re-introduce host-side chain assembly (the drift risk ADR-0025 closed) and force a
  contract change. CSL owns chain assembly; the host owns policy.

- **Make `PersistentWebSessionClient` scope-aware (route inside the storage client).** Rejected —
  it pushes the scope/request-context concept down into the tenant-agnostic `search-client` and
  `db-rdbms` modules (an inverted dependency on a request-scoped web concern), duplicates routing
  across both backend implementations, and — decisively — the background deletion sweep runs with
  no request context, so a context-aware client cannot route it. Routing in the adapter keeps the
  storage clients "one client = one store" and is the only layer that serves both request-scoped
  operations and the context-free sweep (via fan-out).

- **A single scope-aware dispatching webapp chain instead of N chains.** Deferred, consistent with
  ADR-0025: the descriptor model permits it later as an optimisation without a contract change;
  N chains are simpler to audit now.
