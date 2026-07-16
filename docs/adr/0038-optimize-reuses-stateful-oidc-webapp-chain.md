---
status: Accepted
---

# ADR-0038: Optimize reuses the stateful OIDC webapp chain and the JWT-cookie chain is retired

**Deciders**: Sebastian Bathke (megglos), Ben Sheppard (Ben-Sheppard)

## Status

Accepted

## Context

We want Optimize to adopt the CSL for authentication and authorization, like the
Orchestration Cluster (OC) applications (Operate, Tasklist, Admin) already do. Optimize
today ships its own hand-written Spring Security setup
(`AbstractSecurityConfigurerAdapter` and the `CCSMSecurityConfigurerAdapter` /
`CCSaaSSecurityConfigurerAdapter` subclasses).

Optimize's current model is a stateless one. It does not keep server-side sessions. After
login it mints a self-signed JWT and stores it in a cookie. Every request revalidates that
cookie. To make login and API calls work, Optimize carries a lot of custom code:

- a JWT cookie that is split across several cookies (`X-Optimize-Authorization_0`, `_1`, ...)
  because a single cookie can exceed the header size limit of some reverse proxies,
- a separate refresh-token cookie and, on SaaS, a stored service-token cookie,
- `TerminatedSessionService`, a server-side list of logged-out token IDs in Elasticsearch,
  which exists only so that a logout can invalidate a stateless token before it expires,
- CSRF turned off, replaced by a `SameSite=Strict` cookie flag,
- for the self-managed case (CCSM), a custom Camunda Identity SDK login flow instead of
  Spring's `oauth2Login`.

A first attempt (issue #166, PR #492) added a dedicated third webapp chain to CSL,
`OidcJwtCookieWebappSecurityConfiguration`, together with a `JwtCookieAuthenticationFilter`,
a `JwtCookieTokenPort` SPI, and an `OidcAuthenticationEntryPoint` SPI, so that CSL could
serve Optimize's stateless cookie model. During review the direction was questioned: this
mostly moves Optimize's existing code and its debt into CSL instead of letting Optimize
adopt the common CSL chains that OC already uses.

CSL already has a session-based OIDC webapp chain
([`OidcWebappSecurityConfiguration`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/OidcWebappSecurityConfiguration.java),
built by `ScopedWebappSecurityChainBuilder`). It uses Spring `oauth2Login`, keeps the user
in a server session, and refreshes tokens transparently. It reuses the host's
`SessionStorePort` for durable sessions ([ADR-0017](0017-session-store-port-and-web-session-ownership.md),
[ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md)). The API bearer
chain ([ADR-0023](0023-oidc-bearer-tokens-on-api-chain-only.md)) stays as it is.

A shared session store for multi-instance Optimize was never actually a blocker. Optimize
always runs a backing Elasticsearch store and already uses it for the terminated-session
list, so there is no new infrastructure to add. Optimize cannot reuse OC's session-store
adapter as-is, though: that adapter lives in a component Optimize does not depend on. Optimize
implements its own `SessionStorePort` adapter over its Elasticsearch and creates its own
session index. A shared store also means no sticky load balancer is needed, so Optimize keeps
affinity-free scaling. What held Optimize back was hesitation to change behavior: moving from
the self-contained cookie to server-side sessions changes logout, refresh, and cookie
handling. We now accept that change deliberately, because unifying authentication procedures
and setup across the Camunda stack is exactly what we want to achieve over the mid to long
run.

The question this ADR answers: should Optimize adopt CSL's existing stateful OIDC webapp
chain, or should CSL keep and maintain a stateless JWT-cookie chain to preserve Optimize's
current model?

## Decision

Optimize adopts CSL's existing stateful OIDC webapp chain. The dedicated JWT-cookie chain
and its SPIs are retired and not merged.

Concretely:

- Optimize imports the standard CSL chains. It provides a `SecurityPathPort` where
  `webappPaths()` returns the catch-all `/**`, and `apiPaths()` returns only the bearer-only
  public API (`/api/public/**`, `/api/ingestion/variable`). `unprotectedApiPaths()` keeps its
  contract of being a subset of `apiPaths()` (it holds the public parts of the bearer surface,
  and is empty for Optimize). Every other public path — including the public endpoints under
  `/api` (`/api/readyz`, `/api/ui-configuration`, `/api/localization`, `/api/external/**`) as
  well as `/external/**`, static resources, and `/actuator/**` — goes into `unprotectedPaths()`.
  The two buckets are permitted by different chains: `unprotectedPaths()` is the security matcher
  of the order-0 unprotected chain, while `unprotectedApiPaths()` is permitted inside the API
  chain (and is on CSL's CSRF allow-list). So a public path outside the bearer surface must go
  into `unprotectedPaths()` to be reachable at all — placing it in `unprotectedApiPaths()` while
  it is not in `apiPaths()` would leave it permitted by neither chain. That is why Optimize's
  public `/api` paths live in `unprotectedPaths()`, and why the subset contract on
  `unprotectedApiPaths()` matters.
- The webapp chain runs with server-side sessions, backed by an Optimize-provided
  `SessionStorePort` adapter over Optimize's Elasticsearch, following OC's pattern. OC's own
  adapter is not reused (it lives in a component Optimize does not depend on), so Optimize
  reimplements it and creates its own session index. Login is Spring `oauth2Login` against
  Camunda Identity (CCSM) or Auth0 (CCSaaS), configured as OIDC client registrations. This
  removes the custom Identity SDK flow.
- The bearer API chain ([ADR-0023](0023-oidc-bearer-tokens-on-api-chain-only.md)) is
  unchanged. A logged-in browser calls the API off its session; direct machine clients use a
  bearer token on `apiPaths()`.
- Because Optimize's webapp chain uses the `/**` catch-all matcher, the always-on catch-all
  deny chain (`protectedUnhandledPathsSecurityFilterChain` in `BaseSecurityConfiguration`)
  must be made suppressible so two `/**` chains do not collide at startup. A follow-up will
  investigate removing that deny chain entirely (it is tech debt, not urgent).
- The `/**` webapp chain must sort below the bearer API chain, so API paths are claimed first
  and the catch-all does not shadow them. Today the API chain and the webapp chain share one
  order (`ORDER_WEBAPP_API`), which only works because their matchers are disjoint (as in OC).
  CSL is changed to give the two chains **distinct orders, API before webapp**, so a `/**`
  webapp catch-all sorts below the API chain automatically. This is behavior-preserving for
  existing hosts (their API and webapp matchers are disjoint, so a request still matches exactly
  one chain) and lets Optimize use the stock webapp chain through the umbrella without
  re-declaring any bean. The assumption is that no host wants a webapp path to win over an
  overlapping API path; bearer-API-first is the intended convention.
- Optimize deletes its custom security stack: `AbstractSecurityConfigurerAdapter` and its
  subclasses, `SessionService`, `AuthCookieService`, `TerminatedSessionService`, the cookie
  filters, and the Identity SDK login code.

The move is done in one step, not in phases. There is no interim stateless adoption.

### Backward compatibility for operators

Adopting CSL changes the config surface from Optimize's own keys (`security.auth.*`, `api.*`,
`security.responseHeaders.*`, loaded through `ConfigurationService`) to CSL's `camunda.security.*`.
Operators are not forced to migrate. The adoption ships a config bridge — a Spring
`EnvironmentPostProcessor`, mirroring OC's `PersistentWebSessionPropertiesPostProcessor` — that
reads the existing Optimize keys and emits the equivalent `camunda.security.*` properties at low
precedence, so an explicit new value always wins. The keys fall into three groups:

- **Mapped** — OIDC/Identity (`security.auth.ccsm.*` and the `camunda.identity.*` from
  `application-ccsm.yaml` → `camunda.security.authentication.oidc.{issuer-uri, client-id,
  client-secret, audiences}`), token lifetime (`security.auth.token.lifeMin` → session timeout),
  response headers (`security.responseHeaders.HSTS.*`, `Content-Security-Policy`,
  `X-Content-Type-Options` → `camunda.security.http-headers.*`), and the public-API JWK/audience
  (`api.jwtSetUri`, `api.audience`).
- **Obsolete by design** — `security.auth.token.secret`, `security.auth.cookie.maxSize` (cookie
  splitting), the `same-site` flag, `api.accessToken` (static shared token), and
  `X-XSS-Protection` lose meaning under server-side sessions and the CSL chains. The bridge ignores
  them and logs a deprecation warning; it does not fail startup.
- **SaaS-managed / no analog** — some CCSaaS Auth0 keys (`m2mClient.*`, `users.cloud.accountsUrl`)
  have no CSL equivalent and remain platform concerns.

This preserves the config surface, not the behavior: even with old config honored, logout, refresh,
and cookie handling change because sessions are now server-side. The full key-by-key mapping table
lives with the spike.

### Why these particular boundaries

- **Reuse the existing chain instead of a new one.** OC already runs this chain in
  production. Reusing it keeps one webapp security model across all Camunda web apps and
  avoids drift, which is the whole point of centralising the chains
  ([ADR-0006](0006-central-security-filter-chains.md)).
- **Server-side sessions remove the cookie debt now.** A single small session-id cookie
  replaces the split `X-Optimize-Authorization_N` cookies, so the reverse-proxy header size
  problem is gone. Logout invalidates the session in the store, so the terminated-session
  list is no longer needed. CSRF and secure headers come from CSL defaults instead of the
  `SameSite`-only workaround.
- **No new infrastructure.** Optimize already requires Elasticsearch and already writes
  session state to it, so the deployment gains nothing new to run. Optimize still implements
  its own `SessionStorePort` adapter and session index (OC's adapter is not reusable across
  the module boundary), but that is code, not a new operational component. A shared store
  keeps scaling affinity-free, which is the property statelessness was really protecting.
- **Tokens live in the session.** The IdP access and refresh tokens sit in the session's
  authorized-client repository and refresh transparently via `OAuth2RefreshTokenFilter`.
  This covers the SaaS service-token need better than a cookie.

## Consequences

**Positive**

- Optimize uses the same webapp security model as OC. One chain shape, one place to harden.
- The custom cookie stack and its debt (cookie splitting, terminated-session list,
  `SameSite`-only CSRF, custom Identity SDK) are removed, not carried forward.
- CSL gains almost no new code. The stateful chain, the bearer API chain, and the
  unprotected chain already exist. The only CSL changes are making the deny chain suppressible
  and giving the API and webapp chains distinct orders (API first).
- No throwaway work. Nothing is built to be deleted later, which the phased stateless
  approach would have required.

**Negative / accepted trade-offs**

- This is a single, larger, higher-risk change. It swaps the login engine (Identity SDK to
  `oauth2Login`), the session model (stateless cookie to server session), and logout
  semantics at once, in one release. There is no incremental fallback.
- Users must log in again once after the upgrade, because the old cookie is no longer valid.
- The webapp chain now depends on the Elasticsearch session store being reachable. This is
  new operational coupling, although on a store Optimize already runs.
- Read latency of the session store is on the request path. OC already proves this works,
  but it must be confirmed under Optimize's request profile.
- Optimize must implement its own `SessionStorePort` adapter and create a new session index;
  OC's adapter cannot be reused across the module boundary. The old auth-storage index (the
  terminated-session store) has to be removed as part of the upgrade.
- Some legacy config keys become no-ops under the new model. The compat bridge honors what maps
  and logs a deprecation warning for the rest, so operators are not forced to migrate, but the
  bridge and its deprecation surface are extra code to maintain until the old keys are dropped.

## Alternatives Considered

- **Keep the dedicated JWT-cookie chain in CSL (PR #492 as is).** Rejected. It moves
  Optimize's code and its debt into CSL, gives CSL a stateless chain that only Optimize
  would use, and keeps the cookie splitting and the terminated-session workaround alive.
- **Phase 1 adopt CSL statelessly (keep the cookie), phase 2 switch to server sessions.**
  Rejected. Phase 1 would keep all the cookie debt live, and the part of CSL that makes
  `oauth2Login` run statelessly would be built only to be deleted in phase 2. Poor value:
  the session store was available all along, so there is nothing to de-risk by staying
  stateless first, and the behavior change is what we want anyway.
- **Phase 1 with a stateless `oauth2Login` bridge, phase 2 switch to server sessions.**
  Rejected for the same reason, and it front-loads the login-engine swap while still
  carrying the cookie debt. It has the worst effort-to-value ratio.
- **Adopt the stateful chain but keep it stateless via a config toggle on one chain.**
  Rejected. Stateful and stateless differ across the whole chain (login mechanism, token
  store, refresh, session policy), not just in one setting. A toggle would be two strategies
  hidden in one method, harder to read and test.
