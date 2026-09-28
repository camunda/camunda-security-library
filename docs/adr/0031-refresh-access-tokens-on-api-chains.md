---
status: Accepted
---

# ADR-0031: API chains refresh the session access token, with their own authorized-client stack

**Deciders**: Joaquín Felici, Sebastian Bathke

## Status

Accepted

## Context

CSL's API chains restore an existing web session. `ScopedApiSecurityChainBuilder` installs the
per-scope (or default) `SessionRepositoryFilter` before `SecurityContextHolderFilter`, so a browser
that logged in on a webapp chain is authenticated on `/api/**` without presenting a bearer token —
this is what [ADR-0009](0009-session-store-port-and-web-session-ownership.md) and
[ADR-0013](0013-camunda-security-scope-provider-spi.md) set up, and what Optimize relies on after
[ADR-0018](0018-optimize-reuses-stateful-oidc-webapp-chain.md).

What the API chains did *not* do is refresh the OAuth2 access token. `OAuth2RefreshTokenFilter` was
installed only by `ScopedWebappSecurityChainBuilder`, on the primary and the scoped webapp chains.
For a session-authenticated caller the stored authorized client therefore kept its expired access
token for the rest of the session, on every API request, until some request happened to hit a
webapp chain again.

CSL itself does not fail such a request — `OidcUserAuthenticationConverter#decodeAccessToken`
catches the decode failure and falls back to the id_token's claims — so the gap is invisible from
inside the library. It is not invisible to hosts. Optimize's CSL adoption
([camunda/camunda#62798](https://github.com/camunda/camunda/pull/62798)) added a filter that
re-verifies the session's access token against Identity to enforce its permission check, and had to
skip verification entirely once the token expired, because denying on the API chain would have
broken every `/api/**` call for the rest of the session. The result is that a revoked permission
only takes effect after the next webapp request.

Installing the filter is not free of wiring questions. The webapp chain has an OAuth2 client stack
to hand: the primary chain receives `ClientRegistrationRepository`,
`OAuth2AuthorizedClientRepository` and `OAuth2AuthorizedClientManager` as beans, and the scoped
chain builds its own per scope inside `buildOidcWebappChainInternal`. The API chain has none of
that, and `buildScopedWebappChain` is a published builder method with many call sites.

The question this ADR answers: should an API chain that restores sessions refresh the access token,
and if so, where does its authorized-client stack come from?

## Decision

API chains that restore a session refresh the access token, the same way the webapp chain does.

A new value type, `io.camunda.security.spring.scope.ApiTokenRefreshSupport`, carries the three
collaborators the refresh needs — an `OAuth2AuthorizedClientRepository`, an
`OAuth2AuthorizedClientManager`, and the `LogoutHandler` the filter falls back to when the token
cannot be renewed. `ScopedApiSecurityChainBuilder` gained one overload each of `buildOidcApiChain`
and `buildScopedApiChain` that take it, and installs an `OAuth2RefreshTokenFilter` anchored on
`AuthorizationFilter` — the same anchor the webapp chain uses. Passing `null`, which every
pre-existing overload does, installs no filter and leaves those chains byte-for-byte as they were.

Two static factories fix the forced-logout behaviour per chain kind, because a scoped chain has to
expire the cookies it actually set: `forPrimaryChain` clears `camunda-session` and `X-CSRF-TOKEN`,
`forScope` clears the scope's own cookie names under the scope's path. The path-scoped
cookie-clearing handler moved from a private method on `ScopedWebappSecurityChainBuilder` to
`SecurityFilterChainSupport#pathScopedCookieClearingLogoutHandler`, so both sides clear cookies
identically.

The two callers differ in where the stack comes from:

- **Primary chain.** `OidcApiSecurityConfiguration` resolves the `OAuth2AuthorizedClientRepository`
  and `OAuth2AuthorizedClientManager` beans through `ObjectProvider`. They are the very instances
  the primary webapp chain uses. Both come from `OidcWebappClientBeansConfiguration` and are absent
  in a bearer-only deployment (`webapp-enabled=false`), where the chain is built without the filter.
- **Scoped chains.** `ScopedSecurityChainRegistrar` builds the stack per descriptor and caches it by
  `basePath`, next to the existing `sessionFiltersByBasePath` cache: a fresh
  `HttpSessionOAuth2AuthorizedClientRepository`, a `LazyClientRegistrationRepository` over the
  scope's flattened providers built through the new
  `LazyClientRegistrationRepository.withoutLoginRoutes`, and a manager from the existing
  `OAuth2AuthorizedClientManagerFactory` bean. It is built only for an OIDC descriptor that
  configures at least one provider.

### Why these particular boundaries

- **The scoped API chain does not share the webapp chain's instances.** Sharing them would mean
  changing `buildScopedWebappChain`'s signature to accept a stack the registrar owns — a published
  method with roughly seventeen call sites — and it buys nothing.
  `HttpSessionOAuth2AuthorizedClientRepository` keeps no per-instance state: it resolves the
  authorized clients from a session attribute whose name is a class-level constant, so a separate
  instance reads exactly what the login flow stored. And the client-registration repository is never
  consulted on this path — `DefaultOAuth2AuthorizedClientManager#authorize` takes the registration
  off the stored authorized client whenever the authorize request carries one, which
  `OAuth2RefreshTokenFilter`'s always does. It is still constructed, because
  `DefaultOAuth2AuthorizedClientManager` requires a non-null one and a lookup by registration id
  must resolve correctly if a future path ever makes one.
- **The API chain's registration repository validates without login routes.** A scope whose host
  declares no webapp paths gets a working API chain and an inert webapp chain, so this repository can
  be the only one a scope ever builds. Validating it in login mode would apply checks no login route
  in that application reads, and one of them throws rather than warns:
  `requireUserInfoRequiredConsistency` rejects `user-info-required=true` with
  `user-info-enabled=false`, a combination that is inert for a bearer-only scope by that check's own
  reasoning. `LazyClientRegistrationRepository.withoutLoginRoutes` puts it in the same mode
  `ScopedJwtDecoderFactory` and `ScopedOidcClaimsProviderFactory` already use for the same reason.
- **`AuthorizationFilter` as the anchor, not earlier.** Matching the webapp chain keeps one
  ordering rule to reason about, and it means the refresh (and its possible forced logout) runs only
  for a request that was going to be served anyway.
- **One nullable parameter, not three.** The builder already carries a long overload chain; a record
  adds one parameter and names the concept instead of spreading three loose collaborators through
  every signature.
- **Only the OIDC arms.** The BASIC arm authenticates no OAuth2 client and holds no token. The
  permit-all chains built for `unprotected-api=true` are left out deliberately: they are a
  development-only mode, and adding a forced-logout path to a chain whose purpose is to authenticate
  nothing is not worth the behaviour change.

## Consequences

**Positive**

- A session-authenticated API request sees a current access token, so host code that reads it — like
  Optimize's permission-enforcement filter — can trust it instead of skipping verification on
  expiry.
- A revoked permission now takes effect on the next API request, rather than waiting for the session
  to pass through a webapp request.
- The webapp and API chains behave the same way for the same session, which removes a difference
  hosts had to learn about from reading CSL's filter wiring.

**Negative / accepted trade-offs**

- **A behaviour change for expired, unrenewable tokens.** Such a request used to succeed with a
  stale token and now force-logs-out and returns 401 through the chain's authentication entry point.
  A deployment whose IdP issues no refresh token (no `offline_access`) will see API sessions end at
  the access token's lifetime rather than at the session's. This is the webapp chain's existing
  behaviour, applied consistently; it is also the reason this ADR exists rather than a one-line fix.
- **Each OIDC scope with a webapp chain constructs a second `LazyClientRegistrationRepository`**, so
  its no-network provider validation runs twice per scope at startup — once in login mode for the
  webapp chain, once without login routes here. The two modes do not log an identical set of
  warnings, so a scope can now emit the non-login subset twice over.
- **`LazyClientRegistrationRepository` grew a second construction mode.** A caller now has to know
  whether it derives a browser login route before choosing a constructor. The alternative was a
  purpose-built repository for this one caller, which would have duplicated the lazy-resolution and
  caching logic.
- **Bearer-only deployments silently get no filter.** The absence of the client beans is the signal,
  which is correct but implicit; it is logged at `DEBUG` rather than being a configuration error.

## Alternatives Considered

- **Document that API chains never refresh, and tell hosts not to rely on the stored token.** The
  other half of the issue's acceptance criteria. Rejected — it leaves Optimize unable to enforce a
  revoked permission until the next webapp request, and it makes the session-restoring API chain a
  half-measure: good enough to authenticate a caller, not good enough to say anything about them.
- **Share the webapp chain's authorized-client stack with the scoped API chain**, by lifting its
  construction into the registrar and passing it to both builders. Rejected — it changes a published
  builder signature across many call sites to obtain instance identity that, per the reasoning
  above, has no observable effect.
- **Install the filter unconditionally, constructing the beans inside the API builder.** Rejected —
  it would put OIDC client construction inside a builder that hosts also use to assemble standalone
  API chains, and it would give the primary chain a second stack rather than the webapp chain's.
- **Refresh lazily, inside `OidcUserAuthenticationConverter`, at the point the token is decoded.**
  Rejected — the converter has no `HttpServletResponse`, so the refreshed client could not be
  persisted; and it would refresh only for callers that happen to go through that converter, leaving
  every other reader of the stored token with the expired one.
