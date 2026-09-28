---
status: Accepted
---

# ADR-0039: API chains refresh the session access token, with their own authorized-client stack

**Deciders**: Joaquín Felici, Sebastian Bathke

## Status

Accepted

## Context

CSL's API chains restore an existing web session, so a browser that logged in on a webapp chain is
authenticated on `/api/**` without presenting a bearer token
([ADR-0009](0009-session-store-port-and-web-session-ownership.md),
[ADR-0013](0013-camunda-security-scope-provider-spi.md),
[ADR-0018](0018-optimize-reuses-stateful-oidc-webapp-chain.md)).

What they did not do is refresh the OAuth2 access token: the refresh filter was installed only on
the webapp chains. A session-authenticated caller therefore kept an expired access token for the
rest of the session on every API request, until some request happened to hit a webapp chain again.

CSL itself never failed such a request, because the OIDC converter falls back to the id_token's
claims when the access token will not decode. Hosts are not so lucky. Optimize's CSL adoption
([camunda/camunda#62798](https://github.com/camunda/camunda/pull/62798)) re-verifies the session's
access token against Identity to enforce its permission check, and has to skip verification
entirely once the token expires, so a revoked permission only takes effect after the next webapp
request.

Installing the filter needs an authorized-client stack, which an API chain does not have. The
webapp chains get one as beans (primary) or build one per scope (scoped), inside a builder method
with many call sites.

The question this ADR answers: should an API chain that restores a session refresh the access
token, and where does its authorized-client stack come from?

## Decision

API chains that restore a session refresh the access token, the same way the webapp chain does.

`ApiTokenRefreshSupport` carries what the refresh needs: an authorized-client repository, a client
manager, and the logout handler the filter falls back to when the token cannot be renewed. The API
chain builder takes one and installs an `OAuth2RefreshTokenFilter` after `AuthorizationFilter`, the
same anchor the webapp chain uses. Passing `null`, which every pre-existing overload does, installs
no filter.

Two factories fix the forced-logout behaviour per chain kind, because a scoped chain has to expire
the cookies it actually set: `forPrimaryChain` clears the unscoped cookies, `forScope` clears the
scope's own names under the scope's path. The path-scoped cookie-clearing handler moved out of
`ScopedWebappSecurityChainBuilder` into `SecurityFilterChainSupport` so both sides clear
identically.

The primary chain reuses the OAuth2 client beans the primary webapp chain already holds, and is
built without the filter when they are absent (`webapp-enabled=false`), where no session login
exists. Scoped chains get a stack built per descriptor and cached by `basePath`.

### Why these particular boundaries

- **The scoped API chain builds its own stack rather than sharing the webapp chain's.** For a scope
  whose host declares no webapp paths there is no webapp stack to share: that chain is inert, so the
  API chain's is the only one the scope has. Sharing in the other cases would mean threading a stack
  through a builder method with many call sites, to gain instance identity that changes nothing:
  the authorized-client repository keeps no per-instance state, and reads the clients from a session
  attribute named by a class-level constant.
- **Its client-registration repository is validated without login routes.** The repository exists
  because the client manager requires one, and because a lookup by registration id has to resolve
  correctly if any future path makes one. Validating it in login mode would apply checks no login
  route reads, and one of them throws rather than warns: `user-info-required=true` with
  `user-info-enabled=false` is rejected, though it is inert without a login chain.
  `LazyClientRegistrationRepository.withoutLoginRoutes` puts it in the mode the other non-login
  consumers already use.
- **`AuthorizationFilter` as the anchor.** Matching the webapp chain keeps one ordering rule, and
  the refresh runs only for a request that was going to be served anyway.
- **The unprotected matchers are skipped.** Those endpoints answer without authentication, so a
  caller whose session token has expired must still get an answer from them. Without the skip the
  filter runs after the `permitAll` decision and turns a public endpoint into a 401 and a forced
  logout. The filter takes an optional `RequestMatcher` for this; passing none, as the webapp
  chains do, skips nothing.
- **Only the OIDC arms.** A BASIC chain holds no token. The permit-all chains for
  `unprotected-api=true` are left out: a development-only mode is no place for a forced logout.

## Consequences

**Positive**

- A session-authenticated API request sees a current access token, so host code that reads it can
  trust it instead of skipping verification on expiry.
- A revoked permission takes effect on the next API request rather than the next webapp request.
- Webapp and API chains behave the same way for the same session.

**Negative / accepted trade-offs**

- **A behaviour change for expired, unrenewable tokens.** Such a request used to succeed with a
  stale token, and now force-logs-out and returns 401. A deployment whose IdP issues no refresh
  token will see API sessions end at the access token's lifetime. This is the webapp chain's
  existing behaviour, applied consistently.
- **An IdP outage now surfaces on API requests.** A refresh that fails because the IdP is
  unreachable or erroring keeps the session and answers 503 with `Retry-After`, where the request
  previously went through with the stale token. Operators will see this during an IdP outage, and
  clients that do not honour `Retry-After` will see failures for the length of it.
- **Concurrent API requests can each attempt their own refresh.** The filter does no per-session
  coordination, so with refresh-token rotation one request can lose the race and be logged out
  while another has already stored a valid replacement. This is pre-existing on the webapp chain
  and is tracked separately; the API chain makes it easier to hit, because a page can issue several
  API calls at once.
- **A scope with a webapp chain validates its providers twice at startup**, once in login mode and
  once without.
- **`LazyClientRegistrationRepository` grew a second construction mode**, so a caller has to know
  whether it derives a login route.

## Alternatives Considered

- **Document that API chains never refresh, and tell hosts not to rely on the stored token.**
  Rejected: it leaves Optimize unable to enforce a revoked permission until the next webapp request.
- **Share the webapp chain's stack with the scoped API chain.** Rejected: it does not cover the
  API-only scope, which has no webapp stack, and elsewhere it buys only instance identity.
- **Refresh lazily where the token is decoded.** Rejected: that path has no `HttpServletResponse`,
  so the refreshed client could not be persisted, and it would leave every other reader of the
  stored token with the expired one.
