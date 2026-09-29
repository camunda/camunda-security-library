---
status: Accepted
---

# ADR-0031: Send the session idle timeout as OIDC `max_age` on SaaS authorization requests

**Deciders**: Timothy Cline

## Status

Accepted

## Context

In SaaS every Orchestration Cluster shares one Auth0 tenant, and Auth0 keeps its own SSO cookie
that outlives any single application session. When an OC session expires, the webapp sends the user
back through `/oauth2/authorization/{registrationId}`; Auth0 finds its SSO cookie and answers
immediately with a code. The user is silently signed in again, so the OC session timeout
([ADR-0020](0020-configurable-activity-driven-session-idle-timeout.md)) never surfaces as a login
prompt for as long as the Auth0 session lives. The same happens on first login to an OC from any
other Camunda app the user is already signed in to.

The OIDC `max_age` parameter (OpenID Connect Core 1.0 §3.1.2.1) is the standard way to bound this.
The IdP must re-authenticate the user when the last active authentication is older than `max_age`
seconds, and otherwise may answer silently.

CSL already lets a deployment add any query parameter through
`authorize-request.additional-parameters`, but that applies to every deployment, is not tied to the
configured session timeout, and would need to be kept in sync with it by hand. `prompt=login`
forces a login page on every request and so also breaks the silent hand-off from Console to an OC.

What value of `max_age` should CSL send in SaaS, and where should the decision live?

## Decision

When `camunda.security.saas.organization-id` and `cluster-id` are configured, the default
`CamundaOidcAuthorizationRequestResolver` adds `max_age=<seconds>` to every authorization request,
where `<seconds>` is `camunda.security.session.max-inactive-interval`. This covers the primary
chain and every scoped chain, because both resolver construction sites take the value from
`CamundaSecurityLibraryProperties#oidcAuthorizeMaxAge()`.

- Outside SaaS, no `max_age` is sent. Behaviour is unchanged.
- An explicit `max_age` in `authorize-request.additional-parameters` wins; CSL does not overwrite it.
- Hosts that register their own `OAuth2AuthorizationRequestResolver` bean back this default out, as
  before, and are responsible for `max_age` themselves.

### Why these particular boundaries

- **Same value as the session timeout.** A user who was active at the IdP within the last session
  window can still move between Camunda apps without a prompt; one who has not must sign in again,
  which is what an expired session means everywhere else.
- **Every authorization request, not only after expiry.** The resolver has no notion of "this
  request follows an expiry", and a first login is indistinguishable from a re-login at this point.
  Applying it uniformly also covers a fresh browser holding a stale Auth0 cookie.
- **SaaS only.** Self-Managed deployments may use IdPs that ignore or mishandle `max_age`, and their
  operators already have `additional-parameters` for IdP-specific behaviour.

## Consequences

**Positive**

- SaaS session expiry ends in a real login page instead of a silent re-login.
- No Auth0-side configuration change and no effect on other apps' existing sessions.
- No new property to keep aligned with `max-inactive-interval`.

**Negative / accepted trade-offs**

- The timeout is measured from the last authentication at the IdP, not from the last activity. A
  user who signed in to Console, then opens an OC after the window, is asked to sign in again even
  though they are active in Console.
- The IdP must return `auth_time` and honour `max_age`. Auth0 does; CSL does not validate `auth_time`
  in the returned ID token.
- `max_age` follows `max-inactive-interval` implicitly, so shortening one shortens the other.

## Alternatives Considered

- **`prompt=login` via `additional-parameters`.** Rejected: applies to every authorization request
  and breaks the silent Console to OC hand-off.
- **RP-initiated logout at session expiry.** Rejected: only clears the IdP cookie, acts lazily on
  other apps, and requires a redirect at a moment the server cannot rely on the browser being present.
- **A dedicated `max-age` property.** Rejected: a second value that must equal the session timeout
  to be useful, with no use case for them to differ.
