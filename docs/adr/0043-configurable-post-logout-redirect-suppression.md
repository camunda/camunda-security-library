---
status: Accepted
---

# ADR-0043: Suppress `post_logout_redirect_uri` by configuration for IdPs that cannot register it

**Deciders**: Timothy Cline (timcline)

## Status

Accepted

## Context

[ADR-0032](0032-csl-owned-per-chain-oidc-logout-success-handler.md) gave each webapp chain its own
`CamundaOidcLogoutSuccessHandler` and made CSL compose the `post_logout_redirect_uri` itself, as
`{baseUrl}` + the chain's base path + the route the host declares through
`SecurityPathPort#postLogoutRedirectPath()`. That composition is what makes RP-initiated logout
return the browser to the right place under a scoped chain.

It also means the parameter always embeds the chain's base path. For a host that serves each cluster
or tenant under a path prefix, the resulting URL is unique per cluster — `https://<host>/<clusterId>/post-logout`.

OIDC RP-Initiated Logout 1.0 permits an OP to require `post_logout_redirect_uri` to be pre-registered,
and Auth0 does. It matches the parameter against the application's *Allowed Logout URLs* exactly,
accepts `*` only in the subdomain position of the hostname — never in the path — and requires any
query string to match exactly too, so no dynamic value can ride along in one either. A per-cluster
path therefore has no entry that can ever match it.

The failure is not a degraded redirect. Auth0 rejects the *entire* end-session request with
`invalid_request`, so the IdP session is never terminated and the user is not logged out at all.
Confirmed against a Camunda SaaS dev cluster: the end-session URL carrying
`post_logout_redirect_uri=https://<host>/<clusterId>/post-logout` answers HTTP 400 `invalid_request`,
while the identical request with the parameter removed answers HTTP 200 and ends the session.

CSL already lets the composition be skipped — `postLogoutRedirectPath()` returning
`Optional.empty()` sends no parameter. But that method is a *host* declaration, and its contract says
so: "The host owns this route; it is not end-user configuration." A host serves a controller at that
route; whether a given IdP will accept the URL CSL builds from it is a property of the deployment,
not of the host. Today a deployment has no way to say the latter without the host rewriting its own
contract.

Where should the decision to omit `post_logout_redirect_uri` live, given that the route is host-owned
but the constraint that forbids sending it belongs to the deployment's IdP?

## Decision

Add `camunda.security.authentication.oidc.post-logout-redirect-enabled` to `OidcConfiguration`
(`DEFAULT_POST_LOGOUT_REDIRECT_ENABLED = true`).

`ScopedWebappSecurityChainBuilder.oidcLogoutSuccessHandler` takes the `OidcConfiguration` of the
scope whose chain it is building and, when the flag is false, returns the
`CamundaOidcLogoutSuccessHandler` without calling `setPostLogoutRedirectUri`. The end-session request
then goes out with no `post_logout_redirect_uri`, which a strict OP accepts and which still
terminates the IdP session.

The flag is read *before* `pathPort.postLogoutRedirectPath()`, so the host's route declaration is
simply unused rather than having to be blanked to suppress the parameter.

The configuration passed in is the scope's own: `properties.getAuthentication().getOidc()` for the
primary chain, `authentication.getOidc()` for a scoped chain.

### Why these particular boundaries

- **Configuration, not a new SPI method.** The split follows the one the port already documents: the
  route stays host-owned, while the capability of the IdP behind a particular deployment is
  configuration. Putting it in the SPI would push a deployment concern into every host's code.
- **A boolean, not a path or URI override.** There is no useful third value. Auth0's exact-match rule
  covers the query string as well as the path, so no static, registerable URL can carry the scope;
  and the logout origin that a host's post-logout route replays is held on a session whose cookie is
  scoped to the chain's base path, so a cluster-independent landing URL could not read it either. The
  only meaningful choice is send or don't send.
- **Per scope, not global.** The chain's registration and `end_session_endpoint` already resolve from
  the scope's own `AuthenticationConfiguration`; a tenant pointing at its own IdP must likewise get
  that IdP's answer here. `AuthenticationConfiguration#getOidc()` is field-initialized and its setter
  null-guards, so a scope that leaves it unset inherits the default rather than failing.
- **Default `true`.** Every existing deployment keeps sending the parameter, so the change is inert
  until a deployment opts out.
- **Orthogonal to `idp-logout-enabled`.** That flag decides whether to contact the IdP at all; this
  one decides only whether to ask it for a redirect back. Collapsing them would make "my IdP rejects
  this URL" indistinguishable from "don't end the IdP session", which are opposite intents.

## Consequences

**Positive**

- A deployment behind an OP with strict post-logout registration can log out at all, rather than
  having every logout rejected.
- Fixes all CSL hosts at once. Both the Orchestration Cluster webapp (`/post-logout`) and Optimize
  (`/`) declare routes that resolve under a per-cluster prefix, so both hit the same rejection; one
  flag covers them without either host changing code.
- No new SPI surface, and no change to the meaning of `postLogoutRedirectPath()` for deployments
  whose IdP accepts the composed URL.

**Negative / accepted trade-offs**

- When disabled, the user lands on the IdP's own logged-out page instead of returning to the page
  they logged out from. The host's post-logout route goes unused and the stored logout origin is
  discarded silently — the logout works, but the return journey is lost.
- One more OIDC logout flag sitting next to `idp-logout-enabled`. An operator who reaches for the
  wrong one trades a broken logout for a silent re-login, so the two need to stay clearly documented
  apart.
- The switch is per scope, not per provider. A scope with several registrations where only one OP is
  strict must disable the redirect for all of them.
- The flag is read from `getOidc()`, so a scope configured only through `providers.oidc.<id>` always
  gets the default. Acceptable while the logout handler is per chain rather than per registration,
  but it is a seam to revisit if per-provider logout behaviour is ever needed.

## Alternatives Considered

- **Register the URL with the IdP instead.** Rejected — Auth0's wildcards are subdomain-only, so a
  cluster id in the path can never be matched by any entry. The only registration that works is one
  literal entry per cluster on a shared application, which grows without bound and has to be
  maintained by cluster provisioning.
- **Have each host return `Optional.empty()` from `postLogoutRedirectPath()`.** Rejected — it
  contradicts the port's documented contract that the route is not end-user configuration, and it
  duplicates the same knob in every host (both camunda/camunda and Optimize would need one),
  spelled differently each time.
- **A static, cluster-independent post-logout URL registered once per environment.** Rejected — the
  logout origin lives on a session whose cookie is path-scoped to the chain, so such an endpoint
  cannot restore it and could only redirect somewhere fixed. It would also require the host's router
  to serve a path outside every scope prefix.
- **Reuse `idp-logout-enabled`.** Rejected — a different axis. Disabling IdP logout leaves the IdP
  session alive, so the user is silently signed back in on the next login; that replaces one bug with
  a worse one.
- **Detect a non-empty base-path prefix in CSL and skip the parameter automatically.** Rejected — the
  prefix is not what makes the URL invalid; the IdP's registration policy is. Keycloak and Entra
  accept the prefixed URL, and an implicit rule would silently strip a working redirect from them.
