---
status: Proposed
---

# ADR-0031: CSL-owned per-chain OIDC logout success handler

**Deciders**: Sebastian Bathke (megglos)

## Status

Proposed

## Context

[ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md) added per-scope webapp
chains. For each `ScopedSecurityDescriptor` (`basePath` plus `AuthenticationConfiguration`), CSL
builds an `oauth2Login` chain. All of its endpoints (login, logout, `sso-callback`, cookie name and
path, authorization base URI) are derived from `basePath`. This keeps the descriptor
surface-agnostic, as [ADR-0025](0025-camunda-security-scope-provider-spi.md) required.

OIDC logout does not fit this derived model. RP-initiated logout is done by a `LogoutSuccessHandler`.
CSL uses `CamundaOidcLogoutSuccessHandler`, which extends Spring's
`OidcClientInitiatedLogoutSuccessHandler`. It sends the IdP a `post_logout_redirect_uri` (where to
send the browser after the IdP session ends). It also resolves the `end_session_endpoint` and
`client_id` from the authenticated user's `ClientRegistration`.

Today CSL provides this as a single host-overridable bean
(`OidcBeansConfiguration.camundaOidcLogoutSuccessHandler`, `@ConditionalOnMissingBean`). The bean is
built with the host's cluster `ClientRegistrationRepository` and does not set a
`post_logout_redirect_uri`. Both the primary chain and every scoped chain consume this one bean
through an `ObjectProvider<LogoutSuccessHandler>`. A host that wants a post-logout landing page
overrides the bean, for example with `setPostLogoutRedirectUri("{baseUrl}/post-logout")`.

This single shared bean cannot work for scoped chains. The correct handler for a chain depends on two
things that the chain has but a singleton cannot carry:

1. The chain's own `ClientRegistrationRepository`. A scoped chain builds and uses its own per-scope
   `InMemoryClientRegistrationRepository`, from the descriptor's assigned providers only. The shared
   bean holds the cluster repo. So it cannot resolve a scoped user's registration. The
   `end_session_endpoint` and `client_id` stay unresolved and IdP logout never runs.
2. The chain's `basePath` prefix. `OidcClientInitiatedLogoutSuccessHandler` expands `{baseUrl}` to
   `scheme://host:port` plus the servlet context path only. A CSL `basePath`
   (`/physical-tenants/<id>`) is a custom application path, not a context path, so it is dropped.
   Logout under `/physical-tenants/<id>/` then redirects to `http://host/post-logout` instead of
   `http://host/physical-tenants/<id>/post-logout`.

No configuration of the shared bean fixes this. A design where the host supplies the handler cannot
fix it either, because the scoped repo is built inside CSL and the prefix is CSL's to apply. The only
host input that CSL cannot derive is the post-logout route itself (`/post-logout`). That is an
application landing page. It is a host decision, not end-user configuration. In OC the route is fixed
and the end user does not choose it.

The question: how should CSL build a logout success handler that is correct for every webapp chain,
primary and scoped, using each chain's own repository and prefix, with one setup instead of a special
case per chain?

## Decision

CSL builds the logout success handler for every OIDC webapp chain. The host declares the post-logout
route on `SecurityPathPort`, the port it already implements to declare all security-relevant paths.
The host no longer provides a handler bean. The `LogoutSuccessHandler` bean seam is removed.

### 1. Add the route to `SecurityPathPort`

`SecurityPathPort` is the outbound port through which the host declares its HTTP paths (API paths,
unprotected paths, webapp paths, and so on). The post-logout route belongs to the same group: it is a
host-owned path decision, not end-user configuration. We add it as an optional method with a default,
the same pattern the port already uses for `unauthenticatedWebappPaths()` and
`adminFilterBypassPaths()`:

```java
/**
 * Path the browser returns to after logout, relative to the chain root (e.g. "/post-logout").
 * The host owns this route; it is not end-user configuration. CSL prefixes it with the chain's
 * base path and sends it to the IdP as post_logout_redirect_uri. Return null (the default) to send
 * no post_logout_redirect_uri, so the IdP applies its own default.
 */
@Nullable
default String postLogoutRedirectPath() {
  return null;
}
```

The default keeps the change backward compatible. Existing implementers get `null`, which means no
`post_logout_redirect_uri`, the current behavior. The `ScopedSecurityDescriptor` does not change, so
ADR-0027's surface-agnostic descriptor stays intact.

### 2. CSL builds the handler per chain, from that chain's repo and prefix

`ScopedWebappSecurityChainBuilder` already holds the `SecurityPathPort` as a field. It builds the
handler in both its primary and scoped OIDC paths, through one helper:

```java
private LogoutSuccessHandler oidcLogoutSuccessHandler(
    final ClientRegistrationRepository repo, final String prefix) {
  final var handler = new CamundaOidcLogoutSuccessHandler(repo);
  final var path = pathPort.postLogoutRedirectPath();
  if (path != null) {
    handler.setPostLogoutRedirectUri("{baseUrl}" + prefix + path);
  }
  return handler;
}
```

Primary chain: `oidcLogoutSuccessHandler(clientRegistrationRepository, "")` gives the cluster repo
and `{baseUrl}/post-logout`. Scoped chain: `oidcLogoutSuccessHandler(scopedRepo, prefix)` gives the
scope's own repo and `{baseUrl}<basePath>/post-logout`.

The prefix is the only difference between the two. `{baseUrl}` provides scheme, host, and port. The
literal prefix adds back what `{baseUrl}` drops. The route comes from the port. Because each chain
passes its own repository, the `end_session_endpoint` and `client_id` resolve correctly on both
surfaces.

### 3. Remove the bean seam

Delete the `camundaOidcLogoutSuccessHandler` `@ConditionalOnMissingBean` bean and the
`ObjectProvider<LogoutSuccessHandler>` field on the builder. Hosts stop registering a
`LogoutSuccessHandler` bean. The Camunda 8 Orchestration Cluster returns its route from
`postLogoutRedirectPath()` instead of overriding the bean.

We see no current need for a host to supply its own logout success handler. The only customization in
use is the post-logout route, and the port now covers it. So we remove the host-provided-bean feature
instead of keeping it (YAGNI). If a real need for per-host logout behavior comes up later, we add it
back as one mechanism that works the same for primary and scoped chains, not as a shared singleton.

## Consequences

**Positive**

- Primary and scoped chains use one code path. The prefix is the only difference. There is no branch
  and no opt-out.
- Every chain's handler carries its own `ClientRegistrationRepository`. So RP-initiated logout
  (`end_session`, `client_id`) resolves on both surfaces. This fixes the scoped defect and makes the
  primary chain's setup explicit.
- Scoped post-logout redirects resolve under the scope's `basePath`.
- The route lives on `SecurityPathPort`, next to the other host-owned paths. It is a host decision,
  not end-user configuration, which matches how OC treats it (fixed, not user-customizable).
- The `ScopedSecurityDescriptor` does not change. ADR-0027's surface-agnostic descriptor stays
  intact.
- The change is backward compatible. The new port method defaults to `null`, so existing hosts send
  no `post_logout_redirect_uri`, exactly as today.

**Negative / accepted trade-offs**

- A host can no longer replace the logout handler with its own `LogoutSuccessHandler`. The only known
  customization is the route, and the port now carries it. Wider per-host logout behavior is out of
  scope (YAGNI). If it is ever needed, we add it back as one uniform mechanism.
- `postLogoutRedirectPath()` returns one route for all chains. This holds for the physical tenant
  model, where every chain uses the same route under its own prefix. A future need for a different
  route per scope is a follow-up. It is not a reason to keep the broken seam now.
- Each per-scope `post_logout_redirect_uri` must be allow-listed at the IdP. Multi-tenant deployments
  need a wildcard or pattern registration. This is a deployment concern, not a CSL one.

## Alternatives Considered

- A user-facing config property (`camunda.security.authentication.oidc.post-logout-redirect-path`).
  Rejected. The route is a host decision, not end-user configuration. In OC it is fixed. A property
  puts it in the wrong layer and invites end users to change something that is not theirs. Declaring
  it on `SecurityPathPort` keeps it in host code, next to the other host-owned paths.

- A separate host bean carrying the route (a value bean or a provider interface). Rejected as
  redundant. `SecurityPathPort` already exists for exactly this purpose (host-declared paths) and is
  already injected into the builder. A new bean would add a type and wiring for no gain.

- Keep the host-provided `LogoutSuccessHandler` bean and only fix scoped chains. Rejected. The root
  cause is the shared singleton itself. The correct target depends on the chain's own repo and
  prefix, which a singleton cannot carry. A scoped-only fix keeps two paths and leaves the fallback
  on the wrong (cluster) repo, so it stays broken.

- Add a per-scope `logoutRedirectPath` to `ScopedSecurityDescriptor` and let CSL build the scoped
  handler. This was the first draft of this ADR. Rejected in favor of the unified approach. It fixed
  only the scoped chain, kept the host bean seam for the primary chain (two mechanisms), and softened
  ADR-0027's no-webapp-fields rule.

- Let the host provide the scoped handler through a factory or a per-basePath registry bean.
  Rejected. It cannot be done correctly. The scope's `ClientRegistrationRepository` is built inside
  CSL, so a host-built handler carries the wrong repo. Handing the scoped repo to a host factory
  would leak CSL internals and bring back the host-side assembly that ADR-0027 removed.

- Make the route mandatory and fail startup when it is not set. Rejected. It is the most explicit
  option, but it breaks OIDC adopters that rely on default logout with no post-logout redirect. The
  optional route with an IdP default keeps today's behavior and still makes every chain's handler
  correct.

- Read the route back from the host's shared handler and add the prefix. Rejected. The
  `post_logout_redirect_uri` template is a private field of `OidcClientInitiatedLogoutSuccessHandler`
  and cannot be read reliably.
