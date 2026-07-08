---
status: Proposed
---

# ADR-0031: CSL-owned per-chain OIDC logout success handler

**Deciders**: Sebastian Bathke (megglos)

## Status

Proposed

## Context

[ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md) added per-scope **webapp**
chains: for each `ScopedSecurityDescriptor` (`basePath` + `AuthenticationConfiguration`), CSL
assembles an `oauth2Login` chain whose endpoints — login, logout, `sso-callback`, cookie name/path,
authorization base URI — are all **derived from `basePath`**, keeping the descriptor
surface-agnostic (as [ADR-0025](0025-camunda-security-scope-provider-spi.md) required).

OIDC **logout** breaks this cleanly-derived model. RP-initiated logout is done by a
`LogoutSuccessHandler` — CSL's `CamundaOidcLogoutSuccessHandler`, extending Spring's
`OidcClientInitiatedLogoutSuccessHandler` — which sends the IdP a `post_logout_redirect_uri` (where
to return the browser after the IdP session ends) and resolves the `end_session_endpoint` /
`client_id` from the authenticated user's `ClientRegistration`.

CSL currently exposes this as a **single host-overridable bean**
(`OidcBeansConfiguration.camundaOidcLogoutSuccessHandler`, `@ConditionalOnMissingBean`), built with
the host's **cluster** `ClientRegistrationRepository` and **no** `post_logout_redirect_uri` set.
Both the primary and every scoped webapp chain consume that one bean via an
`ObjectProvider<LogoutSuccessHandler>`. A host that wants a post-logout landing page overrides the
bean, e.g. `setPostLogoutRedirectUri("{baseUrl}/post-logout")`.

That single shared bean is structurally unfit for scoped chains, because the correct handler for a
chain depends on two things the chain has but a singleton cannot carry:

1. **The chain's own `ClientRegistrationRepository`.** A scoped chain builds and uses its **own**
   per-scope `InMemoryClientRegistrationRepository` (from the descriptor's assigned providers only).
   The shared bean carries the cluster repo, so it cannot resolve a scoped user's registration —
   `end_session_endpoint` / `client_id` do not resolve and IdP logout is never driven.
2. **The chain's `basePath` prefix.** `OidcClientInitiatedLogoutSuccessHandler` expands `{baseUrl}`
   to `scheme://host:port` + the servlet **context path** only. A CSL `basePath`
   (`/physical-tenants/<id>`) is a custom application path, not a context path, so it is dropped:
   logout under `/physical-tenants/<id>/` redirects to `http://host/post-logout` instead of
   `http://host/physical-tenants/<id>/post-logout`.

No configuration of the shared bean can fix this, and neither can any design where the **host**
supplies the handler: the scoped repo is built inside CSL, and the prefix is CSL's to apply. The
only host input that is genuinely non-derivable is the post-logout **route** (`/post-logout`) — an
application landing page CSL cannot synthesize.

The question: how should CSL produce a logout success handler that is correct for **every** webapp
chain — primary and scoped alike — using each chain's own repository and prefix, with a uniform
setup rather than a per-chain special case?

## Decision

**CSL owns handler construction for every OIDC webapp chain. The host contributes only a
post-logout path via configuration — never a handler bean.** The `LogoutSuccessHandler` bean seam is
removed.

### 1. One config property for the post-logout route

Add an optional CSL property, `camunda.security.authentication.oidc.post-logout-redirect-path`
(relative to the chain root, e.g. `/post-logout`). It carries the single non-derivable datum. It is
**optional**: when unset, no `post_logout_redirect_uri` is sent and the IdP applies its own default
— the current default behavior, preserved.

The descriptor is **not** changed: the path lives in CSL config and applies uniformly, so
ADR-0027's surface-agnostic descriptor is fully preserved.

### 2. CSL builds the handler per chain, from that chain's repo and prefix

`ScopedWebappSecurityChainBuilder` builds the handler in both its primary and scoped OIDC build
paths, via one helper:

```java
private LogoutSuccessHandler oidcLogoutSuccessHandler(
    final ClientRegistrationRepository repo, final String prefix) {
  final var handler = new CamundaOidcLogoutSuccessHandler(repo);
  final var path = properties.getAuthentication().getOidc().getPostLogoutRedirectPath();
  if (path != null) {
    handler.setPostLogoutRedirectUri("{baseUrl}" + prefix + path);
  }
  return handler;
}
```

- **Primary chain**: `oidcLogoutSuccessHandler(clientRegistrationRepository, "")` → cluster repo,
  `{baseUrl}/post-logout`.
- **Scoped chain**: `oidcLogoutSuccessHandler(scopedRepo, prefix)` → the scope's own repo,
  `{baseUrl}<basePath>/post-logout`.

`prefix` is the only variable between the two. `{baseUrl}` supplies scheme/host/port; the literal
`prefix` re-inserts what `{baseUrl}` drops; the configured path is the host route. Because each
chain passes its own repository, `end_session_endpoint` / `client_id` resolve correctly for both.

### 3. Remove the bean seam

Delete the `camundaOidcLogoutSuccessHandler` `@ConditionalOnMissingBean` bean and the
`ObjectProvider<LogoutSuccessHandler>` field on the builder. Hosts stop registering a
`LogoutSuccessHandler` bean (the Camunda 8 Orchestration Cluster drops its `hostLogoutSuccessHandler`
override and sets the property instead).

## Consequences

**Positive**

- **Primary and scoped chains use one code path** — same helper, `prefix` the only difference. No
  branch, no opt-out, no chain-specific special-casing.
- Every chain's handler carries **its own** `ClientRegistrationRepository`, so RP-initiated logout
  (`end_session` / `client_id`) resolves correctly on both surfaces — fixing the scoped defect and
  making the primary chain's construction explicit and consistent.
- Scoped post-logout redirects resolve under the scope's `basePath`.
- **No `ScopedSecurityDescriptor` change** — ADR-0027's surface-agnostic descriptor is untouched;
  the non-derivable route lives in CSL config, applied uniformly.
- Backward-compatible default: unset path → no `post_logout_redirect_uri` → IdP default, exactly as
  today.

**Negative / accepted trade-offs**

- Hosts can no longer replace the logout handler with an arbitrary `LogoutSuccessHandler`. The only
  known customization is the redirect path, now a property; broader per-host logout behavior is out
  of scope (YAGNI) and, if ever needed, would be exposed uniformly rather than via a shared bean.
- A single global path assumes every chain shares the same post-logout route. True for the physical
  tenant model; a future need for per-scope routes would be a follow-up (a per-descriptor override
  layered on top of the global default), not a reason to keep the broken seam now.
- Per-scope `post_logout_redirect_uri`s must each be allow-listed at the IdP; multi-tenant
  deployments need wildcard/pattern registration. A deployment concern, not a CSL one.

## Alternatives Considered

- **Keep the host-provided `LogoutSuccessHandler` bean; only fix scoped chains.** Rejected — the
  root cause is the shared singleton itself: the correct target depends on the chain's own repo and
  prefix, which a singleton cannot carry. Any "fix scoped only" keeps two divergent paths and leaves
  the fallback wired to the wrong (cluster) repo, i.e. still broken.

- **Per-scope `logoutRedirectPath` on `ScopedSecurityDescriptor` (CSL builds the scoped handler).**
  The original proposal in this ADR's first draft. Rejected in favor of unification — it fixed only
  the scoped chain, kept the host bean seam for the primary chain (two mechanisms), and softened
  ADR-0027's no-webapp-fields stance. The global property fixes both chains with one mechanism and
  no descriptor change.

- **Host provides the scoped handler (factory / per-basePath registry bean).** Rejected —
  structurally impossible to do correctly: the scope's `ClientRegistrationRepository` is built
  inside CSL, so a host-built handler carries the wrong repo. Handing the scoped repo to a host
  factory would leak CSL internals and re-introduce the host-side assembly ADR-0027 rejected.

- **Mandatory path (fail-fast if unset).** Rejected — most explicit, but a breaking change for OIDC
  adopters that rely on default logout with no post-logout redirect. Optional-with-IdP-default keeps
  today's behavior while making every chain's handler correct.

- **Read the route back from the host's shared handler and re-prefix it.** Rejected — the
  `post_logout_redirect_uri` template is a private field of `OidcClientInitiatedLogoutSuccessHandler`
  and cannot be reliably extracted.
