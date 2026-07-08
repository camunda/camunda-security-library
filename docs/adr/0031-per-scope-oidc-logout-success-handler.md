---
status: Proposed
---

# ADR-0031: Per-scope OIDC logout success handler

**Deciders**: Sebastian Bathke (megglos)

## Status

Proposed

## Context

[ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md) added per-scope **webapp**
chains: for each `ScopedSecurityDescriptor` (`basePath` + `AuthenticationConfiguration`), CSL
assembles an `oauth2Login` chain whose endpoints — login, logout, `sso-callback`, cookie name/path,
authorization base URI — are all **derived from `basePath`**. It also established, as a hard
constraint carried over from [ADR-0025](0025-camunda-security-scope-provider-spi.md), that the
descriptor stays **surface-agnostic**: it rejected "growing the descriptor with webapp fields
(cookie name/path, redirect URI, login URL)" precisely because *all of those are derivable from
`basePath`*.

OIDC **logout** has one piece that is not. The RP-initiated logout success handler
(`CamundaOidcLogoutSuccessHandler`, extending Spring's `OidcClientInitiatedLogoutSuccessHandler`)
sends the IdP a `post_logout_redirect_uri` telling it where to send the browser after the IdP
session ends. CSL exposes this handler as a single host-registered `LogoutSuccessHandler` bean
(`@ConditionalOnMissingBean`); a host sets its target via
`setPostLogoutRedirectUri("{baseUrl}/post-logout")`, where `/post-logout` is a route **the host
application serves** after logout.

`ScopedWebappSecurityChainBuilder` currently wires that same shared bean into *every* scoped chain:

```java
logoutSuccessHandlerProvider.ifAvailable(logout::logoutSuccessHandler);
```

This is wrong for scoped chains in two ways:

1. **The basePath prefix is dropped.** `OidcClientInitiatedLogoutSuccessHandler` expands `{baseUrl}`
   to `scheme://host:port` + the servlet **context path**. A CSL `basePath`
   (`/physical-tenants/<id>`) is a custom application path, not a servlet context path, so it is not
   part of `{baseUrl}`. A user logging out under `/physical-tenants/<id>/` is redirected to
   `http://host/post-logout` instead of `http://host/physical-tenants/<id>/post-logout`.

2. **The wrong `ClientRegistrationRepository` is used.** The shared bean is built with the host's
   **cluster** `ClientRegistrationRepository`. RP-initiated logout resolves the authenticated user's
   `ClientRegistration` — and thus the `end_session_endpoint` and `client_id` — from that repo. A
   scoped webapp chain builds and uses its **own** per-scope `InMemoryClientRegistrationRepository`
   (`buildOidcWebappChainInternal`), from the descriptor's assigned providers only. The shared
   handler cannot resolve a scoped user's registration, so it falls back to the default target and
   never drives IdP logout.

The redirect target is `{baseUrl}` + `basePath` + `<host post-logout route>`. The first two parts
CSL already knows (`basePath` is the scope identity, and everything else in the scoped chain is
derived from it). The third — the host's post-logout landing route — is application policy CSL
cannot synthesize. This is the distinction from the descriptor fields ADR-0027 rejected: those were
*derivable*; this one is not.

The question: how does a scoped webapp chain get a logout success handler that (a) redirects under
the scope's `basePath` and (b) resolves logout against the scope's own registrations — without
re-introducing host-side chain assembly and without leaking derivable surface concerns into the
host contract?

## Decision

**CSL builds the scoped logout success handler; the host supplies only the one non-derivable
datum — its post-logout route — as an optional field on `ScopedSecurityDescriptor`.**

### 1. `ScopedSecurityDescriptor` gains an optional `logoutRedirectPath`

```java
public record ScopedSecurityDescriptor(
    String basePath, AuthenticationConfiguration authentication, @Nullable String logoutRedirectPath) {

  // Backward-compatible: existing 2-arg callers keep compiling; null = opt out.
  public ScopedSecurityDescriptor(final String basePath, final AuthenticationConfiguration authentication) {
    this(basePath, authentication, null);
  }
}
```

- `logoutRedirectPath` is the host's post-logout landing route, relative to the scope root
  (e.g. `/post-logout`). Validated when non-null: must be absolute (`/`-prefixed).
- `null` means opt out — the chain keeps today's behavior (shared provider), so primary-only and
  non-opting hosts are unaffected.
- A non-canonical 2-arg constructor preserves the ADR-0025/0027 constructor shape, so this is
  source- and behavior-compatible for existing adopters.

This is the **only** addition to the host contract, and it carries the single piece of information
CSL cannot derive. All other logout endpoints (`basePath + /logout`) remain derived, per ADR-0027.

### 2. CSL constructs a per-scope handler with the scope's own repository

In `ScopedWebappSecurityChainBuilder.buildOidcWebappChainInternal`, where the scoped
`ClientRegistrationRepository` already exists, replace the shared-provider wiring with:

```java
if (logoutRedirectPath != null) {
  final var handler = new CamundaOidcLogoutSuccessHandler(clientRegistrationRepository); // scoped repo
  handler.setPostLogoutRedirectUri("{baseUrl}" + prefix + logoutRedirectPath);
  logout.logoutSuccessHandler(handler);
} else {
  logoutSuccessHandlerProvider.ifAvailable(logout::logoutSuccessHandler);
}
```

`{baseUrl}` supplies scheme/host/port; the literal `prefix` (the scope's normalized `basePath`)
re-inserts what `{baseUrl}` drops; `logoutRedirectPath` is the host route. Constructing the handler
here — same package as `CamundaOidcLogoutSuccessHandler`, with the scoped repo in scope — fixes both
defects in one place: the redirect prefix **and** per-scope `end_session`/`client_id` resolution.

`logoutRedirectPath` is threaded from the descriptor (already passed through
`ScopedSecurityChainRegistrar`) into `buildScopedWebappChain`.

### 3. The primary (non-scoped) chain is unchanged

The host's `hostLogoutSuccessHandler` bean and its `{baseUrl}/post-logout` continue to serve the
primary webapp chain via the existing `@ConditionalOnMissingBean` + provider mechanism. Only scoped
chains that opt in via `logoutRedirectPath` diverge.

## Consequences

**Positive**

- Scoped OIDC logout redirects under the scope's `basePath` and drives IdP `end_session` with the
  scope's own client — both defects fixed by one localized change.
- CSL retains ownership of chain assembly (ADR-0025/0027): the host contributes *policy data*, not a
  handler or a chain. This respects ADR-0027's rejection of host-built per-scope components.
- Minimal host surface: one optional descriptor field, set once in the host's
  `CamundaSecurityScopeProvider`. No new bean type, no factory interface, no templating knowledge on
  the host side.
- Additive and backward-compatible: the 2-arg descriptor constructor is retained; `null` opts out;
  primary-only hosts are unaffected.

**Negative / accepted trade-offs**

- The descriptor grows by one field, softening ADR-0027's "no webapp fields" stance. Accepted
  because the field carries a **non-derivable** host route, categorically unlike the derivable
  endpoints ADR-0027 rejected. The distinction is made explicit to keep the boundary principled.
- Per-scope `post_logout_redirect_uri`s must each be allow-listed at the IdP; multi-tenant
  deployments need wildcard/pattern registration. This is a deployment concern, not a CSL one.

## Alternatives Considered

- **Host provides the scoped handler (factory `Function<basePath, LogoutSuccessHandler>` or a
  per-basePath registry bean).** Rejected — structurally impossible to do correctly: the scope's
  `ClientRegistrationRepository` is built *inside* CSL from the descriptor's providers, so a
  host-built handler would carry the wrong (cluster) repo and could not resolve the scope's
  `end_session`/`client_id`. Handing the scoped repo out to a host factory would leak CSL internals
  and re-introduce the host-side assembly ADR-0027 rejected.

- **Global CSL property for the post-logout suffix.** Rejected — a scope is runtime SPI data; the
  post-logout route is per-scope policy. Mixing a static config property into the SPI-driven scope
  model is less cohesive than one optional field next to `basePath`, and it forecloses heterogeneous
  scopes for no gain.

- **Derive the scoped post-logout target to the scope root (`{baseUrl}<basePath>/`), no host
  input.** Rejected — fully ADR-0027-consistent but changes post-logout UX (no dedicated landing
  route), may not match the IdP-registered allow-list entry the host chose, and breaks parity with
  the primary chain's `/post-logout`. Not worth avoiding one optional field.

- **Read the suffix back from the host's shared handler and re-prefix it.** Rejected — the
  `post_logout_redirect_uri` template is a private field of `OidcClientInitiatedLogoutSuccessHandler`
  and cannot be reliably extracted.
