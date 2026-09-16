---
status: Accepted
---

# ADR-0026: Make `post_logout_redirect_uri` configurable and resolve it per client registration

**Deciders**: Timothy Cline (timcline)

## Status

Accepted

Supersedes [ADR-0023](0023-configurable-post-logout-redirect-suppression.md).

## Context

[ADR-0009](0009-session-store-port-and-web-session-ownership.md) made CSL compose the
`post_logout_redirect_uri` itself, as `{baseUrl}` + the chain's base path + the route the host
declares through `SecurityPathPort#postLogoutRedirectPath()`.

[ADR-0023](0023-configurable-post-logout-redirect-suppression.md) added
`camunda.security.authentication.oidc.post-logout-redirect-enabled` so a deployment behind an OP
that will not accept the composed URL can suppress the parameter. Auth0 is the motivating case: it
matches `post_logout_redirect_uri` against its *Allowed Logout URLs* exactly, accepts `*` only in
the subdomain position of the hostname and never in the path, and rejects the *entire* end-session
request with `invalid_request` when no entry matches — so a deployment served under a per-cluster
path prefix is not logged out at all.

ADR-0023 recorded two limits of that answer as accepted trade-offs, and both have since been hit:

- **There is no third value.** ADR-0023 argued a boolean was sufficient because "no static,
  registerable URL can carry the scope". That is true of a URL that must *identify* the scope, but
  it is not the only thing an operator wants. A deployment that has a perfectly registerable landing
  URL — the host root without the cluster prefix, or an off-host account page — cannot ask for it,
  and buys the fix by losing the return journey entirely.
- **The switch is per scope, not per provider.** One `CamundaOidcLogoutSuccessHandler` served every
  registration in a chain, so the flag was AND-ed across every configured provider. In a BYO-IdP
  deployment with several IdPs, one strict IdP silently strips the redirect from all the others.
  ADR-0023 named the fix and deferred it: "A finer per-provider switch is a seam to revisit if
  per-provider logout behaviour is ever needed — it would require the logout handler itself to
  become registration-aware, since today one handler instance is shared by every registration in the
  chain."

So: how does a deployment name the `post_logout_redirect_uri` it wants, and how does each IdP in a
multi-provider deployment get its own answer, without the logout handler growing a shared mutable
per-request field?

## Decision

Add `camunda.security.authentication.oidc.post-logout-redirect-uri` (`String`, default `null`) to
`OidcConfiguration`, and resolve it — along with `post-logout-redirect-enabled` — **per client
registration**.

**Value semantics.** A value starting with `/` is a path and is composed exactly as the host's own
route is: `{baseUrl}` + the chain's base path + the value. Any other value is a URI template handed
to Spring untouched, so an absolute `https://…` URL and a `{baseUrl}/…` template both work, and
neither picks up the chain's base path. The asymmetry is the point: the base path is precisely what
makes the composed URL unregisterable at an OP that matches exactly, so opting out of it has to be
expressible. Unset falls back to the composed host route, so every existing deployment is unchanged.

**Per-registration resolution.** `ScopedWebappSecurityChainBuilder` builds a `Map<String, String>`
of registrationId → template from `ScopedClientRegistrationFactory#flatten` — the same
registrationId-keyed map the chain's `ClientRegistrationRepository` is built from, covering the flat
`oidc.*` block and every `providers.oidc.<id>` entry — and passes it to
`CamundaOidcLogoutSuccessHandler`. `""` means "send no parameter for this registration", which is
how `post-logout-redirect-enabled=false` is expressed. `isPostLogoutRedirectEnabled`'s scope-wide
`allMatch` fold is deleted.

**One delegate per registration.** `CamundaOidcLogoutSuccessHandler` eagerly builds one
`OidcClientInitiatedLogoutSuccessHandler` per configured registration, each with its own
`postLogoutRedirectUri` set once at construction, and dispatches on the authenticated
`registrationId`. A suppressed registration still gets a delegate, one with no template. A
registrationId absent from the map falls through to `super`, which continues to carry the
chain-wide composed route via `setPostLogoutRedirectUri`.

**Validation at the chain builder.** A configured value is rejected at startup when it contains CR
or LF, when its braces are unbalanced, when it names a template variable outside the six Spring
populates (`baseUrl`, `baseScheme`, `baseHost`, `basePort`, `basePath`, `registrationId`), when a
placeholder-free absolute value does not parse or carries no host, or when it is neither absolute nor
a path nor a template. Validation runs before `post-logout-redirect-enabled` is consulted.

### Why these particular boundaries

- **A delegate per registration, not one handler reading the value per request.** Spring's
  `postLogoutRedirectUri` is a private, single-valued *instance field* read inside
  `determineTargetUrl`, and every helper around it (`endSessionEndpoint`, `idToken`, `endpointUri`)
  is private. That leaves two alternatives to a delegate, and both are worse. Calling
  `setPostLogoutRedirectUri` on a shared handler before each `super.determineTargetUrl` is a data
  race: two concurrent logouts on different registrations interleave and one IdP receives the
  other's redirect URI — a correctness bug that will not reproduce under test. Re-implementing
  `endpointUri` means copying Spring internals wholesale and re-deriving them on every Spring
  Security bump. A delegate's field is written once at construction and never again, so the object
  is effectively immutable and needs no synchronization.

- **Delegates are eager, not lazily cached.** The registration set is fixed at construction and a
  delegate is a two-field object, so there is nothing to defer. Building eagerly removes a
  `computeIfAbsent`, a concurrency question, and any unbounded-growth question for an unknown
  registrationId.

- **A suppressed registration and an unknown one resolve differently, and the chain keeps its
  chain-wide default.** These look like the same "no entry" case and are not.
  `buildOidcWebappChain` takes the `ClientRegistrationRepository` as a parameter and CSL's own bean
  is `@ConditionalOnMissingBean`, so a host can supply a repository holding registrations that never
  appear under `camunda.security.authentication.*`. Those cannot be in the map. Before this ADR they
  received the composed route like every other registration, because one template served the whole
  chain; collapsing them into "no entry means send nothing" would silently drop their
  `post_logout_redirect_uri` — a regression for exactly the hosts that are hardest to test. So the
  chain still calls `setPostLogoutRedirectUri` with the composed route, an unknown registrationId
  inherits it through `super`, and a registration configured off gets a delegate with no template so
  it cannot pick that default back up.

- **The delegate returns `null` rather than its own default target URL.** `determineTargetUrl` and
  `onLogoutSuccess` both detect "the IdP published no `end_session_endpoint`" by comparing the
  resolved URL against this handler's `getDefaultTargetUrl()`, and every handler instance carries
  its own copy of that field (plus `useReferer` and `targetUrlParameter`, which the same Spring
  fall-through consults). Letting a delegate's default reach that comparison would make the sentinel
  depend on two objects agreeing about three fields. Returning `null` and falling back to the outer
  handler's own `super.determineTargetUrl` keeps it an identity on one object. The failure mode this
  avoids is silent: a fetch-based logout would answer `200 {"url": "/"}` instead of `204`, and the
  webapp would navigate to `/` believing it was the IdP's end-session URL.

- **Validation in the chain builder, not `OidcConfiguration#validate()`.** `validate()` is reached
  through `CamundaSecurityLibraryProperties`' `@PostConstruct`, which only walks the *cluster*
  properties bean. A scoped `AuthenticationConfiguration` is constructed by the host and handed
  straight to `buildScopedWebappChain`, so a check there would silently miss every per-tenant
  configuration. The chain builder sees both, and knows the chain prefix. This also follows the
  sibling property: `redirect-uri`'s rule is documented on `OidcConfiguration` but enforced in
  `ScopedClientRegistrationFactory#resolveRedirectUri`.

- **Rejecting unknown template variables is worth the code.** Spring expands the template with a
  fixed six-entry variable map, so `{tenantId}` throws from inside `buildAndExpand` on the logout
  request itself — a 500 on the one request a user cannot usefully retry, long after the typo
  shipped. Startup is the right place to find it.

- **`post-logout-redirect-enabled=false` beats a configured URI.** An operator with both set is
  saying "this IdP rejects the parameter", which is the more specific statement about what the OP
  will accept; honouring the URI anyway would resurrect the rejection the flag exists to avoid. The
  combination is logged at `WARN`, because silently ignoring an explicitly configured value is
  otherwise an afternoon lost.

- **Validation runs before the enabled flag is read.** A configured value is checked even when
  `post-logout-redirect-enabled` is `false`, so a typo surfaces at startup rather than lying dormant
  until someone switches the redirect back on. It also means nothing unvalidated reaches a log line.

- **Templates are scanned for brace balance, not regex-matched.** A regex for `{name}` only sees
  *closed* pairs, and the open ones are the dangerous case: `UriComponentsBuilder` does not reject
  an unclosed brace, so `{baseUrl}{tenantId` expands to the literal `https://host{tenantId` and is
  sent to the IdP exactly like that. A closed-pair check finds only `baseUrl`, passes it, and ships
  the malformed URL. Likewise `"://"` is only a lexical hint, so a placeholder-free absolute value is
  parsed and required to carry a scheme and a host — `https://` otherwise passes as "absolute".

- **Default unset, default enabled.** The change is inert until a deployment opts in.

## Consequences

**Positive**

- A deployment behind a strict OP can keep the post-logout redirect instead of trading it away: it
  names a URL the IdP will actually accept, rather than choosing between a rejected logout and no
  return journey.
- Each IdP in a BYO-IdP deployment gets its own answer. A single strict IdP no longer strips the
  redirect from every other provider in the scope — the concrete gap ADR-0023 left open.
- Fixes all CSL hosts at once. Both the Orchestration Cluster webapp (`/post-logout`) and Optimize
  (`/`) compose a route under any per-cluster prefix, so both are covered without either host
  changing code, and `SecurityPathPort#postLogoutRedirectPath()` keeps its meaning as the *default*.
- Misconfiguration surfaces at startup rather than as a 500 on a logout request.

**Negative / accepted trade-offs**

- Three OIDC logout knobs now sit together, and `idp-logout-enabled` remains unwired — no code path
  has read it since ADR-0009 removed the host-provided `LogoutSuccessHandler` bean seam. An operator
  reaching for it still gets no effect at all. That gap predates this ADR and is not closed here.
- A chain now holds one logout delegate per configured registration rather than one handler. The
  objects are trivial and bounded by configuration, but the handler is no longer a single object a
  test can read one template off — tests assert the registrationId-keyed map instead.
- The host route is resolved once per chain, before any registration is examined, so a host that
  violates `SecurityPathPort`'s contract by returning bare `null` now fails at startup even when
  every registration disables the redirect. Previously it booted in that narrow case. The port
  already forbids `null` and both in-tree hosts return `Optional`, so this is a deliberate
  strictness increase rather than a regression.
- A configured absolute URL is opaque to CSL: it cannot verify the host serves anything there, so a
  typo lands the user on a dead page after a successful logout. Validation establishes that the value
  is a well-formed, expandable URL — not that it is the right one, nor that it is registered at the
  IdP.
- The chain-wide template is still set on the handler even when every configured registration
  overrides it, purely so registrations from a host-supplied repository keep it. It is dead weight
  for the common case, and it means two places can now answer "what does this chain send" — the map
  and the inherited field — with the map winning.

## Alternatives Considered

- **Keep the boolean and register the composed URL with the IdP.** Rejected — Auth0's wildcards are
  subdomain-only, so a cluster id in the path can never be matched. The only registration that works
  is one literal entry per cluster, which grows without bound.
- **Carry the resolved template on `ClientRegistration.providerDetails.configurationMetadata`,** the
  way `TokenValidatorFactory.AUDIENCES_METADATA_KEY` already does, and keep one handler that reads
  it per request. Rejected — the handler would still have to get that value into Spring's private
  field, which is the data race described above. It also puts a logout concern into the registration
  factory, which knows neither the chain prefix nor the host's route, and `configurationMetadata` is
  simultaneously the discovery-cache payload (`cacheDiscoveryDocument` requires
  `ClientRegistrations.fromOidcConfiguration` to round-trip it), so writing to it is only safe by
  ordering rather than by construction.
- **A path-only override.** Rejected — it cannot express an off-host URL or opt out of the chain
  prefix, so it does not solve the case that motivated the property.
- **A new `SecurityPathPort` method.** Rejected for the reason ADR-0023 gave and this ADR keeps: the
  route is host-owned, but whether a given IdP accepts the resulting URL is a property of the
  deployment. That split is unchanged.
- **Leave the enabled flag per scope and make only the URI per registration.** Rejected — it would
  leave two adjacent properties on different axes, so an operator disabling one IdP's redirect would
  still silently disable every other IdP's, which is the bug being fixed.
