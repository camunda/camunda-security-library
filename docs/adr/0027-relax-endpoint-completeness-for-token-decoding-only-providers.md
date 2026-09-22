---
status: Accepted
---

# ADR-0027: Relax OIDC endpoint completeness for token-decoding-only providers

**Deciders**: Ben Sheppard

## Status

Accepted

## Context

`ScopedClientRegistrationFactory` validates every OIDC provider block before building a
`ClientRegistration` from it: each configured endpoint URL must be an absolute http(s) URL
(`requireAbsoluteEndpointUrls`), and — separately — the block must set either `issuer-uri` or all
three of `authorization-uri`, `token-uri` and `jwk-set-uri` (`requireEndpointConfiguration`), plus a
non-blank `client-id`. This runs unconditionally for every provider, whether the caller mounts the
browser login chain (`createFromProviderMap`) or only decodes bearer tokens
(`createWithoutLoginRoutes`, used by `ScopedJwtDecoderFactory` and
`ScopedOidcClaimsProviderFactory`).

`authorization-uri` and `token-uri` are load-bearing only for the OAuth2 `authorization_code` flow a
browser login mounts. A provider used solely to validate incoming bearer tokens — a pure
resource-server / API-only deployment, with no interactive login — never runs that flow and never
needs a `client-id` either. Adopters in that position were forced to supply values that mean nothing
to their use case just to satisfy the check, with `jwk-set-uri` (or `issuer-uri`, for discovery)
being the only property their use case actually requires.

The completeness check was not merely a stylistic convenience sitting in front of Spring's own
validation: `buildClientRegistration` unconditionally set
`.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)` on every registration it built,
decode-only ones included. `ClientRegistration.Builder#build()` only enforces `client-id`,
`redirect-uri`, `authorization-uri` and `token-uri` for the `AUTHORIZATION_CODE` and
`CLIENT_CREDENTIALS` grant types — so as long as every registration carried `AUTHORIZATION_CODE`,
Spring's own builder would keep demanding those fields regardless of anything CSL checked.
Relaxing CSL's own rule alone would not have relaxed anything.

The question this ADR answers:

> What should determine which endpoint properties a provider block must supply, so that a caller
> that only decodes tokens isn't forced to configure login-flow-only fields, while a caller that
> mounts the browser login chain keeps today's required fields and named, actionable errors?

## Decision

Reuse the caller-intent distinction `ScopedClientRegistrationFactory` already carries internally as
`LoginRouteChecks` — `ENFORCED` for a caller that derives a browser login route and redirection
endpoint from the configuration (`createFromProviderMap` / `validateWithoutNetwork`), `SKIPPED` for
a caller that does neither (`createWithoutLoginRoutes` / `validateWithoutLoginRoutes`) — as the
condition for which fields a provider block must supply:

- **`requireEndpointConfiguration`** now takes `LoginRouteChecks`. `ENFORCED` keeps today's rule
  unchanged: `issuer-uri`, or all of `authorization-uri`, `token-uri` and `jwk-set-uri`. `SKIPPED`
  narrows to `issuer-uri` or `jwk-set-uri` alone — the only property a `JwtDecoder` actually reads to
  verify a signature.
- **`requireClientId`** now only runs for `ENFORCED`.
- **`buildClientRegistration`**'s grant type is now conditional on `LoginRouteChecks`: `ENFORCED`
  keeps `AuthorizationGrantType.AUTHORIZATION_CODE`; `SKIPPED` uses a new private marker constant,
  `RESOURCE_SERVER_ONLY_GRANT_TYPE` (`new
  AuthorizationGrantType("urn:io.camunda:csl:oauth2-grant-type:resource-server-only")`). This is the
  change that actually makes the relaxation effective: the constant deliberately matches neither
  `AUTHORIZATION_CODE` nor `CLIENT_CREDENTIALS`, so `ClientRegistration.Builder#build()` skips the
  validation that otherwise requires `client-id`, `redirect-uri`, `authorization-uri` and
  `token-uri` — none of which token decoding uses. The registration's grant type and redirect-uri
  are never read by anything in the decoder path (`OidcAccessTokenDecoderFactory`,
  `IssuerAwareJWSKeySelector`, `IssuerAwareTokenValidator`, `TokenValidatorFactory`); only
  `ScopedWebappSecurityChainBuilder` and `ScopedClientRegistrationFactory` itself read those fields,
  both exclusively on the `ENFORCED` path.
- **`flatten()`**'s gate for including the flat `oidc.*` block changes from
  `StringUtils.hasText(clientId)` to a new private predicate, `namesAClientOrAnEndpoint` — true when
  the block sets `client-id`, `issuer-uri`, `authorization-uri`, `token-uri` or `jwk-set-uri` — so a
  flat block configured purely for token decoding (for example, only `jwk-set-uri`) is recognized
  instead of silently dropped. `OidcConfiguration#isAnyPropertySet()` was tried first and reverted:
  it is `true` for a flat block that sets only a callback- or logout-related property (`redirect-uri`,
  `post-logout-redirect-uri`), and such a block is a documented, supported shape in its own right — it
  moves the callback path the unscoped webapp chain mounts while `providers.oidc.<id>` entries supply
  the actual registrations (see "redirect-uri and the redirection endpoint" in the adopter guide).
  Gating on `isAnyPropertySet()` made that redirect-only block eligible for a registration of its own,
  and `LazyClientRegistrationRepository`'s eager, constructor-time validation then rejected it for a
  missing `client-id` nobody configured for it — turning a supported, existing configuration into a
  startup failure. `providers.oidc.<id>.*` entries were never subject to either gate — they are
  included in the provider map unconditionally already.
- A related fix travels with this change: `requireUsableScopes`'s probe registration — used only to
  validate that a configured scope contains no character a scope token disallows — stopped threading
  the real (possibly blank) `client-id` into its synthetic `AUTHORIZATION_CODE` probe, using a fixed
  placeholder instead. The probe is unrelated to client-id; it started failing once client-id
  legitimately became optional for `SKIPPED` providers.

### Why these particular boundaries

- **Reusing `LoginRouteChecks` rather than a new, adopter-facing config flag** because CSL already
  carries the exact distinction needed — whether the caller derives a browser login route from the
  configuration — as an internal enum threaded through the same validation path. The calling code
  (`ScopedJwtDecoderFactory`/`ScopedOidcClaimsProviderFactory` vs. the webapp beans) already knows
  deterministically which mode it's in; introducing a user-facing property to re-express the same
  fact would duplicate a decision the code already makes, and would let the two go out of sync (an
  adopter setting the flag one way while importing beans that assume the other).
- **A synthetic marker grant type rather than an existing Spring constant** (e.g. `JWT_BEARER`,
  `DEVICE_CODE`) because reusing a constant with real OAuth2 semantics the registration doesn't have
  would mislead a future reader and risks being picked up by a Spring `OAuth2AuthorizedClientProvider`
  chain if the registration were ever exposed to one. A private, obviously-synthetic URN cannot
  collide with anything real and its own Javadoc states plainly why it exists.
- **Narrowing `requireEndpointConfiguration` to `issuer-uri` or `jwk-set-uri` for `SKIPPED`, not
  dropping the check entirely,** because completeness is still a real requirement for a decode-only
  provider — it must be able to locate its keys somehow. Only the two properties that exist for the
  login flow (`authorization-uri`, `token-uri`) stop being required; the property token decoding
  itself needs stays mandatory, with the same named, actionable error shape as before.
- **Changing `flatten()`'s gate to `namesAClientOrAnEndpoint` rather than leaving it as
  `hasText(clientId)`** because otherwise the client-id relaxation would be invisible for the flat
  single-provider config shape: a flat block with only `jwk-set-uri` set would be silently excluded
  from the provider map before any validation ran, producing a confusing "at least one OIDC provider"
  error instead of the intended, working configuration. The gate deliberately does not use
  `isAnyPropertySet()` — see "Why these particular boundaries" above for the regression that choice
  caused and why a narrower, purpose-built predicate replaced it.

## Consequences

**Positive**

- A **single-provider** scope configured for token decoding only —
  `providers.oidc.<id>.jwk-set-uri=...` or the flat `oidc.jwk-set-uri=...` equivalent — needs no
  `client-id`, `authorization-uri`, `token-uri` or `redirect-uri`. `issuer-uri` alone (for discovery)
  still works too. This does not extend to a scope with two or more providers: `ScopedJwtDecoderFactory`
  selects an issuer-aware decoder as soon as more than one provider is configured, and
  `OidcAccessTokenDecoderFactory#validateProvidersHaveIssuer` then requires every provider in that
  scope to declare `issuer-uri`, so the token can be routed to its provider by the `iss` claim —
  `jwk-set-uri` alone is not sufficient there, for any provider in the scope. This relaxation is
  therefore reachable only for a scope with exactly one OIDC provider (or a multi-provider scope
  where every provider already sets `issuer-uri`).
- The browser-login path is unchanged: same required fields, same named error messages, same grant
  type. Nothing about webapp/login behaviour was touched.
- A side effect of the `flatten()` change surfaces a previously-silent misconfiguration: a flat block
  that configures real endpoints (`authorization-uri`/`token-uri`/`jwk-set-uri`) but no `client-id`
  used to be dropped without any diagnostic; it now fails fast with the same actionable "client-id
  must be non-blank" error a `providers.oidc.<id>` entry has always produced for the same mistake.

**Negative / accepted trade-offs**

- The decoder-only path now builds a `ClientRegistration` carrying a grant type that has no meaning
  outside this library (`RESOURCE_SERVER_ONLY_GRANT_TYPE`). Anything that inspects
  `ClientRegistration.getAuthorizationGrantType()` outside the classes this ADR audited would see an
  unfamiliar value; this is accepted because no such code was found in the codebase or expected of
  hosts, since the object is never exposed as a bean adopters wire login flows against. This does
  not produce a Spring `WARN`: `Builder#validateAuthorizationGrantTypes()` only logs when a grant
  type's *value* case-insensitively matches one of Spring's predefined constants without `.equals()`
  matching it (a near-miss, e.g. wrong casing on a real grant type) — the marker's URN value matches
  none of them, so the loop that would log never fires for it. `getRedirectUri()` remains set to
  whatever `resolveRedirectUri` computes even for `SKIPPED` providers, since nothing downstream reads
  it there; it is not cleared for symmetry.
- CSL still builds a full `ClientRegistration` object for a resource-server-only provider, rather
  than adopting Spring's own no-client resource-server model
  (`NimbusJwtDecoder.withJwkSetUri(...)`/`JwtDecoders.fromIssuerLocation(...)`) directly. This keeps
  the change contained to `ScopedClientRegistrationFactory` instead of restructuring the ~12 classes
  in the `oidc` package that currently assume every provider has a `ClientRegistration`
  (`IssuerAwareJWSKeySelector`, `IssuerAwareTokenValidator`, `TokenValidatorFactory`,
  `ScopedOidcClaimsProviderFactory`, and others). A future ADR can revisit this if the
  `ClientRegistration`-shaped detour becomes a real maintenance cost.

## Alternatives Considered

- **Revert to the pre-CSL (camunda/camunda 8.9) behaviour: no explicit completeness check at all,
  relying solely on Spring's own `ClientRegistration.Builder` validation.** Rejected — Spring's own
  builder still requires `authorization-uri`/`token-uri` for the `AUTHORIZATION_CODE` grant type, and
  its error (`"authorizationUri cannot be empty"`) names neither the provider nor the configuration
  property — exactly the deficiency CSL's own completeness and URL-absoluteness checks exist to fix
  for the browser-login path. Reverting would regress webapp diagnostics to solve a problem that only
  affects the API-only case, which doesn't need the `AUTHORIZATION_CODE` grant type in the first
  place.
- **Add an adopter-facing `camunda.security.authentication.oidc.mode=resource-server` (or similar)
  property, read explicitly instead of inferred from `LoginRouteChecks`.** Rejected — the calling code
  already knows, deterministically, whether it derives a login route from the configuration; a
  duplicate, adopter-set flag would only create a way for the two to disagree, with no expressive
  gain (there is exactly one axis of variation, and the code already carries it).
- **Bypass `ClientRegistration` entirely for the decode-only path**, building the `JwtDecoder`
  directly from `jwk-set-uri`/`issuer-uri` the way a pure Spring resource server would. Rejected for
  now as a larger restructuring than the actual problem (unwanted required fields) needs — the marker
  grant type reaches the same practical outcome (no `client-id`/`redirect-uri`/`authorization-uri`/
  `token-uri` required) inside the existing model, without touching the dozen classes that assume a
  `ClientRegistration` exists per provider. See "Negative / accepted trade-offs" above.
- **Reuse an existing Spring `AuthorizationGrantType` constant** (`JWT_BEARER`, `DEVICE_CODE`,
  `TOKEN_EXCHANGE`) instead of a private marker. Rejected — each carries real OAuth2 semantics this
  registration doesn't have, and could be mistakenly matched by a Spring `OAuth2AuthorizedClientProvider`
  chain if the registration were ever exposed to one; a synthetic, CSL-namespaced URN cannot collide
  with anything real.
