---
status: Accepted
---

# ADR-0032: Revoke the session refresh token on OIDC logout

**Deciders**: Joaquín Felici

## Status

Accepted

## Context

On OIDC logout CSL invalidates the web session and clears the cookies, which discards the
`OAuth2AuthorizedClient` holding the session's access and refresh tokens. Nothing is ever sent to
the IdP about those tokens. The refresh token therefore stays valid at the authorization server
until its own expiry, so a copy captured from a log, a proxy, or a compromised session store can
keep minting access tokens long after the user believes they signed out.

[ADR-0023](0023-configurable-post-logout-redirect-suppression.md) and
[ADR-0026](0026-per-registration-post-logout-redirect-uri.md) shaped the front-channel half of
logout: the browser-mediated redirect to the provider's `end_session_endpoint`, which ends the
*IdP session*. That redirect says nothing about the tokens this client already holds, and a
provider is free to honour it without invalidating them. Management Identity has revoked the
refresh token on logout since its `GenericAuthentication` SDK, and the Orchestration Cluster never
carried that step over.

Spring Security has no client-side RFC 7009 support at all: there is no revocation analogue of
`OAuth2AccessTokenResponseClient` anywhere in `spring-security-oauth2-client`, so the request has
to be built here. Authenticating it is the awkward part, because a client configured for
`private_key_jwt` needs a signed assertion and the only assertion-building code in the codebase is
bound to Spring's grant-request types.

Where in the logout flow does CSL revoke the session refresh token, and how does it authenticate
that call without duplicating the token endpoint's client-authentication wiring?

## Decision

`RefreshTokenRevocationLogoutHandler` (new, `io.camunda.security.spring.security`) implements
Spring's `LogoutHandler` and POSTs an RFC 7009 revocation request for the session's refresh token.
`ScopedWebappSecurityChainBuilder` registers it via `.addLogoutHandler(...)` on both OIDC webapp
chains, `buildOidcWebappChain` and `buildScopedWebappChain`. The basic-auth chain is untouched.

The revocation endpoint is read from `ClientRegistration.ProviderDetails#getConfigurationMetadata()`
under the standard `revocation_endpoint` key, which issuer discovery already populates and
`ScopedClientRegistrationFactory` already preserves. A new
`camunda.security.authentication.oidc.revocation-endpoint-uri` property is merged into that same
metadata map by `ScopedClientRegistrationFactory#mergeProviderMetadata`, so a deployment that
configures endpoints explicitly instead of discovering them can still opt in. Resolving no endpoint
is not an error: the handler logs at `DEBUG` and does nothing.

Client authentication reuses Spring's `NimbusJwtClientAuthenticationParametersConverter` over a
synthetic `OAuth2RefreshTokenGrantRequest` built from the registration and the tokens being
discarded. The converter returns `null` for any registration that is not on `private_key_jwt` or
`client_secret_jwt`, and that `null` is the signal to fall back to secret-based authentication read
off the `ClientRegistration`.

The signing key is resolved from the OIDC configuration of the scope whose chain the handler sits
on — `primaryOidcSources()` for the primary chain, `flatten(authentication)` for a scoped one —
the same sources `oidcLogoutSuccessHandler` already takes, rather than from the cluster-wide
`OidcProviderConfigurationPort`. A scoped chain may point at its own IdP(s), whose registrationIds
that port has never seen, and may run OIDC while the cluster runs basic auth.

Only `private_key_jwt` and the secret-based methods are supported. `client_secret_jwt` needs an
assertion MAC-signed with the client secret, and CSL has no octet key to sign one with, so such a
registration — reachable only through a host-supplied `ClientRegistrationRepository`, since CSL's
own `CLIENT_AUTHENTICATION_METHODS` does not offer the method — is skipped with a `WARN` rather
than sent an assertion its provider would reject.

Every failure path is fail-soft: the handler catches all exceptions, logs at `WARN` with the
registration id and never the token, and lets logout continue. Two details carry that last
guarantee: the form is written through `body(StreamingHttpOutputMessage.Body)` rather than
`body(Object)`, because `DefaultRestClient#logBody` appends the body object to a `DEBUG` line and a
`MultiValueMap` renders the refresh token and the client credential into it; and failures are
logged by exception type, because `ResourceAccessException` carries the request URI and Spring
strips its query string but not its user-info.

The client does not follow redirects, which is what makes treating a non-2xx as failure more than
a formality: a 3xx arrives as a 3xx rather than being followed into a request that revokes nothing.

### Why these particular boundaries

- **`LogoutHandler`, not the existing `CamundaOidcLogoutSuccessHandler`.** A `LogoutSuccessHandler`
  runs after `SecurityContextLogoutHandler` has invalidated the session, and the session is where
  `HttpSessionOAuth2AuthorizedClientRepository` keeps the authorized client. By then the refresh
  token is unreachable. `LogoutConfigurer` appends its own `SecurityContextLogoutHandler` after
  everything added through `addLogoutHandler`, so a handler registered that way still sees a live
  session, a populated `SecurityContext`, and the authorized client.
- **A synthetic grant request rather than assertion code of our own.** The converter reads only
  `getClientRegistration()` off the request, and produces the same assertion CSL's own default
  token-endpoint wiring produces: same `aud` (the token URI), same `kid` resolution through
  `AssertionJwkProvider`, same per-registration encoder cache. Hand-rolling the JWT would mean a
  second, independently drifting definition of how this deployment authenticates to its IdP, and
  the first symptom of drift would be a silent revocation failure. This matches the default, not
  whatever a host's `OidcTokenEndpointCustomizer` does — see the trade-off below.
- **Its `null` return is the branch, not a re-read of the configured method.** The converter already
  owns the decision of which client-authentication methods produce an assertion. Branching on
  `oidc.getClientAuthenticationMethod()` instead would duplicate that decision in a second place
  and diverge the moment Spring extends the set. The one exception is `client_secret_jwt`, checked
  by name before the request is built: there the question is not "does this method use an
  assertion" — the converter answers yes — but "can this library sign one", and the answer is no.
- **Refresh token only, with `token_type_hint=refresh_token`.** RFC 7009 §2.1 says the server
  SHOULD invalidate the access tokens issued from a revoked refresh token, so revoking the refresh
  token is the single call that covers both. The access token is also about to be discarded with
  the session and is short-lived by construction.
- **Synchronous, on the logout request thread, with fixed short timeouts.** See the trade-off below.
- **No new toggle.** Revocation runs whenever an endpoint resolves. It is strictly more defensive,
  invisible to users, and a deployment that does not want it can decline to publish or configure
  the endpoint.

## Consequences

**Positive**

- A refresh token captured from a logged-out session stops working at logout rather than at its own
  expiry, which shortens the exposure window from hours or days to the length of one request.
- Discovery-based deployments get this with no configuration at all, since `revocation_endpoint` is
  already in the metadata CSL keeps.
- The Orchestration Cluster now matches Management Identity's logout behaviour, closing a gap that
  outlived the migration.

**Negative / accepted trade-offs**

- **Logout now waits on an outbound call to the IdP.** It is bounded by a 2s connect timeout and a
  3s deadline on the whole exchange, and it fails soft, so the worst case is a logout that takes a
  few seconds longer than before and a `WARN` in the log. The deadline has to cover the response
  body, not just each read: a per-read socket timeout — which is what
  `SimpleClientHttpRequestFactory` offers — lets an IdP trickling bytes hold the servlet thread
  serving the logout open indefinitely, so the JDK client is used instead, applying the deadline
  through `HttpRequest.Builder#timeout`. Making it asynchronous would decouple it from session
  invalidation and lose the guarantee that the token is revoked while the refresh token is still
  readable; making the timeouts configurable is property surface nobody has asked for yet.
- **MS Entra is a no-op.** Entra publishes no RFC 7009 revocation endpoint, so Entra deployments
  keep today's behaviour. Management Identity made the same concession in
  `MicrosoftAuthentication`.
- **The revocation call is not covered by the host's observation convention.** The Orchestration
  Cluster instruments its token-endpoint `RestClient` with
  `CustomDefaultClientRequestObservationConvention`; the handler builds its own client, so these
  requests do not appear under the same metrics. Threading a host-supplied client through would mean
  a new SPI for one call.
- **A host that customizes the token endpoint's client authentication is not followed.**
  `OidcTokenEndpointCustomizer` is a host extension point: a host may swap the key source, the
  signing algorithm, the audience, or add assertion claims. This handler builds its own converter
  from CSL's `AssertionJwkProvider` and RS256, so it matches the Orchestration Cluster's
  customizer today but only by construction of both, not by sharing one definition. A host that
  diverges would log in successfully and have every revocation rejected, and fail-soft would hide
  it as a `WARN`. Making the assertion converter a single host-overridable bean that both the
  token endpoint and revocation consume is the real fix; it reshapes an existing SPI and is left
  to follow-up.
- **Revocation only happens on an explicit logout.** A session that simply expires, or one that
  `OAuth2RefreshTokenFilter` force-logs-out because the refresh token already failed, revokes
  nothing. Neither path has a usable refresh token to revoke.

## Alternatives Considered

- **Extend `CamundaOidcLogoutSuccessHandler`.** Rejected: it runs after session invalidation, so the
  authorized client holding the refresh token is already gone. Reordering the chain to fix that
  would put the revocation after the response is committed for the fetch-based logout path.
- **Build the `private_key_jwt` assertion directly with Nimbus.** Rejected: duplicates the
  audience, `kid`, algorithm, and lifetime decisions that the token endpoint's converter already
  makes, in a code path whose failures are invisible.
- **Add an SPI so the host supplies the revocation `RestClient`.** Rejected for now: a new extension
  point for a single fail-soft call, when the only thing the host would add is an observation
  convention. Worth revisiting if revocation metrics are asked for.
- **Share one host-overridable client-authentication converter between the token endpoint and
  revocation.** Deferred, not rejected: it is the correct shape and it is what closes the
  divergence described in the trade-offs, but it changes the contract of
  `OidcTokenEndpointCustomizer`, which hosts already implement. Doing it here would put an SPI
  migration inside a security fix.
- **Revoke asynchronously after logout completes.** Rejected: the refresh token is only readable
  before session invalidation, so an async handoff would have to copy the token out of the session
  and keep it alive past the logout it is meant to end.
- **Gate revocation behind a new property.** Rejected: the presence of a resolvable
  `revocation_endpoint` is already the operator's opt-in, and a second switch would let a
  deployment publish an endpoint and still not use it, which nobody wants.
