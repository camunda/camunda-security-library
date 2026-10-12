---
status: Accepted
---

# ADR-0033: Resolve the interactive-login access-token decoder per scope

**Deciders**: Timothy Cline

## Status

Accepted. Complements [ADR-0030](0030-additional-jwk-set-uris-by-registration-id.md); does not
supersede it.

## Context

`OidcUserAuthenticationConverter` cached the access-token `JwtDecoder` per registration id. A host
registers one converter for every scope, and scopes can share a registration id while differing in
issuer, JWKS, audience, additional JWK Set URIs or `prefer-id-token-claims` (#720). The first scope
to log in after startup then decided the decoder for all of them: another scope's token could fail
to decode (claims silently lost, WARN only), or be validated against a looser audience. The
additional-JWKS lookup ([ADR-0030](0030-additional-jwk-set-uris-by-registration-id.md)) and the
`prefer-id-token-claims` map carried the same assumption.

The converter sees only the `OAuth2AuthenticationToken` and an injected request, so it has no way to
tell which scope a login belongs to. What can the library do so that each scope's login is decoded
and validated from that scope's own configuration, whatever the login order, without `core` learning
what a scope is?

## Decision

- **Cache key.** The decoder cache key is the scope, the registration id and the registration's own
  issuer, JWK Set URI and audiences. Registrations that differ in any of these never share a
  decoder, even when the host supplies no scope.
- **Validator issuer.** `TokenValidatorFactory` takes the expected issuer from the login's own
  `ClientRegistration` and falls back to the providers-map entry only when the registration has
  none. A scope that overrides `oidc` therefore validates against its own issuer, and still gets an
  issuer check when the providers map is empty (scoped-only mode).
- **Host SPI.** `io.camunda.security.spring.spi.OidcLoginScopePort` supplies an opaque scope key for
  the current login, plus that scope's additional JWK Set URIs and `prefer-id-token-claims` map. It
  is passed through `OidcUserAuthenticationConverter.scoped(...)`. The existing public constructors
  wrap their arguments in `OidcLoginScopePort.unscoped(...)` and behave as before.
- **Logging.** Decode-failure and ID-token-fallback WARNs name the registration id and the scope.

ADR-0030's registration-id keying is unchanged: within one scope, the registration id is still the
key of the additional-JWKS lookup.

### Why these particular boundaries

- **The cache key includes registration-derived fields, not only the scope.** The scope key is
  host-supplied and optional. Deriving part of the key from the `ClientRegistration` makes the bug
  impossible for registrations that really differ, with no host change.
- **The port lives in the starter, not `core`.** Its signature speaks `jakarta.servlet` types, and
  `core` must stay free of them and of any notion of a physical tenant. The scope stays an opaque
  string (ADR-0013, ADR-0019).
- **One port for scope, JWKS and preference.** The three answers are all "settings of this login's
  scope", so a host implements one contract instead of three.
- **A static factory, not another public constructor.** A five-argument overload taking the port
  would be source-ambiguous with the existing five-argument constructor for a call ending in
  `null`. `scoped(...)` is unambiguous, and the protected constructor puts the port first for the
  same reason, so host subclasses can still reach it.
- **Registration issuer wins in the validator.** The registration belongs to the login at hand;
  the providers-map entry for the same id may belong to another scope.

## Consequences

**Positive**

- Scopes that share a registration id no longer share decoders, issuer validation or audiences, and
  the outcome no longer depends on login order or on a restart.
- Scoped-only deployments get an issuer check where the providers map is empty.
- Existing hosts compile and behave unchanged.

**Negative / accepted trade-offs**

- A host with scopes sharing a registration id must implement `OidcLoginScopePort` to get per-scope
  additional JWKS and `prefer-id-token-claims`; without it only the registration-derived parts are
  separated.
- One decoder is cached per distinct (scope, registration) pair, so memory grows with the number of
  scopes.
- A registration whose issuer is set only through the providers map (not on the registration) still
  validates against that map entry, which is what a host without scopes gets today.

## Alternatives Considered

- **Key the cache by scope only.** Rejected — it needs a host change for every deployment and does
  nothing for a host that has not implemented the port.
- **Key every lookup by `(scope, registrationId)` in new map types.** Rejected — it pushes scope
  vocabulary into every host-supplied bean and would need a superseding ADR for ADR-0030's lookup,
  for no gain over asking the port.
- **A per-scope `TokenValidatorFactory` and decoder factory supplied by the host.** Rejected for
  now — it is the heavier extension point, and the registration already carries the issuer and
  audiences the validator needs.
- **A public five-argument constructor taking the port.** Rejected — source-ambiguous with the
  existing constructor (see above).
