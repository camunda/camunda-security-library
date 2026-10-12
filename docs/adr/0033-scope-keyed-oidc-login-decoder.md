---
status: Accepted
---

# ADR-0033: Resolve the interactive-login access-token decoder per scope

**Deciders**: Timothy Cline

## Status

Accepted. Complements ADR-0030; does not supersede it.

## Context

`OidcUserAuthenticationConverter` cached the access-token `JwtDecoder` per registration id. A host
registers one converter for every scope, and scopes can share a registration id while differing in
issuer, JWKS, audience, additional JWK Set URIs or `prefer-id-token-claims` (#720). The first scope
to log in after startup then decided the decoder for all of them: another scope's token could fail
to decode (claims silently lost, WARN only), or be validated against a looser audience.

## Decision

- The decoder cache key is the scope, the registration id and the registration's own issuer, JWK Set
  URI and audiences. Registrations that differ in any of these never share a decoder, even when the
  host supplies no scope.
- A new host SPI, `OidcLoginScopeResolver`, supplies an opaque scope key for the current login and
  the scope's additional JWK Set URIs and `prefer-id-token-claims` map. `core` never learns what a
  scope means (ADR-0013, ADR-0019). The existing constructors wrap their arguments in
  `OidcLoginScopeResolver.unscoped(...)`, so current hosts keep working unchanged.
- Decode-failure and fallback WARN logs name the registration id and the scope.

ADR-0030's registration-id keying of the lookup is unchanged: within one scope, the registration id
is still the key.

## Consequences

- A host with scopes that share a registration id implements `OidcLoginScopeResolver` to get
  per-scope additional JWKS and `prefer-id-token-claims`; without it only the registration-derived
  parts (JWKS, issuer, audiences) are separated.
- One decoder is cached per distinct (scope, registration) pair.
