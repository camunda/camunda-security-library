---
status: Accepted
---

# ADR-0033: Carry the interactive-login settings in the client registration

**Deciders**: Sebastian Bathke

## Status

Accepted

## Context

This ADR complements [ADR-0030](0030-additional-jwk-set-uris-by-registration-id.md) and does not
supersede it.

`OidcUserAuthenticationConverter` cached the access-token `JwtDecoder` per registration id. A host
registers one converter for every scope, and scopes can share a registration id while differing in
issuer, JWKS, audience, additional JWK Set URIs or `prefer-id-token-claims` (#720). The first scope
to log in after startup then decided the decoder for all of them. Another scope's token could fail
to decode, which loses its claims with only a WARN, or be validated against a looser audience. The
additional-JWKS lookup of ADR-0030 and the `prefer-id-token-claims` map had the same assumption.

`ScopedClientRegistrationFactory` already builds one `ClientRegistration` per scope, and the
authorized client of a login holds the registration of its own scope. The registration already
carries the audiences and the `user-info-required` flag of its scope as metadata.

How does the converter use the settings of the login's own scope, whatever the login order, without
a scope concept in the converter?

## Decision

- **The registration carries the settings.** `ScopedClientRegistrationFactory` adds the issuer, the
  additional JWK Set URIs and `prefer-id-token-claims` of the scope to the registration metadata,
  like the audiences. Each entry is always present, also when empty or false, because it is
  authoritative by presence.
- **The converter reads them from the login's registration.** When an entry is present, it wins over
  the lookup the host passes to the constructor. When it is absent, as on a registration that a host
  builds itself, the converter uses the lookup as before.
- **The validator takes the issuer from the registration.** `TokenValidatorFactory` uses the issuer
  entry when present, and else the providers-map entry as before.
- **The decoder cache key holds every setting the decoder is built from:** registration id, issuer,
  JWK Set URI, audiences and additional JWK Set URIs.
- **Logging.** The decode-failure WARN names the registration id and its issuer, and the fallback
  WARN names the registration id.

### Why these particular boundaries

- **No new host contract.** The registration is already scoped, so the converter does not need to
  know the scope. A host gets the fix with the library update.
- **Same pattern as the audiences.** Metadata entries that are authoritative by presence already
  carry the audiences and `user-info-required` per registration.
- **The cache key comes from the settings, not from object identity.** A registration read back from
  a persistent session is a new object, so an identity key would build a new decoder on every login.
  The number of distinct settings is bounded by configuration.

## Consequences

**Positive**

- Scopes that share a registration id no longer share a decoder, an issuer check, audiences,
  additional JWK Set URIs or `prefer-id-token-claims`. The result no longer depends on login order or
  on a restart.
- Scoped-only deployments get an issuer check where the providers map is empty.
- Hosts need no change. Existing hosts compile, and they keep their behavior unless registrations
  that share an id really differ.

**Negative / accepted trade-offs**

- To read `prefer-id-token-claims`, the converter loads the authorized client also on the ID-token
  path. This is one more lookup in the session.
- A registration built by a host without the metadata entries keeps the lookup by registration id
  (ADR-0030) and the providers-map issuer, so it is not separated per scope.
- A scope with explicit endpoints and no `issuer-uri` gets no issuer check, the same as an unscoped
  provider without an issuer. The signature check against the scope's own JWK Set still applies.
- The WARNs name the issuer, not the scope. The issuer is what tells two scopes on one registration
  id apart.

## Alternatives Considered

- **A host port that returns the scope of a login and the settings of that scope.** Rejected. It adds
  a public contract that every multi-scope host must implement, while the registration already holds
  the scope's settings. The host would still keep its own per-scope maps.
- **Key the cache by registration id plus a scope from the request.** Rejected for the same reason,
  and the converter would need request knowledge it does not have.
- **A per-scope `TokenValidatorFactory` and decoder factory from the host.** Rejected. It is a larger
  extension point, and the registration already carries the issuer and audiences the validator
  needs.
