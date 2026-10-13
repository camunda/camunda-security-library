---
status: Accepted
---

# ADR-0033: Carry the interactive-login settings in the client registration

**Deciders**: Sebastian Bathke

## Status

Accepted

## Context

This ADR adds to [ADR-0030](0030-additional-jwk-set-uris-by-registration-id.md). It does not replace
it.

`OidcUserAuthenticationConverter` cached one access-token decoder per registration id. A host uses
one converter for all scopes. Two scopes can use the same registration id with a different issuer,
JWK Set, audience, additional JWK Set URIs or `prefer-id-token-claims` (#720). The first login after
startup then set the decoder for all scopes. The token of another scope can then fail to decode.
The user then loses the claims of the access token, and only a WARN shows it. Or the token passes an
audience check that is too weak. The ADR-0030 lookup and the `prefer-id-token-claims` map have the
same problem.

`ScopedClientRegistrationFactory` builds one registration per scope. The authorized client of a
login holds the registration of its scope. This registration already holds the audiences and the
`user-info-required` flag of its scope.

How can the converter use the settings of the scope of the login, without a scope concept in the
converter?

## Decision

- **The registration holds the settings.** `ScopedClientRegistrationFactory` writes the issuer, the
  additional JWK Set URIs and `prefer-id-token-claims` of the scope into the registration metadata.
  It always writes each entry, also when the value is empty or false. An entry that exists always
  wins. `ClientRegistrationMetadata` owns the keys, the type checks, and the read and write.
- **The converter reads the settings from the registration of the login.** If the registration has
  no entry, the converter uses the lookup from the host, as before. This applies to a registration
  that a host builds itself.
- **The validator reads the issuer from the registration.** If the registration has no issuer entry,
  the validator uses the providers map, as before.
- **The decoder cache key holds all settings of the decoder:** registration id, issuer, JWK Set URI,
  audiences and additional JWK Set URIs.
- **Logs.** The WARN for a decode failure names the registration id, the client id and the issuer.
  The log removes credentials and query values from the issuer. For a failed claim check it gives
  the message, which names the claim. For other failures it gives only the exception type, because
  a key-source message can contain the JWK Set URL. The `decodeAccessToken` hook logs at DEBUG, so
  one failure gives one WARN. The WARN for the fallback names the registration id.
- **The converter loads the authorized client once per login.** `getClaims` reads the
  `prefer-id-token-claims` entry from it and passes it to the access-token decode.

### Why these particular boundaries

- **No new host contract.** The registration already belongs to the scope. The converter does not
  need to know the scope. A host gets the fix when it updates the library.
- **The registration entry wins, also when it is empty or false.** The host lookups and the
  providers map are keyed by registration id, so they can hold the value of another scope. A
  fallback to them for an empty entry gives the cross-scope sharing of #720 again. In the library
  wiring, and in the current hosts, the lookups, the providers map and the registrations come from
  the same `OidcConfiguration` objects, so a host sees no other value than before. Only a host that
  builds a lookup or the providers map from other data sees the change.
- **Same pattern as the audiences.** The audiences and `user-info-required` use the same type of
  metadata entry.
- **The cache key uses the settings, not the object.** A persistent session gives a new registration
  object for each login. A key on the object makes a new decoder for each login. The configuration
  sets a limit on the number of different settings.

## Consequences

**Positive**

- Scopes with the same registration id do not share a decoder, an issuer check, audiences,
  additional JWK Set URIs or `prefer-id-token-claims`. The login order and restarts do not change
  the result.
- A deployment with scopes only gets an issuer check, also when the providers map is empty.
- Hosts need no change. Their code compiles. The behavior changes only when registrations with the
  same id have different settings. This change is the fix.

**Negative / accepted trade-offs**

- To read `prefer-id-token-claims`, the converter loads the authorized client before it decides
  which claims to use. `getClaims` keeps it in a local variable and passes it to
  `getAccessTokenClaims(token, client)`, so it loads it only once per login.
- `getClaims` no longer calls the one-argument `getAccessTokenClaims(token)`, so a subclass that
  overrides only that method no longer changes the conversion. The method is deprecated and points
  to the two-argument form. No known host overrides it.
- A registration that a host builds itself has no metadata entries. It keeps the ADR-0030 lookup and
  the issuer of the providers map. Scopes do not get their own settings for it.
- A scope with explicit endpoints and no `issuer-uri` gets no issuer check. This is the same as for
  a provider without scopes. The signature check against the JWK Set of the scope still applies.
- The WARNs name the client id and the issuer, not the scope. The converter does not know the scope.
  Two scopes with the same registration id usually have a different client id or issuer. If both
  are the same, the WARN cannot show the scope.

## Alternatives Considered

- **A host port that gives the scope of a login and the settings of that scope.** Rejected. Each host
  with scopes must then implement a new public contract. The registration already holds the
  settings, and the host must still keep its own map for each scope.
- **A cache key from the registration id and a scope from the request.** Rejected for the same
  reason. Also, the converter cannot get the scope from the request.
- **A `TokenValidatorFactory` and a decoder factory per scope from the host.** Rejected. This is a
  larger extension point. The registration already holds the issuer and audiences that the validator
  needs.
