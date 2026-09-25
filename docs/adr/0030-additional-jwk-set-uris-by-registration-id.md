---
status: Accepted
---

# ADR-0030: Key the login flow's supplementary JWK Set URIs by registration ID, not by issuer

**Deciders**: Joaquín Felici, Bojan Mudric

## Status

Accepted

## Context

`OidcUserAuthenticationConverter` decodes the access token of an interactive login so that
authorization-relevant claims come from the access token rather than the ID token. To do that it
builds a per-registration `JwtDecoder`, and that decoder needs the provider's
`additional-jwk-set-uris`, the supplementary key sets an IdP publishes during a key-rotation
window, or that an identity gateway federating several backends serves alongside the primary one.

The converter received those URIs as a `Map<String, List<String>>` keyed by **issuer URI**. A
`ClientRegistration` only carries an issuer when the provider is configured with `issuer-uri`;
configured instead with explicit `jwk-set-uri`/`authorization-uri`/`token-uri`, it has none. The
lookup therefore resolved nothing for such a provider. The host that supplies the map also built it
with a `getIssuerUri() != null` filter, so there was no entry to find in the first place, and the
converter's own `issuerUri != null` guard, added to avoid an NPE on an unmodifiable map rather than
as a fix, made that outcome silent.

The failure mode is the worst kind: `decodeAccessToken` swallows the `JwtException` at `WARN`,
`getClaims` logs `Falling back to ID Token claims`, and the login succeeds with claims sourced from
the ID token. Claims that exist only on the access token are simply missing, and nothing surfaces as
an error. [ADR-0028](0028-oidc-userinfo-fail-soft-login.md) makes that fallback thinner than it used to be:
a UserInfo failure no longer blocks the login, so the principal attributes the fallback reads can
now be ID-token-only. A deployment can therefore reach a state where the access token did not
decode and UserInfo did not answer, leaving the smallest claim set of all, which makes getting the
access-token decode right more load-bearing rather than less.

The bearer-token path never had this problem.
`OidcAccessTokenDecoderFactory#selectAccessTokenDecoder` reads
`providersById.get(registration.getRegistrationId()).getAdditionalJwkSetUris()`.

[ADR-0024](0024-per-issuer-token-claims-converter-map.md) established issuer keying for the
analogous per-provider claim-converter lookup, because a bearer token identifies its provider by its
`iss` claim alone. What key should the *login* flow use, given that it is not restricted to what a
token happens to carry?

## Decision

The registration ID, carried by a new record
`AdditionalJwkSetUrisByRegistrationId` (`io.camunda.security.spring.converter`) wrapping
`Map<String, List<String>>`.

`OidcUserAuthenticationConverter#getJwtDecoder` resolves supplementary URIs with
`additionalJwkSetUris.get(clientRegistration.getRegistrationId())` and no longer reads the
registration's issuer at all. The five- and six-argument constructors take the record in place of
the issuer-keyed `Map`; the four-argument constructor is unchanged, and an absent, empty or `null`
lookup behaves exactly as before.

CSL registers the lookup itself as
`OidcBeansConfiguration#additionalJwkSetUrisByRegistrationId`, built from
`OidcProviderConfigurationPort.getOidcAuthenticationConfigurations()`: every provider that declares
at least one non-blank `additional-jwk-set-uris` entry, **regardless of whether it declares an
issuer**. It is `@ConditionalOnMissingBean`, so a host can substitute its own.

### Why these particular boundaries

- **Registration ID, not issuer, for the login flow.** `OAuth2AuthenticationToken` carries
  `getAuthorizedClientRegistrationId()`: the login flow knows exactly which registration produced
  the session, so it never has to infer the provider from token content. That makes the key total,
  since every provider has a registration ID and only some have an issuer, and it sidesteps the
  shared-issuer ownership question entirely, rather than resolving it the way
  [ADR-0024](0024-per-issuer-token-claims-converter-map.md) had to. This class already keys
  `preferIdTokenClaimsByRegistrationId` and its own `jwtDecoders` cache the same way, so the lookup
  now agrees with its neighbours.
- **No issuer-ownership dedup when building the bean.** `buildAdditionalJwkSetUrisByIssuer` in
  `OidcAccessTokenDecoderFactory` runs collisions through `IssuerOwnership` and drops the loser's
  URIs, because two registrations sharing an issuer must resolve to one set of keys for a bearer
  token that names only that issuer. Registration IDs are unique by construction, so there is no
  collision to arbitrate and no `WARN` to emit.
- **A dedicated record, not a bare `Map`.** Spring intercepts any injection point whose declared
  type is exactly `java.util.Map` and collects same-value-type beans keyed by bean name instead of
  looking for a `Map` bean, so a raw parameter would receive the wrong thing once any other
  `List<String>`-valued bean exists. It is the reason `TokenClaimsConvertersByIssuer` is a record
  too.
- **Replacing the parameter rather than overloading alongside it.** An issuer-keyed
  `Map<String, List<String>>` and a registration-keyed one share an erasure, so they cannot coexist
  as overloads. Keeping the old parameter under a wrapper type would leave a lookup in the library
  that is structurally incapable of describing a provider without an issuer, reachable by any host
  that had not migrated, and failing the same silent way. A compile error at the one `super(...)`
  call that passes it is a better outcome than dropped claims.

## Consequences

**Positive**

- `additional-jwk-set-uris` now takes effect on the interactive login flow whether or not the
  provider declares `issuer-uri`, closing a silent claim-loss path that had no error signal at all.
- Hosts no longer hand-build the map: the CSL bean replaces the host-side helper, and with it the
  host's "Multiple OIDC providers share the same issuer URI with different additional JWKS URIs"
  startup failure, which existed only because issuer keying forced the question.
- The login flow and the bearer flow now derive supplementary key sets from the same source with
  the same per-provider granularity.

**Negative / accepted trade-offs**

- **A source-incompatible change to a public constructor.** `camunda/camunda`'s
  `ProviderAwareOidcUserAuthenticationConverter` extends this class and passes the issuer-keyed map
  through `super(...)`; that call must be updated in lockstep. It is the only such call site: a
  GitHub-wide search finds no other consumer, and Optimize's own wiring uses the four-argument
  constructor. CSL publishes no deprecation-cycle guarantee at 1.0.x.
- **The fix is not opt-in, and it changes behaviour on existing configuration.** A deployment that
  already sets `additional-jwk-set-uris` on a provider with no `issuer-uri` has been silently
  running on ID-token claims; once the host passes the CSL-supplied lookup, the same configuration
  starts decoding the access token successfully and claims come from there instead. That is the
  point of the fix, but an operator who had come to depend on the ID-token claims, knowingly or
  not, can see different authorization results after an upgrade with no configuration change of
  their own. The escape hatch already exists and needs no new property:
  `camunda.security.authentication.oidc.prefer-id-token-claims=true` short-circuits the
  access-token decode for that registration.
- Two adjacent lookups in `io.camunda.security.spring.converter` are now keyed differently
  (`TokenClaimsConvertersByIssuer` by issuer, this one by registration ID). The difference is
  intrinsic, since a bearer token offers only `iss` while a login offers the registration ID, but it
  is one more thing for a reader to hold, so both records say in their Javadoc which key they use
  and why.
- A host that registers its own `AdditionalJwkSetUrisByRegistrationId` bean must key it by
  registration ID; a mis-keyed override fails exactly as silently as the bug this ADR removes.
  Nothing validates the keys against the configured providers.

## Alternatives Considered

- **Pass `Map<String, OidcConfiguration> providersById` and read `getAdditionalJwkSetUris()` in the
  converter.** This is literally the shape `selectAccessTokenDecoder` uses, and it would also give
  the converter the per-provider settings it currently receives as a separate
  `preferIdTokenClaimsByRegistrationId` map. Rejected for now: it widens the converter's contract
  from "the URIs it needs" to "the whole provider configuration", and collapsing the two maps is a
  refactor of its own that this bug fix should not carry. Worth revisiting if a third
  per-registration setting appears.
- **Keep the issuer-keyed map and fall back to it when the registration-keyed lookup misses.**
  Source-compatible, and the shape [#663](https://github.com/camunda/camunda-security-library/pull/663)
  used for its own additive change. Rejected, because it keeps the broken path reachable and silent, doubles
  the resolution logic, and makes the two 6-argument constructors an ambiguous "biggest constructor"
  for Mockito's `@InjectMocks`.
- **Fix only the host's `getIssuerUri() != null` filter.** Rejected, because a provider with no
  `issuer-uri` still has no key to be filed under, so the map cannot represent it however the host
  builds it. The keying, not the filter, is the defect.
