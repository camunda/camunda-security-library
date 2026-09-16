---
status: Accepted
---

# ADR-0024: Per-issuer claim-converter map for multi-provider bearer-token principal resolution

**Deciders**: Bojan Mudric

## Status

Accepted

## Context

`OidcTokenAuthenticationConverter` always resolved a bearer token's claims with one
`LazyTokenClaimsConverter` — the primary provider's `usernameClaim`/`clientIdClaim`/
`preferUsernameClaim` config — regardless of which configured OIDC provider actually issued the
token. A deployment with multiple `providers.oidc.<id>` registrations using different claim
conventions had every token resolved as if it came from the primary provider, which can
misattribute the principal (wrong claim read, or a client-credentials token misread as a user
token).

`ScopedClientRegistrationFactory#flatten` already merges the flat `oidc.*` block and
`providers.oidc.*` into one registrationId-keyed map, and each entry carries its own issuer and
claim settings. What structure lets `OidcTokenAuthenticationConverter` pick the converter matching
a token's actual issuer, without every host hand-building and maintaining that lookup itself?

## Decision

`TokenClaimsConvertersByIssuer` (`io.camunda.security.spring.converter`), a record wrapping
`Map<String, LazyTokenClaimsConverter>` keyed by issuer URI. `OidcTokenAuthenticationConverter`
gains a three-argument constructor accepting it; a token's `iss` claim looks up the converter,
falling back to the existing default converter when the issuer is absent, unrecognized, or the map
itself is empty.

CSL registers a `TokenClaimsConvertersByIssuer` bean
(`OidcBeansConfiguration#tokenClaimsConvertersByIssuer`) built from every configured provider that
declares an `issuer-uri`, gated on `MembershipPort` and `LazyTokenClaimsConverter` both being
present. The primary/flat provider's entry reuses the existing `LazyTokenClaimsConverter` bean
instance, identified by reference rather than registration-ID key; every other entry gets its own
converter built from that provider's claim settings.

### Why these particular boundaries

- **A dedicated record, not a bare `Map`.** Spring intercepts a bare-`Map`-typed injection point and
  collects same-value-type beans keyed by bean name instead of looking for a `Map` bean — a raw
  `Map<String, LazyTokenClaimsConverter>` parameter would silently receive
  `{"lazyTokenClaimsConverter": <default>}` instead of the issuer-keyed content.
- **Reference identity for the primary entry, not the registration-ID key.** The flat block's
  registration id is configurable (`oidc.registration-id`), and a `providers.oidc.*` entry can reuse
  the default key and overwrite the flat entry in the merged map — a key-based check can silently
  rebuild a converter, or reuse the wrong one, for either misconfiguration.
- **Deterministic dedup order.** `getOidcAuthenticationConfigurations()` returns a `Map.copyOf`,
  whose iteration order is JVM-salted, so when two registrations share an issuer, which one's claim
  config wins is fixed explicitly (flat entry first, then registration ids alphabetically) instead
  of depending on that map's iteration order.
- **Optional collaborator, not a hard dependency.** The two-argument `OidcTokenAuthenticationConverter`
  constructor is preserved, and the bean backs off via `@ConditionalOnBean` when
  `LazyTokenClaimsConverter` is absent — the documented `@Import(OidcBeansConfiguration.class)`
  quickstart doesn't pull in `CamundaAuthenticationBeansConfiguration`, where that bean lives. A host
  on that path keeps working exactly as before instead of failing to start.

## Consequences

**Positive**

- Multi-provider deployments resolve each bearer token's principal using the issuing provider's own
  claim configuration, closing a misattribution risk that existed as long as only one converter was
  possible.
- No new SPI: hosts that already hand-wire `OidcTokenAuthenticationConverter` add one optional
  constructor argument.

**Negative / accepted trade-offs**

- Providers registered only through a per-scope `CamundaSecurityScopeProvider` descriptor
  ([ADR-0013](0013-camunda-security-scope-provider-spi.md)) aren't in this map; their bearer tokens
  keep using the default converter. Tracked as a follow-up
  ([#668](https://github.com/camunda/camunda-security-library/issues/668)).
- A `providers.oidc.<id>` entry that omits `username-claim`/`client-id-claim` gets that
  `OidcConfiguration`'s own defaults, not the flat block's — documented in the adopters guide, not
  solved here.
- The feature is inert for a host that keeps the existing two-argument constructor call; adopting it
  requires a one-line change to the host's own `@Bean` method.

## Alternatives Considered

- **CSL registers `OidcTokenAuthenticationConverter` itself.** Rejected for this change — the
  converter has never been CSL-registered (every host hand-wires it today), and
  [#634](https://github.com/camunda/camunda-security-library/issues/634) already tracks registering
  all six `spring/converter` converters from CSL configuration as one piece of work, including a
  selector property so CSL never registers two converters for the same `Authentication` type. Doing
  it here for one converter only would preempt that issue's design.
- **Warn only when colliding registrations' claim configs actually differ.** Rejected — this is not
  equivalent to the precedent in `buildAdditionalJwkSetUrisByIssuer` (commit `522ee6ef`), which
  silently merges two registrations sharing an issuer because a dropped supplementary JWKS URI only
  risks a validation failure. A dropped claim converter can misattribute the principal, so the WARN
  fires on every collision, deliberately.
