---
status: Accepted
---

# ADR-0020: Issuer-aware `JwtDecoder` for multi-provider OIDC token validation

**Deciders**: Sebastian Bathke

## Status

Accepted

## Context

[ADR-0013](0013-multi-idp-oidc-configuration.md) deliberately punted on multi-provider JWT
validation: "a single decoder cannot correctly validate tokens from multiple IdPs, so the library
refuses to guess." When multiple providers were configured without a flat `oidc.*` block, startup
failed with `IllegalStateException`. Hosts that needed multi-provider token validation had to
register a custom `@Bean JwtDecoder`.

This was acceptable in the short term but blocked OC's adoption of the CSL filter chains
(camunda#38): any OC deployment running with multiple configured IdPs would regress on cutover
because CSL refused to build a multi-issuer decoder.

The monorepo already implemented an issuer-aware decoder in `OidcAccessTokenDecoderFactory`,
`IssuerAwareJWSKeySelector`, and `IssuerAwareTokenValidator`, all of which were ported to CSL
in preceding work. The only missing piece was wiring them into `OidcBeansConfiguration`.

Spring Security offers `JwtIssuerAuthenticationManagerResolver` as an alternative: it routes by
`iss` at the **filter level**, creating one `JwtDecoder` per issuer picked per request. This is
a different shape — it produces a per-issuer `JwtDecoder` and wires into the security filter chain
DSL rather than exposing a single `JwtDecoder` bean. The wider library wiring (resource-server
chain, `OidcUserAuthenticationConverter`, any host bean that injects `JwtDecoder`) all inject
`JwtDecoder`; an issuer-aware *decoder* is the right level for CSL. `JwtIssuerAuthenticationManagerResolver`
also requires discovery metadata for each issuer at startup, which conflicts with the explicit-URI
configuration model CSL supports.

## Decision

Replace the property-reading single-decoder selection logic in `OidcBeansConfiguration#jwtDecoder`
with a registration-count switch:

- **1 registration** (flat block or single `providers.oidc.<id>` entry): `OidcAccessTokenDecoderFactory.createAccessTokenDecoder(reg, additionalJwkSetUris)` — no behavioural change for single-IdP deployments.
- **>1 registrations** (multiple `providers.oidc.*` entries, with or without a flat block): `OidcAccessTokenDecoderFactory.createIssuerAwareAccessTokenDecoder(registrations, additionalJwkSetUrisByIssuer)` — issuer-aware path using `IssuerAwareJWSKeySelector` and `IssuerAwareTokenValidator`.

All registrations for the issuer-aware path must carry an `issuer-uri` (validated at startup by `OidcAccessTokenDecoderFactory.validateClientRegistrationsHaveIssuer`). A token whose `iss` claim matches no configured provider fails with a `BadJwtException` whose message matches `"Unknown issuer '<iss>'. No matching client registration found."` — the message names the issuer to aid diagnosis.

Three new `@ConditionalOnMissingBean` beans are added to `OidcBeansConfiguration`:
`JWSKeySelectorFactory`, `TokenValidatorFactory`, and `OidcAccessTokenDecoderFactory`. Hosts can
override each independently.

`TokenValidatorFactory.createTokenValidator` was updated to add `JwtIssuerValidator` when the
provider's `issuer-uri` is set. The old `jwtDecoder` code called `JwtValidators.createDefaultWithIssuer`
explicitly; `TokenValidatorFactory` must carry the same responsibility so validation is preserved
on both single-issuer and multi-issuer paths.

The startup-time `IllegalStateException` for "multiple providers without a flat block" is removed.

A host-supplied `@Bean JwtDecoder` continues to take precedence via `@ConditionalOnMissingBean`.

## Why issuer-aware decoder over `JwtIssuerAuthenticationManagerResolver`

| Concern | Decoder-level routing | `JwtIssuerAuthenticationManagerResolver` |
|---|---|---|
| Injection shape | Single `JwtDecoder` bean — matches every injection point in CSL | Wires into filter chain DSL only — requires changing chain configuration |
| Discovery requirement | No — works with explicit JWK set URIs | Yes — requires discovery endpoint for each issuer |
| Per-provider `additional-jwk-set-uris` | Native — `IssuerAwareJWSKeySelector` queries per-provider JWKS sources | Not composable — each issuer would need a manually-built resolver |
| Monorepo alignment | Matches OC's existing `OidcAccessTokenDecoderFactory` | Diverges from monorepo approach |

## Consequences

**Positive**

- OC adoption of CSL filter chains no longer blocked by multi-provider JWT validation.
- Single-IdP deployments are unaffected — the decoder factory delegates to the same Nimbus path as before.
- The startup error for multi-provider without flat block is removed, replaced by a runtime `BadJwtException` for unknown issuers (more informative: names the offending issuer, surfaces at request time rather than startup when testing without a real IdP).
- Per-issuer `additional-jwk-set-uris` works on the issuer-aware path via `IssuerAwareJWSKeySelector`.
- Hosts can override `JWSKeySelectorFactory`, `TokenValidatorFactory`, `OidcAccessTokenDecoderFactory`, or `JwtDecoder` independently via `@ConditionalOnMissingBean`.

**Negative / accepted trade-offs**

- The new `jwtDecoder` bean requires `ClientRegistrationRepository` to implement `Iterable<ClientRegistration>`. `InMemoryClientRegistrationRepository` (the library default) does. Hosts using a custom non-iterable repository must register their own `@Bean JwtDecoder` — startup fails with an `IllegalStateException` naming the requirement.
- All multi-provider registrations must have an `issuer-uri`. A multi-provider deployment that uses explicit endpoints without `issuer-uri` is invalid configuration — startup fails at `validateClientRegistrationsHaveIssuer` with a message listing the offending registration ids.
- The per-provider clock skew (`OidcConfiguration.clockSkew`) is not applied per-registration in `TokenValidatorFactory`; all registrations use `OidcConfiguration.DEFAULT_CLOCK_SKEW` (60 s). Hosts needing per-registration clock skew override `TokenValidatorFactory`.

## Alternatives Considered

- **Keep the startup-time `IllegalStateException` and require a flat block.** Rejected — blocks OC adoption and every multi-IdP host must write boilerplate `JwtDecoder` configuration.
- **Use `JwtIssuerAuthenticationManagerResolver`.** Rejected — wrong injection shape and requires discovery metadata (see table above).
- **Build one `JwtDecoder` per issuer and expose a `List<JwtDecoder>` bean.** Rejected — doesn't compose with the single-`JwtDecoder` contract that all filter chains and `OidcUserAuthenticationConverter` inject.
