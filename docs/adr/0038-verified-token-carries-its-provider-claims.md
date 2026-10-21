---
status: Accepted
---

# ADR-0038: A verified token carries the principal claims of the provider that verified it

**Deciders**: Timothy Cline

## Status

Accepted. Supersedes one decision of [ADR-0024](0024-per-issuer-token-claims-converter-map.md), see [Supersedes](#supersedes). Every other decision of ADR-0024, and all of [ADR-0034](0034-named-providers-inherit-principal-claims.md), stay in force.

## Context

[ADR-0024](0024-per-issuer-token-claims-converter-map.md) maps a bearer token with the claim settings (`username-claim`, `client-id-claim`, `prefer-username-claim`) of the provider that issued it. `OidcTokenAuthenticationConverter` finds that provider through `TokenClaimsConvertersByIssuer`: one map from issuer to claim converter, built from the global provider configuration.

The decoders do not route tokens by one global rule:

- The default decoder routes by its own repository's providers, or by the registrations of a host repository.
- Each scoped API chain builds its own decoder from the providers of its scope (`ScopedJwtDecoderFactory`), and a scope can declare other providers, or other claim settings, than the global configuration.
- Since [#61896](https://github.com/camunda/camunda/issues/61896), a decoder also accepts a token whose issuer differs from a configured issuer-uri only by a trailing slash.

A map keyed by issuer alone cannot know which of these decoders verified a token. An example:

| | Provider A | Provider B |
|---|---|---|
| Configured `issuer-uri` | `https://idp` | `https://idp/` |
| `username-claim` | `a_user` | `b_user` |
| In the global configuration | yes | yes |
| In scope S | yes | no |

The identity provider signs its tokens with `iss: https://idp/`, and one such token holds `a_user: alice` and `b_user: bob`.

1. The token reaches the API chain of scope S. S's decoder knows only A, and it accepts `https://idp/` for A, because the two issuers differ only by the trailing slash (#61896). A verifies the token, so the user is Alice.
2. `OidcTokenAuthenticationConverter` then looks the claim settings up in the global map, by the token's issuer `https://idp/`. That key belongs to B, so the map returns B's settings.
3. With B's `username-claim=b_user`, the token authenticates as **Bob**, under the settings of a provider that never verified it.

Changing how the global map treats the two slash forms does not help. If it keeps them apart, it gives this token to B, as above. If it merges them, the first declared provider owns both forms, and a scope that holds only the other provider gets the same mismatch the other way round. The map has one answer per issuer, while each scope can need another.

How can the claim settings of a token always come from the provider that verified it?

## Decision

- **The decoder tags the token.** Every decoder that the library builds (`OidcWebappClientBeansConfiguration#jwtDecoder`, and the decoders of `ScopedJwtDecoderFactory`) returns each token as a `VerifiedJwt`, a subclass of Spring's `Jwt`. It carries the `OidcPrincipalClaims` of the provider whose registration verified the token, resolved with ADR-0034 against the default slot of the decoder's own scope.
- **The owner comes from the decoder's own routing.** `OidcAccessTokenDecoderFactory` gives, with each decoder it selects, the registrationId that verifies a token of each issuer (`OwnedDecoder`). For an issuer-aware decoder that is the registration its `IssuerRegistrations` resolved for the token. For a single registration it is that registration.
- **The converter reads the tag.** `TokenClaimsConvertersByIssuer#forToken` maps a `VerifiedJwt` with a converter for the claims it carries, one converter per distinct set of claims. A token without claims, from the global default slot or from a registration that no provider describes, uses the default converter.
- **The issuer map serves other decoders only.** A token that a decoder of the host verified is no `VerifiedJwt`, and is looked up by issuer, exactly as before #61896.

### Why these particular boundaries

- **On the token, not in a shared lookup.** The decoder is the only component that knows which registration verified a token, and the scope it belongs to. Carrying the answer with the token needs no global state, no shared snapshot of registrations, and no rule that every scope must agree on.
- **A `Jwt` subclass, not a synthetic claim.** Mapping rules and the authorization code read the claims of a token. A claim added by the library could collide with one of the identity provider, or be matched by a rule. A subclass leaves the claims and headers exactly as the identity provider signed them.
- **Plain values in the token.** `Jwt` is serializable, and a session can hold the authentication. The subclass stores the three claims as strings and a boolean, so the tag survives serialization.
- **The default slot keeps the default converter.** A host can register its own `LazyTokenClaimsConverter` bean. Tokens of the global default slot keep using it, as ADR-0024 decided.

## Consequences

- The claim settings of a token come from the provider that verified it, in every scope, and also when two issuer-uris differ only by a trailing slash.
- The per-issuer map no longer has to follow the routing of the decoders. Its lookup is exact again, and it applies only to decoders a host builds itself.
- A scoped token uses the claim settings of its scope. A host that builds scopes from the global configuration, as the orchestration cluster does for physical tenants, gets the same settings as before unless a scope overrides them.
- A host that wraps the library's decoder and rebuilds the `Jwt` loses the tag, and its tokens are looked up by issuer.
- A host that builds `TokenClaimsConvertersByIssuer` with the one-argument constructor keeps the lookup by issuer for every token.

## Alternatives Considered

- **One global rule for issuers that differ only by a slash** (merge them, or keep them apart). Rejected: scopes route by their own providers, and each rule leaves a scope whose decoder and converter disagree.
- **Route the converters by the default decoder's registrations, read from a shared snapshot.** Rejected: it covers the default decoder only, not the scoped decoders, and needs shared state between decoder and converter that must stay consistent across retries and repository changes.
- **Add a claim, such as the registrationId, to the token.** Rejected: see *A `Jwt` subclass, not a synthetic claim*.
- **Per-scope converter beans.** Rejected: `OidcTokenAuthenticationConverter` is one bean for all chains, and the request carries no scope it could select a converter by.

## Supersedes

| Superseded statement | Record | Now |
|---|---|---|
| `OidcTokenAuthenticationConverter` selects the claim converter by the token's issuer, from a map built from the global configuration | ADR-0024 | It uses the claims a `VerifiedJwt` carries, for every decoder the library builds; the issuer map applies to the tokens of other decoders |
