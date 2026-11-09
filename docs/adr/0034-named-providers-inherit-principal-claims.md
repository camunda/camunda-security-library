---
status: Accepted
---

# ADR-0034: Named providers inherit the principal claims of the default slot

**Deciders**: Sebastian Bathke

## Status

Accepted. Supersedes one accepted trade-off of [ADR-0024](0024-per-issuer-token-claims-converter-map.md), see [Supersedes](#supersedes). Every other decision of ADR-0024 stays in force.

## Context

[ADR-0024](0024-per-issuer-token-claims-converter-map.md) resolves the principal of a bearer token with the claims of the provider that issued it. A named provider (`providers.oidc.<id>`) that does not set `username-claim`, `client-id-claim` or `prefer-username-claim` got the defaults of `OidcConfiguration`: `sub`, no client-id claim, and `false`. ADR-0024 accepted this and did not solve it.

The multi-IdP docs tell operators to set these claims once, in the default slot (`oidc.*`), for all providers. Before the per-issuer converters, the default slot applied to all tokens. A setup that follows the docs thus gets another principal for the tokens of a named provider after the upgrade (#724). A user resolves to `sub`, and an M2M client resolves to a user. `groups-claim` already falls back to the default slot.

`OidcConfiguration` initializes `usernameClaim` to `sub` and `preferUsernameClaim` to `false`, so a value that the provider does not set looks the same as a value that it sets to the default.

How can a named provider use the global claims that it does not set, and still use a claim that it sets to the default value?

## Decision

- **`OidcConfiguration` records which principal claims the configuration sets.** The setters and the builder set a flag (`isUsernameClaimSet()`, `isClientIdClaimSet()`, `isPreferUsernameClaimSet()`). The Spring binder calls a setter only for a property that the configuration has. The getters do not change.
- **`OidcPrincipalClaims.resolve(provider, defaultSlot)` applies the rule for each claim:** the value of the provider if it sets one, else the value of the default slot, else the default.
- **The per-issuer converters use this rule** for each named provider. The default slot keeps the default converter.
- **Hosts use `OidcPrincipalClaims.resolve`** where they build claim converters from providers themselves, for example per scope.

### Why these particular boundaries

- **A flag per claim, not a `null` default.** A `null` username claim would change `getUsernameClaim()` for every host. The flag keeps the getter and adds the missing information.
- **A resolver, not a change to `flatten`.** `flatten` returns the configured objects. To apply the rule there, it must copy or change them, and a host can share one provider object between scopes. The resolver reads the two objects and changes nothing.
- **Per claim, not per provider.** A provider can set its own `username-claim` and use the global `client-id-claim`. The rule must look at each claim alone.

## Supersedes

| Superseded statement | Record | Now |
|---|---|---|
| A `providers.oidc.<id>` entry that omits `username-claim`/`client-id-claim` gets that `OidcConfiguration`'s own defaults, not the flat block's | ADR-0024 | It gets the value of the default slot for each claim that it does not set, and the default only when the default slot does not set it either |

## Consequences

**Positive**

- A setup that sets the claims only in the default slot resolves the same principal for every provider, as before the per-issuer converters.
- A provider can still set its own claims, also to the default values.
- The rule is in one place, and hosts can use it for their own converters.

**Negative / accepted trade-offs**

- A host that builds `OidcConfiguration` itself must use the setters or the builder for a claim to count as set. Code that copies a configuration must copy through the setters only for the claims that the source sets.
- The behavior changes for a named provider that relies on the defaults while the default slot sets other claims. Such a setup must now set the defaults on the provider.

## Alternatives Considered

- **Change the defaults to `null` and apply them at the use sites.** Rejected. It changes `getUsernameClaim()` for every host, and each use site must apply the default again.
- **Apply the rule in `flatten`.** Rejected. It must copy each provider, with all of its fields, or change a shared object (see above).
- **Treat a default value as not set.** Rejected. A provider could then not use `sub` or `false` while the default slot sets another value.
