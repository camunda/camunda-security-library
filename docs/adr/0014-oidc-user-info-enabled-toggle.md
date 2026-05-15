---
status: Accepted
---

# ADR-0014: Per-provider `userInfoEnabled` toggle on the OIDC webapp chain

**Deciders**: Ben Sheppard

## Status

Accepted

## Context

[ADR-0006](0006-central-security-filter-chains.md) centralised the OIDC webapp filter chain in CSL. By default, Spring Security's `oauth2Login` DSL fetches the IdP's UserInfo endpoint after token exchange and merges the returned claims into the `OidcUser`. The `ClientRegistration` carries the UserInfo URL — either populated by OIDC discovery when `issuer-uri` is set, or by the explicit `user-info-uri` property when discovery is not used.

Two deployment realities make "always fetch UserInfo" wrong as a default:

1. Some IdPs do not implement `/userinfo` at all, or implement it but return claims the host does not want surfaced (overlap with claim names the host expects to drive from the ID token).
2. The camunda monorepo has long-standing deployments that actively disable the fetch (see [`OidcAuthenticationConfiguration.userInfoEnabled`](https://github.com/camunda/camunda/blob/main/security/security-core/src/main/java/io/camunda/security/configuration/OidcAuthenticationConfiguration.java)). When OC adopts the CSL filter chain (camunda#52121), losing the toggle would regress those deployments.

The `OidcUserService` extension hook in [`OidcWebappSecurityConfiguration`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/OidcWebappSecurityConfiguration.java) is the existing escape valve, but it is all-or-nothing — a host has to hand-roll an entire `OidcUserService` just to skip the fetch.

[ADR-0013](0013-multi-idp-oidc-configuration.md) makes OIDC configuration additive across the flat block and `providers.oidc.<id>.*`. Since each entry binds to the same `OidcConfiguration` type, a per-entry boolean flag automatically becomes per-provider.

The core question this ADR answers is:

> What property shape and wiring should CSL expose so a host can disable the UserInfo fetch, individually per IdP in a multi-provider setup, without writing code or replacing the `OidcUserService`?

## Decision

CSL exposes a boolean `userInfoEnabled` property on `OidcConfiguration`, defaulting to `true`, applied at `ClientRegistration` construction by nulling `userInfoUri` when the flag is false. The name, default, and application mechanism mirror the monorepo's [`ClientRegistrationFactory`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/ClientRegistrationFactory.java) so OC adoption is a drop-in.

### Property shape

```yaml
camunda:
  security:
    authentication:
      # Flat (single-IdP):
      oidc:
        user-info-enabled: true   # default

      # Per-provider (multi-IdP), under the additive ADR-0013 shape:
      providers:
        oidc:
          keycloak:
            user-info-enabled: true
          azure:
            user-info-enabled: false
```

`userInfoEnabled` lives on `OidcConfiguration`. Because both the flat block and each `providers.oidc.<id>` entry bind to that type, the flag is per-provider by construction — no additional plumbing needed.

### Wiring

`OidcBeansConfiguration#buildClientRegistration` builds each `ClientRegistration` from its `OidcConfiguration`. After applying the standard fields, it calls `builder.userInfoUri(null)` when `oidc.isUserInfoEnabled()` returns false. This applies uniformly to both branches of `clientRegistrationBuilder`: the discovery branch (`ClientRegistrations.fromIssuerLocation`) where Spring populated the URI from the IdP's `/.well-known/openid-configuration`, and the explicit-endpoints branch where the host supplied `user-info-uri`. Nulling occurs after the builder picks up either source, so the toggle behaves identically regardless of how the URI was obtained.

The `oauth2Login` DSL is untouched. When the registration has no `userInfoUri`, Spring Security skips the UserInfo step entirely; when it has one, the default flow runs.

### Precedence with host-supplied `OidcUserService`

A host bean registered against `OidcUserService` continues to take precedence over the library default — the precedence model from ADR-0006 is unchanged. The toggle and the bean are independent levers:

| `userInfoEnabled` | Host `OidcUserService` | Result |
|---|---|---|
| `true` (default) | absent | Library default `OidcUserService` runs, fetches UserInfo |
| `true` | present | Host `OidcUserService` runs (may or may not fetch) |
| `false` | absent | No UserInfo call — `userInfoUri` is null on the registration |
| `false` | present | Host `OidcUserService` runs against a registration with no `userInfoUri`; host code can still fetch from any URL it chooses |

The library does not try to second-guess the host. A host that registers its own `OidcUserService` is in full control; the toggle only governs the library's default wiring.

### Why these particular boundaries

- **Boolean, not URL.** The URL is already first-class on `OidcConfiguration` (`userInfoUri`) and populated by discovery when `issuer-uri` is set. The decision worth surfacing to operators is "should we call it?" — not "what is its address?" Mirrors the monorepo.
- **Apply post-build by nulling `userInfoUri` on the registration.** Matches the monorepo's [`ClientRegistrationFactory:87-90`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/ClientRegistrationFactory.java). The alternative — gating the `oauth2Login` DSL via `userInfoEndpoint(...)` — would only cover the webapp chain and would leave any downstream consumer that reads `ClientRegistration.ProviderDetails.userInfoEndpoint` (for example, the augmentation cache tracked in [#218](https://github.com/camunda/camunda-security-library/issues/218)) believing UserInfo is reachable. Nulling at the source keeps the contract honest.
- **Default `true`.** Matches Spring Security's out-of-the-box behaviour and matches the monorepo. Disabling fetch is the opt-in for hosts that need it.
- **Per-provider by construction, no global override.** Because the field lives on `OidcConfiguration`, the additive multi-IdP shape from ADR-0013 already expresses per-provider toggles. A separate global override would create ambiguity with no behavioural gain.
- **No interaction with `userInfoAugmentation`.** The augmentation/caching layer (separate feature, [#218](https://github.com/camunda/camunda-security-library/issues/218)) reads UserInfo at request time, not login time. Whether it requires `userInfoEnabled=true` is that feature's decision to make — out of scope here. The data model for `userInfoAugmentation` already exists on `OidcConfiguration` but is not wired.

### Default implementations and override boundaries

| Concern | Default | Override path |
|---|---|---|
| `userInfoEnabled` | `true` (per-provider) | Set `camunda.security.authentication.oidc.user-info-enabled` or `providers.oidc.<id>.user-info-enabled` to `false` |
| Spring's default `OidcUserService` | Library-supplied via `oauth2Login` | Host registers `@Bean OidcUserService` — takes precedence regardless of toggle |
| UserInfo URL source | Discovery (when `issuer-uri` is set) or explicit `user-info-uri` | Property `user-info-uri` overrides the discovered value |

## Consequences

**Positive**

- OC adoption (camunda#52121) preserves customer deployments that disable UserInfo today, with no code change and no property migration — only a path change from `oidc.userInfoEnabled` to `camunda.security.authentication.oidc.user-info-enabled`/`providers.oidc.<id>.user-info-enabled`.
- The mechanism is uniform across the discovery and explicit-endpoint branches. There is one place in `OidcBeansConfiguration#buildClientRegistration` that applies the toggle, regardless of how the URI was obtained.
- Per-provider expression falls out of ADR-0013 with no new code paths. A multi-IdP deployment can fetch from one IdP and skip the other by setting the flag under each entry.
- The toggle composes with the existing `OidcUserService` SPI rather than competing with it. Hosts that need finer control still register their own bean; hosts that only need on/off get a property.

**Negative / accepted trade-offs**

- A host that disables UserInfo and later enables the augmentation layer ([#218](https://github.com/camunda/camunda-security-library/issues/218)) will need to consider the interaction — the augmentation can no longer source claims from `ClientRegistration.userInfoEndpoint`. Accepted: surfacing that conflict belongs to the augmentation feature, not here.
- Nulling `userInfoUri` on the built `ClientRegistration` loses the discovered URL even though the host configured `issuer-uri`. A future change that wanted to re-enable fetch at runtime (without restart) would need to refresh the registration. Accepted as a non-goal — toggling at runtime is not a use case anyone has asked for.

## Alternatives Considered

- **Gate the `oauth2Login` DSL via `userInfoEndpoint(...)` instead of nulling `userInfoUri`.** Rejected — leaves the URL visible on the registration, so any downstream consumer that reads `ProviderDetails.userInfoEndpoint` (notably the augmentation cache under [#218](https://github.com/camunda/camunda-security-library/issues/218)) would incorrectly conclude UserInfo is reachable. Nulling at the source keeps the contract honest and matches the monorepo.
- **Configure the UserInfo URL explicitly instead of toggling a boolean.** Rejected — the URL is already configurable via `user-info-uri` and via discovery. Operators do not want to know the URL; they want to know whether the call happens.
- **Default `false`.** Rejected — diverges from both Spring Security's default and the monorepo's default. Adopters who today rely on UserInfo claims to populate `OidcUser` would regress silently.
- **Expose only a global flag, not per-provider.** Rejected — `OidcConfiguration` is the natural carrier and the additive ADR-0013 shape already makes the flag per-provider for free. A separate global override would add ambiguity without value.
- **Validate that augmentation cannot be enabled when `userInfoEnabled=false`.** Deferred — augmentation wiring is [#218](https://github.com/camunda/camunda-security-library/issues/218); the validation, if needed, belongs there alongside the augmentation bean construction.
