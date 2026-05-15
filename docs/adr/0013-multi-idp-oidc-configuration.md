---
status: Accepted
---

# ADR-0013: Multi-IdP OIDC configuration via additive `providers.oidc.<id>.*` shape

**Deciders**: Ben Sheppard

## Status

Accepted

## Context

[ADR-0006](0006-central-security-filter-chains.md) centralised the OIDC webapp and API filter chains in CSL. The OIDC infrastructure beans live in `OidcBeansConfiguration` and currently bind a single `ClientRegistration` from the flat `camunda.security.authentication.oidc.*` properties. Spring Security's `OAuth2LoginAuthenticationFilter` routes login attempts per provider via `/oauth2/authorization/{registrationId}` URLs — once multiple `ClientRegistration` instances are present, multi-IdP routing works out of the box.

Orchestration Cluster (OC) already supports multi-IdP today. [`AuthenticationConfiguration#getProviders()`](https://github.com/camunda/camunda/blob/main/security/security-core/src/main/java/io/camunda/security/configuration/AuthenticationConfiguration.java) returns a [`ProvidersConfiguration`](https://github.com/camunda/camunda/blob/main/security/security-core/src/main/java/io/camunda/security/configuration/ProvidersConfiguration.java) carrying `Map<String, OidcAuthenticationConfiguration>`. OC's [`OidcAuthenticationConfigurationRepository`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/OidcAuthenticationConfigurationRepository.java) merges that map with the flat block — flat contributes a registration when `clientId` is non-blank, and the providers map is then merged on top via `Map#putAll` so a colliding provider id overwrites the flat entry. When OC adopts the CSL filter chains (camunda#52121), customers running with multiple configured IdPs would regress on day one unless CSL ships the same behaviour.

This work was previously flagged as out-of-scope on [#54](https://github.com/camunda/camunda-security-library/issues/54) and [#60](https://github.com/camunda/camunda-security-library/issues/60) ("Multi-IdP routing — separate concern"). Reclassified as a must on [#71](https://github.com/camunda/camunda-security-library/issues/71) and delivered across [#74](https://github.com/camunda/camunda-security-library/issues/74) (properties), [#75](https://github.com/camunda/camunda-security-library/issues/75) (autoconfig), and this docs slice.

The core question this ADR answers is:

> What property shape and merge semantics should CSL expose so OC's multi-IdP behaviour is preserved exactly, single-IdP adopters keep working unchanged, and the resource-server `JwtDecoder` does not silently mis-route token validation when multiple providers are configured?

## Decision

CSL exposes two complementary property shapes that combine additively at startup, mirroring OC's `OidcAuthenticationConfigurationRepository`. Hosts choose either or both.

### Property shape

- **Flat** — `camunda.security.authentication.oidc.*` (unchanged from prior releases). Binds to an `OidcConfiguration` on `AuthenticationConfiguration#getOidc()`. The single-IdP path continues to work without any property migration.
- **Providers** — `camunda.security.authentication.providers.oidc.<id>.*`. Binds to `Map<String, OidcConfiguration>` on `AuthenticationConfiguration#getProviders().getOidc()`. The intermediate `oidc` segment exists so the `providers` block can host other provider families (basic, SAML) in future without a schema change.

Both `OidcProvidersConfiguration#setOidc` and `AuthenticationConfiguration#setProviders`/`setOidc` normalise null to a fresh empty instance so YAML `~` bindings cannot reintroduce NPEs in downstream iteration.

### Merge into `ClientRegistrationRepository`

`OidcBeansConfiguration#clientRegistrationRepository` constructs a `LinkedHashMap<String, OidcConfiguration>` and applies, in order:

1. If `flat.getClientId()` is non-blank, put the flat block under `flat.getRegistrationId()` (default `oidc`).
2. `putAll(providers.oidc)` — a colliding provider id overwrites the flat entry.

Each entry is then built into a `ClientRegistration` via a shared `buildClientRegistration(registrationId, oidc)` helper. Blank `registrationId` values fail fast with an `IllegalStateException` that names the misconfigured property; blank URI values are treated as missing via `StringUtils.hasText` so empty environment-variable bindings do not slip through to a generic Spring assertion. The result is wrapped in an `InMemoryClientRegistrationRepository`. An empty merged map throws an `IllegalStateException` pointing the adopter at both property shapes.

### Single `JwtDecoder` with explicit selection rules

`OidcBeansConfiguration#jwtDecoder` keeps the single-decoder model from the prior single-IdP release. Selection is explicit, not first-wins:

1. If the flat block has an `issuer-uri` or `jwk-set-uri`, use it.
2. Otherwise, if exactly one entry under `providers.oidc.*` carries such a source, use that entry.
3. Otherwise (no source anywhere, or multiple providers with sources and no flat block), startup fails with an `IllegalStateException` directing the host to pin the flat block as the resource-server audience or register a custom `@Bean JwtDecoder`.

A single `JwtDecoder` cannot correctly validate tokens issued by multiple IdPs (each carries its own signing keys and audience). The library refuses to guess and surfaces the choice to the host.

### Why these particular boundaries

- **Additive, not exclusive.** An earlier draft made the providers map *replace* the flat block when present and logged a deprecation warning. Rejected during review: OC's repository merges the two shapes, and adopters running OC with both blocks set would regress. Treating the flat block as one ordinary entry in the merged map keeps semantics identical and removes the need for any deprecation messaging — the flat block is not deprecated, only narrower.
- **Mirror OC's collision rule (providers overwrite flat).** OC's `Map#putAll` semantics are what the existing customer base relies on. Diverging — for example, raising on collision — would change behaviour silently for hosts migrating from OC.
- **`clientId` non-blank as the flat-block signal.** Matches OC. The alternative ("flat is set if any URI is set") was rejected because half-configured flat blocks should surface as informative build failures, not be silently ignored.
- **`providers.oidc.<id>.*`, not `providers.<id>.*`.** Mirrors OC's `ProvidersConfiguration { Map<String, OidcAuthenticationConfiguration> oidc; }`. The extra `oidc` segment leaves room for future provider families without a breaking schema change.
- **Per-provider decoders out of scope.** Multi-audience resource-server validation is a separate, larger feature: it touches the chain configuration, not just the bean wiring. The current model lets hosts that need it register their own `JwtDecoder` bean; the `@ConditionalOnMissingBean` back-off keeps the override path clean.
- **No deprecation warning.** The deprecation log shipped in an interim commit during #75 was removed when the shapes became additive. A warning would now be incorrect — the flat block is a regular registration, not a deprecated alternative.

### Default implementations and override boundaries

| Concern | Default | Override path |
|---|---|---|
| `ClientRegistrationRepository` | `InMemoryClientRegistrationRepository` populated from flat + providers map | Host registers any `@Bean ClientRegistrationRepository` — the CSL default backs off via `@ConditionalOnMissingBean` |
| `JwtDecoder` | Single `NimbusJwtDecoder` from flat or sole-provider source | Host registers `@Bean JwtDecoder` for multi-audience scenarios; library refuses to auto-pick across multiple providers |
| Provider routing | Spring Security's `/oauth2/authorization/{registrationId}` | None needed — Spring routes automatically once multiple `ClientRegistration` instances are present |

## Consequences

**Positive**

- OC adopting the CSL filter chains (camunda#52121) keeps multi-IdP login routing working without any code or configuration changes for customers who already use `providers.oidc.*`.
- Single-IdP hosts using only the flat block see no behavioural change — `OidcBeansConfigurationTest` continues to pass against the legacy shape, and the migration to providers is opt-in.
- Behaviour is testable in isolation. `OidcBeansConfigurationClientRegistrationTest` and `OidcBeansConfigurationJwtDecoderTest` exercise the real beans via `ApplicationContextRunner` with explicit endpoint URIs, so no network is required for unit coverage.
- The single-`JwtDecoder` selection is deterministic. Hosts with multiple IdPs that need per-audience validation discover that requirement at startup with an actionable error, not at request time with a confusing 401.

**Negative / accepted trade-offs**

- The library does not solve multi-audience resource-server validation. Hosts needing it must register their own `JwtDecoder`. Accepted because the chain customisation that real multi-IdP token validation would require is a separate feature; surfacing the limitation early is preferable to shipping a decoder that silently works for one provider.
- Collision semantics (providers overwrites flat) are convenient for the OC migration path but mean a host carrying both shapes can shadow the flat block without realising. Mitigated by `OidcBeansConfigurationClientRegistrationTest#shouldLetProviderEntryOverwriteFlatOnRegistrationIdCollision` documenting the rule in executable form.
- The `providers.oidc.*` segment carries an extra level of nesting compared to a hypothetical `providers.<id>.*`. Accepted because matching OC's existing customer configuration shape is worth more than one fewer YAML level, and the segment leaves future provider families room to grow.

## Alternatives Considered

- **Replace the flat block with the providers map; deprecate the flat shape.** Rejected — OC's `OidcAuthenticationConfigurationRepository` merges both shapes, so any OC customer running with both blocks set would regress on adoption. The simpler model (flat is just an additional registration) matches OC exactly and removes the need for deprecation messaging.
- **Auto-select the "first" provider for `JwtDecoder` when no flat block is configured.** Rejected during review — `Map` iteration order depends on the binder implementation, so the choice would be non-deterministic across configurations and Spring Boot upgrades. Worse, the chosen decoder would silently fail to validate tokens from the other providers. Refusing to guess and asking the host to pin or override is the safe default.
- **Throw on `registrationId` collision between flat and providers.** Rejected — diverges from OC's `Map#putAll` behaviour and breaks the migration path for OC customers who legitimately use the providers map to override the flat block.
- **Promote per-provider `JwtDecoder` resolution into the library.** Rejected as scope — multi-audience resource-server validation touches the chain DSL (`oauth2ResourceServer(...).jwt(...)`), not just bean wiring. Tracked separately if and when a host needs it.
- **Drop the `oidc` segment from the property path (`providers.<id>.*`).** Rejected — diverges from OC's `ProvidersConfiguration` shape, breaking the goal of zero-change OC migration, and leaves no room for other provider families.
