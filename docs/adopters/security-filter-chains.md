# Adopting the central security filter chains

This guide is for host applications (Hub, Orchestration Cluster (OC) gateways, future Camunda services) that embed the Camunda Security Library. It explains how to wire the central filter chains, what host-side beans are required, and how to extend or override library defaults.

For the rationale behind this design — why the chains live in CSL, and why hosts opt in via explicit `@Import` rather than relying on Spring Boot auto-configuration — see [ADR-0003](../adr/0003-no-spring-boot-auto-configuration.md).

## Why a central library owns the filter chains

Authentication and authorization enforcement must be on for every Camunda platform component, and the surface around it (CSRF, hardened HTTP headers, OAuth2 refresh handling, RFC 7807 failure responses) has to be consistent across hosts. Owning these chains in one library means:

- Every host gets the same hardened defaults — CSRF cookie name, CSP, HSTS, X-Frame-Options, COOP/COEP/CORP, permissions policy.
- The 401 vs 403 distinction, JSON problem-detail bodies, and bearer-token failure logging behave identically everywhere.
- Refresh-token expiry, forced-logout-on-failure, and the OIDC entry-point delegation (browser → 302, API → 401) are wired once and tested once.
- A security regression in any of these areas is a single PR in the CSL, not a coordinated rollout across N host repos.

Hosts retain control of *which* paths to protect (`SecurityPathPort`), the values of the configurable knobs (CSRF on/off, auth method, OIDC issuer, etc.), and any per-host extension behaviour through the library's extension hooks.

## Quickstart

1. Add the starter to your build:

   ```xml
   <dependency>
     <groupId>io.camunda</groupId>
     <artifactId>camunda-security-library-spring-boot-starter</artifactId>
     <version>${camunda.security.library.version}</version>
   </dependency>
   ```

2. Provide a `SecurityPathPort` bean — the only mandatory host-supplied bean:

   ```java
   @Bean
   public SecurityPathPort securityPaths() {
     return new SecurityPathPort() {
       @Override public Set<String> apiPaths() { return Set.of("/api/**", "/v2/**"); }
       @Override public Set<String> unprotectedApiPaths() { return Set.of("/v2/license", "/v2/status"); }
       @Override public Set<String> unprotectedPaths() { return Set.of("/actuator/**", "/error"); }
       @Override public Set<String> webappPaths() { return Set.of("/login/**", "/operate/**"); }
       @Override public Set<String> webComponentNames() { return Set.of("operate", "tasklist"); }
       @Override public Set<String> unauthenticatedWebappPaths() {
         return Set.of("/default-ui.css", "/tasklist/assets/**");
       }
     };
   }
   ```

3. `@Import` the configuration classes you want active. The CSL does not use Spring Boot auto-configuration ([ADR-0003](../adr/0003-no-spring-boot-auto-configuration.md)) — nothing activates by simply adding the dependency. Hosts opt in to each capability explicitly:

   ```java
   @Configuration
   @Import({
       BaseSecurityConfiguration.class,            // unprotected paths + catch-all deny
       OidcWebappSecurityConfiguration.class,      // OIDC browser session chain
       OidcApiSecurityConfiguration.class,         // OIDC bearer-token API chain
       OidcBeansConfiguration.class,               // JwtDecoder / ClientRegistrationRepository / etc.
       AuthFailureHandlerConfiguration.class       // RFC 7807 problem-detail responses
   })
   public class HostSecurityConfiguration {}
   ```

   For HTTP basic auth instead, swap `OidcWebappSecurityConfiguration` / `OidcApiSecurityConfiguration` / `OidcBeansConfiguration` for `BasicAuthWebappSecurityConfiguration` / `BasicAuthApiSecurityConfiguration`. For development without authentication, replace the protected API config with `UnprotectedApiSecurityConfiguration`. Each configuration's beans are gated by `@ConditionalOnMissingBean` so a host that registers its own `JwtDecoder`, `AuthFailureHandler`, etc. silently overrides the library default.

4. Set the auth method and any auth-mode-specific properties in `application.yaml`:

   ```yaml
   camunda:
     security:
       authentication:
         method: oidc
         oidc:
           issuer-uri: https://login.example.com/realms/camunda
           client-id: camunda-app
           client-secret: ...
           redirect-uri: "{baseUrl}/sso-callback"
   ```

   `@Import` is the activation enabler — without it the configuration is never processed. `@ConditionalOnProperty` annotations on the imported configurations are still evaluated by Spring, so both gates must pass: a host that `@Import`s `OidcWebappSecurityConfiguration` without setting `camunda.security.authentication.method=oidc` will silently get no OIDC chain. Match the property to the configuration you import.

For HTTP basic auth instead, set:

```yaml
camunda:
  security:
    authentication:
      method: basic
```

Under basic auth the library resolves users through the outbound [`BasicAuthUserDetailsPort`](./ports.md#basicauthuserdetailsport): the host provides a `BasicAuthUserDetailsPort` adapter (a scope-agnostic username lookup), and CSL supplies the `UserDetailsService` (`CamundaUserDetailsService`) plus a default delegating `PasswordEncoder`. Spring Boot assembles the global `AuthenticationManager` from those two beans, so the `BasicAuthApiSecurityConfiguration` / `BasicAuthWebappSecurityConfiguration` chains need no extra wiring. Both library beans are `@ConditionalOnMissingBean`, so a host can register its own `UserDetailsService` or `PasswordEncoder` to override the default; without a `BasicAuthUserDetailsPort` bean the CSL `UserDetailsService` does not activate. See [ADR-0010](../adr/0010-user-details-port.md).

For local development without authentication, set:

```yaml
camunda:
  security:
    authentication:
      unprotected-api: true
```

The library logs a `WARN` at startup when `unprotected-api=true` so this configuration can't quietly leak into a production deployment.

## Configuration reference

All properties live under `camunda.security.*`. Spring's relaxed binding accepts kebab-case and camelCase.

### `camunda.security.authentication.*`

| Property | Type | Default | Effect |
|---|---|---|---|
| `method` | `BASIC` \| `OIDC` | unset | Selects the auth-mode chains. If unset, only the unprotected-paths and catch-all chains run; protected API and webapp chains are inactive. |
| `unprotected-api` | boolean | `false` | When `true`, swaps the protected API chain for a permit-all variant. Development only. |

The property key strings for `method` and `unprotected-api` are exposed as public constants in [`CamundaSecurityFilterChainConstants`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/CamundaSecurityFilterChainConstants.java) so hosts can reference them without hardcoding the literal string:

```java
import io.camunda.security.spring.security.CamundaSecurityFilterChainConstants;

// e.g. when writing a custom @Conditional or reading the property programmatically
environment.getProperty(CamundaSecurityFilterChainConstants.AUTHENTICATION_METHOD_PROPERTY);
environment.getProperty(CamundaSecurityFilterChainConstants.UNPROTECTED_API_PROPERTY);
```

Use the constants in `@ConditionalOnProperty` declarations to avoid typos and to surface any future key renames at compile time:

```java
@ConditionalOnProperty(
    name = CamundaSecurityFilterChainConstants.AUTHENTICATION_METHOD_PROPERTY,
    havingValue = "oidc")
```

For most conditional use cases the CSL ships purpose-built meta-annotations (see [Conditional annotations](./conditional-annotations.md)) that are type-safe and encode the correct defaults — prefer those over raw `@ConditionalOnProperty` strings in host code.

### `camunda.security.authentication.oidc.*` (consulted when `method=oidc`)

| Property | Type | Default | Effect |
|---|---|---|---|
| `issuer-uri` | string | unset | OIDC issuer. The library uses this to discover the JWK set if `jwk-set-uri` is unset. |
| `client-id` | string | unset | OAuth2 client id. |
| `client-secret` | string | unset | OAuth2 client secret. |
| `jwk-set-uri` | string | unset | Explicit JWK set URI. If unset, derived from `issuer-uri`. |
| `additional-jwk-set-uris` | list&lt;string&gt; | empty | Secondary JWK Set URIs consulted when the primary `jwk-set-uri` does not resolve a token's signing key. See [Multiple JWK Set URIs](#multiple-jwk-set-uris) below and [ADR-0006](../adr/0006-multi-idp-oidc-configuration.md). |
| `authorization-uri`, `token-uri`, `user-info-uri` | string | unset | Endpoint overrides for non-discovery flows. |
| `user-info-enabled` | boolean | `true` | When `false`, the built `ClientRegistration` has its `userInfoUri` nulled so Spring Security does not call the IdP's UserInfo endpoint after token exchange. See [Disabling the UserInfo fetch](#disabling-the-userinfo-fetch) below and [ADR-0007](../adr/0007-oidc-user-info-enabled-toggle.md). |
| `user-info-augmentation.enabled` | boolean | `false` | When `true`, enables request-time claim augmentation from the UserInfo endpoint. See [UserInfo claim augmentation](#userinfo-claim-augmentation) below. |
| `user-info-augmentation.cache-ttl` | duration | `5m` | How long a successful UserInfo response is cached per token identity (`iss+jti`, or `iss+sub+iat+exp` when `jti` is absent). |
| `user-info-augmentation.cache-max-size` | int | `10000` | Maximum number of entries in the UserInfo claims cache. |
| `user-info-augmentation.negative-cache-ttl` | duration | `5s` | How long a failed UserInfo fetch is cached before retrying. Limits retry traffic when the IdP is degraded. |
| `redirect-uri` | string | unset | OAuth2 redirect-uri template. |
| `scope` | list&lt;string&gt; | `[openid, profile]` | OAuth2 scopes requested. |
| `audiences` | list&lt;string&gt; | empty | Reserved; not consumed by the default beans. |
| `registration-id` | string | `oidc` | Spring Security client registration id. |
| `client-authentication-method` | string | `client_secret_basic` | Spring Security `ClientAuthenticationMethod` literal. |

### UserInfo claim augmentation

The `user-info-augmentation` block enables an opt-in, request-time mechanism
that calls the IdP's `/userinfo` endpoint and merges the returned claims onto
the JWT. This is distinct from the `user-info-enabled` toggle (which controls
whether Spring Security calls UserInfo during the *login* flow): augmentation
operates on every authenticated API request using the bearer token.

**When to use augmentation vs. `user-info-enabled`:**

- Use `user-info-enabled: false` when you want to skip the UserInfo call
  entirely during the webapp OAuth2 login flow (e.g. the IdP does not expose
  `/userinfo`, or you only need id-token claims for the session).
- Use `user-info-augmentation.enabled: true` when your IdP omits
  authorization-relevant claims (groups, roles, custom attributes) from the
  access token. Augmentation fetches these at request time and merges them in.

> **Note:** augmentation sources the UserInfo endpoint URI from the
> `ClientRegistration`. Setting `user-info-enabled: false` nulls that URI. If
> that leaves *every* configured provider without a UserInfo URI (a single-IdP
> setup, or a multi-IdP setup where all providers disable it), CSL fails fast
> at startup with an `IllegalStateException` rather than silently running
> without augmentation — enabling augmentation with nothing it can ever
> augment is treated as a configuration mismatch. In a multi-IdP setup where
> only *some* providers disable `user-info-enabled`, the coupling is silent
> instead: tokens from those providers' issuers skip augmentation at request
> time with no error surfaced (logged at DEBUG). Leave `user-info-enabled` at
> its default (`true`) for any provider you want augmentation to cover. See
> [ADR-0007](../adr/0007-oidc-user-info-enabled-toggle.md) for the full
> mechanism.

**JWT-wins invariant.** UserInfo claims are merged additively: JWT claims always
win on any conflict. The UserInfo response can never override `sub`, `iss`,
`aud`, `exp`, or any other claim that is already present in the signed token.
This preserves the cryptographic trust boundary of the JWT.

**Fail-open.** If the `/userinfo` call fails (network error, non-2xx status,
JSON parse error, or a `sub` mismatch per OIDC §5.3.2), the auth chain
continues with the original JWT claims unchanged. Failed fetches are
negatively cached for `negative-cache-ttl` to limit retry traffic while the
IdP is degraded.

**Example:**

```yaml
camunda:
  security:
    authentication:
      method: oidc
      oidc:
        issuer-uri: https://keycloak.example.com/realms/camunda
        client-id: camunda
        client-secret: ${KEYCLOAK_SECRET}
        user-info-augmentation:
          enabled: true
          cache-ttl: 5m
          cache-max-size: 10000
          negative-cache-ttl: 5s
```

Tuning `negative-cache-ttl`: a lower value recovers faster after the IdP
returns to health; a higher value reduces load on a degraded endpoint. The
5-second default is conservative — raise it (e.g. `30s`) if your IdP has
frequent short outages that generate high retry traffic.

### Multi-IdP OIDC (`camunda.security.authentication.providers.oidc.<id>.*`)

The library supports multiple OIDC providers by binding a map of `OidcConfiguration` instances under `camunda.security.authentication.providers.oidc.<id>.*`. Each map key becomes the Spring Security `registrationId`, so login routing works through Spring's standard `/oauth2/authorization/<id>` URL — no chain customisation is required. The shape mirrors OC's [`ProvidersConfiguration`](https://github.com/camunda/camunda/blob/main/security/security-core/src/main/java/io/camunda/security/configuration/ProvidersConfiguration.java) so hosts migrating from OC keep their existing configuration. See [ADR-0006](../adr/0006-multi-idp-oidc-configuration.md) for the design rationale.

Each entry under `providers.oidc.<id>` accepts the same properties as the flat `oidc.*` block, with one exception: `registration-id` is ignored — the map key is always used as the Spring Security registration id. Configuring `providers.oidc.keycloak.registration-id: something-else` does not change the registration id; the value is silently overwritten by `keycloak`.

Two-provider example:

```yaml
camunda:
  security:
    authentication:
      method: oidc
      providers:
        oidc:
          keycloak:
            issuer-uri: https://keycloak.example.com/realms/camunda
            client-id: camunda-keycloak
            client-secret: ${KEYCLOAK_SECRET}
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
          azure:
            issuer-uri: https://login.microsoftonline.com/<tenant-id>/v2.0
            client-id: camunda-azure
            client-secret: ${AZURE_SECRET}
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
```

With this configuration, users start a login at `/oauth2/authorization/keycloak` or `/oauth2/authorization/azure`.

> **Multi-provider token validation** works automatically — the library builds an issuer-aware
> `JwtDecoder` when multiple providers are configured. No flat `oidc.*` block or custom
> `@Bean JwtDecoder` is required. See [JwtDecoder selection rules](#resource-server-jwtdecoder-selection).

#### Combining the flat and providers shapes

The flat `oidc.*` block and the `providers.oidc.*` map are **additive**. When `oidc.client-id` is non-blank, the flat block contributes a `ClientRegistration` under its own `registration-id` (default `oidc`); the providers map is then merged on top, so a colliding provider id overwrites the flat entry. This matches OC's [`OidcAuthenticationConfigurationRepository`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/OidcAuthenticationConfigurationRepository.java), so hosts migrating from OC with both blocks set behave identically.

Migrating a single-IdP host to the providers shape:

```yaml
# Before — flat shape only
camunda:
  security:
    authentication:
      method: oidc
      oidc:
        issuer-uri: https://keycloak.example.com/realms/camunda
        client-id: camunda
        client-secret: ${KEYCLOAK_SECRET}

# After — providers shape, login URL becomes /oauth2/authorization/keycloak
camunda:
  security:
    authentication:
      method: oidc
      providers:
        oidc:
          keycloak:
            issuer-uri: https://keycloak.example.com/realms/camunda
            client-id: camunda
            client-secret: ${KEYCLOAK_SECRET}
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
```

The flat shape stays supported indefinitely — there is no deprecation. Migrate when adding a second provider, or stay on the flat shape if a single IdP is all the host needs.

#### Resource-server `JwtDecoder` selection

The library ships a single `JwtDecoder` bean that automatically selects the appropriate
validation strategy based on the number of configured OIDC providers:

- **Single provider** (flat `oidc.*` block or single `providers.oidc.<id>` entry): a single-issuer
  `NimbusJwtDecoder` is built from the registration's JWK set URI. Behaviour is identical to prior
  releases — no configuration change required.
- **Multiple providers** (two or more entries across flat and providers shapes): an **issuer-aware**
  decoder is built. When a token arrives, the library reads its `iss` claim and routes key selection
  and validation to the matching registration. A token whose `iss` matches no configured provider
  fails with a `BadJwtException` whose message matches `"Unknown issuer '<iss>'. No matching client registration found."`. All provider registrations must have an
  `issuer-uri` configured; startup fails with a message listing any offending registration ids
  otherwise.

For the issuer-aware path, per-provider `audiences` and `additional-jwk-set-uris` are honoured
independently — a token from provider A is validated against A's audience list and A's JWK set
URIs only.

A host-supplied `@Bean JwtDecoder` continues to take precedence via `@ConditionalOnMissingBean`.
The library's default `JWSKeySelectorFactory`, `TokenValidatorFactory`, and
`OidcAccessTokenDecoderFactory` beans are also overridable independently.

See [ADR-0006](../adr/0006-multi-idp-oidc-configuration.md) for the design rationale.

#### Multiple JWK Set URIs

When the IdP publishes signing keys across more than one JWK Set endpoint (typically during a key-rotation window or when an identity gateway federates multiple backends), set `additional-jwk-set-uris` alongside the primary `jwk-set-uri`:

```yaml
camunda:
  security:
    authentication:
      method: oidc
      oidc:
        issuer-uri: https://primary-idp.example.com/
        client-id: camunda
        client-secret: ${CLIENT_SECRET}
        redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
        jwk-set-uri: https://primary-idp.example.com/.well-known/jwks.json
        additional-jwk-set-uris:
          - https://secondary-idp.example.com/.well-known/jwks.json
          - https://legacy-idp.example.com/.well-known/jwks.json
```

`issuer-uri` is set alongside `jwk-set-uri` here because `ClientRegistration` construction requires either `issuer-uri` (for discovery of authorization/token endpoints) or all three of `authorization-uri`/`token-uri`/`jwk-set-uri` explicitly. The `additional-jwk-set-uris` wiring is independent of which path you choose to populate the registration; the only constraint is that the registration ends up with a primary `jwk-set-uri`, whether you set it explicitly or discovery resolves it from `issuer-uri`.

The default `JwtDecoder` queries the primary `jwk-set-uri` first, then each entry in `additional-jwk-set-uris` in declared order. The first source that resolves the token's `kid` wins. If an additional URI is unreachable, the failure is logged at WARN and the next source is tried — a failing additional URI does not break validation against the primary or other working URIs.

Two constraints to be aware of:

- **A resolvable `jwk-set-uri` is required.** Set `jwk-set-uri` explicitly, or set `issuer-uri` so OIDC discovery populates it. A provider that resolves neither fails at startup with `OIDC Provider '<id>' is missing a valid 'jwk-set-uri'`.
- **`kid` collision precedence.** If two JWK Sets publish a key with the same `kid` (unlikely in practice), the primary `jwk-set-uri` wins because it is queried first. Reorder `additional-jwk-set-uris` to change precedence among the additional URIs.

See [ADR-0006](../adr/0006-multi-idp-oidc-configuration.md) for the design rationale, the choice of composite `JWKSource` over Spring's `JwtIssuerAuthenticationManagerResolver`, and the lazy failure model.

#### Disabling the UserInfo fetch

By default Spring Security calls the IdP's UserInfo endpoint after token exchange and merges the returned claims into the `OidcUser`. Some IdPs do not implement `/userinfo`, and some hosts prefer to source claims only from the ID token. Set `user-info-enabled: false` on either the flat block or any provider entry to skip the fetch on that registration — the library nulls `userInfoUri` on the built `ClientRegistration`, so Spring Security has nothing to call.

The flag is per-provider. A multi-IdP deployment can fetch UserInfo from one IdP and skip it on another:

```yaml
camunda:
  security:
    authentication:
      method: oidc
      providers:
        oidc:
          keycloak:
            issuer-uri: https://keycloak.example.com/realms/camunda
            client-id: camunda-keycloak
            client-secret: ${KEYCLOAK_SECRET}
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            # user-info-enabled defaults to true — Spring fetches UserInfo
          azure:
            issuer-uri: https://login.microsoftonline.com/<tenant-id>/v2.0
            client-id: camunda-azure
            client-secret: ${AZURE_SECRET}
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            user-info-enabled: false   # skip the /userinfo call for Azure
```

A host-supplied `OidcUserService` bean still takes precedence in both modes (see [ADR-0007](../adr/0007-oidc-user-info-enabled-toggle.md)) — `user-info-enabled` only governs the library's default wiring.

### Customizing the authorization request (`resource`, `additional-parameters`)

CSL ships a default `OAuth2AuthorizationRequestResolver` (`CamundaOidcAuthorizationRequestResolver`) from `OidcBeansConfiguration`. It wraps Spring Security's `DefaultOAuth2AuthorizationRequestResolver` per registration and injects two `OidcConfiguration` properties into the outgoing OAuth2 authorization request. Hosts that need different customizer logic register their own `OAuth2AuthorizationRequestResolver` bean; CSL backs off via `@ConditionalOnMissingBean`.

#### `resource` (RFC 8707)

When `resource` is set on a provider, every entry in the list is added as a `resource` query parameter on the IdP authorization URL. Use this when the IdP requires an explicit audience for the issued access token.

#### `authorize-request.additional-parameters`

Arbitrary key/value pairs that are appended verbatim to the authorization request. Useful for IdP-specific extensions such as `prompt`, `audience`, or vendor-specific switches. Values are passed through unchanged — the library does not interpret them.

#### Worked example

Both knobs are valid on the flat block and on any `providers.oidc.<id>.*` entry:

```yaml
camunda:
  security:
    authentication:
      method: oidc
      oidc:
        issuer-uri: https://idp.example.com
        client-id: camunda
        client-secret: ${OIDC_SECRET}
        redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
        resource:
          - https://api.example.com
        authorize-request:
          additional-parameters:
            prompt: consent
            audience: https://api.example.com
      providers:
        oidc:
          partner:
            issuer-uri: https://partner.example.com
            client-id: camunda-partner
            client-secret: ${PARTNER_SECRET}
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            resource:
              - https://partner-api.example.com
```

If you need behaviour the customizer does not cover (e.g. PKCE forcing, claims request, dynamic per-request parameters), register your own `OAuth2AuthorizationRequestResolver` bean — CSL's default will back off and the OIDC webapp chain will pick yours up automatically.

### OIDC groups claim extraction

If your IdP exposes group membership in an OIDC claim, configure `camunda.security.authentication.oidc.groupsClaim` to point at that claim.

- Plain claim names such as `groups` are accepted and are normalized to a JSONPath internally.
- JSONPath expressions such as `$.realm_access.roles` are also accepted.
- `OidcGroupsClaimValidator` validates the value during configuration binding and enforces the supported plain-claim and JSONPath-style formats, but does not guarantee full JSONPath syntax validation at bind time.
- `OidcGroupsExtractor` reads the configured claim from the OIDC claims map and returns the groups as a `List<String>`.

Example:

```yaml
camunda:
  security:
    authentication:
      oidc:
        groups-claim: groups
```

In this example, the library treats `groups` as the claim source for group mapping and extracts the claim contents as strings. A single string claim is returned as a one-element list, a list-valued claim is returned as a `List<String>`, and a missing claim yields an empty result. If the claim resolves to a non-string value, extraction fails fast with an `IllegalArgumentException` so the OIDC configuration can be corrected early.

### `camunda.security.csrf.*`

| Property | Type | Default | Effect |
|---|---|---|---|
| `enabled` | boolean | `true` | Toggles CSRF protection on the webapp chains. |
| `cookie-http-only` | boolean | `false` | When `false`, the CSRF cookie is readable by browser-side JavaScript so it can echo the token. Flip to `true` only for API-only hosts. |
| `ignored-path-patterns` | set&lt;string&gt; | empty | Ant-style patterns CSRF protection skips, in addition to the always-ignored unprotected paths and login/logout endpoints. |

### `camunda.security.http-headers.*`

Each subkey configures one HTTP response header. Shapes:

| Subkey | Properties |
|---|---|
| `content-type-options` | `disabled: boolean` |
| `cache-control` | `disabled: boolean` |
| `hsts` | `disabled: boolean`, `max-age-in-seconds: long`, `include-sub-domains: boolean`, `preload: boolean` |
| `frame-options` | `disabled: boolean`, `mode: DENY \| SAMEORIGIN` |
| `content-security-policy` | `enabled: boolean`, `policy-directives: string`, `report-only: boolean` |
| `referrer-policy` | typed enum value |
| `permissions-policy` | string |
| `cross-origin-opener-policy` | typed enum value |
| `cross-origin-embedder-policy` | typed enum value |
| `cross-origin-resource-policy` | typed enum value |

Defaults are the hardened production set (CSP locked down, HSTS at one year, COOP `SAME_ORIGIN_ALLOW_POPUPS`, etc.). Override only what you need.

## Required and supplied beans

### Required from the host

| Bean | Why |
|---|---|
| `SecurityPathPort` | The library has no way to know which paths are API vs webapp vs unprotected; the host declares this. |

### Supplied by the library (overridable)

Many library-supplied infrastructure beans intended to be overridden (including those listed below) have `@ConditionalOnMissingBean`. Define your own bean of the same type and the library's default backs off — **provided the CSL configuration class is loaded via `@ImportAutoConfiguration` (either the umbrella `CamundaSecurityAutoConfiguration` or the individual class).** A direct `@Import` parses CSL's `@Configuration` class before the host's own `@Bean` methods, so the CSL default registers first and either fails the host's override with `BeanDefinitionOverrideException` (named beans) or silently wins over it (unnamed beans of the same type). When you intend to override one of the beans below, replace the `@Import({…})` in the [Quickstart](#quickstart) with `@ImportAutoConfiguration({…})` for the relevant configuration classes — see [ADR-0003 §Fine-grained `@Import`](../adr/0003-no-spring-boot-auto-configuration.md#what-this-means-for-adopters).

| Bean | When | Override use case |
|---|---|---|
| `JwtDecoder` | `method=oidc` | Custom JWT validators (audience, issuer pinning), narrower or custom JWS algorithm sets, multi-issuer routing. Multi-JWKS for a single issuer is now built in — see [Multiple JWK Set URIs](#multiple-jwk-set-uris). |
| `ClientRegistrationRepository` | `method=oidc` | Multi-IdP support, dynamic client registration |
| `OAuth2AuthorizedClientRepository` | `method=oidc` | Custom session storage |
| `OAuth2AuthorizedClientManager` | `method=oidc` | Custom OAuth2 client provider chain |
| `AuthFailureHandler` (`JsonProblemDetailAuthFailureHandler` by default) | always | Host-specific problem-detail schema |

### Supplied by Spring Boot (no library involvement)

| Bean | Provided by |
|---|---|
| `ObjectMapper` | `JacksonAutoConfiguration` — consumed by the default `AuthFailureHandler` |

### Authentication converters

CSL ships two `CamundaAuthenticationConverter<Authentication>` implementations for OIDC resource-server chains. Neither is auto-wired — the host registers whichever one it needs as a bean.

| Converter | When to use |
|---|---|
| `OidcTokenAuthenticationConverter` | Standard OIDC deployments where memberships (roles, groups, tenants) are resolved from a database via `MembershipPort`. Reads `sub` or a client-id claim and delegates resolution to `LazyTokenClaimsConverter`. |
| `JwtGrantedAuthoritiesAuthenticationConverter` | Deployments where the JWT itself is the authoritative source of roles — for example, SaaS tokens where an upstream `JwtAuthenticationConverter` has already extracted role authorities from a fixed claim before CSL runs. No `MembershipPort` call is made. Only suitable for user tokens where the configured claim (`sub` by default) identifies the principal; M2M/client-credentials tokens must be handled separately. |

**Registering the converter.** Pass the same `usernameClaim` used by `OidcConfiguration` so both converters resolve the principal identically; falls back to `sub` when unset, blank, or absent from the token.

```java
@Bean
public CamundaAuthenticationConverter<Authentication> authenticationConverter(
    CamundaSecurityLibraryProperties properties) {
  return new JwtGrantedAuthoritiesAuthenticationConverter(
      properties.getAuthentication().getOidc().getUsernameClaim());
}
```

**Ordering when both are registered.** Both converters return `true` from `supports()` for `JwtAuthenticationToken`. `CamundaSpringAuthenticationDelegatingConverter` picks the first match in list order. Registering both in the same application context is a misconfiguration for almost all deployments — a deployment strategy should need only one. If you genuinely need both, use `@Primary` or `@Order` to make the selection explicit; wrong ordering silently applies the wrong authorization logic with no error or log entry.

## Extension hooks

Seven extension points let hosts contribute additional path-scoped API chains, customise specific OAuth2/OIDC concerns, supply a per-chain JWT authentication converter, enable CORS, add an HTTPS redirect, or contribute CSP/security-header behavior — all without replacing entire chains. Host-specific filter wiring beyond these hooks (authorization filters, matcher tweaks) will be addressed in a follow-up PR.

### `CamundaSecurityScopeProvider` — contribute path-scoped API chains

When a host needs to expose additional path-scoped API surfaces — each with its own isolated set of OIDC providers or a per-scope basic-auth authority — it implements `CamundaSecurityScopeProvider` and registers it as a bean. CSL builds one `SecurityFilterChain` per returned descriptor alongside its own chains; no action is required when no provider bean is present.

```java
public interface CamundaSecurityScopeProvider {
  List<ScopedSecurityDescriptor> get();
}
```

**The descriptor.** `ScopedSecurityDescriptor(String basePath, AuthenticationConfiguration authentication)` carries two fields:

- `basePath` — the scope's path prefix. CSL derives the chain's security matchers by prefixing each entry from `SecurityPathPort.apiPaths()` (and `SecurityPathPort.unprotectedApiPaths()`) with `basePath`. The API surface is host-defined: when the host's `apiPaths()` is `{"/v2/**"}`, a `basePath` of `/scopes/abc` produces a matcher of `/scopes/abc/v2/**`; a host with `apiPaths()={"/api/**"}` produces `/scopes/abc/api/**` instead. Keeping the descriptor surface-agnostic means that if a future surface type (e.g. a scope-specific webapp) is added, the same descriptor record is reused without changing the host contract.
- `authentication` — a (merged) `AuthenticationConfiguration` carrying only the OIDC providers or auth method for this scope. CSL builds a dedicated `JwtDecoder` from this configuration via `ScopedJwtDecoderFactory.buildIssuerAwareDecoder(AuthenticationConfiguration)`. The isolation is structural: a per-scope `TokenValidatorFactory` is built from the scope's own merged provider configuration, so both issuer and audience validation are enforced using the scope's values. Concretely: a token whose `iss` claim matches none of the scope's providers fails with an informative `BadJwtException`; a token whose `aud` claim does not include any of the scope's configured audiences is also rejected, even when two scopes share the same issuer (shared-IdP / physical-tenant isolation). The auth method (OIDC resource-server or HTTP Basic) is selected from `authentication.getMethod()`.

**Declaring the provider bean.** The collector that enumerates descriptors runs during Spring's bean-definition registration phase, before the enclosing `@Configuration` class is constructed. It calls `getBean` on each `CamundaSecurityScopeProvider` at that point. If the provider is a non-static `@Bean` on a `@Configuration` class that uses inter-`@Bean` method references (CGLIB enhancement), Spring will instantiate the configuration class too early and log:

> "Cannot enhance @Configuration bean definition ... created too early"

The configuration class then loses CGLIB proxy behaviour silently — inter-`@Bean` calls will not route through the Spring container. To avoid this, declare the provider as one of:

- a **`static @Bean`** on the host `@Configuration` (preferred), or
- a `@Bean` on a **`@Configuration(proxyBeanMethods = false)`** class, or
- a **standalone `@Component`** or `@Service` bean without inter-bean method references.

**Example.**

```java
@Configuration
public class HostScopeConfiguration {

  // IMPORTANT: declare as static @Bean to avoid the "created too early" CGLIB warning.
  @Bean
  public static CamundaSecurityScopeProvider hostScopeProvider(final MyScopes myScopes) {
    return () ->
        myScopes.all().stream()
            .map(
                scope ->
                    new ScopedSecurityDescriptor(
                        "/scopes/" + scope.id(), scope.authenticationConfiguration()))
            .toList();
  }
}
```

How each scope's `AuthenticationConfiguration` is assembled (which providers it carries, per-provider overrides, the auth method) is entirely the host's concern — CSL only consumes the finished configuration.

**Per-scope auth method independence.** Each scope selects its own authentication method via the
descriptor's `authentication.getMethod()`, independently of the cluster's global
`camunda.security.authentication.method`. CSL provides the per-scope OIDC infrastructure
(`ScopedJwtDecoderFactory`, `ScopedClientRegistrationFactory`, `OidcAccessTokenDecoderFactory`,
`JWSKeySelectorFactory`) through the unconditional `ScopedOidcInfrastructureConfiguration` class,
which is always active as a member of the `CamundaSecurityAutoConfiguration` umbrella. A host can
therefore contribute an OIDC-scoped descriptor even when the cluster's global method is `basic` —
no global OIDC configuration is required and no additional `@Import` is needed.

**Dev-mode note.** When `camunda.security.authentication.unprotected-api=true` is set globally, all contributed scoped chains are also built as permit-all — the descriptor's `authentication.method` is ignored in this mode. This matches the global chain behaviour in dev environments, but means per-scope security is not enforced when the flag is on. Don't set this flag in production or any environment where per-scope isolation is a requirement.

**Activation.** `ScopedSecurityChainConfiguration` is part of the `CamundaSecurityAutoConfiguration` umbrella — no additional `@Import` is needed when a host uses the umbrella. Hosts that `@Import` individual CSL configurations must add `ScopedSecurityChainConfiguration.class` to their `@Import` list. Each descriptor contributes both a scoped API chain and a scoped webapp chain. See [ADR-0013](../adr/0013-camunda-security-scope-provider-spi.md) for the design rationale.

### `OidcResourceServerCustomizer` — customise the OAuth2 resource-server DSL

The OIDC **API** chain (`OidcApiSecurityConfiguration`) routes through every `OidcResourceServerCustomizer` bean inside `oauth2ResourceServer(...)`. Use this for RFC 9728 protected-resource metadata, custom JWT validators, or swapping the bearer-token entry point.

> The OIDC **webapp** chain has no resource server — it authenticates users interactively via `oauth2Login` and serves them from the resulting session; JWT bearer tokens are validated only on the API chain. Consequently `OidcResourceServerCustomizer` beans apply to the API chain only and have no effect on webapp paths. A bearer token presented to a webapp path is not authenticated there; the chain's delegating entry point returns `401` for `Authorization`-bearing requests.

```java
@Bean
public OidcResourceServerCustomizer protectedResourceMetadata(...) {
  return oauth2 -> oauth2.protectedResourceMetadata(...);
}
```

### `JwtAuthenticationConverter` — per-chain JWT authority mapping

`ScopedApiSecurityChainBuilder.buildOidcApiChain(...)` and `buildScopedApiChain(...)` each have an
overload that accepts a Spring Security `Converter<Jwt, Authentication>` (a.k.a.
`JwtAuthenticationConverter`), applied only to that specific chain instance:

```java
@Bean
public SecurityFilterChain apiV1FilterChain(
    final HttpSecurity http,
    final ScopedApiSecurityChainBuilder builder,
    final JwtDecoder jwtDecoder,
    @Qualifier("apiV1") final Converter<Jwt, Authentication> apiV1Converter)
    throws Exception {
  return builder.buildOidcApiChain(
      http, List.of("/v1/**"), List.of(), jwtDecoder, apiV1Converter, null);
}
```

Use this when your application builds **multiple simultaneous OIDC API chains that need different
authority-mapping logic** — for example, distinct chains per API version. This is a genuinely
per-chain hook, not a globally-registered customizer: passing `null` (or, for the
`buildScopedApiChain` overload, a supplier that returns `null`) preserves Spring Security's default
`JwtAuthenticationConverter` behavior for that chain. See
[ADR-0016](../adr/0016-cors-and-https-redirect-host-hooks.md) for why this is a method
parameter rather than an `ObjectProvider`-discovered bean like `OidcResourceServerCustomizer` or
`HttpsRedirectCustomizer` below.

> **Not the same as CSL's `CamundaAuthenticationConverter`.** The [Authentication
> converters](#authentication-converters) section above documents `OidcTokenAuthenticationConverter`
> and `JwtGrantedAuthoritiesAuthenticationConverter` — CSL's own higher-level contract that maps a
> Spring Security `Authentication` into a `CamundaAuthentication` (tenants, roles, memberships).
> This section is about the lower-level Spring Security seam that runs *before* that: the raw
> `Converter<Jwt, Authentication>` wired directly into `oauth2ResourceServer().jwt(...)`, which
> determines what kind of `Authentication`/`GrantedAuthority` set exists in the first place before
> CSL's own converter ever sees it. Most deployments only need CSL's `CamundaAuthenticationConverter`
> layer; this per-chain hook exists for the narrower case of a host running multiple API chains that
> must each map JWT claims to authorities differently before CSL's layer runs.

### `OidcTokenEndpointCustomizer` — customise the OAuth2 login token endpoint

Used most commonly to wire `private_key_jwt` client authentication. Implement the interface and register a bean; `OidcWebappSecurityConfiguration` picks it up via `ObjectProvider` if present.

```java
@Bean
public OidcTokenEndpointCustomizer privateKeyJwtCustomizer(MyJwkProvider jwks) {
  return tokenEndpoint -> {
    // configure the token response client with private_key_jwt assertions
  };
}
```

### `CorsConfigurationSource` — enable CORS

By default CSL disables CORS on every security filter chain. To enable it, register a `CorsConfigurationSource` bean:

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.addAllowedOriginPattern("https://*.example.com");
    config.addAllowedMethod("*");
    config.addAllowedHeader("*");
    config.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

CSL picks up the bean automatically via `@ConditionalOnMissingBean` and applies it to all security filter chains, including the catch-all deny chain (so preflight `OPTIONS` requests for unmatched paths also receive CORS headers). When no bean is registered the previous behaviour (CORS disabled) is preserved.

> **Do not register mappings on `NoOpCorsConfigurationSource`.** If you inject the default `CorsConfigurationSource` bean and call `registerCorsConfiguration(...)` on it, the registrations are silently ignored because CSL keys off the marker type, not the registered mappings. Always register your own `CorsConfigurationSource` bean to enable CORS.

See [ADR-0016](../adr/0016-cors-and-https-redirect-host-hooks.md) for the design rationale.

### `HttpsRedirectCustomizer` — enforce HTTPS

To redirect HTTP requests to HTTPS, register an `HttpsRedirectCustomizer` bean:

```java
@Bean
public HttpsRedirectCustomizer httpsRedirectCustomizer() {
    return http -> http.addFilterBefore(
        new MyHttpsRedirectFilter(),
        org.springframework.security.web.context.SecurityContextHolderFilter.class);
}
```

The customizer receives full `HttpSecurity` access, so the redirect strategy, excluded paths, and response code are entirely host-controlled. CSL applies the customizer to every filter chain. When no bean is registered CSL leaves HTTP→HTTPS policy to the host's infrastructure layer (load balancer, ingress).

The anchor passed to `addFilterBefore` must exist in the target chain. `SecurityContextHolderFilter` is always present in CSL's chains and is the safe choice.

See [ADR-0016](../adr/0016-cors-and-https-redirect-host-hooks.md) for the design rationale.

### `SecurityHeadersCustomizer` — dynamic CSP, additional, or route-varying response headers

Register a `SecurityHeadersCustomizer` bean to contribute response-header behavior CSL's static, property-driven `camunda.security.http-headers.*` configuration cannot express — including a dynamic Content-Security-Policy (e.g. a fresh nonce on every response), headers CSL doesn't know about, or header application varied by route:

```java
@Bean
public SecurityHeadersCustomizer nonceBasedCsp() {
  return http -> http.headers(headers -> headers.addHeaderWriter(new MyNonceCspHeaderWriter()));
}
```

```java
@Bean
public SecurityHeadersCustomizer extraHeaders() {
  return http -> http.headers(headers -> headers.addHeaderWriter(
      (request, response) -> response.setHeader("X-My-Header", "value")));
}
```

CSL applies every registered customizer, in `@Order` order, to every content-serving filter chain (the same set `HttpsRedirectCustomizer` applies to, minus the catch-all deny-all chain, which serves no content). This coexists with `camunda.security.http-headers.*` (including `content-security-policy.*`) — your custom `HeaderWriter` is additive via `addHeaderWriter`, not a replacement for CSL's static configuration, unless your writer itself overwrites the header. If you register multiple customizers with distinct concerns (e.g. one for CSP, one for other headers), use `@Order` to control their relative sequencing. See [ADR-0016](../adr/0016-cors-and-https-redirect-host-hooks.md) for the design rationale.

### Other host beans the chains pick up automatically

- `LogoutSuccessHandler` — wired into the OIDC webapp chain for IdP-coordinated logout. The CSL ships a default (`CamundaOidcLogoutSuccessHandler`) via `OidcBeansConfiguration` when `authentication.method=oidc` and the host activates CSL through the `CamundaSecurityAutoConfiguration` umbrella; a host-registered bean replaces it. See [OIDC logout](#oidc-logout).
- `OidcUserService` — wired into the OIDC user-info endpoint.

These are looked up via `ObjectProvider#ifAvailable`; absence is fine, the chain falls back to Spring Security defaults.

## Web app authorization

The CSL's `WebAppAuthorizationCheckFilter` enforces per-web-app `ACCESS` permission on every authenticated webapp request. It runs immediately after Spring Security's `AuthorizationFilter` on the webapp chain. The filter is host-pluggable on two axes:

- **Which web app does the request belong to?** A single-web-app host returns a constant; a multi-web-app host derives from the URL path. Implement `WebAppProviderPort`.
- **What happens when access is denied?** The library default redirects to `<contextPath>/<webApp>/forbidden`. Override `WebAppAccessDeniedHandlerPort` to return JSON, forward, or anything else.

The actual permission decision delegates to the unified `AuthorizationCheckPort` (ADR-0014): the filter asks for `ACCESS` on the resolved web app as a `COMPONENT` resource and treats `Either.right(...)` as authorized. Hosts supply an `AuthorizationCheckPort` — either their own bean, or the ingredients for the library default (an `AuthorizationScopeRepositoryPort`, from which `AuthorizationConfiguration` builds `AuthorizationService`). Activation rationale lives in [ADR-0014](../adr/0014-unified-authz-framework-in-core.md).

### Activation

Add `WebAppAuthorizationFilterConfiguration` to your `@Import` list. The filter and its supporting beans are created only when all the required SPIs are present; otherwise the chain configuration's `addFilterAfterIfAvailable` call is a no-op.

```java
@Configuration
@Import({
    BaseSecurityConfiguration.class,
    OidcWebappSecurityConfiguration.class,
    OidcApiSecurityConfiguration.class,
    OidcBeansConfiguration.class,
    AuthFailureHandlerConfiguration.class,
    WebAppAuthorizationFilterConfiguration.class
})
public class HostSecurityConfiguration {}
```

### Opting out

If your host doesn't enforce per-web-app authorization (for example Hub, which has no resource→permission model that maps onto the `AuthorizationResourceType.COMPONENT` + `PermissionType.ACCESS` shape), simply omit `WebAppAuthorizationFilterConfiguration` from your `@Import` list. The chain configurations inject the filter via `ObjectProvider`; when the bean isn't there, `addFilterAfterIfAvailable(...)` is a no-op. Nothing else in the webapp chain changes.

There is no halfway state to worry about — the filter is either fully wired (you imported the configuration and registered the SPIs) or completely absent (you didn't). It's safe to add later when the host's authorization model is ready.

### Single-web-app host: constant `WebAppProviderPort`

A host that serves a single web app returns a constant id for every request:

```java
@Bean
public WebAppProviderPort singleWebAppProviderPort() {
  return request -> Optional.of("operate");
}
```

### Multi-web-app host: path-derived `WebAppProviderPort`

A host that routes `/operate/...`, `/tasklist/...`, etc. to different webapps derives the id from the first non-empty path segment:

```java
@Bean
public WebAppProviderPort pathDerivedWebAppProviderPort(final SecurityPathPort pathPort) {
  return request -> {
    final String uri = request.getRequestURI();
    final String contextPath = request.getContextPath();
    final String relative = uri.startsWith(contextPath) ? uri.substring(contextPath.length()) : uri;
    if (relative.isEmpty() || "/".equals(relative)) {
      return Optional.empty();
    }
    final int slash = relative.indexOf('/', 1);
    final String segment = slash > 0 ? relative.substring(1, slash) : relative.substring(1);
    return pathPort.webComponentNames().contains(segment) ? Optional.of(segment) : Optional.empty();
  };
}
```

`Optional.empty()` signals "this request doesn't belong to a web app" and the filter passes through without invoking the permission check. Filter requests for static assets, anonymous users, and `/forbidden` URLs are pre-filtered by the filter itself — the provider only has to handle the path-derivation question.

### Authorization data: `AuthorizationScopeRepositoryPort`

The webapp filter delegates the decision to an `AuthorizationCheckPort`. The simplest way to provide one is to register an `AuthorizationScopeRepositoryPort` (plus a `MembershipPort`): the library then builds an `AuthorizationChecker` and the default `AuthorizationService` (`AuthorizationCheckPort`) for you via `AuthorizationConfiguration`.

`AuthorizationScopeRepositoryPort` returns the scopes a set of pre-resolved owner IDs hold for a `(resourceType, permissionType)`; the library resolves the principal's owners (user/client, groups, roles, mapping rules) through `MembershipPort` before calling it. Back it with your authorization store:

```java
@Bean
public AuthorizationScopeRepositoryPort authorizationScopeRepository(final MyAuthzStore store) {
  return new MyAuthorizationScopeRepository(store);
}
```

See `SearchAuthorizationScopeRepository` in the `camunda/camunda` monorepo for a search-index-backed implementation. Hosts that need bespoke decision logic can instead register their own `AuthorizationCheckPort` bean directly — the library default backs off via `@ConditionalOnMissingBean(AuthorizationCheckPort.class)`.

### Custom `WebAppAccessDeniedHandlerPort` (optional)

The default `RedirectingWebAppAccessDeniedAdapter` calls `response.sendRedirect("<contextPath>/<webApp>/forbidden")`. To return a 403 JSON body instead:

```java
@Bean
public WebAppAccessDeniedHandlerPort jsonProblemDetailDeniedHandler(final ObjectMapper objectMapper) {
  return (request, response, webApp, authentication) -> {
    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    objectMapper.writeValue(
        response.getWriter(),
        Map.of(
            "type", "about:blank",
            "title", "Forbidden",
            "status", 403,
            "detail", "No ACCESS permission for web app '" + webApp + "'",
            "instance", request.getRequestURI()));
  };
}
```

Registering any `WebAppAccessDeniedHandlerPort` bean disables the library default. The handler is invoked exactly once per denied request; the filter does not call `filterChain.doFilter(...)` afterwards.

### Required and supplied beans for web app authorization

| Bean | Default | When |
|---|---|---|
| `WebAppProviderPort` | None — host must register | Always required |
| `CamundaAuthenticationProvider` | None — host must register | Always required |
| `SecurityPathPort` | None — host must register | Always required (already present for any CSL chain) |
| `AuthorizationCheckPort` | `AuthorizationService` (gated on `AuthorizationChecker` + `@ConditionalOnMissingBean`) | The filter requires this bean — supply it either by registering an `AuthorizationScopeRepositoryPort` (default service materialises) or by registering a custom `AuthorizationCheckPort` directly |
| `AuthorizationScopeRepositoryPort` | None — host must register | Required when relying on the default `AuthorizationService`. Not needed if the host supplies its own `AuthorizationCheckPort` |
| `MembershipPort` | None — host must register | Required for the default `AuthorizationService` — the claims converter resolves principal owners through it |
| `WebAppAccessDeniedHandlerPort` | `RedirectingWebAppAccessDeniedAdapter` (gated on `WebAppProviderPort` + `@ConditionalOnMissingBean`) | Override for JSON 403, forwards, etc. |

If any of the required beans is missing (and `AuthorizationCheckPort` not satisfied either way), the filter bean isn't created. The webapp chain still works — it just doesn't enforce the per-web-app `ACCESS` check. Adopt incrementally by registering the SPIs as you build out the host's authorization data layer.

Note: `MembershipPort` behaves differently from the rows above. Once an `AuthorizationScopeRepositoryPort` is registered (so `AuthorizationChecker` is built), `AuthorizationConfiguration` requires a `LazyTokenClaimsConverter` to construct `AuthorizationService` — and that converter is only created when `MembershipPort` is present. So a missing `MembershipPort` in that situation doesn't silently omit the filter; it fails Spring context startup with an unsatisfied dependency.

## Admin user setup

The CSL's `AdminUserCheckFilter` ensures an admin user has been provisioned before letting requests reach the rest of the application. If no admin user exists, the filter hands off to the host so the browser can be sent to a setup wizard (or whatever the host's response shape is). Once an admin user exists, the filter passes every request through. The filter is host-pluggable on two axes:

- **Has an admin user been provisioned?** Implement `AdminUserPresencePort.adminUserExists()`. Hosts answer from any combination of static configuration and live storage — the library has no opinion on the data layer.
- **What happens when no admin user exists?** The library default redirects to `<contextPath>/admin/setup`. Override `AdminUserMissingHandlerPort` to return JSON, forward, or anything else.

A third concern — which paths bypass the check entirely (typically the setup endpoint plus its static assets) — is declared on the existing `SecurityPathPort` via `adminFilterBypassPaths()`, alongside the host's other path declarations. Activation rationale lives in [ADR-0004](../adr/0004-admin-user-setup-spis.md).

### Activation

Add `AdminUserCheckFilterConfiguration` to your `@Import` list. The filter and its supporting beans are created only when the required SPIs are present; otherwise the chain configurations skip adding the filter:

```java
@Configuration
@Import({
    BaseSecurityConfiguration.class,
    OidcWebappSecurityConfiguration.class,
    OidcApiSecurityConfiguration.class,
    OidcBeansConfiguration.class,
    AuthFailureHandlerConfiguration.class,
    AdminUserCheckFilterConfiguration.class
})
public class HostSecurityConfiguration {}
```

### Opting out

If your host doesn't enforce admin-user setup (for example Hub, which doesn't model admins this way), simply omit `AdminUserCheckFilterConfiguration` from your `@Import` list. The chain configurations look up the filter via `ObjectProvider`; when the bean isn't there, the conditional addition is a no-op. Nothing else in the webapp chain changes.

There is no halfway state to worry about — the filter is either fully wired (you imported the configuration and registered the SPIs) or completely absent (you didn't). It's safe to add later when the host has an admin-presence concept in place.

### Static-config-only `AdminUserPresencePort`

A host that bootstraps admin presence from a `@Value`-injected boolean (or any other static configuration) can implement the port as a one-line lambda:

```java
@Bean
public AdminUserPresencePort staticAdminUserPresence(
    @Value("${myapp.admin-user.bootstrapped:false}") final boolean bootstrapped) {
  return () -> bootstrapped;
}
```

### Live-data `AdminUserPresencePort`

A host that consults its authorization storage to determine whether an admin user has been provisioned might combine a static-config check with a live-data lookup, mirroring the OC source behaviour:

```java
@Bean
public AdminUserPresencePort liveAdminUserPresence(
    final MyAuthzConfig authzConfig, final MyRoleService roleService) {
  return () -> {
    if (!authzConfig.bootstrappedAdminUsers().isEmpty()) {
      return true;
    }
    return roleService.hasMembers("admin", MemberType.USER);
  };
}
```

The library calls `adminUserExists()` once per request that isn't on a bypass path, so the implementation should either be cheap or cache its result. If the call throws, the filter logs at error and lets the request through — a transient secondary-storage outage must not block users.

### Bypass paths via `SecurityPathPort`

Override `adminFilterBypassPaths()` on your `SecurityPathPort` implementation to declare the setup endpoint plus any prefixes whose sub-paths the setup UI needs to load:

```java
@Override
public Set<String> adminFilterBypassPaths() {
  return Set.of("/admin/setup", "/admin/assets");
}
```

Each entry matches the request's path within the application (i.e. the URI with the servlet context path stripped) when the path equals the entry exactly or starts with `entry + "/"`. So `/admin/setup` matches `/admin/setup` (the setup endpoint itself) but not `/admin/setupbar`, and `/admin/assets` matches every sub-path under it.

### Custom `AdminUserMissingHandlerPort` (optional)

The default `RedirectingAdminUserMissingAdapter` calls `response.sendRedirect("<contextPath>/admin/setup")`. To return a JSON 503 instead:

```java
@Bean
public AdminUserMissingHandlerPort jsonProblemDetailMissingHandler(final ObjectMapper objectMapper) {
  return (request, response) -> {
    response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    objectMapper.writeValue(
        response.getWriter(),
        Map.of(
            "type", "about:blank",
            "title", "Service Unavailable",
            "status", 503,
            "detail", "No admin user has been provisioned",
            "instance", request.getRequestURI()));
  };
}
```

Registering any `AdminUserMissingHandlerPort` bean disables the library default. The handler is invoked exactly once per request that fails the presence check; the filter does not call `filterChain.doFilter(...)` afterwards.

### Required and supplied beans for admin user setup

| Bean | Default | When |
|---|---|---|
| `AdminUserPresencePort` | None — host must register | Always required |
| `SecurityPathPort` | None — host must register | Always required (already present for any CSL chain). Override `adminFilterBypassPaths()` to declare the setup endpoint + asset prefixes |
| `AdminUserMissingHandlerPort` | `RedirectingAdminUserMissingAdapter` (gated on `AdminUserPresencePort` + `@ConditionalOnMissingBean`) | Override for JSON 503, forwards, alternative redirect targets, etc. |

If `AdminUserPresencePort` is absent, the filter bean isn't created. The webapp chain still works — it just doesn't enforce the admin-presence check. Adopt incrementally by registering the port once your host's authorization data layer is ready to answer.

### Filter ordering when both this and `WebAppAuthorizationCheckFilter` are active

When a host activates both `AdminUserCheckFilterConfiguration` and `WebAppAuthorizationFilterConfiguration`, the chain configurations anchor the webapp filter on the admin filter so the admin-presence redirect runs before any per-web-app permission check. The order is structurally guaranteed via `addFilterAfter(WebAppAuthorizationCheckFilter, AdminUserCheckFilter.class)` — not left to insertion-order tiebreakers — so an unprovisioned system always redirects to setup before a missing permission triggers a forbidden response.

## OIDC logout

When `authentication.method=oidc`, CSL builds a [`CamundaOidcLogoutSuccessHandler`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/CamundaOidcLogoutSuccessHandler.java) for every OIDC webapp chain — the primary chain and each path-scoped chain — inside `ScopedWebappSecurityChainBuilder`. The handler extends Spring Security's `OidcClientInitiatedLogoutSuccessHandler` with two additions over plain RP-initiated logout. Rationale lives in [ADR-0009](../adr/0009-session-store-port-and-web-session-ownership.md).

**What ships by default**

1. **Post-logout redirect from the `Referer` header.** When the `Referer` on the logout request matches the current application's scheme, host, and effective port (default ports normalised), the URL is stored on the HTTP session under [`CamundaOidcLogoutSuccessHandler.POST_LOGOUT_REDIRECT_ATTRIBUTE`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/CamundaOidcLogoutSuccessHandler.java) (string `"postLogoutRedirect"`). Cross-origin referers, host-confusion attempts (`https://app.example.com.evil.com/`, `https://app.example.com@evil.com/`), CR/LF-injection, and unparseable URLs are rejected. Hosts that render a post-logout page read the session attribute via the constant — not the literal string — to keep the contract stable.
2. **`login_hint` → `logout_hint` propagation.** When the OIDC user has a `login_hint` claim, it is appended as a `logout_hint` query parameter to the IdP's end-session URL. This lets providers that maintain multiple sessions per user terminate the correct one.

If the IdP's discovery document does not expose `end_session_endpoint`, the local session is still terminated and a human-readable explanation is stored on the session under `CamundaOidcLogoutSuccessHandler.REDIRECT_MESSAGE_ATTRIBUTE` so a post-logout page on the subsequent request can render it.

The handler is multi-IdP-aware — it looks up the `ClientRegistration` by the principal's `authorizedClientRegistrationId`.

**Activation and the post-logout route**

There is no `LogoutSuccessHandler` bean to register or override. CSL constructs one handler per OIDC webapp chain, each bound to that chain's own `ClientRegistrationRepository` and its own base-path prefix — a shared singleton cannot carry either, which is why the bean seam was removed.

The one host input is the post-logout landing route, declared on `SecurityPathPort`:

```java
@Override
public Optional<String> postLogoutRedirectPath() {
  return Optional.of("/post-logout");
}
```

CSL sends the IdP `{baseUrl}<basePath><route>` as the `post_logout_redirect_uri`, so a scoped chain resolves it under its own prefix. The route must start with `/`. The default is `Optional.empty()`, meaning no `post_logout_redirect_uri` is sent and the IdP applies its own default — never return `null`. Every per-scope redirect URI must be allow-listed at the IdP; multi-tenant deployments need a wildcard or pattern registration. See [ADR-0009](../adr/0009-session-store-port-and-web-session-ownership.md).

**Reading the post-logout redirect URL**

```java
import static io.camunda.security.spring.security.CamundaOidcLogoutSuccessHandler.POST_LOGOUT_REDIRECT_ATTRIBUTE;

@GetMapping("/logged-out")
public String loggedOut(final HttpSession session, final Model model) {
  final Object target = session.getAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE);
  model.addAttribute("returnTo", target instanceof String s ? s : "/");
  return "logged-out";
}
```

The CSL stores the attribute; rendering the post-logout page (or redirecting to the stored URL) remains a host concern.

**Overriding the default**

Register your own `LogoutSuccessHandler` bean. The CSL default backs off and the chain wires your bean instead:

```java
@Bean
LogoutSuccessHandler hostLogoutSuccessHandler(
    final ClientRegistrationRepository clientRegistrationRepository) {
  final var handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
  handler.setPostLogoutRedirectUri("{baseUrl}/host-specific-logged-out");
  return handler;
}
```

Registering a custom `LogoutSuccessHandler` bean is the only override path — there is no opt-out flag.

## Failure response contract

`AuthFailureHandler` is an interface; the library's default implementation (`JsonProblemDetailAuthFailureHandler`) returns RFC 7807 problem-detail JSON for every authentication and authorization failure on every chain. Bodies look like:

```json
{
  "type": "about:blank",
  "title": "Unauthorized",
  "status": 401,
  "detail": "<exception message>",
  "instance": "/api/foo"
}
```

The 401 vs 403 split:

- 401 — no authentication present, or authentication failed.
- 403 — authentication present but insufficient permissions.

For OIDC API chains, bearer-token failures additionally pass through `LoggingAuthenticationFailureHandler`, which routes `AuthenticationServiceException` (technical / IdP-side problems) to a 500 response with a `WARN` log so the source of the failure is captured. Other authentication failures keep the standard 401 response.

To return a different problem-detail schema, register your own `AuthFailureHandler` bean. The library's default backs off automatically.

## CSRF, headers, sessions

When `camunda.security.csrf.enabled=true` (the default), every API and webapp chain applies cookie-backed CSRF protection through `CsrfProtectionRequestMatcher`. Allowed methods (GET/HEAD/TRACE/OPTIONS), unprotected paths, the login endpoint, the logout endpoint, and any host-supplied `csrf.ignored-path-patterns` are exempt. Browser clients receive the token on authenticated GETs and the login response — the cookie name and header are both `X-CSRF-TOKEN`. Set `cookie-http-only=true` for API-only hosts that read the token from the response header instead of the cookie.

HTTP response headers are configured by `HeaderConfiguration`. Defaults are the hardened production set: nosniff, cache-control, HSTS (1 year, no preload), X-Frame-Options `SAMEORIGIN`, the bundled CSP and permissions policy, `Referrer-Policy: STRICT_ORIGIN_WHEN_CROSS_ORIGIN`, COOP `SAME_ORIGIN_ALLOW_POPUPS`, COEP `UNSAFE_NONE`, CORP `SAME_SITE`. Override individual values under `camunda.security.http-headers.*`.

Session policy:

- API chains (OIDC and basic) — `SessionCreationPolicy.NEVER`. Stateless; no cookie issued.
- Webapp chains — session-backed. The cookie is `camunda-session`; logout clears it along with `X-CSRF-TOKEN`.

## What this library deliberately does *not* provide

- **Multi-IdP routing.** `OidcWebappSecurityConfiguration` uses Spring Security's default authorization request resolver. Multi-IdP support is a follow-up PR.
- **`private_key_jwt` defaults.** Implement `OidcTokenEndpointCustomizer` if needed.
- **A user database, role mapping, or membership resolution.** Those belong to the authorization side of the CSL — see the policy-model documents.

## Migrating an existing host

A typical migration from a host-owned `WebSecurityConfig`:

1. Replace your `@Bean SecurityFilterChain` methods by deleting them. Add an `@Import` list for the library's configuration classes — pick the ones that match your auth method and API protection mode (see the [Quickstart](#quickstart) snippet). Per [ADR-0003](../adr/0003-no-spring-boot-auto-configuration.md) hosts opt in to each capability explicitly; nothing activates by simply adding the dependency.
2. Move whatever you previously hand-rolled into `OidcResourceServerCustomizer` / `OidcTokenEndpointCustomizer` beans where applicable. For per-web-app authorization, register a `WebAppProviderPort` and an `AuthorizationCheckPort` (or an `AuthorizationScopeRepositoryPort` + `MembershipPort` so the library builds the default) and `@Import(WebAppAuthorizationFilterConfiguration.class)` — see [Web app authorization](#web-app-authorization). For admin-user setup, register an `AdminUserPresencePort` and `@Import(AdminUserCheckFilterConfiguration.class)` — see [Admin user setup](#admin-user-setup).
3. Implement `SecurityPathPort` with the path patterns your previous chains used.
4. Bind your existing security config to `camunda.security.*` properties (or set them explicitly).
5. If you previously constructed `JwtDecoder` / `ClientRegistrationRepository` / `OAuth2AuthorizedClientRepository` / `OAuth2AuthorizedClientManager` by hand, either delete those beans (the library's defaults will activate) or leave them and the library's defaults back off via `@ConditionalOnMissingBean`.
6. Delete the old `WebSecurityConfig`.
7. Run your existing security integration tests — RFC 7807 response bodies, 401/403 split, CSRF cookie name, and CSP defaults should match the centralised behaviour. Update any tests that asserted host-specific quirks that aren't part of the new baseline.

If a behavioural difference between your old chain and the central one looks like a bug, file it against the CSL — the goal is that the central chain is strictly better than what each host had before.
