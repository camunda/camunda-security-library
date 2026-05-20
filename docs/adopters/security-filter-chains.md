# Adopting the central security filter chains

This guide is for host applications (Hub, Orchestration Cluster (OC) gateways, future Camunda services) that embed the Camunda Security Library. It explains how to wire the central filter chains, what host-side beans are required, and how to extend or override library defaults.

For the rationale behind this design — why the chains live in CSL — see [ADR-0006](../adr/0006-central-security-filter-chains.md). For why hosts opt in via explicit `@Import` rather than relying on Spring Boot auto-configuration, see [ADR-0008](../adr/0008-no-spring-boot-auto-configuration.md).

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

3. `@Import` the configuration classes you want active. The CSL does not use Spring Boot auto-configuration ([ADR-0008](../adr/0008-no-spring-boot-auto-configuration.md)) — nothing activates by simply adding the dependency. Hosts opt in to each capability explicitly:

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
| `additional-jwk-set-uris` | list&lt;string&gt; | empty | Secondary JWK Set URIs consulted when the primary `jwk-set-uri` does not resolve a token's signing key. See [Multiple JWK Set URIs](#multiple-jwk-set-uris) below and [ADR-0015](../adr/0015-additional-jwk-set-uris-composite-decoder.md). |
| `authorization-uri`, `token-uri`, `user-info-uri` | string | unset | Endpoint overrides for non-discovery flows. |
| `user-info-enabled` | boolean | `true` | When `false`, the built `ClientRegistration` has its `userInfoUri` nulled so Spring Security does not call the IdP's UserInfo endpoint after token exchange. See [Disabling the UserInfo fetch](#disabling-the-userinfo-fetch) below and [ADR-0014](../adr/0014-oidc-user-info-enabled-toggle.md). |
| `redirect-uri` | string | unset | OAuth2 redirect-uri template. |
| `scope` | list&lt;string&gt; | `[openid, profile]` | OAuth2 scopes requested. |
| `audiences` | list&lt;string&gt; | empty | Reserved; not consumed by the default beans. |
| `registration-id` | string | `oidc` | Spring Security client registration id. |
| `client-authentication-method` | string | `client_secret_basic` | Spring Security `ClientAuthenticationMethod` literal. |

### Multi-IdP OIDC (`camunda.security.authentication.providers.oidc.<id>.*`)

The library supports multiple OIDC providers by binding a map of `OidcConfiguration` instances under `camunda.security.authentication.providers.oidc.<id>.*`. Each map key becomes the Spring Security `registrationId`, so login routing works through Spring's standard `/oauth2/authorization/<id>` URL — no chain customisation is required. The shape mirrors OC's [`ProvidersConfiguration`](https://github.com/camunda/camunda/blob/main/security/security-core/src/main/java/io/camunda/security/configuration/ProvidersConfiguration.java) so hosts migrating from OC keep their existing configuration. See [ADR-0013](../adr/0013-multi-idp-oidc-configuration.md) for the design rationale.

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

> **Important — `JwtDecoder` selection.** The configuration above has no flat `oidc.*` block, and the library's default `JwtDecoder` refuses to auto-pick across multiple providers (see [JwtDecoder selection rules](#resource-server-jwtdecoder-selection) below). As shown, startup fails with an `IllegalStateException` because both the OIDC webapp chain and the OIDC API chain depend on the `JwtDecoder` bean. To run this two-provider configuration, either add a flat `oidc.*` block to pin the resource-server audience, or register a custom `@Bean JwtDecoder` in the host application — `OidcBeansConfiguration` backs off via `@ConditionalOnMissingBean` so the library's default no longer activates.

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

The library ships a single `JwtDecoder` bean. With multiple providers, a single decoder cannot correctly validate tokens from every IdP (each carries its own signing keys and audience), so selection is deterministic and explicit:

1. The flat `oidc.*` block is preferred if it has an `issuer-uri` or `jwk-set-uri`.
2. Otherwise, if exactly one entry under `providers.oidc.*` has such a source, that entry is used.
3. Otherwise (no source anywhere, or multiple providers with sources and no flat block), startup fails with an `IllegalStateException`.

When startup fails because of rule 3, either pin the flat block as the resource-server audience or register a custom `@Bean JwtDecoder` in the host application — `OidcBeansConfiguration` backs off via `@ConditionalOnMissingBean`.

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

`issuer-uri` is set alongside `jwk-set-uri` here because `ClientRegistration` construction requires either `issuer-uri` (for discovery of authorization/token endpoints) or all three of `authorization-uri`/`token-uri`/`jwk-set-uri` explicitly. The `additional-jwk-set-uris` wiring is independent of which path you choose to populate the registration; the only constraint is that the primary `jwk-set-uri` is set explicitly (the `JwtDecoder` does not consume discovered JWKS endpoints when additional URIs are configured).

The default `JwtDecoder` queries the primary `jwk-set-uri` first, then each entry in `additional-jwk-set-uris` in declared order. The first source that resolves the token's `kid` wins. If an additional URI is unreachable, the failure is logged at WARN and the next source is tried — a failing additional URI does not break validation against the primary or other working URIs.

Two constraints to be aware of:

- **Explicit `jwk-set-uri` is required.** Discovery via `issuer-uri` alone is not supported when `additional-jwk-set-uris` is set. Set `jwk-set-uri` explicitly even if it points at the same endpoint the discovery document would resolve to. Startup fails with an actionable error otherwise.
- **`kid` collision precedence.** If two JWK Sets publish a key with the same `kid` (unlikely in practice), the primary `jwk-set-uri` wins because it is queried first. Reorder `additional-jwk-set-uris` to change precedence among the additional URIs.

See [ADR-0015](../adr/0015-additional-jwk-set-uris-composite-decoder.md) for the design rationale, the choice of composite `JWKSource` over Spring's `JwtIssuerAuthenticationManagerResolver`, and the lazy failure model.

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

A host-supplied `OidcUserService` bean still takes precedence in both modes (see [ADR-0014](../adr/0014-oidc-user-info-enabled-toggle.md)) — `user-info-enabled` only governs the library's default wiring.

### Customising the authorisation request (`resource`, `additional_parameters`)

CSL ships a default `OAuth2AuthorizationRequestResolver` (`CamundaOidcAuthorizationRequestResolver`) from `OidcBeansConfiguration`. It wraps Spring Security's `DefaultOAuth2AuthorizationRequestResolver` per registration and injects two `OidcConfiguration` properties into the outgoing OAuth2 authorisation request. Hosts that need different customizer logic register their own `OAuth2AuthorizationRequestResolver` bean; CSL backs off via `@ConditionalOnMissingBean`.

#### `resource` (RFC 8707)

When `resource` is set on a provider, every entry in the list is added as a `resource` query parameter on the IdP authorisation URL. Use this when the IdP requires an explicit audience for the issued access token.

#### `authorize-request.additional-parameters`

Arbitrary key/value pairs that are appended verbatim to the authorisation request. Useful for IdP-specific extensions such as `prompt`, `audience`, or vendor-specific switches. Values are passed through unchanged — the library does not interpret them.

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

Every library-supplied bean has `@ConditionalOnMissingBean`. Define your own bean of the same type and the library's default backs off.

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

## Extension hooks

Two extension points let hosts customise specific OAuth2/OIDC concerns without replacing entire chains. Host-specific filter wiring (authorization filters, header rewrites, matcher tweaks) will be addressed in a follow-up PR with a more focused approach than a generic `HttpSecurity` mutator.

### `OidcResourceServerCustomizer` — customise the OAuth2 resource-server DSL

Both OIDC chains route through every `OidcResourceServerCustomizer` bean inside `oauth2ResourceServer(...)`. Use this for RFC 9728 protected-resource metadata, custom JWT validators, or swapping the bearer-token entry point.

```java
@Bean
public OidcResourceServerCustomizer protectedResourceMetadata(...) {
  return oauth2 -> oauth2.protectedResourceMetadata(...);
}
```

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

### Other host beans the chains pick up automatically

- `LogoutSuccessHandler` — wired into the OIDC webapp chain for IdP-coordinated logout. The CSL ships a default (`CamundaOidcLogoutSuccessHandler`) via `OidcBeansConfiguration` when `authentication.method=oidc` and the host activates CSL through the `CamundaSecurityAutoConfiguration` umbrella; a host-registered bean replaces it. See [OIDC logout](#oidc-logout).
- `OidcUserService` — wired into the OIDC user-info endpoint.

These are looked up via `ObjectProvider#ifAvailable`; absence is fine, the chain falls back to Spring Security defaults.

## Web app authorization

The CSL's `WebAppAuthorizationCheckFilter` enforces per-web-app `ACCESS` permission on every authenticated webapp request. It runs immediately after Spring Security's `AuthorizationFilter` on the webapp chain. The filter is host-pluggable on two axes:

- **Which web app does the request belong to?** A single-web-app host returns a constant; a multi-web-app host derives from the URL path. Implement `WebAppProviderPort`.
- **What happens when access is denied?** The library default redirects to `<contextPath>/<webApp>/forbidden`. Override `WebAppAccessDeniedHandlerPort` to return JSON, forward, or anything else.

The actual permission decision delegates to `ResourcePermissionPort` — see [ADR-0007](../adr/0007-resource-permission-port-and-authorization-repository.md). Hosts implement `AuthorizationRepositoryPort` for the data; the library supplies a default `ResourcePermissionService` that does an exact-id match. Hosts that need different matching semantics override `ResourcePermissionPort` directly. Activation rationale lives in [ADR-0009](../adr/0009-web-app-authorization-spis.md).

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

If your host doesn't enforce per-web-app authorization (for example Hub, which has no resource→permission model that maps onto the `ResourceType.COMPONENT` + `PermissionType.ACCESS` shape), simply omit `WebAppAuthorizationFilterConfiguration` from your `@Import` list. The chain configurations inject the filter via `ObjectProvider`; when the bean isn't there, `addFilterAfterIfAvailable(...)` is a no-op. Nothing else in the webapp chain changes.

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

### Authorization data: `AuthorizationRepositoryPort`

Implement the outbound port that returns the principal's authorization records for a given resource type. The library calls this per request through the default `ResourcePermissionService`:

```java
@Bean
public AuthorizationRepositoryPort authorizationRepository(final MyAuthzStore store) {
  return (authentication, resourceType) ->
      store.findGrants(authentication.authenticatedUsername(), resourceType).stream()
          .map(grant -> new Authorization(
              grant.resourceType(),
              grant.resourceId(),
              Set.copyOf(grant.permissionTypes())))
          .collect(Collectors.toSet());
}
```

The library's default `ResourcePermissionService` then matches by exact resource id and required permission. Hosts that need wildcard semantics, caching, or instrumentation register their own `ResourcePermissionPort` bean — the default backs off via `@ConditionalOnMissingBean`.

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
| `ResourcePermissionPort` | `ResourcePermissionService` (gated on `AuthorizationRepositoryPort` + `@ConditionalOnMissingBean`) | The filter requires this bean — supply it either by registering an `AuthorizationRepositoryPort` (default service materialises) or by registering a custom `ResourcePermissionPort` directly |
| `AuthorizationRepositoryPort` | None — host must register | Required when relying on the default `ResourcePermissionService`. Not needed if the host supplies its own `ResourcePermissionPort` |
| `WebAppAccessDeniedHandlerPort` | `RedirectingWebAppAccessDeniedAdapter` (gated on `WebAppProviderPort` + `@ConditionalOnMissingBean`) | Override for JSON 403, forwards, etc. |

If any of the required beans is missing (and `ResourcePermissionPort` not satisfied either way), the filter bean isn't created. The webapp chain still works — it just doesn't enforce the per-web-app `ACCESS` check. Adopt incrementally by registering the SPIs as you build out the host's authorization data layer.

## Admin user setup

The CSL's `AdminUserCheckFilter` ensures an admin user has been provisioned before letting requests reach the rest of the application. If no admin user exists, the filter hands off to the host so the browser can be sent to a setup wizard (or whatever the host's response shape is). Once an admin user exists, the filter passes every request through. The filter is host-pluggable on two axes:

- **Has an admin user been provisioned?** Implement `AdminUserPresencePort.adminUserExists()`. Hosts answer from any combination of static configuration and live storage — the library has no opinion on the data layer.
- **What happens when no admin user exists?** The library default redirects to `<contextPath>/admin/setup`. Override `AdminUserMissingHandlerPort` to return JSON, forward, or anything else.

A third concern — which paths bypass the check entirely (typically the setup endpoint plus its static assets) — is declared on the existing `SecurityPathPort` via `adminFilterBypassPaths()`, alongside the host's other path declarations. Activation rationale lives in [ADR-0010](../adr/0010-admin-user-setup-spis.md).

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

When `authentication.method=oidc` and a host activates CSL via the `CamundaSecurityAutoConfiguration` umbrella, [`OidcBeansConfiguration`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/OidcBeansConfiguration.java) registers a default `LogoutSuccessHandler` — [`CamundaOidcLogoutSuccessHandler`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/CamundaOidcLogoutSuccessHandler.java) — that extends Spring Security's `OidcClientInitiatedLogoutSuccessHandler` with two additions over plain RP-initiated logout. Activation rationale lives in [ADR-0012](../adr/0012-oidc-logout-success-handler.md).

**What ships by default**

1. **Post-logout redirect from the `Referer` header.** When the `Referer` on the logout request matches the current application's scheme, host, and effective port (default ports normalised), the URL is stored on the HTTP session under [`CamundaOidcLogoutSuccessHandler.POST_LOGOUT_REDIRECT_ATTRIBUTE`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/CamundaOidcLogoutSuccessHandler.java) (string `"postLogoutRedirect"`). Cross-origin referers, host-confusion attempts (`https://app.example.com.evil.com/`, `https://app.example.com@evil.com/`), CR/LF-injection, and unparseable URLs are rejected. Hosts that render a post-logout page read the session attribute via the constant — not the literal string — to keep the contract stable.
2. **`login_hint` → `logout_hint` propagation.** When the OIDC user has a `login_hint` claim, it is appended as a `logout_hint` query parameter to the IdP's end-session URL. This lets providers that maintain multiple sessions per user terminate the correct one.

If the IdP's discovery document does not expose `end_session_endpoint`, the local session is still terminated and a human-readable explanation is stored on the session under `CamundaOidcLogoutSuccessHandler.REDIRECT_MESSAGE_ATTRIBUTE` so a post-logout page on the subsequent request can render it.

The handler is multi-IdP-aware — it looks up the `ClientRegistration` by the principal's `authorizedClientRegistrationId`.

**Activation**

The bean lives in `OidcBeansConfiguration` (already a member of the `CamundaSecurityAutoConfiguration` umbrella), so hosts activating CSL via the recommended opt-in path get the default `LogoutSuccessHandler` automatically:

```java
@Configuration
@ImportAutoConfiguration(CamundaSecurityAutoConfiguration.class)
public class HostSecurityConfiguration {}
```

The bean is `@ConditionalOnMissingBean(LogoutSuccessHandler.class)` — a host-registered bean wins. The umbrella is the activation path that makes `@ConditionalOnMissingBean` evaluate reliably; see [ADR-0008](../adr/0008-no-spring-boot-auto-configuration.md) for the rationale.

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

1. Replace your `@Bean SecurityFilterChain` methods by deleting them. Add an `@Import` list for the library's configuration classes — pick the ones that match your auth method and API protection mode (see the [Quickstart](#quickstart) snippet). Per [ADR-0008](../adr/0008-no-spring-boot-auto-configuration.md) hosts opt in to each capability explicitly; nothing activates by simply adding the dependency.
2. Move whatever you previously hand-rolled into `OidcResourceServerCustomizer` / `OidcTokenEndpointCustomizer` beans where applicable. For per-web-app authorization, register a `WebAppProviderPort` and `AuthorizationRepositoryPort` and `@Import(WebAppAuthorizationFilterConfiguration.class)` — see [Web app authorization](#web-app-authorization). For admin-user setup, register an `AdminUserPresencePort` and `@Import(AdminUserCheckFilterConfiguration.class)` — see [Admin user setup](#admin-user-setup).
3. Implement `SecurityPathPort` with the path patterns your previous chains used.
4. Bind your existing security config to `camunda.security.*` properties (or set them explicitly).
5. If you previously constructed `JwtDecoder` / `ClientRegistrationRepository` / `OAuth2AuthorizedClientRepository` / `OAuth2AuthorizedClientManager` by hand, either delete those beans (the library's defaults will activate) or leave them and the library's defaults back off via `@ConditionalOnMissingBean`.
6. Delete the old `WebSecurityConfig`.
7. Run your existing security integration tests — RFC 7807 response bodies, 401/403 split, CSRF cookie name, and CSP defaults should match the centralised behaviour. Update any tests that asserted host-specific quirks that aren't part of the new baseline.

If a behavioural difference between your old chain and the central one looks like a bug, file it against the CSL — the goal is that the central chain is strictly better than what each host had before.
