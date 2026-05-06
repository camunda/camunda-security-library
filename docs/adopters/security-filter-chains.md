# Adopting the central security filter chains

This guide is for host applications (Hub, Orchestration Cluster gateways, future Camunda services) that embed the Camunda Security Library. It explains how to wire the central filter chains, what host-side beans are required, and how to extend or override library defaults.

For the rationale behind this design — why the chains are Spring Boot auto-configured rather than `@Import`-composed — see [ADR-0006](../adr/0006-central-security-filter-chains.md).

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

3. Set the auth method and any auth-mode-specific properties in `application.yaml`:

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

   That's it. The library activates the `BaseSecurity` chains (always-on unprotected paths + catch-all deny), the OIDC API chain, the OIDC webapp chain, and provides default `JwtDecoder` / `ClientRegistrationRepository` / `OAuth2AuthorizedClientRepository` / `OAuth2AuthorizedClientManager` / `AuthFailureHandler` beans wired to those properties.

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

### `camunda.security.authentication.oidc.*` (consulted when `method=oidc`)

| Property | Type | Default | Effect |
|---|---|---|---|
| `issuer-uri` | string | unset | OIDC issuer. The library uses this to discover the JWK set if `jwk-set-uri` is unset. |
| `client-id` | string | unset | OAuth2 client id. |
| `client-secret` | string | unset | OAuth2 client secret. |
| `jwk-set-uri` | string | unset | Explicit JWK set URI. If unset, derived from `issuer-uri`. |
| `additional-jwk-set-uris` | list&lt;string&gt; | empty | Reserved for multi-JWKS-source hosts; not consumed by the default beans. |
| `authorization-uri`, `token-uri`, `user-info-uri` | string | unset | Endpoint overrides for non-discovery flows. |
| `redirect-uri` | string | unset | OAuth2 redirect-uri template. |
| `scope` | list&lt;string&gt; | `[openid, profile]` | OAuth2 scopes requested. |
| `audiences` | list&lt;string&gt; | empty | Reserved; not consumed by the default beans. |
| `registration-id` | string | `oidc` | Spring Security client registration id. |
| `client-authentication-method` | string | `client_secret_basic` | Spring Security `ClientAuthenticationMethod` literal. |

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
| `JwtDecoder` | `method=oidc` | Custom JWT validators (audience, issuer pinning), multi-JWKS-source hosts |
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

- `LogoutSuccessHandler` — wired into the OIDC webapp chain for IdP-coordinated logout.
- `OidcUserService` — wired into the OIDC user-info endpoint.

These are looked up via `ObjectProvider#ifAvailable`; absence is fine, the chain falls back to Spring Security defaults.

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

1. Replace your `@Bean SecurityFilterChain` methods by deleting them — the library's auto-configurations supply the chains. Don't `@Import` anything from the library; just include the dep.
2. Move whatever you previously hand-rolled into `OidcResourceServerCustomizer` / `OidcTokenEndpointCustomizer` beans where applicable. For host-specific filter wiring (authorization filters, header rewrites), park the change until the follow-up PR introduces the new filter approach.
3. Implement `SecurityPathPort` with the path patterns your previous chains used.
4. Bind your existing security config to `camunda.security.*` properties (or set them explicitly).
5. If you previously constructed `JwtDecoder` / `ClientRegistrationRepository` / `OAuth2AuthorizedClientRepository` / `OAuth2AuthorizedClientManager` by hand, either delete those beans (the library's defaults will activate) or leave them and the library's defaults back off via `@ConditionalOnMissingBean`.
6. Delete the old `WebSecurityConfig`.
7. Run your existing security integration tests — RFC 7807 response bodies, 401/403 split, CSRF cookie name, and CSP defaults should match the centralised behaviour. Update any tests that asserted host-specific quirks that aren't part of the new baseline.

If a behavioural difference between your old chain and the central one looks like a bug, file it against the CSL — the goal is that the central chain is strictly better than what each host had before.
