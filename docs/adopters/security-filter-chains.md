# Adopting the central security filter chains

This guide is for host applications (Hub, Orchestration Cluster gateways, future Camunda services) that embed the Camunda Security Library. It explains how to wire the central filter chains, what host-side beans are required, and how to extend or override library defaults.

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

## Web app authorization

The CSL's `WebAppAuthorizationCheckFilter` enforces per-web-app `ACCESS` permission on every authenticated webapp request. It runs immediately after Spring Security's `AuthorizationFilter` on the webapp chain. The filter is host-pluggable on two axes:

- **Which web app does the request belong to?** A single-web-app host returns a constant; a multi-web-app host derives from the URL path. Implement `WebAppProvider`.
- **What happens when access is denied?** The library default redirects to `<contextPath>/<webApp>/forbidden`. Override `WebAppAccessDeniedHandler` to return JSON, forward, or anything else.

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

### Single-web-app host: constant `WebAppProvider`

A host that serves a single web app returns a constant id for every request:

```java
@Bean
public WebAppProvider singleWebAppProvider() {
  return request -> Optional.of("operate");
}
```

### Multi-web-app host: path-derived `WebAppProvider`

A host that routes `/operate/...`, `/tasklist/...`, etc. to different webapps derives the id from the first non-empty path segment:

```java
@Bean
public WebAppProvider pathDerivedWebAppProvider(final SecurityPathPort pathPort) {
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

### Custom `WebAppAccessDeniedHandler` (optional)

The default `RedirectingWebAppAccessDeniedHandler` calls `response.sendRedirect("<contextPath>/<webApp>/forbidden")`. To return a 403 JSON body instead:

```java
@Bean
public WebAppAccessDeniedHandler jsonProblemDetailDeniedHandler(final ObjectMapper objectMapper) {
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

Registering any `WebAppAccessDeniedHandler` bean disables the library default. The handler is invoked exactly once per denied request; the filter does not call `filterChain.doFilter(...)` afterwards.

### Required and supplied beans for web app authorization

| Bean | Default | When |
|---|---|---|
| `WebAppProvider` | None — host must register | Always required |
| `AuthorizationRepositoryPort` | None — host must register | Always required |
| `CamundaAuthenticationProvider` | None — host must register | Always required |
| `SecurityPathPort` | None — host must register | Always required (already present for any CSL chain) |
| `ResourcePermissionPort` | `ResourcePermissionService` (gated on `AuthorizationRepositoryPort` + `@ConditionalOnMissingBean`) | Override only if you need different matching semantics |
| `WebAppAccessDeniedHandler` | `RedirectingWebAppAccessDeniedHandler` (gated on `WebAppProvider` + `@ConditionalOnMissingBean`) | Override for JSON 403, forwards, etc. |

If any of the required beans is missing, the filter bean isn't created. The webapp chain still works — it just doesn't enforce the per-web-app `ACCESS` check. Adopt incrementally by registering the SPIs as you build out the host's authorization data layer.

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
2. Move whatever you previously hand-rolled into `OidcResourceServerCustomizer` / `OidcTokenEndpointCustomizer` beans where applicable. For per-web-app authorization, register a `WebAppProvider` and `AuthorizationRepositoryPort` and `@Import(WebAppAuthorizationFilterConfiguration.class)` — see [Web app authorization](#web-app-authorization).
3. Implement `SecurityPathPort` with the path patterns your previous chains used.
4. Bind your existing security config to `camunda.security.*` properties (or set them explicitly).
5. If you previously constructed `JwtDecoder` / `ClientRegistrationRepository` / `OAuth2AuthorizedClientRepository` / `OAuth2AuthorizedClientManager` by hand, either delete those beans (the library's defaults will activate) or leave them and the library's defaults back off via `@ConditionalOnMissingBean`.
6. Delete the old `WebSecurityConfig`.
7. Run your existing security integration tests — RFC 7807 response bodies, 401/403 split, CSRF cookie name, and CSP defaults should match the centralised behaviour. Update any tests that asserted host-specific quirks that aren't part of the new baseline.

If a behavioural difference between your old chain and the central one looks like a bug, file it against the CSL — the goal is that the central chain is strictly better than what each host had before.
