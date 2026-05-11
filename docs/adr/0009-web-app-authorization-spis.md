---
status: Accepted
---

# ADR-0009: Web app authorization SPIs (`WebAppProviderPort`, `WebAppAccessDeniedHandlerPort`)

## Status

Accepted

## Context

[ADR-0006](0006-central-security-filter-chains.md) centralised the API and webapp filter chains in CSL but deferred host-specific filter wiring — authorization filters in particular — to a follow-up:

> Host-specific filter wiring (authorization filters, header rewrites, matcher tweaks) will be addressed in a follow-up PR with a more focused approach than a generic `HttpSecurity` mutator.

The web app authorization filter is the first concrete instance of that follow-up. It runs after `AuthorizationFilter` on the webapp chain and decides whether the authenticated principal has `ACCESS` on the web app the request is bound for. The behaviour is the same in every host, but two pieces of input vary:

1. **Which web app does this request belong to?**
   - A single-web-app host returns a constant id (e.g. `Optional.of("operate")`).
   - A host serving several web apps (Orchestration Cluster, with `/operate/...`, `/tasklist/...`, `/identity/...`) derives the id from the URL path's first segment.
2. **What happens when the check denies access?**
   - The OC-derived behaviour the filter was lifted from redirects the browser to `<contextPath>/<webApp>/forbidden` so the SPA shell can render its own forbidden page.
   - Hosts may want a 403 JSON body, a `RequestDispatcher.forward(...)` to a static page, or any other transport-appropriate response.

A single library class can't make either decision. Both are host-specific behaviours, not configuration values. Hosts that don't enforce per-web-app authorization at all (no resource→permission concept) simply don't `@Import` the configuration — the filter never activates and the rest of the webapp chain runs unchanged.

The authorization decision itself ("does this principal have `ACCESS` on `<componentId>`?") is delegated to the two-layer SPI captured in [ADR-0007](0007-resource-permission-port-and-authorization-repository.md): hosts implement `AuthorizationRepositoryPort` for the data, and the library supplies `ResourcePermissionService` as the default `ResourcePermissionPort`. Hosts that need different matching semantics override `ResourcePermissionPort` directly.

Activation is governed by [ADR-0008](0008-no-spring-boot-auto-configuration.md): the library does not use Spring Boot auto-configuration while it is under development. Hosts opt-in to the web app authorization filter by `@Import`ing the configuration class explicitly.

The core question for this ADR is:

> What SPI shape lets hosts plug in the web-app-id derivation and the access-denied response without duplicating the filter, while keeping the authorization decision itself uniform across hosts?

## Decision

Two host-pluggable SPIs are introduced alongside the lifted filter:

- **`WebAppProviderPort`** (`io.camunda.security.spring.spi`) — `Optional<String> webAppFor(HttpServletRequest)`. Hosts implement to return either a constant id or a path-derived id. Returning `Optional.empty()` signals "this request doesn't belong to a web app" and the filter passes through.
- **`WebAppAccessDeniedHandlerPort`** (`io.camunda.security.spring.spi`) — `void handle(request, response, webApp, authentication)`. Hosts implement to choose the response shape. The library supplies a default `RedirectingWebAppAccessDeniedHandler` that preserves the OC-derived redirect-to-forbidden behaviour; it backs off via `@ConditionalOnMissingBean(WebAppAccessDeniedHandlerPort.class)` when a host registers its own.

These sit alongside (not on top of) the authorization SPIs from ADR-0007:

- `ResourcePermissionPort` (`core/port/in/`) — the inbound port the filter calls. Default implementation is `ResourcePermissionService`, registered behind `@ConditionalOnMissingBean(ResourcePermissionPort.class)`.
- `AuthorizationRepositoryPort` (`core/port/out/`) — the outbound port the default `ResourcePermissionService` consults to read the host's authorization records. Required only when relying on the library default — a host that registers its own `ResourcePermissionPort` bean bypasses `AuthorizationRepositoryPort` entirely. The library has no opinion on storage.

The filter and these SPIs are wired by `WebAppAuthorizationFilterConfiguration` — a plain `@Configuration` per ADR-0008. Hosts adopt by adding it to their `@Import` list:

```java
@Configuration
@Import({
    BaseSecurityConfiguration.class,
    OidcWebappSecurityConfiguration.class,
    OidcBeansConfiguration.class,
    AuthFailureHandlerConfiguration.class,
    WebAppAuthorizationFilterConfiguration.class
})
public class HubSecurityConfiguration {}
```

Each bean inside `WebAppAuthorizationFilterConfiguration` is gated on the host SPIs it depends on (`@ConditionalOnBean`) and library defaults are gated on `@ConditionalOnMissingBean`. A host that imports the configuration but hasn't yet registered (for example) a `WebAppProviderPort` gets the chain wired exactly as before — the filter bean isn't created and the chain configuration's `addFilterAfterIfAvailable` call cleanly skips it.

### Why these particular SPI boundaries

- **`WebAppProviderPort` is a single-method interface returning `Optional<String>`** because the only host-specific decision is "what web app id, if any, does this request belong to?". A larger interface (e.g. an SPI that also picks the `ResourceType`) would couple two unrelated decisions; an `Optional` return naturally captures the "no web app, pass through" case without exception-driven control flow.
- **`WebAppAccessDeniedHandlerPort` is a separate SPI rather than a property template** because hosts choose between substantively different transport behaviours (redirect, JSON 403, forward, custom logging, custom telemetry). That's a behavioural decision, not a configuration value. Reducing it to a property string would either constrain hosts to one shape or balloon into a mini-DSL.
- **`ResourcePermissionPort` is *not* re-exposed as a webapp-specific SPI.** The two-layer authorization surface lives in `core/`; the webapp filter is one of many call sites. Adding a webapp-only port would split the authorization model unnecessarily.

### Default implementations and override boundaries

| SPI | Default | Override use case |
|---|---|---|
| `WebAppProviderPort` | None — host must register | Always |
| `WebAppAccessDeniedHandlerPort` | `RedirectingWebAppAccessDeniedHandler` (preserves OC behaviour) | 403 JSON, forward to error page, custom telemetry |
| `ResourcePermissionPort` | `ResourcePermissionService` (exact-id match over `AuthorizationRepositoryPort` records) | Wildcard semantics, caching, instrumentation |
| `AuthorizationRepositoryPort` | None — host must register | Always |

### Filter wiring

`OidcWebappSecurityConfiguration` and `BasicAuthWebappSecurityConfiguration` inject `ObjectProvider<WebAppAuthorizationCheckFilter>` and call the `SecurityFilterChainSupport.addFilterAfterIfAvailable(http, provider, AuthorizationFilter.class)` helper. The filter is added immediately after Spring Security's `AuthorizationFilter` so the principal is fully authenticated before the per-web-app check runs. When the filter bean is absent (no host SPIs registered), the helper is a no-op — no `BeanCreationException`, no duplicate chain registrations.

A companion `FilterRegistrationBean<WebAppAuthorizationCheckFilter>` with `setEnabled(false)` prevents Spring Boot from also registering the filter into the global servlet chain. The filter only ever runs as part of the relevant Spring Security chain.

## Consequences

**Positive**

- Hosts that need per-web-app authorization share the filter implementation; only the host-specific bits (web app derivation, denial response) are pluggable.
- Hosts that don't enforce per-web-app authorization (no resource→permission concept that maps to `ResourceType.COMPONENT` + `PermissionType.ACCESS`) simply don't `@Import` the configuration. The chain configurations inject the filter via `ObjectProvider`; absence is a clean no-op.
- Hosts can adopt incrementally — registering a `WebAppProviderPort` alone is harmless because the filter requires `WebAppProviderPort` + `ResourcePermissionPort` + `WebAppAccessDeniedHandlerPort` + `CamundaAuthenticationProvider` + `SecurityPathPort` to materialise.
- The redirect-to-forbidden default preserves the source behaviour the filter was lifted from; hosts that want a different denial response register one bean.
- The denial response is a behaviour, not a property — type-safe, testable, and unconstrained.
- Activation is opt-in per ADR-0008. A host that imports neither `WebAppAuthorizationFilterConfiguration` nor any of its prerequisites sees no behavioural change.

**Negative / accepted trade-offs**

- Hosts must register a `WebAppProviderPort` and a `ResourcePermissionPort` before the filter activates. The `ResourcePermissionPort` requirement is satisfied either by registering an `AuthorizationRepositoryPort` (the library default `ResourcePermissionService` then materialises) or by registering a custom `ResourcePermissionPort` bean directly. There is no "auto-detect web apps from `SecurityPathPort.webComponentNames()`" fallback. This is intentional: hosts may want different derivation logic from path patterns (case-sensitivity, prefix stripping, multi-tenancy). A future iteration can supply a path-segment derivation default if a clear convention emerges.
- Two interfaces (`WebAppProviderPort` and `WebAppAccessDeniedHandlerPort`) live in `io.camunda.security.spring.spi` (the starter module) rather than under `io.camunda.security.core.port.out` because their signatures speak `HttpServletRequest`/`HttpServletResponse`. The `core` module is jakarta-servlet-free by design ([ADR-0006](0006-central-security-filter-chains.md)), so any servlet-coupled SPI must live in the starter.

## Alternatives Considered

- **Auto-detect web app id from `SecurityPathPort.webComponentNames()`.** Rejected — the path-to-component derivation differs subtly between hosts (Hub's single-app shortcut, OC's `/<webApp>/...` prefix, future Camunda services that may use a different scheme). A baked-in derivation either over-fits to OC or hides the host-specific decision behind config that's harder to debug than a one-method SPI.
- **Property template for the denial response (`camunda.security.web-app.access-denied.redirect-template=...`).** Rejected — covers only the redirect case. Hosts that want JSON 403 or forwards would need an escape hatch that ends up looking like the SPI we'd otherwise have started with.
- **Webapp-specific `WebAppPermissionPort`.** Rejected — the two-layer authorization shape from ADR-0007 already covers this. The filter calls `ResourcePermissionPort.hasPermission(authentication, ResourceType.COMPONENT, webApp, PermissionType.ACCESS)` and reuses the same default implementation that other authorization call sites will use.
- **Auto-configuration via `@AutoConfiguration` + `AutoConfiguration.imports`.** Rejected — superseded by [ADR-0008](0008-no-spring-boot-auto-configuration.md). Hosts opt-in via explicit `@Import`.
