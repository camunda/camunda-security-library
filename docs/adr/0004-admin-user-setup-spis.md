---
status: Accepted
---

# ADR-0004: Admin-user setup SPIs (`AdminUserPresencePort`, `AdminUserMissingHandlerPort`)

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

[ADR-0003](0003-no-spring-boot-auto-configuration.md) centralised the API and webapp filter chains in CSL but deferred host-specific filter wiring — including the admin-user setup filter — to follow-ups. [ADR-0014](0014-unified-authz-framework-in-core.md) handled the first such filter (web-app authorization). This ADR captures the second.

The admin-user setup filter ensures an admin user has been provisioned before letting requests reach the rest of the application. If no admin user exists, the filter hands off to the host so the browser can be sent to a setup wizard (or whatever the host's response shape is). Once an admin user exists, the filter passes every request through.

The behaviour is the same in every host that uses it, but two pieces of input vary:

1. **Has an admin user been provisioned?**
   - The OC-derived behaviour the filter was lifted from answers this in two steps: a static-config check (`securityConfig.getInitialization().getDefaultRoles().get("admin").get("users").isEmpty()`), and if that's empty, a live data check via `roleServices.hasMembersOfType("admin", USER, ...)`.
   - Other hosts may have entirely different authorization models (Hub doesn't model admins this way at all) or want to combine static and live data differently.
2. **What happens when no admin user exists?**
   - The OC source redirects the browser to `<contextPath>/admin/setup` so the SPA shell can render the setup wizard.
   - Hosts may want a 503 JSON body, a `RequestDispatcher.forward(...)` to a static page, an alternative redirect target, or any other transport-appropriate response.

A third concern — which paths bypass the check entirely (typically the setup endpoint plus its static assets) — is also host-specific, but the existing `SecurityPathPort` already exists for declaring path patterns the chains operate on. Adding a dedicated SPI for the admin-filter's bypass set would split host-supplied path declarations across two interfaces for no benefit.

A single library class can't make either of the two varying decisions above. Both are host-specific behaviours, not configuration values. Hosts that don't enforce admin-user setup at all (Hub, for example) simply don't `@Import` the configuration — the filter never activates and the rest of the webapp chain runs unchanged.

Activation is governed by [ADR-0003](0003-no-spring-boot-auto-configuration.md): the library does not use Spring Boot auto-configuration while it is under development. Hosts opt-in to the admin-user setup filter by `@Import`ing the configuration class explicitly.

During the OC adoption of CSL ([camunda/camunda#52770](https://github.com/camunda/camunda/pull/52770)), wiring the filter into both webapp chains surfaced a trap: a freshly IdP-authenticated OIDC/SaaS user navigating to `/operate` was 302'd to `/admin/setup`, because there was no `init.users` static seed for SaaS and the IdP-provisioned user's membership had not yet been projected into the live store. Pre-CSL, OC ran the equivalent check only on the BasicAuth chain — admin provisioning under OIDC is driven by IdP claims and mapping rules, not an in-app setup wizard. The filter's wiring was narrowed accordingly; see "Filter wiring" below for the current, standing shape.

The core question for this ADR is:

> What SPI shape lets hosts plug in the presence check and the missing-user response without duplicating the filter, while keeping the library free of host-specific authorization-model dependencies?

## Decision

Two host-pluggable SPIs are introduced alongside the lifted filter:

- **`AdminUserPresencePort`** (`io.camunda.security.core.port.out`) — `boolean adminUserExists()`. No-arg, framework-free. The host's implementation decides whether to consult static configuration, live storage, or any combination. The OC source's two-step (config + role-services) check collapses into one host-defined boolean — the library no longer encodes the OC-specific ordering between the two.
- **`AdminUserMissingHandlerPort`** (`io.camunda.security.spring.spi`) — `void handle(HttpServletRequest, HttpServletResponse) throws IOException, ServletException`. Hosts implement to choose the response shape. The library supplies a default `RedirectingAdminUserMissingAdapter` that preserves the OC-derived `<contextPath>/admin/setup` redirect; it backs off via `@ConditionalOnMissingBean(AdminUserMissingHandlerPort.class)` when a host registers its own.

Bypass paths reuse the existing `SecurityPathPort`:

- **`SecurityPathPort.adminFilterBypassPaths()`** — added as a `default` method returning empty. Hosts that activate the filter override it to declare path prefixes the filter passes through without consulting `AdminUserPresencePort`. Matched against the request's path within the application (i.e. the URI with the servlet context path stripped) using exact-or-sub-path semantics — so `/admin/setup` matches the setup endpoint without also matching `/admin/setupbar`, and `/admin/assets` matches every sub-path under it.

The filter and these SPIs are wired by `AdminUserCheckFilterConfiguration` — a plain `@Configuration` per [ADR-0003](0003-no-spring-boot-auto-configuration.md). Hosts adopt by adding it to their `@Import` list:

```java
@Configuration
@Import({
    BaseSecurityConfiguration.class,
    OidcWebappSecurityConfiguration.class,
    OidcBeansConfiguration.class,
    AuthFailureHandlerConfiguration.class,
    AdminUserCheckFilterConfiguration.class
})
public class HostSecurityConfiguration {}
```

Each bean inside `AdminUserCheckFilterConfiguration` is gated on the host SPIs it depends on (`@ConditionalOnBean`) and library defaults are gated on `@ConditionalOnMissingBean`. A host that imports the configuration but hasn't yet registered an `AdminUserPresencePort` gets the chain wired exactly as before — the filter bean isn't created and the chain configuration's conditional addition cleanly skips it.

### Why these particular SPI boundaries

- **`AdminUserPresencePort` collapses the OC two-step check into a single boolean** because the library has no business encoding the OC-specific ordering between static config and live data. Each host knows which sources it has and how to combine them; the library only needs the answer. A larger interface that exposed the static/live split would couple the library to an authorization-model concept (default-roles → admin → users members) that not every host shares. The single-method shape also lets hosts answer instantly from a `@Value`-injected boolean during early bootstrap, without dragging in an entire data layer just to satisfy the contract.
- **`AdminUserMissingHandlerPort` is a separate SPI rather than a property template** because hosts choose between substantively different transport behaviours (redirect to a host-specific URL, JSON 503, forward to a static page, custom telemetry). That's a behavioural decision, not a configuration value. Reducing it to a property string would either constrain hosts to one shape or balloon into a mini-DSL — the same reasoning as `WebAppAccessDeniedHandlerPort` in [ADR-0014](0014-unified-authz-framework-in-core.md).
- **Bypass paths reuse `SecurityPathPort.adminFilterBypassPaths()` rather than a dedicated SPI** because they're paths, and the host already implements `SecurityPathPort` to declare every other security-path concern (api/webapp/unprotected/web-component-names). Splitting path declarations across two ports for the sake of "admin-only" semantics would force hosts to maintain two related interfaces and obscure that the filter is participating in the same path-declaration model as the rest of the chain.
- **The two SPIs split between `core/port/out/` and `io.camunda.security.spring.spi`** because their signatures differ in framework coupling. `AdminUserPresencePort` speaks only Java types — it lives in `core/port/out/` alongside the framework-free outbound ports. `AdminUserMissingHandlerPort` speaks `HttpServletRequest`/`HttpServletResponse` — and `core` is jakarta-servlet-free by design (enforced by `DomainArchTest`), so any servlet-coupled SPI must live in the starter. This mirrors the split of `WebAppProviderPort`/`WebAppAccessDeniedHandlerPort` in [ADR-0014](0014-unified-authz-framework-in-core.md).

### Default implementations and override boundaries

| SPI | Default | Override use case |
|---|---|---|
| `AdminUserPresencePort` | None — host must register | Always |
| `AdminUserMissingHandlerPort` | `RedirectingAdminUserMissingAdapter` (preserves OC behaviour) | JSON 503, alternative redirect target, forward to error page, custom telemetry |
| `SecurityPathPort.adminFilterBypassPaths()` | Empty set (`default` method) | Override to declare the setup endpoint plus any static-asset prefixes the setup UI loads |

### Filter wiring

`AdminUserCheckFilterConfiguration` creates the `AdminUserCheckFilter` bean, gated on the three host SPIs, regardless of authentication method. The actual chain wiring happens one layer down, in `ScopedWebappSecurityChainBuilder`, which both `BasicAuthWebappSecurityConfiguration` and `OidcWebappSecurityConfiguration` delegate to when they build their `SecurityFilterChain` bean (`buildBasicWebappChain(...)` / `buildOidcWebappChain(...)`). `buildBasicWebappChain` looks up the filter via `ObjectProvider<AdminUserCheckFilter>.getIfAvailable()` and, when present, wires it with `addFilterAfter(adminFilter, AuthorizationFilter.class)`. `buildOidcWebappChain` never looks up the filter at all — its only optional filter slot below `OAuth2RefreshTokenFilter` is `WebAppAuthorizationCheckFilter`, anchored directly on the refresh-token filter. Only the OIDC-chain builder method omits the lookup; the filter bean's own creation is unaffected. A host that genuinely needs an admin-presence check on a custom OIDC chain still has direct access to the bean and can wire it into its own chain configuration.

This wiring was chosen over two alternatives considered at the same time: gating `AdminUserCheckFilterConfiguration` itself on `camunda.security.authentication.method=basic` (bean-creation time), or adding a `default boolean appliesTo(authenticationMethod)` escape hatch to `AdminUserPresencePort` so the filter could consult it before redirecting (port-call time). Chain-assembly time — simply omitting the OIDC chain's `addFilterAfter(...)` call — won because it is the smallest delta and mirrors the pre-CSL contract exactly (OC's pre-CSL admin filter was only ever wired into the BasicAuth chain; no new property surface, no new SPI method), and because it keeps "bean available" separate from "bean wired": a host with a custom OIDC chain, or a deployment that genuinely wants admin-setup enforcement under OIDC, can still opt in by wiring the existing bean itself — a door that bean-creation-time gating would close, and that a port-call-time gate would wrongly push into host SPI code that has nothing to do with wiring.

When both `AdminUserCheckFilter` and `WebAppAuthorizationCheckFilter` are present on the BasicAuth chain, the webapp filter is anchored on the admin filter so the relative order is structurally guaranteed — admin-presence redirect always runs before any per-web-app permission check. When the admin filter bean is absent, both chains are wired exactly as if the filter did not exist — no `BeanCreationException`, no duplicate registrations.

The two webapp chains now wire a different filter set by design. This asymmetry is documented in code, not left implicit: `AdminUserCheckFilterConfiguration`'s class-level Javadoc states plainly that "the filter is wired into the BasicAuth webapp chain only; the OIDC webapp chain intentionally does not add it," and `ScopedWebappSecurityChainBuilder` carries the same rationale as an inline comment in both `buildOidcWebappChain` and `buildOidcWebappChainInternal`.

A companion `FilterRegistrationBean<AdminUserCheckFilter>` with `setEnabled(false)` prevents Spring Boot from also registering the filter into the global servlet chain. The filter only ever runs as part of the relevant Spring Security chain.

## Consequences

**Positive**

- Hosts that need admin-user setup share the filter implementation; only the host-specific bits (presence check, missing-user response) are pluggable.
- Hosts that don't enforce admin-user setup (Hub, for example) simply don't `@Import` the configuration. The chain configurations look up the filter via `ObjectProvider`; absence is a clean no-op.
- The redirect-to-setup default preserves the source behaviour the filter was lifted from; hosts that want a different missing-user response register one bean.
- The missing-user response is a behaviour, not a property — type-safe, testable, and unconstrained.
- `AdminUserPresencePort.adminUserExists()` carries no library-imposed authorization-model concepts. Hosts answer however suits their data layer. Hosts that bootstrap admin presence from static config can implement the port as a one-line lambda; hosts that consult live storage can query asynchronously, cache, or instrument as they see fit.
- Activation is opt-in per [ADR-0003](0003-no-spring-boot-auto-configuration.md). A host that imports neither `AdminUserCheckFilterConfiguration` nor any of its prerequisites sees no behavioural change.
- The OIDC admin-setup trap surfaced during OC's OIDC/SaaS adoption smoke test is closed at the library layer: hosts that wire `AdminUserPresencePort` get correct behaviour for both auth methods out of the box, without a per-host workaround. OC was able to remove the `AdminUserPresenceAdapter` short-circuit it had shipped as an interim fix ([camunda/camunda#52770](https://github.com/camunda/camunda/pull/52770)).

**Negative / accepted trade-offs**

- Hosts must register an `AdminUserPresencePort` before the filter activates. There is no "auto-detect from `SecurityConfiguration.getInitialization().getDefaultRoles()`" fallback. This is intentional: the library doesn't model `SecurityConfiguration`, doesn't depend on `RoleServices`, and doesn't carry zeebe-protocol enums — those are OC-specific authorization-model concerns that don't belong in CSL. A host that wants the OC behaviour reproduces it in a five-line implementation of the port.
- Bypass paths live on `SecurityPathPort` rather than a dedicated SPI. Hosts that already implement `SecurityPathPort` for other path declarations need to add `adminFilterBypassPaths()` (and the default-empty method makes this a non-breaking source-only change).
- `AdminUserMissingHandlerPort` lives in `io.camunda.security.spring.spi` (the starter module) rather than under `io.camunda.security.core.port.out` because its signature speaks `HttpServletRequest`/`HttpServletResponse`. Same reasoning as the servlet-coupled SPIs in [ADR-0014](0014-unified-authz-framework-in-core.md).
- A host that wants the library-default admin-setup redirect under OIDC does not get it via `@Import` alone — they must explicitly wire `addFilterAfter(adminUserCheckFilter, ...)` in their own chain configuration. Accepted because there is no live use case for it, and because re-enabling it by default would reopen the OIDC-trap scenario the narrowed wiring exists to close.
- The two webapp chains are asymmetric in which filters they wire, by design. This is called out in code — `AdminUserCheckFilterConfiguration`'s class-level Javadoc states the BasicAuth-only wiring explicitly, and `ScopedWebappSecurityChainBuilder` carries a matching comment in both `buildOidcWebappChain` and `buildOidcWebappChainInternal` — so the asymmetry is documented, not implicit.

## Alternatives Considered

- **Single combined `AdminUserService` SPI that does both the presence check and the missing-user response.** Rejected — couples two unrelated decisions. A host might want the OC presence behaviour with a JSON 503 response (or vice versa). Splitting them keeps each SPI minimal and recombination free.
- **Leave the OIDC admin-setup trap unaddressed in CSL and document it as a known gotcha.** Rejected — every adopter that wires `AdminUserPresencePort` would have to re-derive the same workaround OC already paid for during its OIDC/SaaS smoke test. A library-default fix for a known footgun belongs in the library, not in adopter-side documentation.

Consolidates records previously numbered 0011 (admin-user-check filter) (see git history).
