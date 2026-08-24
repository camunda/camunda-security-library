---
status: Accepted
---

# ADR-0023: OIDC bearer-token validation lives on the API chain only

**Deciders**: Ben Sheppard (Ben-Sheppard), Patrick Wunderlich (p-wunderlich), Sebastian Bathke (megglos)

## Status

Accepted

## Context

The CSL ships two OIDC filter chains, selected by `securityMatcher`:

- [`OidcWebappSecurityConfiguration`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/OidcWebappSecurityConfiguration.java) — matches `SecurityPathPort.webappPaths()`. Intended to authenticate **users** interactively via the OAuth2 authorization-code login flow (`oauth2Login`) and serve them from the resulting HTTP session.
- [`OidcApiSecurityConfiguration`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/OidcApiSecurityConfiguration.java) — matches `SecurityPathPort.apiPaths()`. Intended for **direct, programmatic API access** authenticated with a JWT bearer token (`oauth2ResourceServer().jwt(...)`), e.g. client-credentials machine clients.

The intended authentication model:

- **Webapp chains** require an interactive login and issue a session. The session cookie is *also* honoured on the API chain (the API chain is `SessionCreationPolicy.NEVER` — it does not *create* a session but reads an existing one), so a logged-in browser can call the API without a bearer token.
- **API chains** are the home for direct programmatic access via bearer tokens.

However, the webapp chain *also* configured `oauth2ResourceServer().jwt(...)`. That installed a `BearerTokenAuthenticationFilter` on the webapp-matched paths, so a request to a webapp path carrying `Authorization: Bearer <jwt>` was validated and authenticated by the webapp chain too. This duplicated the API chain's responsibility and blurred the webapp-vs-API boundary, without serving a real use case: direct API access uses API paths, and browsers use the session.

The question this ADR answers: should JWT bearer-token validation be configured on the OIDC webapp chain, or exclusively on the OIDC API chain?

## Decision

**Bearer-token (JWT resource-server) validation is configured on the OIDC API chain only.** The `oauth2ResourceServer(...)` block is removed from `OidcWebappSecurityConfiguration`. The webapp chain authenticates exclusively through `oauth2Login` → session.

**The delegating `AuthenticationEntryPoint` on the webapp chain is kept** (requests with an `Authorization` header → `401` via `BearerTokenAuthenticationEntryPoint`; browser navigations → `302` to the IdP/login). Without a resource server this is no longer a Spring-Security entry-point-precedence workaround but a deliberate UX choice: an API-style caller that wrongly presents a bearer token to a webapp path receives a clean `401` rather than an HTML login redirect.

Consequences of the removal, all intended:

- A bearer token presented to a **webapp** path is no longer authenticated there; it falls through to the entry point and gets a `401`.
- The `OidcResourceServerCustomizer` SPI (RFC 9728 protected-resource metadata, custom JWT validators, bearer entry-point swaps) now applies to the **API chain only**. This is conceptually correct — those are all resource-server concerns. The change in wiring scope is documented in [security-filter-chains.md](../adopters/security-filter-chains.md).
- The webapp chain no longer needs the resource-server `JwtDecoder` bean (`oauth2Login` validates the **ID token** via its own `OidcIdTokenDecoderFactory`, not this bean). The `JwtDecoder` bean is still produced by `OidcBeansConfiguration` and still consumed by the API chain.

This refines, and does not contradict, [ADR-0008](0008-no-spring-boot-auto-configuration.md), which centralised the chains but did not pin which chain owns bearer-token validation.

## Consequences

**Positive**

- The webapp-vs-API boundary is clear: sessions authenticate webapp paths, bearer tokens authenticate API paths, and a browser session still works on API paths.
- `OidcResourceServerCustomizer` beans now have a single, predictable application point (the API chain), matching their resource-server semantics.
- Less duplicated configuration and one fewer constructor dependency on the webapp chain.

**Negative / accepted trade-offs**

- **Behavioural change for adopters:** any host (or test) that relied on presenting a bearer token directly to a *webapp* path now gets a `401` there. The team confirmed no host depends on this (bearer access uses API paths). Hosts that need bearer access on a given path must declare it under `apiPaths()`.
- `OidcResourceServerCustomizer` beans no longer fire on the webapp chain. This is intended, but is a contract change called out in the adopter docs.

## Alternatives Considered

### Bearer validation on the API chain only (chosen) vs on both chains

- **Chosen:** resource server on the API chain only; webapp chain is login/session only.
- **Pro:** matches the intended model; clean boundary; removes duplication; `OidcResourceServerCustomizer` gets a single, semantically-correct application point.
- **Con:** a behavioural change for any caller that sent bearer tokens to webapp paths (confirmed not a real use case).

### Keep the resource server on the webapp chain

- **Pro:** no behavioural change; a bearer token works on any path.
- **Con:** duplicates the API chain, blurs the boundary, makes `OidcResourceServerCustomizer` apply in two places with different intent, and serves no real use case. Rejected.

### Remove the delegating entry point as well

When the resource server is gone, the entry point's original justification (Spring Security 7.x resource-server entry-point precedence over the login entry point) disappears, so one could drop the delegation and always redirect to the IdP.

- **Chosen:** keep the delegation as a deliberate UX choice.
- **Pro:** an API-style caller hitting a webapp path gets a clean `401` instead of an HTML `302` redirect it cannot follow.
- **Con:** a small amount of retained configuration whose rationale changes; the code comment was rewritten to reflect the new reasoning.
