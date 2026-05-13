---
status: Accepted
---

# ADR-0012: Ship `CamundaOidcLogoutSuccessHandler` as the default OIDC `LogoutSuccessHandler`

**Deciders**: Ben Sheppard

## Status

Accepted

## Context

[ADR-0006](0006-central-security-filter-chains.md) centralised the OIDC webapp filter chain in CSL. The chain already calls `logoutSuccessHandlerProvider.ifAvailable(logout::logoutSuccessHandler)`, so any `LogoutSuccessHandler` bean — host- or library-supplied — is wired into the OIDC logout DSL. Until now the CSL has shipped no default for that slot.

Orchestration Cluster (OC) currently registers its own [`CamundaOidcLogoutSuccessHandler`](https://github.com/camunda/camunda/blob/main/authentication/src/main/java/io/camunda/authentication/config/CamundaOidcLogoutSuccessHandler.java) that extends Spring Security's `OidcClientInitiatedLogoutSuccessHandler` and adds two customisations on top of vanilla RP-initiated logout:

1. **Post-logout redirect URI**: the validated `Referer` header is stored on the session so the host application can navigate back to the originating page once IdP logout completes. Validation is a same-origin check — redirects pointing elsewhere are rejected to avoid open-redirect attacks.
2. **`login_hint` → `logout_hint` propagation**: when the OIDC user has a `login_hint` claim, it is forwarded as a `logout_hint` query parameter to the IdP's end-session endpoint. This lets the IdP terminate the right session for users with multiple active identities at the same provider.

When OC adopts the CSL filter chains (camunda#52121), the existing behaviour disappears unless either OC keeps registering its own bean indefinitely or the CSL ships an equivalent default. Treating this as host UX — owned per-host — would force every adopter (OC, Hub, future hosts) to copy-paste the same handler.

The core question this ADR answers is:

> Should the CSL ship a default `LogoutSuccessHandler` that preserves OC's referer + `login_hint` behaviour, and where does the SPI boundary sit so hosts can override without re-implementing the common case?

## Decision

The CSL ships a default `LogoutSuccessHandler` for the OIDC webapp chain, behind `@ConditionalOnMissingBean(LogoutSuccessHandler.class)` so any host-registered bean wins:

- **`CamundaOidcLogoutSuccessHandler`** (`io.camunda.security.spring.security`) — `final`, extends `OidcClientInitiatedLogoutSuccessHandler`. Logic lifted from OC; OC's `RequestValidationUtils.isAllowedRedirect` is inlined as a private static `isSameOriginRedirect` helper. Trace-level logging on every fallback branch (no `end_session_endpoint`, non-OAuth2 authentication, non-`OidcUser` principal, unknown `registrationId`, missing `login_hint`).
- **Bean lives in `OidcBeansConfiguration`** alongside the other OIDC infrastructure beans (`JwtDecoder`, `ClientRegistrationRepository`, `OAuth2AuthorizedClientRepository`, `OAuth2AuthorizedClientManager`). The configuration class is already gated on `camunda.security.authentication.method=oidc`, already provides the `ClientRegistrationRepository` the handler depends on, and is already a member of the `CamundaSecurityAutoConfiguration` umbrella — no new configuration class is needed.
- **Public `POST_LOGOUT_REDIRECT_ATTRIBUTE` and `REDIRECT_MESSAGE_ATTRIBUTE` constants on `CamundaOidcLogoutSuccessHandler`.** Both attributes are written to the HTTP session — not the request — so the values survive the redirect that the `LogoutSuccessHandler` issues and are readable by the post-logout page on the subsequent request. Hosts reference these constants instead of hard-coding the strings.

Activation follows [ADR-0008](0008-no-spring-boot-auto-configuration.md): nothing activates by adding the dependency. Because `OidcBeansConfiguration` is already a member of the `CamundaSecurityAutoConfiguration` umbrella, hosts activating CSL via `@ImportAutoConfiguration(CamundaSecurityAutoConfiguration.class)` get the default logout handler automatically. The umbrella is also the activation path that makes `@ConditionalOnMissingBean(LogoutSuccessHandler.class)` evaluate reliably — fine-grained `@Import` of individual CSL configurations is documented in ADR-0008 as carrying conditional-bean-timing fragility that the umbrella resolves.

### Why these particular boundaries

- **Default ships in CSL, not OC.** OC's behaviour is the right default for any Camunda webapp adopting OIDC RP-initiated logout. Forcing each host to copy-paste the same handler is duplicate code with no value. The `@ConditionalOnMissingBean` back-off preserves full host control.
- **`@Bean` on `OidcBeansConfiguration`, not a new sibling configuration class.** The earliest draft of this work introduced a dedicated `OidcWebappLogoutConfiguration`. Code review pointed out that `OidcBeansConfiguration` already groups OIDC infrastructure beans with the same activation gate, the same `ClientRegistrationRepository` dependency, and existing umbrella membership — adding a separate class duplicated all three for one extra `@Bean`. The chain configuration `OidcWebappSecurityConfiguration` was not a candidate: its only `@Bean` is the `SecurityFilterChain`, which depends on `HttpSecurity` and is not slice-testable without booting Spring Security.
- **Same-origin validation inlined, not a shared port.** The redirect check has no host-overridable behaviour. Promoting it to an SPI would invite host divergence on a security-critical check. The check compares scheme, host, and effective port (default ports normalised) on parsed `URI` values rather than using a `startsWith` prefix match — prefix matching is vulnerable to host-confusion bypasses such as `https://app.example.com.evil.com/` and `https://app.example.com@evil.com/`.
- **Attribute-name constants on the handler itself, not on a separate constants class.** Both attribute names are written exclusively by this handler and read by hosts that pair with it. Co-locating them on the handler keeps the contract discoverable from the type that owns the behaviour; if future handlers need shared attribute keys, a dedicated constants class can be introduced then.
- **Multi-IdP-aware for free.** The handler looks up `ClientRegistration` by the principal's `authorizedClientRegistrationId`, so once multi-IdP routing (tracked separately) lands, RP-initiated logout works across every configured provider with no additional wiring.

### Default implementations and override boundaries

| Concern | Default | Override path |
|---|---|---|
| `LogoutSuccessHandler` | `CamundaOidcLogoutSuccessHandler` registered by `OidcBeansConfiguration` | Host registers any `@Bean LogoutSuccessHandler` — the CSL default backs off |
| Post-logout redirect attribute name | `CamundaOidcLogoutSuccessHandler.POST_LOGOUT_REDIRECT_ATTRIBUTE` | Host reads the constant; if a host registers its own handler, the host owns the attribute name |
| Same-origin redirect check | Inlined `isSameOriginRedirect` (same scheme/host/port; rejects CR/LF) | Host registers its own `LogoutSuccessHandler` if a different policy is needed |

## Consequences

**Positive**

- OC adopting the CSL filter chains keeps OIDC RP-initiated logout working without registering its own handler — `feat/adopt-camunda-security-library` can drop the local bean once the CSL release publishes.
- Any future Camunda host (Hub, others) gets the same behaviour out of the box; copy-paste of `CamundaOidcLogoutSuccessHandler` across hosts is avoided.
- The public `POST_LOGOUT_REDIRECT_ATTRIBUTE` constant on `CamundaOidcLogoutSuccessHandler` gives hosts a stable contract for reading the redirect URI from the session, decoupled from the handler's internal storage detail.
- No new configuration class introduced for hosts to manage: the bean joins the existing `OidcBeansConfiguration`, which hosts already opt into via the umbrella. `@ConditionalOnMissingBean` back-off is exercised by a real Spring `ApplicationContextRunner` slice (`OidcBeansConfigurationTest`).

**Negative / accepted trade-offs**

- The CSL now owns a behaviour that previously lived in OC's tree. Future tweaks (for example, switching off the `Referer`-based redirect for hosts that prefer a configured target URL) require either a host bean replacement or a follow-up extension point — accepted because the current default matches every known host's needs.
- `OidcBeansConfiguration` grows by one bean. Accepted because the cohesion is right (OIDC infrastructure, shared activation gate, shared `ClientRegistrationRepository` dependency) and the alternative (a one-bean sibling configuration) duplicates the gate and forces an extra umbrella entry.

## Alternatives Considered

- **Leave the slot empty; each host registers its own bean.** Rejected — every adopter ends up copying the same handler. The `@ConditionalOnMissingBean` model already gives hosts full override capability, so shipping a default does not cost them control.
- **Add the `@Bean` to `OidcWebappSecurityConfiguration`.** Rejected — that class's only existing `@Bean` is the `SecurityFilterChain`, which requires `HttpSecurity`. Hanging a second `@Bean` off it makes slice-testing the conditional back-off impossible without booting the entire Spring Security filter stack.
- **Promote `isSameOriginRedirect` to an outbound port.** Rejected — six lines, security-critical, no known host that wants a different policy. An SPI would invite divergence on a check that should be uniform.
- **Expose only the handler class; require hosts to construct it themselves.** Rejected — defeats the purpose of a default. Hosts pay zero cost for the bean registration; opting out costs one `@Bean` definition.
