---
status: Accepted
---

# ADR-0029: Warn instead of block on provider-block validation

**Deciders**: Ben Sheppard, Sebastian Bathke

## Status

Accepted. Reverses one statement of [ADR-0025](0025-deferred-oidc-resolution.md) and one consequence of [ADR-0026](0026-per-registration-post-logout-redirect-uri.md), see [Supersedes](#supersedes). Every other decision of both records stays in force.

## Context

A CSL release added no-network checks on each OIDC provider block (URL shape, client-id presence, endpoint completeness, redirect-uri and post-logout-redirect-uri usability, registration-id addressability) and wired them to run eagerly, in `ScopedClientRegistrationFactory`, from `LazyClientRegistrationRepository`'s constructor. A block that failed any check aborted the whole application context, including for deployments that had started successfully before.

This is the case ADR-0025 sets out to prevent for network-dependent failures ("an identity provider that does not answer stops the start") but reintroduces for a configuration shape CSL itself considers wrong. A block CSL was already treating as a hard error may still be one an operator has running in production, deliberately or not.

What should a provider block CSL considers invalid do to application startup?

## Decision

Provider-block validation in `ScopedClientRegistrationFactory` never blocks startup. A block that fails a check logs a `WARN` naming the provider and the problem, and the application starts and keeps running regardless.

Two things can still stop a provider from working: Spring's own `ClientRegistration.Builder#build()` (a blank client-id, for one), and `ClientRegistrations#fromIssuerLocation` (a malformed `issuer-uri`). Both already run per-registration, deferred to first use through `DeferredOidcResolution` (ADR-0025), so one bad provider never takes down another — except for a host that calls `createFromProviderMap`, `createWithoutLoginRoutes` or `create(AuthenticationConfiguration)` eagerly from its own `@Bean` method, which still gets that failure at startup.

A caller that also composes the value for something else — `ScopedWebappSecurityChainBuilder`'s redirect-uri and post-logout-redirect-uri wiring to Spring — falls back to its own default on the exact same condition Spring's own redirection-endpoint/logout-handler wiring falls back on, so the two agree. Outside that condition, a value CSL's broader diagnostic warns about is still used as configured; the WARN is the only signal.

This does not extend to a caller's own arguments (`scopedRedirectUriPath`) or to checks that predate this decision and are unrelated to it: the issuer-aware decoder's multi-provider issuer requirement (`OidcAccessTokenDecoderFactory`) and the UserInfo-mapping requirement (`CachingOidcClaimsProvider`) both still throw, as before.

## Supersedes

| Superseded statement | Record | Now |
|---|---|---|
| "A configuration error that needs no network still stops the start: the repository validates each provider block" | ADR-0025 | The repository still validates each provider block, but a failed check warns; it does not stop the start |
| "Misconfiguration surfaces at startup rather than as a 500 on a logout request" | ADR-0026 | Misconfigured post-logout-redirect-uri warns at startup and falls back to the default at logout; it causes neither a startup failure nor a 500 |

## Consequences

**Positive**

- A deployment that worked before these checks were added keeps working after an upgrade, instead of failing to start.
- The diagnostic is unchanged: the same message that used to abort the start now warns, so the problem is still visible and still names the provider.

**Negative / accepted trade-offs**

- A misconfigured provider can run in production indefinitely without anyone noticing, if nobody reads startup logs. The previous behaviour forced attention; this one only offers it.
- An operator relying on startup failure as a config-validation gate (e.g. failing a CI deploy) loses that gate for this class of error.

## Alternatives Considered

- **Keep blocking, but only for provider blocks added after this release (a compatibility flag).** Rejected — adds a second validation mode to maintain, and the flag itself would need a default that reproduces this same decision for existing deployments.
- **Rate-limit the warning instead of removing the check that blocks.** Rejected — doesn't address the actual problem, which is that a previously-working deployment stops starting at all.
