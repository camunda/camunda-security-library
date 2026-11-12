# Proof of concept: change the primary chains at runtime like a scope

Branch `mk-csl-poc-default-full-reload` (local), version `1.2.1-pt-poc-default-full-SNAPSHOT`, on top
of `mk-csl-poc-default-chain-reload` (primary credential rotation) and `csl-poc-runtime-security`
(scoped reload, [ADR-0040](../adr/0040-change-scoped-security-at-runtime.md)). Not production-ready.

Question: can a host change the security of its primary (unscoped) chains at runtime exactly as it
changes a scope, so that its default surface (the camunda monorepo's `default` physical tenant on
`/v2`, the webapps and login) is treated like any other scope? Answer for OIDC: yes, with the scope
machinery and no new mechanism. The camunda side is in its branch `pt-poc-default-tenant-security`,
`POC-NOTES.md`, section "The default tenant's HTTP security at runtime".

## What works, and which test shows it

All in `PrimarySecurityReloadTest` (spring-boot-starter): the primary OIDC API and webapp chains, a
runtime scope next to them, two loopback OpenID providers (`MockIdentityProvider`), requests through
`FilterChainProxy` with the registered chain beans.

| Capability | Proven by |
|---|---|
| A new issuer on both primary chains: old bearer tokens 401, new 200, login goes to the new provider | `#shouldServeAnotherIssuerOnTheApiAndWebappChains` |
| New audiences | `#shouldValidateBearerTokensAgainstTheNewAudiences` |
| New client id (login uses it) | `#shouldServeAChangedClientId` |
| A named provider added at runtime: its tokens accepted, login through it | `#shouldServeNamedProvidersAddedAtRuntime` |
| Sessions of the startup generation and of a later one end on an authentication change (webapp and API) | `#shouldEndTheSessionsOfThePrimaryChainsWhenTheirAuthenticationChanges` |
| A secret-only change keeps the session; it refreshes with the new secret; a new login uses it | `#shouldKeepTheSessionAndRefreshItsTokenWithTheRotatedSecret` |
| A secret the provider rejects keeps the previous one (`apply` and `rotateCredentials`) | `#shouldKeepThePreviousSecretWhenTheIdentityProviderRejectsTheNewOne` |
| An unreachable new provider keeps the previous generation (`KEPT_PREVIOUS`); applied once it answers | `#shouldKeepThePreviousGenerationWhileTheNewProviderCannotBeReached` |
| `APPLY` applies it anyway | `#shouldApplyAnUnreachableProviderWhenAskedTo` |
| The method cannot change; `rotateCredentials` refuses more than credentials | `#shouldRejectAChangeOfTheAuthenticationMethod`, `#shouldRejectARotationThatChangesMoreThanTheCredentials` |
| A scope keeps its generation, bearer tokens and session | `#shouldLeaveTheScopesUntouched` |
| 20 changes: every earlier generation, its chains, client stack and registrations collected | `#shouldReleaseEveryRetiredPrimaryGeneration` |

Mutation checks (made the named tests fail, then reverted): an unbound primary session repository
(`PrimaryChains.servingFingerprint()` returning `null`) fails the session test; views that keep
serving the startup chains fail 9 of the 13 tests.

## How it works

```java
package io.camunda.security.core.port.in;

public interface PrimarySecurityReloadPort extends PrimaryCredentialsReloadPort {
  ScopeReloadResult apply(AuthenticationConfiguration authentication);
  ScopeReloadResult apply(AuthenticationConfiguration authentication, UnreachableIdentityProviderPolicy policy);
  ScopeReloadResult rotateCredentials(AuthenticationConfiguration authentication); // IAE unless credential-only
  ScopeReloadResult refreshCredentials();
}
```

| Piece | What |
|---|---|
| `PrimaryChains` (bean) | The primary chains' slot. `OidcApiSecurityConfiguration` and `OidcWebappSecurityConfiguration` register their startup chain with it and return a `PrimaryChainView` instead. Holds the published `ScopeGeneration`, `null` until the first change |
| `PrimaryChainView` | `SecurityFilterChain` + `Ordered` (same order as the bean). Serves the startup chain until the first change, the published generation after it; pins the matched chain for `getFilters()` like `ScopeChainView` |
| `PrimarySecurityReloadService` | Builds the next generation with the scope machinery: `ScopedJwtDecoderFactory` decoder, `ScopedOidcClients` (login stack when there is a webapp chain), `ScopedApiSecurityChainBuilder.buildOidcApiChain` with the host's API paths, and a new `ScopedWebappSecurityChainBuilder.buildOidcWebappChain(http, authentication, clients, sessionFilter)`. Checks provider reachability (`IdentityProviderCheck`), and for a credential change the credentials (`ClientCredentialsCheck`), then publishes with one volatile write; `ScopeRetirement` releases the replaced generation |
| `buildOidcWebappChain(http, authentication, clients, sessionFilter)` | The primary webapp chain (same matchers, cookies `camunda-session`/`X-CSRF-TOKEN`, `/login`, `/logout`, picker) with registrations, authorized clients, token endpoint, assertion keys, redirect-uri and post-logout settings from the given configuration instead of the application's beans |
| Primary sessions | `DefaultWebSessionFilterConfiguration` wraps its repository in `ScopeAuthenticationBoundSessionRepository` keyed by the primary generation's fingerprint. The startup chains get a generation marker too, so sessions created before the first change are bound and end with it |
| `ScopeRetirement` | Also keeps the discovery entries of the issuers the primary chains still use |

`PrimarySecurityReloadPort` replaces the in-place `PrimaryCredentialsReloadService` of
`mk-csl-poc-default-chain-reload`: once a generation serves, the application's
`ClientRegistrationRepository`, `JwtDecoder`, `OAuth2AuthorizedClientManager`,
`OidcTokenEndpointCustomizer` and `AssertionJwkProvider` beans are no longer read by the primary
chains. They stay in the context for the startup generation and for any other consumer.

## Measurements

Apple M5 Pro (18 cores), JDK 21, another heavy build running, loopback providers. Per change, from
`ScopeReloadResult.duration()` in `#shouldReleaseEveryRetiredPrimaryGeneration` (20 issuer/audience
changes): p50 3–7 ms, max 6–21 ms over 3 runs. End to end in the camunda monorepo against Keycloak,
the primary change took 21–48 ms per member (p50 25 ms, 48 changes) and the alias scope 17–36 ms.

Full `./mvnw verify`: api 241, core 180, validation 267, spring-boot-starter 1,756, all green (base
of this branch: 241 / 180 / 267 / 1,748; `PrimaryCredentialRotationTest`'s 5 tests are folded into
the 13 of `PrimarySecurityReloadTest`).

## Not done, or not proven

- **BASIC primary chains**: refused (`IllegalArgumentException`). A BASIC scope has nothing to change
  but its method, which stays fixed.
- **Host hooks the scope path does not have**: the new generation uses the library's token endpoint
  (no host observation `RestClient`, as for scopes); a host `CamundaLoginPickerFilter` bean, a host
  `OAuth2AuthorizationRequestResolver` bean and host extra token validators (`TokenValidatorFactory`
  extras, for example SaaS organisation/cluster validators) serve the startup generation only;
  `ScopedJwtDecoderFactory` uses the default clock skew, not `oidc.clock-skew`. All four are what a
  scope gets today; a host that needs them per generation needs a hook.
- **Privilege evaluator**: Spring Security's `WebInvocationPrivilegeEvaluator` keeps the startup
  chains' rules, as for startup scopes (code reading).
- **Two publishes, not one, when a host serves the same configuration as primary chains and a
  scope** (the camunda alias `/physical-tenants/default`): they are separate slots, so for a moment
  one serves the new configuration and the other the old. An atomic pair needs one port call that
  builds both and publishes both under one lock.
- **`unprotected-api=true` and webapp-less hosts**: the code builds a generation without a webapp
  chain (API refresh then has no login stack), but no test covers it.
- `LazyClientRegistrationRepository.prepareCredentials/publishCredentials` and
  `OidcAuthenticationConfigurationRepository.replaceCredentials` from the in-place rotation are now
  unused.

## Open questions

1. Should a host be able to keep its own primary beans per generation (a factory SPI for decoder,
   registrations, manager, token endpoint), or is the scope stack the contract for every runtime
   generation?
2. Should the primary chains and a scope that mirrors them be changeable in one atomic call?
3. The credential check (`ClientCredentialsCheck`) runs for primary credential changes only, not for
   scoped ones; should scopes get it too?

## How to run

```bash
./mvnw verify -pl spring-boot-starter -Dtest=PrimarySecurityReloadTest -Dsurefire.failIfNoSpecifiedTests=false
./mvnw verify   # full build, ~1 min of tests
./mvnw install -DskipTests   # for the camunda monorepo branch
```
