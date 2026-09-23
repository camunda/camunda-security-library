---
status: Accepted
---

# ADR-0028: OIDC login fails soft when the IdP rejects UserInfo, unless required

**Deciders**: Bojan Mudric

## Status

Accepted

## Context

[ADR-0007](0007-oidc-user-info-enabled-toggle.md) gave CSL a login-time `userInfoEnabled` toggle
(should `oauth2Login` call `/userinfo` at all?) and a request-time claim-augmentation layer that
is fail-open by design. Neither covers what happens when the login-time fetch is attempted and
the IdP rejects it: Spring Security's stock `OidcUserService` treats that as fatal, and CSL wires
no default of its own — absent a host bean, Spring's raw default runs unmodified.

This was mostly latent under Spring Security 6, which only called `/userinfo` when the granted
scopes intersected `{profile, email, address, phone}`. Camunda's documented Entra scope
(`<client-id>/.default,openid,profile,email`) makes Entra echo back resource-qualified scope
strings that never match, so Spring 6 silently skipped the call — the Entra/`.default` audience
mismatch (the access token is `aud`-scoped to the Camunda client, not to MS Graph's `/userinfo`)
never surfaced. Spring 7 replaced that check with "is there a userinfo URI, and is the grant
`authorization_code`?" — always true once `userInfoUri` is set — so the same mismatch now reaches
the user as a login failure.

The mismatch is structural, not a misconfiguration, for several IdPs: Entra always (UserInfo is
served by MS Graph, requiring `aud=00000003-...`, never the Camunda client), and Auth0 / Okta /
PingFederate whenever their access token is bound to an `audience` other than their own userinfo
endpoint. No client-side scope tweak makes every IdP accept the same token at both the resource
server and `/userinfo` — see camunda-security-library#557 for the per-IdP behavior table.

**Prior art.** The same defect exists in `camunda/camunda` for the 8.9 release line
(pre-CSL-extraction code): [issue #58310](https://github.com/camunda/camunda/issues/58310), fixed
by [PR #63587](https://github.com/camunda/camunda/pull/63587) with the same
wrap-the-delegate/marker-exception/`retrieveUserInfo=false` design this ADR adopts, merged with
528 unit + 23 integration tests green against the real login filter chain — production evidence
the mechanism holds. That fix targets one `WebSecurityConfig.oidcUserService()` bean with no
scoped-chain concept, so it ships without a `user-info-required` escape hatch; this ADR keeps one
(see below) because CSL's `ScopedWebappSecurityChainBuilder` applies one `OidcUserService` bean
across a primary chain and every per-scope chain, where different providers can legitimately want
different behavior. The two fixes share no runtime code — CSL isn't used in the 8.9 line — so
there's no backward-compatibility coupling between them.

`CachingOidcClaimsProvider` already established the precedent for this endpoint on the
*augmentation* path: attempt the call, fail open, log, negative-cache. `OidcUserService` is a
different extension point (login-time, not request-time), but the same question applies here.

## Decision

### `FailSoftOidcUserService` — the new default `OidcUserService`

`spring-boot-starter/.../oidc/FailSoftOidcUserService.java` extends Spring Security's
`OidcUserService`. `ScopedWebappSecurityChainBuilderConfiguration` registers it as a
`@ConditionalOnMissingBean @Bean OidcUserService`, so a host bean of that type still takes
absolute precedence (ADR-0007's existing escape valve is unchanged); the default only fills a
previously-empty gap. `ScopedWebappSecurityChainBuilder` already resolves `OidcUserService` via
`ObjectProvider#ifAvailable(...)` for both the primary chain and every per-scope chain, so the new
default reaches both with no further changes.

**The discriminator.** A transport/audience failure and an OIDC S:5.3.2 `sub`-validation failure
both surface from Spring Security as `OAuth2AuthenticationException` with the identical
`invalid_user_info_response` error code — confirmed against `spring-security-oauth2-client:7.1.1`
sources, not assumed. Catching broadly around `loadUser()` would risk silently accepting a
forged/misdirected UserInfo response — exactly what OIDC S:5.3.2 defends against. Instead,
`FailSoftOidcUserService` wraps only the fetch delegate (`OidcUserService#setOauth2UserService`,
`public final`) and translates its failure into a private marker exception
(`UserInfoFetchFailedException`, a plain `RuntimeException` holding the original
`OAuth2AuthenticationException` — deliberately *not* a subclass of it, so the marker can never be
mistaken for the exception type whose ambiguity motivated this design). The `sub`-validation code
runs strictly after the delegate returns successfully, so it's never inside the catch —
structurally, not heuristically, excluded from fail-soft handling. The marker never escapes
`loadUser()`: the `user-info-required=true` branch rethrows the original exception, never the
marker.

Logged at WARN without the throwable (registration id + error code only, full cause at DEBUG):
Spring wires this same bean into `OidcAuthorizedClientRefreshedEventListener`, so for a
structurally-mismatched IdP this fires on every access-token refresh, not just at login — a full
stack trace each time would be log noise.

**The fallback value.** On a caught fetch failure, the class delegates to a second, internally
held `OidcUserService` configured with `setRetrieveUserInfo(request -> false)` (also `public
final`). That takes the exact code path `user-info-enabled=false` already takes, so the fail-soft
result is provably identical to what an operator gets today by disabling UserInfo outright — not
a hand-rolled approximation.

### `user-info-required` — the per-provider escape hatch

A new boolean property on `OidcConfiguration`, `userInfoRequired` (default `false`), threaded
through `ScopedClientRegistrationFactory#mergeProviderMetadata` into
`ClientRegistration.getProviderDetails().getConfigurationMetadata()` under
`FailSoftOidcUserService.USER_INFO_REQUIRED_METADATA_KEY` — the same mechanism this factory
already uses for `TokenValidatorFactory.AUDIENCES_METADATA_KEY` and `end_session_endpoint`.
`FailSoftOidcUserService` reads the flag off the `ClientRegistration` at call time; when `true`, a
fetch failure is re-thrown instead of degraded. Defaults to `false`, matching the acceptance
criterion: only the previously-hard-failure case changes behavior.

```yaml
camunda:
  security:
    authentication:
      oidc:
        user-info-required: false   # default

      providers:
        oidc:
          groups-only-idp:
            user-info-required: true
```

Metadata, not a registrationId-keyed map held by the bean, because `ScopedWebappSecurityChainBuilder`
applies the *same* `OidcUserService` bean to the primary chain and to every per-scope chain, each
potentially resolving its own, independently-configured `OidcConfiguration` map. A bean-held map
built once would be blind to scope-only providers and unsafe under registrationId collisions
across scopes with different values. Metadata travels with the `ClientRegistration` itself, so
both paths are correct with no new plumbing — the same reasoning [ADR-0007](0007-oidc-user-info-enabled-toggle.md)
already applied to `userInfoEnabled`.

`user-info-required=true` combined with `user-info-enabled=false` is rejected at startup by
`ScopedClientRegistrationFactory#validateWithoutNetwork`: with the fetch disabled, login never
attempts the call `user-info-required` is meant to make mandatory, so the combination can only be
a configuration mistake. Mirrors `CachingOidcClaimsProvider#forConfiguredMappings`'s existing
fail-fast policy for an analogous "enabled but can never do anything" mismatch.

### Default implementations and override boundaries

| Concern | Default | Override path |
|---|---|---|
| `OidcUserService` on the webapp login chain | `FailSoftOidcUserService` | Host registers `@Bean OidcUserService` — takes precedence regardless of `user-info-required`, same as ADR-0007's existing escape valve |
| `user-info-required` | `false` (per-provider) | Set `camunda.security.authentication.oidc.user-info-required` or `providers.oidc.<id>.user-info-required` to `true` |
| Fail-soft fallback claims | ID-token-only, via a `retrieveUserInfo=false`-configured `OidcUserService` | Not overridable independent of the bean itself — replace the whole `OidcUserService` bean for different fallback semantics |

## Consequences

**Positive**

- Login no longer fails hard for Entra (`<client-id>/.default`) or any IdP whose access token is
  audience-bound away from its own `/userinfo` — the structural issue behind
  camunda-security-library#557 and camunda/camunda#53685.
- Providers whose UserInfo call succeeds today are unaffected byte-for-byte: the success path is
  `super.loadUser()`'s own unmodified logic.
- The OIDC S:5.3.2 `sub`-validation defense is preserved exactly — proven by a dedicated test
  (`stillThrowsOnSubMismatchRegardlessOfUserInfoRequired`), not just asserted.
- The core mechanism is independently validated in production: the same design shipped in
  [camunda/camunda#63587](https://github.com/camunda/camunda/pull/63587) for the 8.9 line, merged
  with 528 unit + 23 integration tests green against the real login filter chain.
- A provider that genuinely needs UserInfo (groups-only-in-UserInfo authorization) keeps today's
  hard-failure behavior via one property.
- No change to `ScopedWebappSecurityChainBuilder`, `OidcWebappSecurityConfiguration`, or any
  chain-building code — the fix is entirely a new default bean plus one metadata key.

**Negative / accepted trade-offs**

- `FailSoftOidcUserService` re-derives a small amount of Spring Security's own wiring (a second
  internally-configured `OidcUserService` for the fallback) rather than there being a public hook
  for "give me the no-UserInfo branch's result directly." Accepted: hand-building `DefaultOidcUser`
  duplicates more logic and risks drifting from Spring's own behavior on a future upgrade.
- The discriminator relies on `OidcUserService#setOauth2UserService` and `#setRetrieveUserInfo`
  being `public final` setters with stable single-call-site semantics in Spring Security 7.1.x. A
  future major version that restructures `OidcUserService` internally could require rework; this
  is flagged for `mvn verify` on the next Spring Security upgrade rather than mitigated further now.
- A registration built entirely outside `ScopedClientRegistrationFactory` (a host that replaces
  `ClientRegistrationRepository` and supplies no `OidcUserService`) now gets the fail-soft
  *default* for its own custom providers too, since the metadata key is simply absent (treated as
  `false`). Deliberate — pinned by `defaultsToFailSoftWhenRegistrationCarriesNoCslMetadata` — not
  an oversight: the safer default is "don't fail login hard," and a host wanting the old behavior
  sets `user-info-required=true` on its own registrations' metadata, or supplies its own bean.
- Because Spring wires this same bean into `OidcAuthorizedClientRefreshedEventListener`, a
  *transient* `/userinfo` failure during an access-token refresh — not just at initial login —
  narrows the live session's claims to ID-token-only instead of failing the refresh outright, the
  way it would have before this change. Fail-closed, never an escalation of privilege — CSL's
  authorization mapping never grants more from an absent claim than a present one — and the same
  `user-info-required=true` escape hatch applies to a provider whose refreshed sessions can't
  tolerate a narrowed claim set.

## Alternatives Considered

- **Catch broadly around `OidcUserService#loadUser()` and branch on the caught exception's error
  code or `getCause()` presence.** Rejected — both failures share the `invalid_user_info_response`
  error code in Spring Security 7.1.x; a cause-presence check happens to differ today but isn't a
  documented contract, so it's one patch release away from silently defeating OIDC S:5.3.2's
  token-substitution defense.
- **Thread a registrationId -> `OidcConfiguration` map into the bean at construction time**, the
  way `CachingOidcClaimsProvider` builds its issuer -> URL map once. Rejected —
  `ScopedWebappSecurityChainBuilder` applies one bean to the primary chain and every scoped chain
  alike, each with its own, independently-resolved provider map; a bean-held map can't see
  scope-only providers and breaks under registrationId collisions with different values.
- **Make the marker exception itself an `OAuth2AuthenticationException` subclass** (what
  `camunda/camunda#63587` does), so a required-and-failed rethrow needs no unwrapping. Rejected
  here specifically because this design *does* rethrow (the sibling fix never does — it only ever
  catches-and-degrades): a marker assignable to the exception type whose ambiguity motivated this
  design thins the structural guarantee, and the instance must never leave `loadUser()` regardless
  — persisted into a serializing session store via `WebAttributes.AUTHENTICATION_EXCEPTION`, an
  internal marker type would be a deserialization hazard. A plain `RuntimeException` holding the
  original as a field is simpler and strictly safer once unwrapping happens either way.
- **Always fail soft, with no per-provider override**, matching the narrower fix in
  `camunda/camunda#63587`. Rejected for CSL specifically: that fix targets one bean with no
  multi-provider/scoped-chain concept, so always-fail-soft was a complete answer there. CSL's
  `ScopedWebappSecurityChainBuilder` serves potentially many independently-configured providers
  through the same bean, and a provider whose authorization-relevant claims live only in UserInfo
  would otherwise silently lose them rather than fail loudly — worse than today's hard failure.
  `user-info-required` keeps that provider's existing behavior available.

Consolidates no prior records.
