---
status: Accepted
---

# ADR-0028: OIDC login fails soft when the IdP rejects UserInfo, unless required

**Deciders**: Bojan Mudric

## Status

Accepted

## Context

[ADR-0007](0007-oidc-user-info-enabled-toggle.md) gave CSL a login-time `userInfoEnabled` toggle
(should the `oauth2Login` DSL call `/userinfo` at all?) and a request-time claim-augmentation
layer that is fail-open by design. Neither covers what happens when the login-time fetch is
attempted and the IdP rejects it: Spring Security's stock `OidcUserService` treats that as fatal,
and CSL wires no default of its own — `ScopedWebappSecurityChainBuilder` only picks up a host
`OidcUserService` bean if one exists (`ObjectProvider#ifAvailable`), so absent one, Spring's raw
default runs unmodified.

This was mostly latent under Spring Security 6, which only called `/userinfo` when the granted
scopes intersected `{profile, email, address, phone}`. Camunda's documented Entra scope
(`<client-id>/.default,openid,profile,email`) makes Entra echo back resource-qualified scope
strings that never match, so Spring 6 silently skipped the call — the Entra/`.default` audience
mismatch (the access token is `aud`-scoped to the Camunda client, not to MS Graph's `/userinfo`)
never surfaced. Spring 7's `OidcUserRequestUtils.shouldRetrieveUserInfo` replaced that check with
"is there a userinfo URI, and is the grant `authorization_code`?" — always true for any provider
with `userInfoUri` set — so the same audience mismatch now reaches the user as a login failure.

The mismatch is structural, not a misconfiguration, for several IdPs: Entra always (UserInfo is
served by MS Graph, requiring `aud=00000003-...`, never the Camunda client), and Auth0 / Okta /
PingFederate whenever their access token is bound to an `audience` other than their own userinfo
endpoint. No client-side scope tweak makes every IdP accept the same token at both the resource
server and `/userinfo` — see camunda-security-library#557 for the per-IdP behavior table.

**Prior art.** The same defect exists in `camunda/camunda` for the 8.9 release line (pre-CSL-extraction
code): [issue #58310](https://github.com/camunda/camunda/issues/58310), fixed by
[PR #63587](https://github.com/camunda/camunda/pull/63587) with the same wrap-the-delegate /
marker-exception / `retrieveUserInfo=false` design this ADR adopts, merged with 528 unit tests +
23 integration tests green against the real login filter chain — production evidence the
mechanism holds, not just a source-reading argument. That fix targets a single
`WebSecurityConfig.oidcUserService()` bean with no scoped-chain concept, so it ships without a
`user-info-required` escape hatch; this ADR keeps one (see below) because CSL's
`ScopedWebappSecurityChainBuilder` applies one `OidcUserService` bean across a primary chain and
every per-scope chain, where different providers can legitimately want different behavior. The
two fixes share no runtime code — CSL is not used in the 8.9 line — so there is no
backward-compatibility coupling between them either way.

`CachingOidcClaimsProvider` already established the precedent for this exact endpoint on the
*augmentation* path: attempt the call, fail open, log, negative-cache. `OidcUserService` is a
different extension point (`oauth2Login`'s login-time hook, not request-time), but the same
question applies: what does CSL do by default when `/userinfo` fails at login? What property
shape lets a provider that genuinely cannot tolerate missing UserInfo claims (e.g. groups
available only via UserInfo) opt back into today's hard-failure behavior?

## Decision

### `FailSoftOidcUserService` — the new default `OidcUserService`

`spring-boot-starter/.../oidc/FailSoftOidcUserService.java` extends Spring Security's
`OidcUserService`. `ScopedWebappSecurityChainBuilderConfiguration` registers it as a
`@ConditionalOnMissingBean @Bean OidcUserService`, so a host bean of that type still takes
absolute precedence (ADR-0007's existing "all-or-nothing" escape valve is unchanged) and the
default only fills a previously-empty gap. No new dependency on `ScopedWebappSecurityChainBuilder`
was needed — it already resolves `OidcUserService` via `ObjectProvider#ifAvailable(...)` for both
the primary chain and every per-scope chain, so the new default reaches both automatically.

**The discriminator.** A transport/audience failure and an OIDC S:5.3.2 `sub`-validation failure
both surface from Spring Security as `OAuth2AuthenticationException` with the identical
`invalid_user_info_response` error code — confirmed by reading
`spring-security-oauth2-client:7.1.1`'s `OidcUserService`/`DefaultOAuth2UserService` sources, not
assumed. Catching broadly around `loadUser()` would risk silently accepting a forged/misdirected
UserInfo response — exactly the token-substitution attack OIDC S:5.3.2 defends against. Instead,
`FailSoftOidcUserService` wraps only the fetch delegate (`OidcUserService#setOauth2UserService`,
`public final`) and translates its failure into a private marker exception
(`UserInfoFetchFailedException`, a plain `RuntimeException` holding the original
`OAuth2AuthenticationException` as a field — deliberately *not* a subclass of it, so the marker can
never be mistaken for, or accidentally caught as, the exception type whose ambiguity motivated
this design). The `sub`-validation code runs strictly after that delegate returns successfully and
is therefore never inside the catch — structurally, not heuristically, excluded from fail-soft
handling. The marker never escapes `loadUser()`: the `user-info-required=true` branch rethrows the
original exception it wraps, not itself. Logged at WARN without the original throwable
(registration id + error code + message only, full cause at DEBUG): Spring Security's
`OAuth2LoginConfigurer` wires this same bean into `OidcAuthorizedClientRefreshedEventListener`, so
for a structurally-mismatched IdP this fires on every access-token refresh, not just at login — a
full stack trace on every occurrence would be log noise.

**The fallback value.** On a caught fetch failure, the class delegates to a second, internally
held `OidcUserService` configured with `setRetrieveUserInfo(request -> false)` (also `public
final`). That reproduces the exact code path `user-info-enabled=false` already takes — the same
`DefaultOidcUser` construction, the same authority set — so the fail-soft result is provably
identical to what an operator gets today by disabling UserInfo outright, not a hand-rolled
approximation of it.

### `user-info-required` — the per-provider escape hatch

A new boolean property on `OidcConfiguration`, `userInfoRequired` (default `false`), threaded
through `ScopedClientRegistrationFactory#mergeProviderMetadata` into
`ClientRegistration.getProviderDetails().getConfigurationMetadata()` under
`FailSoftOidcUserService.USER_INFO_REQUIRED_METADATA_KEY` — the same mechanism this factory
already uses for `TokenValidatorFactory.AUDIENCES_METADATA_KEY` and `end_session_endpoint`.
`FailSoftOidcUserService` reads the flag off the `ClientRegistration` it is handed at call time;
when `true`, a fetch failure is re-thrown instead of degraded.

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
applies the *same* `OidcUserService` bean to the primary chain and to every per-scope chain
(`buildOidcWebappChainInternal`), each potentially resolving its own, independently-configured
`OidcConfiguration` map (`ScopedClientRegistrationFactory#flatten`). A bean-held map built once
from the cluster's own properties would be blind to scope-only providers and unsafe under
registrationId collisions across scopes with different values. Metadata travels with the
`ClientRegistration` itself, so both paths are correct with no new plumbing — the same reasoning
[ADR-0007](0007-oidc-user-info-enabled-toggle.md) already applied to `userInfoEnabled`.

`user-info-required=true` combined with `user-info-enabled=false` is rejected at startup by
`ScopedClientRegistrationFactory#validateWithoutNetwork` — with the fetch disabled,
`userInfoUri` is nulled and login never attempts the call `user-info-required` is meant to make
mandatory, so the combination can only mean a configuration mistake. This mirrors
`CachingOidcClaimsProvider#forConfiguredMappings`'s existing fail-fast policy for an analogous
"enabled but can never do anything" config mismatch.

### Why these particular boundaries

- **Wrap only the fetch delegate, not the whole `loadUser()` call.** The only way to make the
  fail-soft/still-throws split a structural guarantee rather than an error-code or
  cause-presence heuristic that Spring's own source does not document as stable.
- **Log at WARN without the caught throwable, full cause at DEBUG.** This bean also serves every
  access-token refresh via `OidcAuthorizedClientRefreshedEventListener`, so a structurally
  mismatched IdP logs this repeatedly, not once; a full stack trace on every occurrence is noise
  an operator has to scroll past.
- **Reuse Spring's own `retrieveUserInfo=false` code path for the fallback**, rather than
  hand-building a `DefaultOidcUser`. Removes an entire class of "does the hand-rolled fallback
  really match what `user-info-enabled=false` produces" bugs and keeps this class small.
- **Metadata on `ClientRegistration`, not a config map held by the bean.** The only shape that is
  correct for both the primary chain and every scoped chain without new plumbing — see Decision
  above.
- **`user-info-required` defaults to `false`.** Matches the acceptance criterion and keeps
  today's *successful* UserInfo flows completely unchanged; only the previously-hard-failure case
  (an unhandled `OAuth2AuthenticationException` from a stock Spring `OidcUserService`) changes
  behavior.
- **Fail fast on `user-info-required=true` + `user-info-enabled=false`.** An operator error that
  is cheaper to see at startup than to discover as "why does this provider's users never get an
  ID-token-only fallback message, they just silently succeed with no groups" in production.

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
- Providers whose UserInfo call succeeds today are unaffected byte-for-byte: the success path in
  `FailSoftOidcUserService` is `super.loadUser()`'s own unmodified logic.
- The OIDC S:5.3.2 `sub`-validation defense is preserved exactly — proven by a dedicated test
  (`stillThrowsOnSubMismatchRegardlessOfUserInfoRequired`), not just asserted in prose.
- The core mechanism (wrap the delegate, marker exception, `retrieveUserInfo=false` fallback) is
  independently validated in production: the same design shipped in
  [camunda/camunda#63587](https://github.com/camunda/camunda/pull/63587) for the 8.9 line, merged
  with 528 unit + 23 integration tests green against the real login filter chain.
- A provider that genuinely needs UserInfo (groups-only-in-UserInfo authorization) keeps today's
  hard-failure behavior via one property, rather than losing the option entirely.
- No change to `ScopedWebappSecurityChainBuilder`, `OidcWebappSecurityConfiguration`, or any
  chain-building code — the fix is entirely a new default bean plus one metadata key.

**Negative / accepted trade-offs**

- `FailSoftOidcUserService` re-derives a small amount of Spring Security's own wiring (holding a
  second internally-configured `OidcUserService` for the fallback) rather than there being a
  public Spring Security hook for "give me the no-UserInfo branch's result directly." Accepted:
  the alternative (hand-building `DefaultOidcUser`/`OidcUserAuthority` construction) duplicates
  more logic and risks drifting from Spring's own behavior on a future Spring Security upgrade.
- The discriminator relies on `OidcUserService#setOauth2UserService` and `#setRetrieveUserInfo`
  being `public final` setters with predictable single-call-site semantics in Spring Security
  7.1.x. A future major Spring Security version that restructures `OidcUserService` internally
  (e.g. inlines the delegate call, or changes what's `final`) could require rework; this is
  flagged for the pre-push `mvn verify` (Spring Security upgrades in this repo already run the
  full suite) rather than mitigated further now.
- A registration built entirely outside `ScopedClientRegistrationFactory` (a host that replaces
  `ClientRegistrationRepository` and does not register its own `OidcUserService`) now gets the new
  fail-soft *default* for its own custom providers too, since the metadata key is simply absent
  (treated as `false`/not-required). This is a deliberate, described default-behavior change
  (`defaultsToFailSoftWhenRegistrationCarriesNoCslMetadata` pins it) rather than an oversight —
  the safer default is "don't fail login hard," and a host wanting the old behavior sets
  `user-info-required=true` on its own registrations' metadata, or supplies its own
  `OidcUserService` bean.
- Because Spring Security's `OAuth2LoginConfigurer` wires this same bean into
  `OidcAuthorizedClientRefreshedEventListener` (see Decision above), a *transient* `/userinfo`
  failure during an access-token refresh — not just at initial login — degrades that refresh the
  same way: the live session's claims narrow to ID-token-only (fewer authorities) instead of the
  refresh failing outright, the way it would have before this change. This is fail-closed, never an
  escalation of privilege — CSL's authorization mapping never grants more from an absent claim than
  from a present one — and the same `user-info-required=true` escape hatch applies: a provider whose
  refreshed sessions cannot tolerate a narrowed claim set opts back into failing the refresh instead.

## Alternatives Considered

- **Catch broadly around `OidcUserService#loadUser()` and branch on the caught exception's error
  code or `getCause()` presence.** Rejected — both the `sub`-validation failure and the transport
  failure share the `invalid_user_info_response` error code in Spring Security 7.1.x; a
  cause-presence check happens to differ today but is not a documented contract of either class,
  so it is one Spring Security patch release away from silently defeating OIDC S:5.3.2's
  token-substitution defense.
- **Thread a registrationId -> `OidcConfiguration` map into the bean at construction time**, the
  way `CachingOidcClaimsProvider` builds its issuer -> URL map once for cluster-wide augmentation.
  Rejected — `ScopedWebappSecurityChainBuilder` applies one `OidcUserService` bean to the primary
  chain and to every scoped chain alike, each with its own, independently-resolved provider map;
  a bean-held map can't see scope-only providers and breaks under registrationId collisions with
  different `user-info-required` values across scopes.
- **Make the marker exception itself an `OAuth2AuthenticationException` subclass** (what
  `camunda/camunda#63587` does), so a required-and-failed rethrow needs no unwrapping. Rejected
  for this ADR's design specifically because it *does* rethrow (the sibling fix never does — it
  only ever catches-and-degrades): a marker assignable to the very exception type whose ambiguity
  motivated this design thins the structural guarantee, and the instance must never leave
  `loadUser()` regardless (an internal marker persisted into a serializing session store via
  `AbstractAuthenticationFailureHandler`'s `WebAttributes.AUTHENTICATION_EXCEPTION` would be a
  deserialization hazard). A plain `RuntimeException` holding the original as a field is simpler
  and strictly safer once unwrapping happens either way.
- **Always fail soft, with no per-provider override**, matching the narrower fix that shipped in
  `camunda/camunda#63587`. Rejected for CSL specifically: that fix targets one
  `WebSecurityConfig.oidcUserService()` bean with no multi-provider/scoped-chain concept, so
  always-fail-soft was a complete answer there. CSL's `ScopedWebappSecurityChainBuilder` serves
  potentially many independently-configured providers through the same bean, and a provider whose
  authorization-relevant claims live only in UserInfo (not the ID token) would otherwise silently
  lose those claims rather than fail loudly — worse than today's hard failure for that specific
  case. `user-info-required` keeps that provider's existing hard-failure behavior available.

Consolidates no prior records.
