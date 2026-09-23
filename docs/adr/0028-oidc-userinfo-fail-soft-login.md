---
status: Accepted
---

# ADR-0028: OIDC login fails soft when the IdP rejects UserInfo, unless required

**Deciders**: Bojan Mudric

## Status

Accepted

## Context

[ADR-0007](0007-oidc-user-info-enabled-toggle.md) added two things to CSL: a login-time
`userInfoEnabled` toggle that controls whether `oauth2Login` calls `/userinfo` at all, and a
request-time claim-augmentation layer that fails open by design. Neither one covers what happens
when the login-time fetch runs and the IdP rejects it. Spring Security's stock `OidcUserService`
treats that rejection as fatal. CSL wired no default `OidcUserService` of its own, so without a
host bean, Spring's raw default ran unmodified.

This problem was mostly hidden under Spring Security 6. That version only called `/userinfo` when
the granted scopes intersected `{profile, email, address, phone}`. Camunda's documented Entra
scope is `<client-id>/.default,openid,profile,email`. Entra echoes back resource-qualified scope
strings that never match this set, so Spring 6 silently skipped the call. The access token is
`aud`-scoped to the Camunda client, not to MS Graph's `/userinfo` endpoint, and that mismatch never
surfaced. Spring 7 replaced the old check with a simpler rule: call `/userinfo` whenever a userinfo
URI is set and the grant type is `authorization_code`. That rule is true for almost every
registration, so the same mismatch now reaches the user as a login failure.

The mismatch is structural for several IdPs, not a misconfiguration. Entra always rejects the
token this way: UserInfo is served by MS Graph, which requires `aud=00000003-...`, never the
Camunda client's own audience. Auth0, Okta, and PingFederate reject it too, whenever their access
token is bound to an `audience` other than their own userinfo endpoint. No client-side scope
change makes every IdP accept the same token at both the resource server and `/userinfo`. See
camunda-security-library#557 for the per-IdP behavior table.

**The same defect in camunda/camunda 8.9.** The same defect exists in `camunda/camunda` for the
8.9 release line, from before CSL was extracted out of that codebase: see [issue
#58310](https://github.com/camunda/camunda/issues/58310). [PR
#63587](https://github.com/camunda/camunda/pull/63587) fixed it there. That fix wraps the delegate
call, translates the failure into a marker exception, and falls back to `retrieveUserInfo=false` —
the same three techniques this ADR uses. It merged with 528 unit tests and 23 integration tests
passing against the real login filter chain, which confirms the design works in production.

That fix targets a single `WebSecurityConfig.oidcUserService()` bean. It has no concept of scoped
chains, so it ships with no `user-info-required` override property. This ADR keeps that property
(see below), because CSL's `ScopedWebappSecurityChainBuilder` applies one `OidcUserService` bean
across a primary chain and every per-scope chain, and different providers behind those chains can
legitimately need different behavior. The two fixes share no runtime code, since CSL is not used
in the 8.9 line. An upgrade from 8.9 to 8.10 needs no migration for this behavior either way: PR
#63587 added no configuration property, so its fail-soft behavior there is unconditional, which is
equivalent to `user-info-required=false` in this ADR. This property is a pure addition on top of
that existing behavior.

`CachingOidcClaimsProvider` already does the equivalent thing on the augmentation path: it
attempts the call, fails open, logs the failure, and caches the negative result. `OidcUserService`
is a different extension point — it runs at login time, not request time — but the same question
applies to it.

## Decision

### `FailSoftOidcUserService`: the new default `OidcUserService`

`spring-boot-starter/.../oidc/FailSoftOidcUserService.java` extends Spring Security's
`OidcUserService`. `ScopedWebappSecurityChainBuilderConfiguration` registers it as a
`@ConditionalOnMissingBean` bean. The bean method declares the generic return type
`OAuth2UserService<OidcUserRequest, OidcUser>`, not the narrower `OidcUserService`. This matches
the exact type that `OAuth2LoginConfigurer.getOidcUserService()` looks up internally, so a host
bean of that generic shape backs this default off correctly, even one that does not itself extend
`OidcUserService`. ADR-0007's existing override path keeps working, and this default only fills a
gap that was previously empty. `ScopedWebappSecurityChainBuilder` already resolves the bean through
`ObjectProvider#ifAvailable(...)` for both the primary chain and every per-scope chain, so the new
default reaches both with no further changes.

**The discriminator.** A transport failure, an audience failure, and an OIDC S:5.3.2
subject-mismatch failure all surface from Spring Security as the same thing: an
`OAuth2AuthenticationException` with the error code `invalid_user_info_response`. This was
confirmed against the `spring-security-oauth2-client:7.1.1` sources directly, not assumed. A
malformed response fails differently: `DefaultOAuth2UserService` throws a plain
`IllegalArgumentException`, not an `OAuth2AuthenticationException`, for an empty body, a body with
no claims, or a body missing the name attribute.

Catching broadly around `loadUser()` would create two problems. First, it could accept a forged or
misdirected UserInfo response, which is exactly what OIDC S:5.3.2 defends against. Second, it would
miss the `IllegalArgumentException` cases above entirely, since they are not the caught type.

`FailSoftOidcUserService` avoids both problems by wrapping only the fetch delegate:
`OidcUserService#setOauth2UserService`, a `public final` setter meant for exactly this kind of
substitution. It catches any `RuntimeException` there. A caught `IllegalArgumentException` is
normalized into an `OAuth2AuthenticationException` with the same `invalid_user_info_response` code,
so every failure shape ends up carrying that code. The result is wrapped in a private marker
exception, `UserInfoFetchFailedException`. This marker is a plain `RuntimeException` holding the
normalized failure as a field. It is deliberately not a subclass of `OAuth2AuthenticationException`,
so it can never be mistaken for the exception type whose ambiguity motivated this design.

The `sub`-validation code runs strictly after the delegate returns successfully. It is never inside
the wrapped call, so it is excluded from fail-soft handling by construction, not by a runtime
check. The marker itself never escapes `loadUser()`: the `user-info-required=true` branch rethrows
the normalized failure, never the marker.

The WARN log omits the throwable: it carries only the registration id and the error code. The full
cause goes to DEBUG instead. Spring wires this same bean into
`OidcAuthorizedClientRefreshedEventListener`, so for a structurally mismatched IdP, this warning
fires on every access-token refresh, not only at login. A full stack trace on every refresh would
flood the log.

**The fallback value.** On a caught fetch failure, the class delegates to a second `OidcUserService`
instance held internally. That instance is configured with `setRetrieveUserInfo(request -> false)`,
also a `public final` setter. This takes the exact code path that `user-info-enabled=false` already
takes, so the fail-soft result is provably identical to what an operator gets today by disabling
UserInfo outright. It is not a hand-built approximation.

### `user-info-required`: the per-provider override

A new boolean property on `OidcConfiguration`, `userInfoRequired`, defaults to `false`.
`ScopedClientRegistrationFactory#mergeProviderMetadata` carries it into
`ClientRegistration.getProviderDetails().getConfigurationMetadata()`, under
`FailSoftOidcUserService.USER_INFO_REQUIRED_METADATA_KEY`. This is the same mechanism the factory
already uses for `TokenValidatorFactory.AUDIENCES_METADATA_KEY` and `end_session_endpoint`.
`FailSoftOidcUserService` reads the flag off the `ClientRegistration` at call time. When the flag
is `true`, a fetch failure is re-thrown instead of degraded. The default of `false` matches the
acceptance criterion: only the previously-hard-failure case changes behavior.

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

The flag lives in metadata, not in a registrationId-keyed map held by the bean.
`ScopedWebappSecurityChainBuilder` applies the same `OidcUserService` bean to the primary chain and
to every per-scope chain, and each chain can resolve its own, independently configured
`OidcConfiguration` map. A bean-held map built once would miss scope-only providers, and it would
behave unpredictably under registrationId collisions across scopes with different values. Metadata
travels with the `ClientRegistration` itself, so both paths are correct with no new plumbing.
[ADR-0007](0007-oidc-user-info-enabled-toggle.md) already applied this same reasoning to
`userInfoEnabled`.

`ScopedClientRegistrationFactory#validateWithoutNetwork` rejects two configurations at startup,
both because they leave `user-info-required=true` with no way to ever take effect. The first is
`user-info-required=true` combined with `user-info-enabled=false`: with the fetch disabled, login
never attempts the call this flag is meant to make mandatory. The second is
`user-info-required=true` on a manual-endpoints provider — one with no `issuer-uri` — that also
sets no `user-info-uri`: that provider never resolves a UserInfo endpoint to call, so the flag is
inert the same way, reached by a different route. Neither check applies to the `issuer-uri` path,
because discovery only runs against the network, and whether it yields a `userinfo_endpoint` is not
known at validation time. Both checks mirror
`CachingOidcClaimsProvider#forConfiguredMappings`'s existing fail-fast policy for the same kind of
"enabled but can never do anything" mismatch.

### Default implementations and override boundaries

| Concern | Default | Override path |
|---|---|---|
| `OidcUserService` on the webapp login chain | `FailSoftOidcUserService` | Host registers a bean of type `OAuth2UserService<OidcUserRequest, OidcUser>` (or the narrower `OidcUserService`). Takes precedence regardless of `user-info-required`, same as ADR-0007's existing override path |
| `user-info-required` | `false` (per-provider) | Set `camunda.security.authentication.oidc.user-info-required` or `providers.oidc.<id>.user-info-required` to `true` |
| Fail-soft fallback claims | ID-token-only, via a `retrieveUserInfo=false`-configured `OidcUserService` | Not overridable on its own. Replace the whole `OidcUserService` bean for different fallback behavior |

## Consequences

**Positive**

- Login no longer fails hard for Entra (`<client-id>/.default`) or for any IdP whose access token
  is bound to an audience other than its own `/userinfo`. This is the structural issue behind
  camunda-security-library#557 and camunda/camunda#53685.
- A provider whose UserInfo call succeeds today is unaffected: the success path still runs
  `super.loadUser()`'s own, unmodified logic.
- The OIDC S:5.3.2 `sub`-validation defense still applies exactly as before. A dedicated test,
  `stillThrowsOnSubMismatchRegardlessOfUserInfoRequired`, proves this rather than only asserting
  it.
- The core mechanism is already validated in production: the same design shipped in
  [camunda/camunda#63587](https://github.com/camunda/camunda/pull/63587) for the 8.9 line, with 528
  unit tests and 23 integration tests passing against the real login filter chain.
- An upgrade from 8.9 to 8.10 needs no migration for this behavior. `camunda/camunda#63587` added
  no configuration property, so its fail-soft behavior there is unconditional and equivalent to
  `user-info-required=false` here. The new property is a pure addition on top of that behavior,
  not a breaking change.
- A provider that genuinely needs UserInfo, for example one whose groups live only in UserInfo,
  keeps today's hard-failure behavior. It opts in with one property.
- No change to `ScopedWebappSecurityChainBuilder`, `OidcWebappSecurityConfiguration`, or any
  chain-building code. The fix adds one new default bean and one new metadata key.

**Negative / accepted trade-offs**

- `FailSoftOidcUserService` re-implements a small piece of Spring Security's own wiring: a second,
  internally configured `OidcUserService` for the fallback. There is no public hook that returns
  "the no-UserInfo branch's result" directly. This is accepted: hand-building a `DefaultOidcUser`
  would duplicate more logic and risk drifting from Spring's own behavior on a future upgrade.
- The discriminator depends on `OidcUserService#setOauth2UserService` and `#setRetrieveUserInfo`
  staying `public final` setters with stable, single-call-site behavior in Spring Security 7.1.x. A
  future major version that restructures `OidcUserService` internally could require rework. This is
  flagged for `mvn verify` on the next Spring Security upgrade, and not mitigated further now.
- A registration built entirely outside `ScopedClientRegistrationFactory` — a host that replaces
  `ClientRegistrationRepository` and supplies no `OidcUserService` — now gets the fail-soft default
  for its own custom providers too, since the metadata key is simply absent and treated as `false`.
  This is deliberate, and pinned by the test `defaultsToFailSoftWhenRegistrationCarriesNoCslMetadata`,
  not an oversight: the safer default is "don't fail login hard." A host that wants the old behavior
  sets `user-info-required=true` on its own registrations' metadata, or supplies its own bean.
- Because Spring wires this same bean into `OidcAuthorizedClientRefreshedEventListener`, a transient
  `/userinfo` failure during an access-token refresh, not only at initial login, narrows the live
  session's claims to ID-token-only instead of failing the refresh outright, the way it would have
  before this change. This is fail-closed in effect, never an escalation of privilege: CSL's
  authorization mapping never grants more from an absent claim than from a present one. The same
  `user-info-required=true` override applies to a provider whose refreshed sessions cannot tolerate
  a narrowed claim set.

## Alternatives Considered

- **Catch broadly around `OidcUserService#loadUser()` and branch on the caught exception's error
  code or on `getCause()` being present.** Rejected. Both failures share the
  `invalid_user_info_response` error code in Spring Security 7.1.x. A check based on `getCause()`
  presence happens to differ today, but this is not a documented contract. A single patch release
  could remove that difference and silently defeat the OIDC S:5.3.2 token-substitution defense.
- **Thread a registrationId-to-`OidcConfiguration` map into the bean at construction time**, the way
  `CachingOidcClaimsProvider` builds its issuer-to-URL map once. Rejected.
  `ScopedWebappSecurityChainBuilder` applies one bean to the primary chain and to every scoped chain
  alike, and each chain resolves its own, independently built provider map. A bean-held map cannot
  see scope-only providers, and it behaves unpredictably under registrationId collisions with
  different values across scopes.
- **Make the marker exception itself a subclass of `OAuth2AuthenticationException`**, the way
  `camunda/camunda#63587` does. Rejected for this design specifically, because this design does
  rethrow the marker's content — the 8.9 fix never does; it only ever catches and degrades. A marker
  assignable to the exception type whose ambiguity motivated this design would weaken the structural
  guarantee the design relies on. The marker instance must also never leave `loadUser()`: a session
  store can persist it through `WebAttributes.AUTHENTICATION_EXCEPTION`, and an internal marker type
  reaching that store would be a deserialization risk. A plain `RuntimeException` holding the
  normalized original as a field is simpler, and strictly safer, since unwrapping happens either
  way.
- **Always fail soft, with no per-provider override**, matching the narrower fix in
  `camunda/camunda#63587`. Rejected for CSL specifically. That fix targets one bean with no
  multi-provider or scoped-chain concept, so always-fail-soft was a complete answer there. CSL's
  `ScopedWebappSecurityChainBuilder` can serve many independently configured providers through the
  same bean. A provider whose authorization-relevant claims live only in UserInfo would otherwise
  lose them silently instead of failing loudly, which is worse than today's hard failure.
  `user-info-required` keeps that provider's existing behavior available.

Consolidates no prior records.
