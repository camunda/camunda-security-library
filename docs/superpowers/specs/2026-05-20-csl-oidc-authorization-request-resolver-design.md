# CSL OIDC Authorization Request Resolver — Design

**Issue:** [camunda/camunda-security-library#232](https://github.com/camunda/camunda-security-library/issues/232)
**Date:** 2026-05-20
**Status:** Approved — ready for implementation plan

## Summary

Lift OC's `ClientAwareOAuth2AuthorizationRequestResolver` into CSL as the default
`OAuth2AuthorizationRequestResolver` bean for the OIDC webapp chain. The resolver reads two
already-existing `OidcConfiguration` properties — `resource` (RFC 8707) and
`authorize_request.additional_parameters` — and injects them into the OAuth2 authorization request
sent to the IdP. The bean is registered with `@ConditionalOnMissingBean` so hosts that already
provide their own resolver (including OC today) keep winning until the monorepo cleanup PR lands.

No new configuration properties. No `AuthorizeRequest` model changes. Pure wiring + a lifted class.

## Goals

- Provide a CSL-default `OAuth2AuthorizationRequestResolver` that honours the existing `resource`
  and `authorize_request.additional_parameters` properties.
- Preserve `@ConditionalOnMissingBean` back-off so OC's current resolver continues to take precedence
  until OC drops it.
- Keep the existing `clientRegistrationRepository` flat-plus-providers merge as the single source of
  truth for registrationId → `OidcConfiguration` lookup; both beans must agree on the mapping.

## Non-goals

- Caching changes. Keep the per-registrationId `ConcurrentHashMap` cache from OC's implementation
  unchanged; benchmark only if it becomes an issue later.
- New authorization-request customisations (PKCE forcing, claims request, etc.). Defer.
- ADR. The data shape is already established by an existing `OidcConfiguration`; this is a mechanical
  lift. If the wiring location proves contentious, raise an ADR then.
- Deleting OC's resolver in `camunda/camunda`. Covered by the monorepo follow-up that lands after the
  next CSL release.

## Design

### New class: `CamundaOidcAuthorizationRequestResolver`

- Package: `io.camunda.security.spring.oidc`
- `final class CamundaOidcAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver`
- Constructor:
  `(ClientRegistrationRepository clientRegistrationRepository,
    Map<String, OidcConfiguration> sourcesByRegistrationId)`
- Holds a `ConcurrentHashMap<String, OAuth2AuthorizationRequestResolver>` cache keyed by
  registrationId. Each cache entry is a `DefaultOAuth2AuthorizationRequestResolver` with a customizer
  applied once at construction.
- Path matcher: `/oauth2/authorization/{registrationId}` — the same base URI Spring Security's
  default uses, and the same matcher OC's resolver uses.

#### Customizer

For a given `registrationId`, the customizer applied to `OAuth2AuthorizationRequest.Builder`:

1. If `oidcConfiguration.getAuthorizeRequest().getAdditionalParameters()` is non-null and non-empty,
   call `builder.additionalParameters(map)` with every entry.
2. If `oidcConfiguration.getResource()` is non-null and non-empty, call
   `builder.additionalParameters(Map.of(OAuth2ParameterNames.RESOURCE, list))`.

Both calls invoke `OAuth2AuthorizationRequest.Builder#additionalParameters(Map<String, Object>)`,
which merges entries into the builder's existing map (rather than replacing it), so configured
`additional_parameters` and `resource` coexist in the final request. Mirror OC exactly — no merging
logic beyond what the builder already provides. If a customer puts `resource` inside
`additional_parameters` as well as in the top-level `resource` field, the top-level call lands
second and wins; this matches OC's order today.

#### Behaviour matrix

| Path / arg                                 | Result                                                                                       |
|--------------------------------------------|----------------------------------------------------------------------------------------------|
| `registrationId` is null or blank          | Return `null` (Spring contract for non-matching paths)                                       |
| `registrationId` not in sources map / repo | Throw `IllegalArgumentException("Invalid Client Registration with ID '<id>'")` (OC's format) |
| Both customisations unset                  | Produces exactly what `DefaultOAuth2AuthorizationRequestResolver` alone would produce        |

### Wiring in `OidcBeansConfiguration`

**1. Extract the flat-plus-providers merge** currently inside `clientRegistrationRepository()` (the
five lines that build the `LinkedHashMap`) into a private static helper:

```java
private static Map<String, OidcConfiguration> buildOidcSources(
    AuthenticationConfiguration authentication) {
  final OidcConfiguration flat = authentication.getOidc();
  final Map<String, OidcConfiguration> providers = authentication.getProviders().getOidc();
  final Map<String, OidcConfiguration> sources = new LinkedHashMap<>();
  if (StringUtils.hasText(flat.getClientId())) {
    sources.put(flat.getRegistrationId(), flat);
  }
  sources.putAll(providers);
  return sources;
}
```

`clientRegistrationRepository()` then calls it. Pure refactor; no behaviour change.

**2. Add a new `@Bean` method** below `clientRegistrationRepository()`:

```java
@Bean
@ConditionalOnMissingBean(OAuth2AuthorizationRequestResolver.class)
public OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver(
    final ClientRegistrationRepository clientRegistrationRepository,
    final CamundaSecurityLibraryProperties properties) {
  return new CamundaOidcAuthorizationRequestResolver(
      clientRegistrationRepository,
      buildOidcSources(properties.getAuthentication()));
}
```

**3. No changes to `OidcWebappSecurityConfiguration`** — it already consumes
`ObjectProvider<OAuth2AuthorizationRequestResolver>` and wires whichever bean is present.

## Tests

### `CamundaOidcAuthorizationRequestResolverTest` (new, unit)

`@ExtendWith(MockitoExtension.class)` with a `@Mock ClientRegistrationRepository`. Stubs the repo to
return a real `ClientRegistration` built via `ClientRegistration.withRegistrationId(...).clientId(...)…build()`
so the underlying `DefaultOAuth2AuthorizationRequestResolver` can produce a real
`OAuth2AuthorizationRequest`. Sources map built directly in each test.

Cases:

1. **No customisations set** — neither `resource` nor `additional_parameters` configured. Assert the
   resulting `request.getAdditionalParameters()` has no `resource` key and no host-defined keys.
2. **`additionalParameters` only** — every configured entry appears in
   `request.getAdditionalParameters()`.
3. **`resource` only** — `request.getAdditionalParameters().get("resource")` equals the configured
   `List<String>`.
4. **Both set** — both visible; no collisions.
5. **Unknown registrationId** — throws `IllegalArgumentException` with the exact message
   `"Invalid Client Registration with ID '<id>'"`.
6. **Null / blank registrationId** — both `resolve(HttpServletRequest)` (path that doesn't match)
   and `resolve(HttpServletRequest, null)` / `resolve(HttpServletRequest, "")` return `null`.

### `OidcBeansConfigurationTest` additions (`ApplicationContextRunner`)

Two tests next to the existing logout-handler tests:

1. **Default wiring** — with no host bean, `ctx.getBean(OAuth2AuthorizationRequestResolver.class)` is
   an instance of `CamundaOidcAuthorizationRequestResolver`.
2. **Host bean wins** — when the host registers an `OAuth2AuthorizationRequestResolver` bean, CSL
   backs off (`hasSingleBean` + identity check against the host bean).

The existing `StubOidcInfrastructure` already supplies a stub `ClientRegistrationRepository`. The new
bean also needs `CamundaSecurityLibraryProperties`, which `CamundaSecurityConfiguration` already
binds in the existing test runner. Properties: minimal — only what is needed for the bean to
construct.

### `OidcWebappAuthorizationRequestResolverHookTest.chainBuildsWithoutHostResolver` (update)

The test currently asserts `doesNotHaveBean(OAuth2AuthorizationRequestResolver.class)`. Flip it:
assert that the chain's `OAuth2AuthorizationRequestRedirectFilter` holds an instance of
`CamundaOidcAuthorizationRequestResolver` (re-uses the reflection helper already in that test). The
second test in the file, `hostResolverBeanIsWiredIntoTheAuthorizationRequestRedirectFilter`, is
unaffected — host bean still wins via `@ConditionalOnMissingBean`.

## Adopter guide

Add a sub-section to `docs/adopters/security-filter-chains.md` under the OIDC webapp chain area,
titled **"Customising the authorisation request (`resource`, `additional_parameters`)"**. Content:

- One paragraph stating CSL now ships a default
  `CamundaOidcAuthorizationRequestResolver` that reads two `OidcConfiguration` properties and that
  hosts can override the bean wholesale.
- One paragraph on `resource` (RFC 8707) — list of audience identifiers added as `resource` query
  parameters on the authorisation URL.
- One paragraph on `authorize_request.additional_parameters` — arbitrary key/value pairs appended
  to the authorisation request (e.g. `prompt`, `audience`).
- Worked YAML example showing both under the flat block and a multi-provider entry.
- Override note: hosts that need different customizer logic register their own
  `OAuth2AuthorizationRequestResolver` bean; CSL's `@ConditionalOnMissingBean` backs off.

## Verification

```
mvn verify
```

Expected: `BUILD SUCCESS` with the new resolver unit tests, the two new
`OidcBeansConfigurationTest` cases, and the updated
`OidcWebappAuthorizationRequestResolverHookTest.chainBuildsWithoutHostResolver` all passing. No
regression in the rest of the OIDC test suite.
