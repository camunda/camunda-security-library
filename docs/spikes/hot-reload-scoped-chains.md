# Proof of concept: change scoped security at runtime

Branch: `csl-poc-runtime-security` (local), version `1.2.1-pt-poc-SNAPSHOT`, built on CSL `main`
at 1.2.1-SNAPSHOT and on Carlo Sana's spike `spike/hot-reload-scoped-chains`. Not production-ready;
the design is recorded as [ADR-0040](../adr/0040-change-scoped-security-at-runtime.md) (proposed).

Serves the two Physical Tenants at Scale epics: tenant lifecycle (a tenant's chains appear, change
or go away without a restart) and dynamic secrets (a rotated client secret or `private_key_jwt`
keystore takes effect without a restart or a configuration change).

## What works

| Capability | How | Proven by |
|---|---|---|
| Add, replace, remove one scope; others untouched | `ScopedSecurityReloadPort.apply` / `remove`; per-slot lock | `ScopedSecurityChainReloadTest#shouldRebuildOnlyTheScopeThatChanged` and the rest of that class |
| Re-read all providers, rebuild only what changed | `reloadAll()`; complete fingerprint per scope | `#shouldServeAScopeAddedByReloadingAll`, `#shouldNotRebuildAnUnchangedScope` |
| Failed build keeps the old chain live | build off to the side, publish only on success | `#shouldKeepTheLiveGenerationWhenTheNextOneFailsToBuild`, `#shouldRejectAnInvalidSetAndLeaveLiveScopesUntouched` |
| Removed scope fails closed (404, whole base path) | tombstone generation | `#shouldAnswerNotFoundForARemovedRuntimeScope`, `#shouldAnswerNotFoundForARemovedStartupScope`, concurrency test end state |
| OIDC: issuer, audiences, client, named providers changed at runtime | per-generation decoder and client stack | `OidcScopeRuntimeTest` (12 tests) |
| Client secret rotation, sessions kept, in-flight login finishes | `rotateCredentials`; `CurrentRegistrationAuthorizedClientRepository` | `OidcScopeRuntimeTest#shouldKeepTheSessionAndRefreshItsTokenWithTheRotatedSecret`, `#shouldFinishALoginStartedBeforeTheSecretWasRotated` |
| Keystore replaced at same path / new path | `refreshCredentials` / `rotateCredentials`; per-generation `ScopedAssertionJwks` | `AssertionKeyRotationTest` (also shows the old key stays cached until refresh) |
| Atomic per scope (API + webapp together) | one volatile generation; matches/getFilters pinning | `ScopeSwapConcurrencyTest` |
| Sessions end on an authentication change, other scopes untouched | `ScopeAuthenticationBoundSessionRepository` + `ScopeFingerprints` | `OidcScopeRuntimeTest#shouldEndTheSessionsOf…`, `#shouldKeepTheSessionsOfOtherScopes`, `ScopeFingerprintsTest` |
| Unreachable new IdP keeps the old chain; other scopes unaffected | `IdentityProviderCheck`, `UnreachableIdentityProviderPolicy` | `OidcScopeRuntimeTest#shouldKeepTheLiveGenerationWhenTheNewIdentityProviderCannotBeReached`, `#shouldApplyAnUnreachableIdentityProviderOnRequestAndRecoverWhenItAnswers` |
| No reflection; nothing retained after retirement | `ScopeCapturingObjectPostProcessor` wraps the shared processor bean | `ScopedSecurityChainReloadTest#shouldReleaseEveryRetiredGeneration`, `#shouldReleaseTheSessionStateOfARemovedScope`, `OidcScopeRuntimeTest#shouldReleaseTheOidcStateOfRetiredGenerations` |
| Bounded caches across reloads | discovery and decoder eviction on retirement; slots bounded by base paths | `#shouldReleaseTheOidcStateOfRetiredGenerations` (discovery cache empty after), `#shouldKeepOneSlotPerBasePathAcrossChanges`, `ScopedClientRegistrationFactoryDiscoveryCacheTest`, `OidcUserAuthenticationConverterTest` |

Mutation checks (each made the named tests fail, then reverted): disabling the session-binding
check fails the issuer/client session tests; returning the stored authorized client instead of
rebinding fails the rotated-secret refresh test; not wrapping the shared post-processor fails the
garbage-collection tests.

## Public API for hosts

```java
package io.camunda.security.core.port.in;

public interface ScopedSecurityReloadPort {
  ScopeReloadReport reloadAll();
  ScopeReloadResult apply(ScopedSecurityDescriptor descriptor);
  ScopeReloadResult apply(ScopedSecurityDescriptor descriptor, UnreachableIdentityProviderPolicy policy);
  ScopeReloadResult remove(String basePath);
  ScopeReloadResult rotateCredentials(ScopedSecurityDescriptor descriptor); // IAE unless credential-only
  ScopeReloadResult refreshCredentials(String basePath);
}
```

```java
package io.camunda.security.api.model.scope;

public record ScopeReloadResult(
    String basePath, ScopeReloadOutcome outcome, long generation, Duration duration,
    RuntimeException failure) {
  boolean applied();
  boolean sessionsInvalidated();
  Optional<RuntimeException> failureCause();
  ScopeReloadResult orThrow();
}
public record ScopeReloadReport(List<ScopeReloadResult> results) {
  List<ScopeReloadResult> failures();
  Optional<ScopeReloadResult> result(String basePath);
}
public enum ScopeReloadOutcome { ADDED, REPLACED, CREDENTIALS_ROTATED, CREDENTIALS_REFRESHED,
  UNCHANGED, REMOVED, ABSENT, KEPT_PREVIOUS, FAILED; boolean applied(); }
public enum UnreachableIdentityProviderPolicy { KEEP_PREVIOUS, APPLY }
```

The bean is registered by `ScopedSecurityChainConfiguration` (part of the
`CamundaSecurityAutoConfiguration` umbrella) whenever a `CamundaSecurityScopeProvider` bean exists;
inject `ScopedSecurityReloadPort`. Other public additions: `OAuth2AuthorizedClientManagerFactory`
gains a default three-argument `create(…, refreshTokenResponseClient)`;
`ScopedWebappSecurityChainBuilder.buildScopedWebappChain(…, ScopedOidcClients)`;
`ScopedClientRegistrationFactory.evictDiscovery(Collection<String>)` / `cachedDiscoveryIssuers()`;
`OidcUserAuthenticationConverter.evictDecoders(Collection<ClientRegistration>)`;
`LazyClientRegistrationRepository.resolvedRegistrations()`.

## What the camunda monorepo must do

1. **Make the scope provider live.** `PhysicalTenantScopeProvider` builds its descriptors once in
   its constructor from the `Environment`; it must return the current tenant set on every `get()`,
   because `reloadAll()` and a restart read it. Build a fresh `AuthenticationConfiguration` per
   change; never mutate one a scope was built from.
2. **Call the port on every node.** A change is local to the node. On a tenant lifecycle event
   call `apply(descriptor)` / `remove(basePath)` on each node (event bus, or each node polling the
   tenant store and calling `reloadAll()`); on a secret-store rotation call
   `rotateCredentials(descriptor)` (new value or keystore path) or `refreshCredentials(basePath)`
   (same path and passwords, new file). Check `result.applied()`; retry `KEPT_PREVIOUS` and
   `FAILED`. Until every node has applied a change, sessions created on an updated node are ended
   by a node still on the old configuration, and the reverse — use sticky sessions or apply
   quickly.
3. **Rebuild host-side per-tenant state.** These are built once from the `Environment` and are not
   touched by CSL: `OidcOverrideBeansConfiguration#oidcTokenAuthenticationConverter`
   (`PhysicalTenantAwareOidcTokenAuthenticationConverter`, its per-tenant
   `TokenClaimsConvertersByIssuer` and `ScopedOidcClaimsProviderFactory` claim providers),
   `PhysicalTenantOidcSettingsRegistry`, `ProviderAwareOidcUserAuthenticationConverter`'s
   per-tenant claim converters, `PhysicalTenantGroupsClaims`, `ClusterAdminUser`. They need the
   same treatment: rebuilt per tenant on change, published atomically, old entries dropped. Until
   then a reconfigured tenant authenticates with CSL's new chain but maps claims with the old
   converter.
4. **Token endpoint.** Scoped login chains no longer use the host `OidcTokenEndpointCustomizer`;
   its `resolvedJwks` cache only serves the primary chain now. Its `resource` parameter handling is
   reproduced by CSL; its observation-instrumented `RestClient` is not (needs a hook if wanted).
   For the primary chain's own rotation, the host customizer's `resolvedJwks` and its
   `authorizedClientManager` bean (which resolves keys through the cluster port on every refresh)
   remain the host's to evict.
5. **Upgrade.** Depend on `1.2.1-pt-poc-SNAPSHOT` from the local repository (installed by
   `./mvnw install`).

## Known limits and open points

- **Per node, not cluster-wide.** No coordination between nodes; see above.
- **Sessions in host stores.** Sessions of a changed or removed scope are rejected when read and
  deleted then; until read or expired they stay in a host-owned store. A scope removed and re-added
  with an identical configuration accepts its old sessions again (in-memory stores lose them).
  Refresh tokens of ended sessions are not revoked at the IdP.
- **Fingerprint by introspection.** Every bean property of `AuthenticationConfiguration` is
  authentication-relevant except `clientSecret`, `password`, `keyPassword`, `path`, `keyAlias`.
  A future credential property must be added to `ScopeFingerprints.CREDENTIAL_PROPERTIES`, or a
  rotation of it ends sessions (fail-safe, not fail-open). `UNCHANGED` checks cost ~1 ms.
- **Withdrawing trust from an unreachable provider.** The default `KEEP_PREVIOUS` keeps trusting
  the previous configuration until a later change succeeds; a host that withdraws trust must pass
  `APPLY`. A replacement whose providers resolve from the discovery cache is not re-checked over the
  network.
- **Single-provider scope with an unreachable provider under `APPLY`.** Every bearer token of the
  scope gets 500 until it answers, including tokens of the issuer the change removed (ADR-0025).
- **Startup scopes.** Their chain beans stay registered; Spring Security's privilege evaluator
  keeps the authorization rules of their first generation (used for error-page access checks).
- **Shared post-processor bean name.** The wrapper relies on Spring Security's bean name
  `objectPostProcessor`; if that changes, a WARN is logged and the leak tests fail. Objects
  post-processed lazily at request time (none found) would not be captured.
- **Mutable configuration.** A host that mutates an `AuthenticationConfiguration` after handing it
  over changes a live scope without a new generation.
- **Not covered by tests.** `unprotected-api=true` scopes at runtime; persistent (`SessionStorePort`)
  stores at runtime beyond the existing isolation tests; scoped logout/revocation after rotation;
  a real servlet container; Hub.
- **Slow providers stall their own scope, and `reloadAll()`.** The provider check runs under the
  scope's lock with Spring's discovery timeout; other scopes' per-scope changes proceed, but
  `reloadAll()` applies scopes one after another.
- **Cookie-name collisions under concurrency.** Two different base paths that sanitize to the same
  cookie name and are added at the same moment are not both rejected; sequential adds are.
- **Observability.** One INFO per change, WARN for `KEPT_PREVIOUS`, ERROR for `FAILED`; no
  metrics or health indicator.

## Measurements

MacBook (18 cores, other builds running), JDK 21, `MockHttpServletRequest` through
`FilterChainProxy`, loopback IdP. Latencies are per change, measured by `ScopeReloadResult.duration()`.

| Change | p50 | p99 |
|---|---|---|
| BASIC add (1,000 scopes) | 2.2 ms | 4.6 ms |
| BASIC replace | 2.2 ms | 4.8 ms |
| Unchanged (fingerprint only) | 0.85 ms | 1.3 ms |
| Remove | 18 µs | 28 µs |
| OIDC add (100 scopes) | 3.4 ms | 8.8 ms |
| OIDC replace incl. provider check | 3.9 ms | 9.7 ms |

- Heap: ~26 KiB per BASIC scope (approximate, `Runtime` before/after 1,000 adds).
- Request: median 69 µs for a bearer request (JWT verification included) through the dispatching
  chain with 1,100 scope slots (100 live OIDC scopes, 1,000 removed); the slot is found by path
  prefix, not by scanning scopes.
- Concurrency: ~2.5 million requests from 8 threads in 8 s while ~3,500 changes ran (add, replace,
  remove of BASIC and OIDC, startup and runtime scopes): 0 unexpected answers, 0 chains observed
  with two generations, 0 requests served by an older generation than one already observed.
  Change latency under that load: replace p50 3.4 ms / p99 11.7 ms, add p50 2.5 ms / p99 8.6 ms.

## Test counts

Full `./mvnw verify`: api 241, core 180, validation 267, spring-boot-starter 1,743 — all green
(baseline on `main`: 229 / 180 / 267 / 1,650). New test dependency: `org.awaitility:awaitility`
(test scope, version from the Spring Boot BOM).
