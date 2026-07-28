---
status: Accepted
---

# ADR-0039: CSL-owned `SessionRepositoryFilter` subclass exposes its session repository

**Deciders**: Sebastian Bathke (megglos)

## Status

Accepted

Refines the filter-construction detail of
[ADR-0027](0027-scoped-webapp-security-chains-and-per-scope-sessions.md) §3 (per-scope filters) and
[ADR-0031](0031-explicit-default-session-filter-replaces-global-filter.md) (the explicit default
filter). Both ADRs' decisions stand unchanged: same filters, same installation points, same
repository-resolution order.

## Context

CSL installs `SessionRepositoryFilter` instances explicitly, one per surface: the default
(non-scoped) filter from `DefaultWebSessionComponentsFactory` (ADR-0031) and one per physical-tenant
scope from `ScopedWebSessionComponentsFactory` (ADR-0027). Which `SessionRepository` a given filter
is bound to is the whole point of both ADRs: per-scope stores give store-level isolation on top of
cookie isolation (ADR-0029), and the default surface must reuse the durable `WebSessionRepository`
bean rather than a fresh in-memory one.

Tests therefore have to answer "which store is this chain's filter bound to?". Spring Session offers
no accessor for it, so five test classes reached into the framework's private field:

```java
final var field = SessionRepositoryFilter.class.getDeclaredField("sessionRepository");
field.setAccessible(true);
```

That couples CSL tests to a Spring Session implementation detail. A field rename in a Spring Session
upgrade breaks all five, and the reflection block was copy-pasted per test, with a `try`/`catch` and
a `@SuppressWarnings` each. Reviewed on
[#432](https://github.com/camunda/camunda-security-library/pull/432), tracked as
[#435](https://github.com/camunda/camunda-security-library/issues/435).

The alternatives that avoid touching production code do not cover the need. Injecting a repository
bean does not work: `ScopedSecurityChainRegistrar.resolveSessionRepository` deliberately constructs a
per-scope `MapSessionRepository` when no durable per-scope provider is contributed, so an injected
bean is never consulted. Minting a session through the real chain works for *seeding* (the pattern
exists in `ScopedWebappSessionIsolationTest`) but cannot serve the assertions that compare repository
*instances* across scopes, and would require a full OIDC-login simulation for the webapp chain.

## Decision

**1. CSL owns the filter type it installs.** Introduce
`io.camunda.security.spring.session.CamundaSessionRepositoryFilter<S>`, a `final` subclass of
`SessionRepositoryFilter<S>` that keeps a reference to the repository it was constructed with and
exposes it through a **package-private** `sessionRepository()` accessor. It overrides nothing: the
superclass keeps its own reference and performs all session resolution and commit work.

Both component factories construct it, and both keep their declared return type
`SessionRepositoryFilter<S>`, so no call site, bean type, or chain assembly changes.

The class and its constructor are `public` because the two factories live in sibling packages
(`spring.security`, `spring.scope`). The accessor stays package-private: it is a test seam, not a
host-facing API.

**2. Tests reach the accessor through a same-package test-support class.**
`io.camunda.security.spring.session.WebSessionTestAccess` (test sources, production package) exposes
`repositoryOf`, `mapRepositoryOf`, `durableRepositoryOf`, and `storePortOf`. Being in the production
package, it also reaches `WebSessionRepository.sessionStorePort()` directly, which removes the last
reflective hop in `ScopedWebappSessionIsolationTest`. `repositoryOf` fails with a clear
`AssertionError` when handed a filter that is not a `CamundaSessionRepositoryFilter`, which is the
signal that production code bypassed a CSL factory.

**3. Where reflection stays, use `ReflectionTestUtils`.** Some assertions read internals of
third-party classes that have no accessor and that CSL does not own, for example Spring Security's
`CsrfFilter.tokenRepository` and `CookieCsrfTokenRepository.cookieName`. Those cannot be designed
away. For them, use `org.springframework.test.util.ReflectionTestUtils` rather than hand-rolled
`getDeclaredField` + `setAccessible` + `try`/`catch`.

The rule: **remove reflection where CSL owns the object; use `ReflectionTestUtils` where the
internals belong to a framework.**

## Consequences

- No behaviour change. No new configuration property, no change to cookie naming, session
  resolution, or store routing.
- One new public type in the starter jar. Hosts never construct it; the beans it backs keep their
  declared `SessionRepositoryFilter<?>` type.
- A Spring Session field rename can no longer break CSL's session tests.
- New code that installs a `SessionRepositoryFilter` must build it through one of the two component
  factories, otherwise the store-binding assertions fail with the `AssertionError` above. That is the
  intended pressure: CSL should not install session filters from anywhere else.
- Test-support code now lives in `io.camunda.security.spring.session` in test sources, alongside the
  more general `io.camunda.security.spring.testsupport`. The split is deliberate — package-private
  access is the reason this one cannot move.

## Alternatives Considered

**Keep the reflection, wrapped in `ReflectionTestUtils`.** Proposed on #435 as a low-effort interim
step: it removes the `try`/`catch` and `@SuppressWarnings` boilerplate in the two scoped tests while
staying reflection-based. Rejected as the end state for CSL-owned objects, since the accessor deletes
those call sites entirely for the same effort. Adopted for framework-owned internals (decision 3).

**A package-private subclass inside `spring.scope` only.** Zero public surface and it fixes the two
tests named in the issue. Rejected: the default-surface tests build their filter through the mirrored
factory and would keep the reflection, so the same seam would be built twice and the two surfaces
would drift.

**An accessor keyed by basePath on `ScopedSecurityChainRegistrar`.** Would expose the per-scope
repositories from the registrar's own cache. Rejected: it only serves scoped chains, requires tests
to obtain a `BeanDefinitionRegistryPostProcessor` bean by concrete type, and adds a second cache to
production code, while the filter subclass serves both surfaces with no extra state.

**A faithful webapp-chain mint helper (full OIDC-login simulation).** Rejected for cost and coverage:
authorization-request redirect, callback with matching code/state/nonce, token exchange against
`OidcTestServer`, likely `OidcTestServer` extensions, and it still would not expose the repository
instance the cross-scope assertions compare.
