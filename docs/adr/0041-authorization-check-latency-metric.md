---
status: Accepted
---

# ADR-0041: Native latency metric for `AuthorizationCheckPort` checks

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

[camunda-security-library#568](https://github.com/camunda/camunda-security-library/issues/568) /
[camunda/camunda#45046](https://github.com/camunda/camunda/issues/45046): the legacy zeebe engine
class `AuthorizationCheckBehavior` cached authorization lookups and measured a
`zeebe.authorization.check.latency` Timer around every check. It was deleted by
[camunda/camunda#58368](https://github.com/camunda/camunda/pull/58368) once the engine finished
migrating to `core`'s `AuthorizationCheckPort`. The Timer was a pre-migration performance baseline
(added by CSL#403) so post-migration latency could be compared against it — the acceptance
criterion for CSL#402. It must be re-implemented natively, with the exact same metric definition, so
that baseline comparison stays valid.

The engine calls `AuthorizationCheckPort` through `AuthorizationPortsFactory`
([ADR-0028](0028-unified-authz-framework-in-core.md)) directly, with no Spring container in that
path. A Micrometer decorator built only in `spring-boot-starter` would never see engine-side checks.

What shape lets every host — Spring-based and the non-Spring zeebe engine alike — supply a working
Timer from one identical spec, without `core` depending on Micrometer?

## Decision

1. **New framework-free port in `core`**, `AuthorizationCheckLatencyRecorder`
   (`core/port/out`), with the Timer's name, description, base unit, and SLO buckets defined as
   plain `String`/`Duration` constants next to it, and a `noop()` factory. No Micrometer import in
   `core`.
2. **`AuthorizationService` gets an additive constructor overload** taking the recorder. Only the
   two terminal `check(...)` overloads (scope-based, property-based) are wrapped in a
   `try`/`finally` around `System.nanoTime()`. The `Map<String,Object>`-claims overload is left
   untimed — it is a pure delegation to the scope-based overload, so timing it too would record two
   samples per claims-based call. The `finally` block calls the recorder through a private helper
   that catches and discards any `RuntimeException`, so a failing recorder implementation can never
   affect the authorization result — see "Amendments" below.
3. **`AuthorizationPortsFactory.create(...)` widened** with an additive overload taking the
   recorder; the existing overloads delegate to it with `noop()`.
4. **[ADR-0040](0040-scoped-authorization-check-port-factory.md)'s `ScopedAuthorizationCheckPortFactory.create(...)`
   also widened**, with an additive overload taking the recorder, shared across every scope's
   port; the existing overload delegates to it with `noop()`. Both factories in `core` that build
   `AuthorizationService` now accept a recorder, so no `AuthorizationCheckPort` construction path
   is left uninstrumented.
5. **`spring-boot-starter` supplies `MicrometerAuthorizationCheckLatencyRecorder`**, built from the
   shared spec constants, wired via a nullable `MeterRegistry` — the same optional-metrics pattern
   `CachingOidcClaimsProvider` already uses in the same module.
6. **Untagged**, matching the deleted baseline exactly, to preserve comparability with historical
   dashboards and alerts over a richer tag set that was never shipped.

### Why these particular boundaries

- **A framework-free port in `core`, not solely a `spring-boot-starter` decorator** — the engine
  calls `AuthorizationPortsFactory`/`AuthorizationService` directly, so a Spring-only decorator
  would silently miss every engine-side check.
- **Shared spec constants defined once, next to the port** — every host builds an identical Timer
  without redeclaring the spec, which is what keeps CSL#568's "matches the deleted baseline"
  criterion true as the two repos version independently.
- **Only the two terminal overloads timed** — the claims-map overload delegates to the scope-based
  one; timing both would double-count every claims-based call in
  `zeebe_authorization_check_latency_seconds_count`, skewing the Grafana SLO-breach ratios the
  deleted baseline fed.
- **Additive constructors/factory overloads, not a breaking signature change** — both signatures
  were already touched by [ADR-0040](0040-scoped-authorization-check-port-factory.md) shortly
  before this decision; avoids further churn on the same constructors.

## Consequences

**Positive**

- CSL#568's acceptance criterion (matching the deleted pre-migration baseline) holds without
  re-deriving the spec per host.
- Both the Spring hosts and the non-Spring zeebe engine can supply a working recorder from the same
  contract.
- Every `AuthorizationCheckPort` construction path in `core` — including
  [ADR-0040](0040-scoped-authorization-check-port-factory.md)'s per-scope factory — can accept a
  recorder; no factory in `core` forces a no-op by construction. This does not by itself
  instrument any specific host: [camunda/camunda#59594](https://github.com/camunda/camunda/pull/59594)
  (open, not yet merged), which wires `ScopedAuthorizationCheckPortFactory` as `dist`'s primary,
  `@ConditionalOnMissingBean`-gated `AuthorizationCheckPort` bean, still calls the 5-arg overload
  today and will keep getting a no-op recorder until its `WebAppAuthorizationCheckPortConfiguration`
  is separately updated to pass one through — that update is not part of this ADR.

**Negative / accepted trade-offs**

- Hosts building their own Timer from the shared constants must apply
  `Timer.builder(...).serviceLevelObjectives(...)` correctly — Micrometer publishes those bucket
  boundaries in nanoseconds, not converted to seconds, which is easy to get wrong when asserting
  against them.

## Alternatives Considered

- **A `spring-boot-starter`-only Micrometer decorator wrapping `AuthorizationCheckPort`.** Rejected
  — the zeebe engine builds and calls the port directly through `AuthorizationPortsFactory`,
  bypassing Spring `@Bean` decoration entirely; a decorator would silently miss every engine-side
  check.
- **Time all three `check(...)` overloads uniformly.** Rejected — the claims-map overload is a pure
  delegation to the scope-based overload; timing both double-counts every claims-based call.
- **Tag the Timer by resource type or outcome.** Rejected — the deleted baseline was untagged;
  tagging now would break comparability with historical dashboards and alerts for no proven
  benefit.
- **Leave `ScopedAuthorizationCheckPortFactory` un-widened and track the gap as a follow-up
  issue.** Rejected — the widening is a same-shaped additive overload as
  `AuthorizationPortsFactory`'s (decision 3), costs nothing to add alongside it, and closes the
  gap before [camunda/camunda#59594](https://github.com/camunda/camunda/pull/59594) merges rather
  than after, with no dependency on that PR's unmerged shape: the factory signature is decided
  entirely within `core`.

## Amendments

Found during review of the implementing PR, by diffing against the actual deleted baseline
(`AuthorizationMetricsDoc`/`AuthorizationCheckMetrics`, pulled from `camunda/camunda` git history):

- **`METRIC_DESCRIPTION` is not an exact match of the deleted baseline text.** The deleted
  description read "...in `AuthorizationCheckBehavior`, including cache hits" — accurate then,
  because the Guava authorization cache sat inside the timed block. This port's description drops
  the dead class reference (correct, the class no longer exists) but initially also kept "including
  cache hits", even though `AuthorizationService`'s timed overloads have no cache in their timed
  region; the re-homed cache-access metrics (tracked separately, see Context) live outside this
  window. Fixed to `"Latency of each authorization check"`. Decision 1 and the Context's "exact
  same metric definition" claim apply to name, SLO buckets, and untagged-ness — not this field.
- **The recorder call is now guarded against `RuntimeException`.** The deleted
  `AuthorizationCheckMetrics.record()` swallowed exceptions with the comment "Metrics failures must
  never affect authorization decisions"; the first cut of this port's `finally`-block call site had
  no equivalent guard, so a failing implementation (e.g. a Micrometer registry under backpressure)
  could propagate out of `AuthorizationService.check(...)` and mask the real authorization result.
  Fixed by adding the same guard at the call site in `AuthorizationService`, rather than in each
  implementation, so every current and future `AuthorizationCheckLatencyRecorder` (the Micrometer
  adapter today, a non-Spring zeebe/engine adapter later) is protected without having to remember
  the guard independently.
