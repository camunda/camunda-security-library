---
status: Accepted
---

# ADR-0022: `core`-owned assembly factories and native latency instrumentation for `AuthorizationCheckPort`

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

[ADR-0017](0017-unified-authz-framework-in-core.md) put the authorization graph in `core` and gave
non-Spring consumers a plain-Java entry point, `AuthorizationPortsFactory`. Three follow-on requests
all land on that same surface — the code a host writes when it assembles an
`AuthorizationCheckPort`/`AuthorizationChecker` graph itself, with or without a Spring container:

- **Selecting the tenant-access implementation.** 72661d8 moved `DefaultTenantAccessProvider` and
  `TenantOwnedEntity` into `core` (see ADR security/002 in camunda/camunda for the full relocation
  decision) but left the disabled counterpart, `DisabledTenantAccessProvider`, behind in the
  monorepo's search module. The enabled/disabled selection stayed a ternary in the monorepo's Spring
  `@Bean` method, naming a `core` type and a monorepo type side by side — split ownership of what is
  one decision: which implementation backs multi-tenancy checks.
  [camunda-security-library#592](https://github.com/camunda/camunda-security-library/issues/592)
  proposed collapsing it into a CSL-side factory, `TenantAccessProvider.of(cslProperties, checker)`.
  That literal signature does not fit: `CamundaSecurityLibraryProperties` lives in
  `spring-boot-starter`, and `core` must not depend on `spring-boot-starter` — that inverts the module
  dependency direction the whole library is built on.
- **Several scope repositories in one host.**
  [camunda-security-library#596](https://github.com/camunda/camunda-security-library/issues/596)
  tracks an OC request: OC hand-rolls per-scope authorization fan-out around `core`'s internals —
  building a new `AuthorizationService` on every check call — instead of depending only on
  `AuthorizationCheckPort`. `AuthorizationPortsFactory` already assembles this kind of graph, but only
  for a single scope, and it builds its own claims converter. Neither fits: OC needs one port per
  scope with a fail-hard lookup, and must reuse its *existing* claims resolver rather than a second
  one that could diverge from it. (A second consumer named in that issue turned out to construct a
  monorepo-owned class `core` cannot reach; its fix lives entirely in the monorepo.)
- **A latency metric that survives the migration.**
  [camunda-security-library#568](https://github.com/camunda/camunda-security-library/issues/568) /
  [camunda/camunda#45046](https://github.com/camunda/camunda/issues/45046): the legacy zeebe engine
  class `AuthorizationCheckBehavior` cached authorization lookups and measured a
  `zeebe.authorization.check.latency` Timer around every check. It was deleted by
  [camunda/camunda#58368](https://github.com/camunda/camunda/pull/58368) once the engine finished
  migrating to `core`'s `AuthorizationCheckPort`. That Timer was a pre-migration performance baseline
  (added by CSL#403) so post-migration latency could be compared against it — the acceptance
  criterion for CSL#402. It must be re-implemented natively, with the same metric definition, for the
  comparison to stay valid. The engine calls `AuthorizationCheckPort` through
  `AuthorizationPortsFactory` directly, with no Spring container in that path, so a Micrometer
  decorator built only in `spring-boot-starter` would never see engine-side checks.

What `core`-owned shapes let a host pick its tenant-access implementation, assemble a fail-hard
`AuthorizationCheckPort` per scope reusing its own claims resolver, and publish the pre-migration
latency Timer — without `core` depending on `spring-boot-starter`, Spring, or Micrometer?

## Decision

### 1. `DisabledTenantAccessProvider` moves into `core.authz`, selected by `TenantAccessProvider.of(boolean)`

`DisabledTenantAccessProvider` now sits in `io.camunda.security.core.authz` alongside
`DefaultTenantAccessProvider`. Behaviour-preserving: it returns `TenantAccess.wildcard(null)` from
all three `TenantAccessProvider` methods, matching the monorepo original.

A static factory on the interface itself, `TenantAccessProvider.of(boolean multiTenancyChecksEnabled)`,
selects between the two. It takes a plain `boolean`, not the monorepo's
`CamundaSecurityLibraryProperties` or any other `spring-boot-starter` type — callers extract the flag
from their own configuration before calling. That keeps the factory usable from non-Spring consumers,
consistent with `AuthorizationPortsFactory`'s plain-Java-factory precedent in the same package. The
monorepo's `tenantAccessProvider` `@Bean` method becomes
`TenantAccessProvider.of(cslProperties.getMultiTenancy().isChecksEnabled())`, naming no
monorepo-local implementation.

### 2. `AuthorizationService`'s claims dependency is the `TokenClaimsAuthenticationResolver` contract

`AuthorizationService` takes `TokenClaimsAuthenticationResolver` (the public contract in
`api/context`) instead of the concrete `core`-internal `LazyTokenClaimsConverter`. Behaviourally a
no-op — the concrete type implements that interface and delegates to the same logic — but it lets
decision 3 accept any resolver without exposing a `core`-internal type as a public parameter.

This changes the constructor's descriptor: source-compatible, but **not** binary-compatible. A host
that calls the constructor directly hits `NoSuchMethodError` at runtime until it recompiles against
the new CSL version — bumping the dependency version alone is not enough.

### 3. `ScopedAuthorizationCheckPortFactory` — one fail-hard check port per scope

`ScopedAuthorizationCheckPortFactory.create(...)` builds one `AuthorizationCheckPort` per entry in a
`Map<String, AuthorizationScopeRepositoryPort>`, sharing one caller-supplied claims resolver, one
evaluator registry, and both global flags across every scope. It returns
`ScopedAuthorizationCheckPorts`, a holder whose only method, `forScope(String)`, throws
`IllegalStateException` for an unknown (or `null`) scope rather than falling back to another scope's
port — resolving authorizations against the wrong scope's storage would break scope isolation. The
holder is a `public static final` nested class with a private constructor over a `Map.copyOf(...)`,
deliberately not a record: a record would let a caller read the map directly and get a silent `null`
instead of the fail-hard lookup.

`core` types for this kind of per-scope host surface are conventionally named `Scoped*`; the
convention is documented in `AGENTS.md` alongside this change.

### 4. `AuthorizationCheckLatencyRecorder` — a framework-free port carrying the shared metric spec

`AuthorizationCheckLatencyRecorder` is an outbound port in `core/port/out` with a single
`record(long durationNanos)` method and a `noop()` factory. The Timer's spec lives next to it as
plain `String`/`Duration` constants — `METRIC_NAME`, `METRIC_DESCRIPTION`, `METRIC_BASE_UNIT`,
`METRIC_SLO_BUCKETS` — so every host builds an identical Timer without redeclaring the spec, which is
what keeps CSL#568's "matches the deleted baseline" criterion true as the two repos version
independently. No Micrometer import in `core`.

The Timer is **untagged**, matching the deleted baseline exactly, to preserve comparability with
historical dashboards and alerts over a richer tag set that was never shipped.

Two spec fields deviate from a literal reading of "the same metric definition"; both are deliberate,
and the claim is scoped to name, SLO buckets, and untagged-ness:

- `METRIC_DESCRIPTION` is `"Latency of each authorization check"`. The deleted baseline's description
  read "...in `AuthorizationCheckBehavior`, including cache hits" — accurate then, because the Guava
  authorization cache sat inside the timed block. The dead class reference is gone with the class,
  and "including cache hits" is omitted on purpose: `AuthorizationService`'s timed overloads have no
  cache in their timed region, and the re-homed cache-access metrics are tracked separately, outside
  this window.
- `METRIC_BASE_UNIT` (`"ns"`) is documentation-only. `Timer.Builder` has no `baseUnit(...)` setter —
  verified with `javap` against the `micrometer-core` jar on the classpath; `Gauge.Builder`,
  `Counter.Builder`, and `DistributionSummary.Builder` all expose one, `Timer.Builder` does not. A
  Timer's reported unit is registry-defined (seconds for Prometheus, for example), not settable
  per-timer. The deleted baseline had the same shape: its `AuthorizationMetricsDoc.getBaseUnit()` also
  returned `"ns"` and was never plumbed into the live meter either. The constant declares the unit
  convention `record(long durationNanos)` uses, for adapters to apply where they can — not something
  every adapter's meter is guaranteed to carry.

### 5. Only the two terminal `check(...)` overloads are timed, and the recorder call is guarded

`AuthorizationService`'s scope-based and property-based `check(...)` overloads take
`System.nanoTime()` on entry and record the elapsed time in a `finally` block, so a check is timed
including any short-circuit taken before the check logic runs. The `Map<String, Object>`-claims
overload is left untimed: it is a pure delegation to the scope-based overload, which is already
timed, so timing it too would record two samples for one logical check and skew
`zeebe_authorization_check_latency_seconds_count` and the Grafana SLO-breach ratios the deleted
baseline fed.

The recorder is invoked through a private helper that catches `RuntimeException`, so a failing
recorder — a Micrometer registry under backpressure, say — can never propagate out of
`check(...)` and mask the real authorization result. The guard sits at the call site in
`AuthorizationService`, not in each implementation, so every current and future recorder (the
Micrometer adapter today, a non-Spring zeebe/engine adapter later) is protected without having to
remember the guard independently. A suppressed failure is logged once at `WARN`, latched by an
`AtomicBoolean`, so a broken recorder is not invisible at default log levels but does not flood the
log from a per-check code path.

### 6. Both `core` factories accept a recorder; `spring-boot-starter` supplies the Micrometer adapter

`AuthorizationService`, `AuthorizationPortsFactory.create(...)`, and
`ScopedAuthorizationCheckPortFactory.create(...)` each gain an **additive** overload taking the
recorder (shared across every scope's port, in the scoped factory's case); the pre-existing overloads
delegate to it with `AuthorizationCheckLatencyRecorder.noop()`. Every `AuthorizationCheckPort`
construction path in `core` can therefore accept a recorder — none is forced to a no-op by
construction.

`spring-boot-starter` supplies the package-private `MicrometerAuthorizationCheckLatencyRecorder`,
which builds its `Timer` from the shared constants (`Timer.builder(METRIC_NAME)`, `.description(...)`,
`.serviceLevelObjectives(...)`). `AuthorizationConfiguration` injects the host's `MeterRegistry` with
`@Autowired(required = false)`; a `null` registry leaves the adapter's `Timer` null and `record(...)`
a no-op — the same optional-metrics pattern `CachingOidcClaimsProvider` already uses in that module.

### Why these particular boundaries

- **A `core` factory taking a plain `boolean`, not the issue's `of(cslProperties, checker)`** — the
  properties type lives in `spring-boot-starter`; depending on it from `core` would invert the
  library's module direction.
- **A separate class from `AuthorizationPortsFactory`, not an overload on it** — that factory's own
  Javadoc reserves it for single-scope, non-Spring consumers.
- **An eager `Map`, not a provider SPI** (unlike the per-scope session-store contract in
  [ADR-0012](0012-session-store-port-and-web-session-ownership.md) §4, where the host is called back
  per scope as chains are registered) — the host knows every scope at wiring time here, so there is
  no laziness or decoupling need a callback would serve.
- **The scoped factory takes the host's own resolver rather than building one** — this is why
  decision 3 is not the shape [ADR-0017](0017-unified-authz-framework-in-core.md) rejected under
  "duplicated assembly between `AuthorizationPortsFactory` and the starter beans": routing a host's
  existing wiring through a factory that builds its own checker and converter would silently discard
  the host's own instances. This factory cannot, because it never builds one.
- **Flags and evaluators are global, not per-scope** — matches OC's existing behaviour of applying one
  configuration to every tenant; a per-scope flag would itself be a behaviour change, out of scope
  here.
- **A framework-free port in `core`, not solely a `spring-boot-starter` decorator** — the engine calls
  `AuthorizationPortsFactory`/`AuthorizationService` directly, so a Spring-only decorator would
  silently miss every engine-side check.
- **Additive constructor and factory overloads, not breaking signature changes** — the same
  constructors were already touched by decision 2 shortly before the metric work; the additive shape
  avoids further churn on them.

## Consequences

**Positive**

- The multi-tenancy enabled/disabled choice is expressed once, in `core`, and is reachable from
  non-Spring consumers.
- OC can depend on `AuthorizationCheckPort` alone, dropping its own per-call assembly. The resolver
  widening is behaviour-preserving, verified by existing tests passing unmodified.
- CSL#568's acceptance criterion (matching the deleted pre-migration baseline) holds without
  re-deriving the spec per host, and both Spring hosts and the non-Spring zeebe engine can supply a
  working recorder from the same contract.
- Every `AuthorizationCheckPort` construction path in `core`, including the per-scope factory, can
  accept a recorder; no factory in `core` forces a no-op by construction.

**Negative / accepted trade-offs**

- Widening `AuthorizationService`'s claims parameter is not binary-compatible (decision 2): a direct
  caller must recompile, not just bump the version.
- A second per-scope assembly entry point now exists alongside `AuthorizationPortsFactory`,
  overlapping in what it builds internally but differing in Spring-vs-non-Spring shape and resolver
  ownership; kept separate for the reasons above rather than merged.
- Hosts building their own Timer from the shared constants must apply
  `Timer.builder(...).serviceLevelObjectives(...)` correctly — Micrometer publishes those bucket
  boundaries in nanoseconds, not converted to seconds, which is easy to get wrong when asserting
  against them.
- This ADR does not by itself instrument any specific host. As of this writing,
  [camunda/camunda#59594](https://github.com/camunda/camunda/pull/59594) — which wires
  `ScopedAuthorizationCheckPortFactory` as `dist`'s primary, `@ConditionalOnMissingBean`-gated
  `AuthorizationCheckPort` bean — is open and still calls the 5-arg (no-recorder) overload, so it
  will keep getting a no-op recorder until its `WebAppAuthorizationCheckPortConfiguration` is
  separately updated to pass one through.
- **The `ResourceAccessProvider` side of decision 1 is still open.**
  `DisabledResourceAccessProvider` does live in `core.authz` today (added by commit 16ce2f0; no ADR
  records that move), but nothing in CSL selects it: there is no `DefaultResourceAccessProvider` in
  `core` to select between, and the only reference to the disabled class is its own unit test. So
  `ResourceAccessProvider.of(boolean)` is not merely missing — it is unwritable until the enabled
  implementation moves too, which still depends on `ResourcePropertyMatcherRegistry` →
  `UserTaskPropertyMatcher` → `io.camunda.search.entities.UserTaskEntity`, a monorepo search-domain
  type with no CSL equivalent. No ADR currently tracks closing this gap.

## Alternatives Considered

- **`TenantAccessProvider.of(cslProperties, checker)`** (CSL#592's literal proposal). Rejected —
  inverts `core`'s dependency direction onto `spring-boot-starter`.
- **An overload on `AuthorizationPortsFactory` for the per-scope case.** Rejected — contradicts that
  factory's documented single-scope, non-Spring contract.
- **Have the scoped factory build the claims resolver internally, mirroring
  `AuthorizationPortsFactory.create`.** Rejected — risks a second, diverging converter instance next
  to the host's own.
- **A `spring-boot-starter`-only Micrometer decorator wrapping `AuthorizationCheckPort`.** Rejected —
  the zeebe engine builds and calls the port directly through `AuthorizationPortsFactory`, bypassing
  Spring `@Bean` decoration entirely; a decorator would silently miss every engine-side check.
- **Tag the Timer by resource type or outcome.** Rejected — the deleted baseline was untagged;
  tagging now would break comparability with historical dashboards and alerts for no proven benefit.

Consolidates records previously numbered 0039, 0040 (see git history).
