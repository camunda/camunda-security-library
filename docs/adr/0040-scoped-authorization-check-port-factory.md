---
status: Accepted
---

# ADR-0040: A scoped `AuthorizationCheckPort` factory for hosts with several scope repositories

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

[camunda-security-library#596](https://github.com/camunda/camunda-security-library/issues/596)
tracks a monorepo (OC) request: OC hand-rolls per-scope authorization fan-out around `core`'s
internals — building a new `AuthorizationService` on every check call — instead of depending only
on `AuthorizationCheckPort`.

`AuthorizationPortsFactory` (ADR-0028) already assembles this kind of graph, but only for a single
scope, for non-Spring consumers, and it builds its own claims converter. None of that fits: OC needs
one port per scope with a fail-hard lookup, and must reuse its *existing* claims resolver rather
than a second one that could diverge from it.

(A second consumer named in the issue turned out to construct a monorepo-owned class `core` cannot
reach; its fix lives entirely in the monorepo. This ADR covers the check-port plane only.)

## Decision

1. **Widen `AuthorizationService`'s claims dependency to the `TokenClaimsAuthenticationResolver`
   port**, replacing the concrete `LazyTokenClaimsConverter`. Behaviourally a no-op — the concrete
   type already delegates to the same logic under the port's method name — but it lets decision 2
   accept any resolver without exposing a `core`-internal type as a public parameter.

   This changes the constructor's descriptor: source-compatible, but not binary-compatible. A host
   that calls it directly today hits `NoSuchMethodError` at runtime until it recompiles against the
   new CSL version — bumping the dependency version alone is not enough.

2. **New factory, `ScopedAuthorizationCheckPortFactory`**, builds one `AuthorizationCheckPort` per
   entry in a `Map<String, AuthorizationScopeRepositoryPort>`, sharing one caller-supplied claims
   resolver, evaluators, and flags across every scope. Returns a holder whose only method,
   `forScope(String)`, throws on an unknown scope instead of falling back to another scope's port.

### Why these particular boundaries

- **A separate class from `AuthorizationPortsFactory`, not an overload on it** — that factory's own
  Javadoc reserves it for single-scope, non-Spring consumers.
- **An eager `Map`, not a lazy SPI** (unlike ADR-0029's session-store case) — the host knows every
  scope at wiring time, so there's no laziness or decoupling need to serve.
- **Takes the host's own resolver rather than building one** — this is why decision 2 isn't ADR-0028
  §6's rejected "route the Spring bean through a factory" alternative: that alternative risked a
  factory silently diverging from a host's existing converter, and this factory can't, because it
  never builds one.
- **Flags and evaluators are global, not per-scope** — matches OC's existing behaviour of applying
  one configuration to every tenant; a per-scope flag would be a behaviour change, out of scope here.
- The returned holder is a plain final class wrapping a private map, not a record — a record would
  let a caller read the map directly and get a silent `null` instead of the fail-hard lookup.
- `core` types for this kind of per-scope host surface are conventionally named `Scoped*`
  (documented in `AGENTS.md` alongside this change).

## Consequences

**Positive**

- OC can depend on `AuthorizationCheckPort` alone, dropping its own per-call assembly.
- The resolver widening is behaviour-preserving, verified by existing tests passing unmodified.

**Negative / accepted trade-offs**

- A second per-scope assembly entry point now exists alongside `AuthorizationPortsFactory`,
  overlapping in what it builds internally but differing in Spring-vs-non-Spring shape and
  resolver ownership; kept separate for the reasons above rather than merged.
- The issue's second named consumer is out of `core`'s reach and not addressed here.

## Alternatives Considered

- **Overload on `AuthorizationPortsFactory`.** Rejected — contradicts its single-scope, non-Spring
  contract.
- **Build the resolver internally, mirroring `AuthorizationPortsFactory.create`.** Rejected — risks
  a second, diverging converter instance.
- **A `Scoped*Provider` SPI, like ADR-0029.** Rejected — that laziness serves a Spring-Session-timing
  constraint that doesn't apply here.
