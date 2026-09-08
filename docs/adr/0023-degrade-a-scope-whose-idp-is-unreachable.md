---
status: Accepted
---

# ADR-0023: Degrade a scope whose identity provider is unreachable, instead of failing startup

**Deciders**: Ana Vinogradova

## Status

Accepted

## Context

`ScopedSecurityChainRegistrar` registers an API chain and a webapp chain per scope, and building
either resolves that scope's OIDC discovery document over HTTP. Any failure propagated out of
Spring bean creation and killed the application context, so one scope's unreachable identity
provider took every other scope's API surface down with it.

Discovery is now retried once for a transient cause, which covers a brief outage. What should
happen when a scope's identity provider cannot be resolved at all?

## Decision

That scope degrades; every other scope starts normally.

`ScopedSecurityChainRegistrar.degradeOrRethrow` catches the failure, logs ERROR naming the
basePath and the configured issuer, and registers a chain that claims the scope's own paths and
answers 503 — `buildDegradedScopedApiChain` at `ORDER_API`, `buildDegradedScopedWebappChain` at
`ORDER_WEBAPP`.

A wiring error is rethrown, and so is any failure on a scope not using OIDC: neither reaches a
network, so both are configuration errors that belong at startup.

### Why these particular boundaries

- **The chain is registered, never omitted.** Unclaimed paths fall to whatever matches next,
  which on a host that disables the catch-all chain
  ([ADR-0018](0018-optimize-reuses-stateful-oidc-webapp-chain.md)) is the cluster-wide webapp
  chain — authenticating against the cluster's issuer instead of the scope's.
- **The degraded chain claims exactly what the real one would**, including the webapp heartbeat
  path ([ADR-0020](0020-configurable-activity-driven-session-idle-timeout.md)).
- **Not decided by exception type.** A connect timeout and a mistyped issuer both arrive as
  `IllegalArgumentException`; an issuer mismatch arrives as `IllegalStateException`, the same
  type a wiring error uses.
- **503, not 401 or 404.** The scope's tokens are not invalid; they cannot be checked at all.
  This extends the existing "an identity provider outage is not a 401" policy, which specified
  500.

## Consequences

**Positive**

- One tenant's identity provider outage no longer takes down every tenant.
- A misconfigured deployment still fails loudly at startup.

**Negative / accepted trade-offs**

- A degraded scope stays degraded until the process restarts; nothing rebuilds the chain.
- Nothing alerts on it beyond one ERROR line — no metric, no health indicator.
- Startup is still blocked around 60 s per distinct unreachable issuer, because failed
  discovery is not cached.
- A degraded scope also refuses its own `unprotectedApiPaths` (`/v2/license`, `/v2/status`).
- An unresolvable *hostname* degrades rather than failing fast, being indistinguishable from an
  outage. Mitigated by naming the issuer in the ERROR log.

## Alternatives Considered

- **Synthesize a fallback `ClientRegistration` so the real chain still builds.** Rejected —
  `TokenValidatorFactory.resolveAudiences` treats an empty audience list as authoritative and
  installs no `AudienceValidator`, so the scope would accept any token minted at that issuer.
- **Omit the failed scope's chain entirely.** Rejected — its paths would fall through to the
  cluster-wide chain, as above.
- **Gate degradation on the retry's transient-failure predicate.** Rejected — that predicate is
  false for a 4xx, so one tenant's mistyped issuer would still take the cluster down.
- **Report the degraded scope through a health indicator.** Deferred, not rejected: it is the
  answer to the first two trade-offs above, but CSL has no health indicator today and readiness
  wiring belongs to the host.
