---
status: Accepted
---

# ADR-0012: Implicit `default` physical tenant and request rewrite for non-prefixed paths

**Deciders**: Ben Sheppard, Bojan Mudric

> Initial decider set, matching [ADR-0011](0011-physical-tenant-authentication-chain-layering.md). Additional sign-off from platform and security stakeholders is expected as the design firms up; any change in scope or decider composition is captured by a superseding ADR per the immutability rule in [`.claude/docs/guardrails.md`](../../.claude/docs/guardrails.md).

## Status

Accepted

> Companion to [ADR-0011](0011-physical-tenant-authentication-chain-layering.md). ADR-0011 defines the per-tenant chain shape for requests that arrive with a `/physical-tenants/{id}/...` prefix. This ADR defines how non-prefixed requests are handled in Multi-Engine deployments and how the `default` tenant is resolved. Read both together for the full Multi-Engine picture.

## Context

[ADR-0011](0011-physical-tenant-authentication-chain-layering.md) introduced a per-tenant filter chain at `/physical-tenants/{tenantId}/**` driven by configured entries under `camunda.security.physical-tenants[]`. It did not specify what happens to **non-prefixed** requests in a Multi-Engine deployment — `/v2/x`, `/login`, `/tasklist/...`, etc.

The FUA BFF team's Multi-Engine proposal ("Multi-Engine Impact on the FUA BFF") landed two related constraints alongside CSL's chain work:

1. The browser-visible URL for a customer who has not opted into Multi-Engine (typing `/tasklist/123`) must stay clean. No 30x redirects, no forced URL change.
2. Every downstream component — security chains, controllers, context propagation — should see a uniformly tenant-prefixed dispatch path so the same code paths handle prefixed and non-prefixed traffic.

The agreed mechanism between teams is an **internal server-side rewrite**: bare paths are rewritten in-process to `/physical-tenants/default/...` before any security chain runs. The user's address bar is unchanged; the dispatch path is normalised.

That creates two design questions this ADR answers:

> 1. How is the `default` tenant configured and resolved?
> 2. How is the rewrite activated, and how does it coexist with pre-Multi-Engine adopters who have no concept of physical tenants?

## Decision

### `default` is reserved and implicit from the top-level OIDC config

The tenant id `"default"` is reserved. It is **not** configured as an entry under `camunda.security.physical-tenants[]`. Its configuration *is* the existing top-level slot at `camunda.security.authentication.oidc.*`, the one [ADR-0011](0011-physical-tenant-authentication-chain-layering.md) left untouched:

```yaml
camunda:
  security:
    authentication:
      method: oidc
      oidc:                        # this is the default tenant's profile
        issuer-uri: https://default.example/idp
        client-id: ...
    physical-tenants:              # additional tenants only
      - id: acme
        oidc: { issuer-uri: https://acme.example/idp, ... }
      - id: globex
        oidc: { issuer-uri: https://globex.example/idp, ... }
```

`PhysicalTenantConfiguration.setId("default")` rejects the value at configuration-binding time with a message naming the reserved status and pointing the adopter at the top-level slot. The check is a hard collision guard: there is no scenario where the literal id `default` legitimately appears under `physical-tenants[]`.

The per-tenant chain from [ADR-0011](0011-physical-tenant-authentication-chain-layering.md) is extended so that, when activated, its `securityMatcher` includes `/physical-tenants/default/**` in addition to the per-configured-tenant patterns, and its `AuthenticationManager` map includes a `default` entry built from the top-level `JwtDecoder` bean. The `default` entry is present whenever the per-tenant chain registers, independent of whether the request arrived via rewrite or via a user directly typing the prefix.

### Internal server-side rewrite for non-prefixed paths

A new filter — `DefaultPhysicalTenantRewriteFilter` — wraps the request with an `HttpServletRequestWrapper` overriding `getRequestURI()` and `getServletPath()` so the dispatch path becomes `/physical-tenants/default/<original-path>`. The browser address bar is unchanged: no 30x redirect, no `RequestDispatcher.forward(...)`.

The original request URI is preserved on the request as a well-known attribute (`io.camunda.security.spring.filter.DefaultPhysicalTenantRewriteFilter.ORIGINAL_REQUEST_URI`) so audit logging or downstream components that need the user-visible path can recover it. The attribute name is part of the library's public contract for the duration of this design.

### Bypass paths

The rewrite filter does not rewrite:

- Anything in `SecurityPathPort.clusterScopedPaths()` — a new default method on the existing SPI, returning `Set.of()` by default. Hosts override to declare cluster-scoped paths (`/v2/cluster/**`, `/v2/license`, etc.) that must reach top-level handlers untouched.
- Anything already in `SecurityPathPort.unprotectedPaths()` or `unprotectedApiPaths()`. The host has already declared these as not requiring auth; routing them through a tenant prefix adds risk without value.
- Anything already starting with `/physical-tenants/` (idempotency — a rewritten request must not be re-rewritten if the filter chain re-enters).

### Activation model: two gates, one of which is `@Conditional`

The rewrite filter is registered when:

- The host opts in by `@Import`ing `DefaultPhysicalTenantRewriteConfiguration` per [ADR-0008](0008-no-spring-boot-auto-configuration.md), AND
- `camunda.security.physical-tenants[]` is non-empty, gated by a custom `@Conditional` matching that property's presence.

Both must be true. The two gates are deliberately independent: a host can pre-wire the `@Import` ahead of the Multi-Engine roll-out, and the rewrite flips on automatically when tenants are added to config.

The rewrite **silently no-ops** when `physical-tenants[]` is empty even if the configuration is imported. This is a deliberate departure from [ADR-0011](0011-physical-tenant-authentication-chain-layering.md)'s fail-fast-on-empty rule for the chain configuration:

| Configuration | Activation behaviour on empty `physical-tenants[]` | Rationale |
|---|---|---|
| `PhysicalTenantOidcApiSecurityConfiguration` (ADR-0011) | **Fail-fast** | This config *is* Multi-Engine. Importing it without tenants is a wiring mistake. |
| `DefaultPhysicalTenantRewriteConfiguration` (this ADR) | **Silent no-op** | This config is *companion* behaviour layered on Multi-Engine. Importing it without tenants is the legitimate "pre-wire now, flip on later" path. |

### Pre-Multi-Engine adopters are unaffected

A deployment with `physical-tenants[]` empty sees no behaviour change from this ADR:

- The rewrite filter does not register (or registers and no-ops).
- The per-tenant chain from [ADR-0011](0011-physical-tenant-authentication-chain-layering.md) does not register if its config isn't imported, or fails fast if it is.
- The existing top-level chains continue to serve every request exactly as they do today.

The rewrite model is strictly additive on top of the existing chains. Adopters who never set `physical-tenants[]` cannot tell this ADR shipped.

### Session-cookie upgrade compatibility (forward note)

Pre-Multi-Engine adopters carry browser sessions backed by the existing top-level cookie (`camunda-session`, `Path=/`). When such an adopter activates Multi-Engine with the rewrite, every existing request to `/v2/x` is rewritten to `/physical-tenants/default/v2/x` and is served by the default-tenant chain. To preserve those sessions across the upgrade, the **default tenant retains the legacy cookie identity** (`camunda-session`, `Path=/`) rather than adopting the per-tenant `camunda-session-{id}` / `Path=/physical-tenants/{id}/` shape that configured tenants follow.

This is a deliberate asymmetry: configured tenants get scoped cookies; the `default` tenant keeps the unscoped legacy cookie because it is the upgrade path. Cross-tenant cookie pollution does not materialise in practice — each tenant chain's session repository reads only its own cookie name, so the default's `camunda-session` is ignored by `acme`'s chain even if the browser sends it.

The session-cookie design itself lives in [#208](https://github.com/camunda/camunda-security-library/issues/208) — this ADR pins the upgrade-compat constraint that #208's implementation must respect.

## Consequences

**Positive**

- The browser-visible URL for single-tenant customers stays clean: `/tasklist/123` stays `/tasklist/123` in the address bar, even though the security chain processes `/physical-tenants/default/tasklist/123` internally.
- The library's invariant in Multi-Engine deployments is simple and uniform: every authenticated request lands on a per-tenant chain with a concrete tenant id. Downstream code — filters, controllers, the `PhysicalTenantContextProvider` SPI from [#209](https://github.com/camunda/camunda-security-library/issues/209), the adapter-routing pattern from [#210](https://github.com/camunda/camunda-security-library/issues/210) — never has to handle a "no tenant" case post-filter.
- Adopters who already configure `camunda.security.authentication.oidc.*` for their single-tenant deployment, and then add explicit physical tenants, get a working multi-tenant deployment in which their existing top-level config *is* the default tenant's config. No duplication, no migration step for the default.
- The reserved-id collision guard surfaces misconfiguration at startup with a message pointing the adopter at the right slot, rather than silently shadowing the implicit default.
- The two-gate activation model lets adopters pre-wire the `@Import` ahead of rolling out tenants, without that import doing anything until tenants are actually configured.

**Negative / accepted trade-offs**

- A component reaching for `request.getRequestURI()` post-filter sees the rewritten path. We mitigate via the `ORIGINAL_REQUEST_URI` attribute, but the contract is "use the attribute if you need the user-typed path". Components that don't know about this and log the rewritten URI as if it were the request URI produce slightly confusing logs.
- The library now ships two configurations with asymmetric activation semantics — one fails fast on empty tenants, one silently no-ops. The asymmetry is deliberate (the table above documents it) but readers must understand both rules.
- `default` becomes a reserved identifier across the library. A future adopter whose own tenant catalogue happens to include a tenant called `default` has to rename it. We expect this to be rare; the reserved-id message points the way.
- The `ORIGINAL_REQUEST_URI` attribute is now part of the library's public contract. Renaming it later would be a breaking change.

## Alternatives Considered

- **`default` as an explicit entry in `physical-tenants[]`.** Rejected — duplicates the top-level OIDC config slot and creates two ways of saying the same thing. Adopters would either omit it (and the rewrite would target nothing) or copy-paste it (and divergence becomes inevitable). The implicit-from-top-level model lets the existing slot do double duty.
- **Explicit `default-id` property** (`camunda.security.physical-tenants.default-id=acme`) naming which configured tenant is the default. Rejected — adds a config knob with no real adopter benefit. The BFF proposal's value-add (clean bookmarks for single-tenant customers) is realised by the rewrite mechanism, not by who "default" points to. Letting `default` mean "the top-level slot" keeps the YAML cleaner.
- **Implicit-first-entry** (`physical-tenants[0]` is the default). Rejected — YAML lists are commonly reformatted by editors and CI tools; a silent semantic change on reorder is a sharp edge.
- **30x redirect instead of internal forward.** Rejected — the BFF proposal made the case explicitly: bookmarks survive untouched, no "two URLs for the same page" indexing/SEO concerns, the customer-visible URL never grows a prefix until the customer opts in by typing one.
- **Always-on rewrite that registers regardless of `physical-tenants[]`.** Rejected — would force pre-Multi-Engine adopters who happen to import the config (during incremental rollout) into an effectively broken state: every request rewrites to `/physical-tenants/default/...` but no per-tenant chain exists to serve it.
- **Fail-fast on empty `physical-tenants[]` even for the rewrite config.** Rejected — the rewrite is companion behaviour, not the activation switch for Multi-Engine. Pre-wiring the import without tenants must be safe.
- **Hardcoded bypass list in the library** (e.g., `/v2/cluster/**`, `/v2/license`, `/actuator/**`). Rejected — these are Hub/OC URL conventions, not universal. Greenfield adopters shouldn't inherit the literals. The `SecurityPathPort.clusterScopedPaths()` SPI lets each host declare its own.
- **A property-list bypass (`camunda.security.physical-tenants.rewrite-bypass-paths=...`).** Rejected — splits "what kind of path is this?" knowledge across two places (the SPI and the property file). Hosts already wire `SecurityPathPort`; co-locating the cluster-scoped declaration there keeps the model consistent.
