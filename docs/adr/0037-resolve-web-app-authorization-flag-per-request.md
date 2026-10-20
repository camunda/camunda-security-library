---
status: Accepted
---

# ADR-0037: Resolve the web app authorization flag per request

**Deciders**: Ana Vinogradova

## Status

Accepted. Builds on the global-disable gate of the webapp filter in [ADR-0014](0014-unified-authz-framework-in-core.md) (section 10).

## Context

The webapp filter skips the COMPONENT ACCESS check when `camunda.security.authorizations.enabled` is `false`. One filter bean serves every chain, so all scopes share that one value. A host whose scopes have their own flag, for example one per physical tenant, gets the wrong result: users open the web app without a grant when the scope is on and the global flag is off, and users without a grant are forbidden when the scope is off and the global flag is on.

A scope descriptor carries only a base path and the authentication settings ([ADR-0013](0013-camunda-security-scope-provider-spi.md)), so the filter has no per-scope flag to read.

How can a host give the filter a flag that depends on the request, without the filter learning what a scope is?

## Decision

- A new SPI, `WebAppAuthorizationEnabledPort`, in `io.camunda.security.spring.spi`: `boolean isAuthorizationEnabled(HttpServletRequest)`.
- The filter asks it for each request, after the `/forbidden` and static-resource checks. If it returns `false`, the request passes without a check.
- Without a host bean, the filter uses the global flag, read once when it is created. The existing `boolean` constructor stays.
- The host must also supply a scope-aware `AuthorizationCheckPort`: the default one approves every request while the global flag is off. `ScopedAuthorizationCheckPortFactory` ([ADR-0019](0019-authorization-check-latency-metric.md)) takes one flag for all its scopes, so call it once per scope.

The SPI lives in the starter because its signature uses `HttpServletRequest`, which `core` does not have.

## Consequences

**Positive**

- A scope with its own flag is enforced in both directions, and a host without the bean sees no change.

**Negative / accepted trade-offs**

- Two places read the flag, the SPI and the check port, and CSL cannot check that they agree. A host that registers only the SPI, with the global flag off, gets a check port that approves every request.
- The SPI runs for most requests, so it must be cheap and must not throw.

## Alternatives Considered

- **Put the flag on `ScopedSecurityDescriptor` and build one filter per chain.** Each scope's descriptor would carry its own `authorizations.enabled`, and the chain builder would create a filter with that value for each chain. Rejected for two reasons:
  - `ScopedSecurityDescriptor` is a public record that hosts build themselves. A new component changes its constructor for every host.
  - The primary chain has no descriptor, so it would still need a second way to get its flag.

  The per-request SPI covers the primary chain and every scoped chain in one way, and changes no existing type.
