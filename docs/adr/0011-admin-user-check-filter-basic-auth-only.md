---
status: Accepted
---

# ADR-0011: Wire `AdminUserCheckFilter` only into the BasicAuth webapp chain

**Deciders**: Sebastian Bathke

## Status

Accepted

## Context

[ADR-0010](0010-admin-user-setup-spis.md) introduced `AdminUserCheckFilter` together with `AdminUserPresencePort`, `AdminUserMissingHandlerPort`, and the `SecurityPathPort.adminFilterBypassPaths()` bypass set. The wiring section of that ADR added the filter to **both** webapp chains (`BasicAuthWebappSecurityConfiguration` and `OidcWebappSecurityConfiguration`) whenever a host registered an `AdminUserPresencePort`.

During the OC adoption of CSL ([camunda/camunda#52770](https://github.com/camunda/camunda/pull/52770)), the OIDC/SaaS smoke surfaced a trap: a freshly IdP-authenticated user navigating to `/operate` was 302'd to `/admin/setup`, because the host's `AdminUserPresencePort` reported "no admin" — there was no `init.users` static seed for SaaS, and the IdP-provisioned user's membership had not yet been projected into the live store.

Pre-CSL, OC ran the equivalent check **only** on the BasicAuth chain; the OIDC chain never invoked it because admin provisioning under OIDC is driven by IdP claims and mapping rules, not by an in-app setup wizard. OC's interim fix short-circuits the host port to return `true` whenever the auth method is OIDC. That workaround works but lives in every adopter that wires the SPI, which is the wrong layer.

The core question this ADR answers is:

> Where in the wiring should the library decide that `AdminUserCheckFilter` does not run on the OIDC webapp chain — at bean-creation time (gate the configuration), at port-call time (let the SPI decline), or at chain-assembly time (omit `addFilterAfter(...)` from the OIDC chain)?

## Decision

`OidcWebappSecurityConfiguration` does not wire `AdminUserCheckFilter` into the OIDC webapp chain. The `ObjectProvider<AdminUserCheckFilter>` parameter and the `addFilterAfter(adminFilter, OAuth2RefreshTokenFilter.class)` call are removed from that chain configuration; the OIDC chain's only optional filter slot below the refresh-token filter is `WebAppAuthorizationCheckFilter`, anchored directly on `OAuth2RefreshTokenFilter`.

`AdminUserCheckFilterConfiguration` itself is unchanged in terms of bean-creation gating: the filter bean is still created whenever an `AdminUserPresencePort`, an `AdminUserMissingHandlerPort`, and a `SecurityPathPort` are all present in the context. Only `BasicAuthWebappSecurityConfiguration` wires it into a chain. A host that genuinely needs an admin-presence check on a custom OIDC chain still has direct access to the bean and can `addFilterAfter(...)` it where appropriate in its own chain configuration.

This decision **narrows the wiring portion of [ADR-0010](0010-admin-user-setup-spis.md)** (which stated the filter is added to both webapp chains). The SPI design from ADR-0010 — the two ports, the bypass-paths reuse of `SecurityPathPort`, the explicit-import activation model — is unchanged and still stands.

### Why chain-assembly time rather than bean-creation or port-call time

Three locations could enforce "no admin-setup redirect under OIDC":

1. **Chain-assembly time** (this ADR): `OidcWebappSecurityConfiguration` omits the `addFilterAfter(adminFilter, ...)`. The filter bean still exists; only its chain wiring is conditional.
2. **Bean-creation time**: gate `AdminUserCheckFilterConfiguration` on `camunda.security.authentication.method=basic` so the filter (and its supporting beans) are not created when OIDC is configured. The chain's `ObjectProvider` lookup then yields nothing.
3. **Port-call time**: add `default boolean appliesTo(authenticationMethod)` to `AdminUserPresencePort` (default `true`) and have the filter consult it before redirecting.

Chain-assembly is chosen because:

- **It is the smallest delta and mirrors the pre-CSL contract.** OC's pre-CSL admin filter was only wired into the BasicAuth chain. Other adopters that pre-dated CSL had the same shape. Reproducing this at the wiring layer is a literal lift of the prior structural decision; no new property surface, no new SPI method, no new conditional.
- **Bean availability and wiring are different concerns.** A host that owns a custom OIDC chain (or a multi-tenant setup where some tenants do enforce admin-setup over OIDC) can still grab the filter bean and wire it themselves. Bean-creation-time gating closes that door; chain-assembly-time gating leaves it open.
- **The decision lives next to the wiring it governs.** A future reader inspecting `OidcWebappSecurityConfiguration` sees the missing wiring and the explanatory comment in the same place. A bean-creation gate would put the rationale far from the chain that needs to behave differently, and a port-call gate would push it into host SPI code that has nothing to do with wiring.

### Why not port-level `appliesTo(authenticationMethod)`

This was [suggestion 2 in GH-189](https://github.com/camunda/camunda-security-library/issues/189). Rejected because:

- The host port shouldn't have to know about library-level wiring concerns. It models "is there an admin user?", not "should the filter be active for this request?".
- Every adopter would have to opt out per-method or accept the trap. Library-side wiring is the correct enforcement point — the chain configurations already know which auth method they are.
- Adds a method to a public SPI for what is structurally a one-line decision in the chain configuration.

### Why not bean-creation-time gating

This was [suggestion 3 in GH-189](https://github.com/camunda/camunda-security-library/issues/189) — gate `AdminUserCheckFilterConfiguration` on `camunda.security.authentication.method=basic`. Initially drafted, rejected on reconsideration because:

- It conflates "filter is available" with "filter is wired into the default chain". A host that builds a custom OIDC chain (extending or replacing the library's) and wants the admin check would have to register the filter bean itself, even though the library already knows how to build it.
- The property gate at the configuration level is symmetric with `BasicAuthWebappSecurityConfiguration` only at first glance — that configuration is gated because the chain itself is BasicAuth-specific, whereas `AdminUserCheckFilterConfiguration` defines a generic filter that happens to be wired only into one chain by default. The two activation rules answer different questions and should not be coupled.

## Consequences

**Positive**

- The GH-189 trap is closed at the library layer. Adopters that wire `AdminUserPresencePort` get correct behaviour out of the box for both auth methods, without per-host workarounds.
- OC can remove its `AdminUserPresenceAdapter` short-circuit ([camunda/camunda#52770](https://github.com/camunda/camunda/pull/52770)) once this lands.
- The wiring rule lives next to the chain it governs (in `OidcWebappSecurityConfiguration`), so a reader of that chain sees both the omission and the rationale.
- The filter bean remains available in the application context, so hosts can compose it into custom chains if their authorization model genuinely benefits from an admin-presence check under OIDC.

**Negative / accepted trade-offs**

- A host that wants the library-default admin-setup redirect under OIDC (purely on the BasicAuth-shaped behaviour) does not get it via `@Import` alone — they must explicitly add `addFilterAfter(adminUserCheckFilter, ...)` in their own chain configuration. We accept this because we have no live use case for it and because the OIDC-trap scenario the library-default would re-open is worse than its absence.
- The two webapp chain configurations are now slightly asymmetric in which filters they wire. The Javadoc on `AdminUserCheckFilterConfiguration` and the comment block in `OidcWebappSecurityConfiguration` call this out so the asymmetry is documented in code, not implicit.

## Alternatives Considered

- **Port-level `appliesTo(authenticationMethod)` (GH-189 suggestion 2).** Rejected — see "Why not" above. Pushes a wiring concern into the host SPI.
- **`@ConditionalOnProperty(method=basic)` on `AdminUserCheckFilterConfiguration` (GH-189 suggestion 3).** Rejected — see "Why not" above. Conflates bean availability with chain wiring and closes the door on custom-chain reuse.
- **Leave the trap in CSL and document it.** Rejected. Every adopter that wires the SPI would have to re-derive the same workaround OC already paid for. The library-default for a known footgun belongs in the library.
