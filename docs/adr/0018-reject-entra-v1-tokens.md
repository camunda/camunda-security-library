---
status: Accepted
---

# ADR-0018: Reject Microsoft Entra v1 tokens at the token-claims conversion layer

**Deciders**: Timothy Cline (timcline)

## Status

Accepted

## Context

Microsoft Entra ID issues tokens in two formats controlled by the application manifest's
`requestedAccessTokenVersion` setting:

- **v1.0** — default for legacy registrations; `iss` is `https://sts.windows.net/<tenant>/`.
- **v2.0** — opt-in; `iss` is `https://login.microsoftonline.com/<tenant>/v2.0`. Required
  for the full OIDC-compliant claim set.

CSL maps token claims to its identity model (`CamundaAuthentication`) via
`LazyTokenClaimsConverter`. Entra v1 tokens omit or differ in several claims the model
relies on (for example, the `oid` subject identifier and the group membership format). When
a v1 token is accepted without validation, CSL silently produces an incorrect or empty
`CamundaAuthentication`, and the failure surfaces as an authorization error or missing
identity data far from its root cause.

The camunda repo (PR 55876, 8.9 branch) established a guard for this case.
This ADR records the port of that decision into the CSL for 8.10.

What behaviour change should CSL apply when it receives a Microsoft Entra v1 token?

## Decision

`LazyTokenClaimsConverter.convert()` calls `validateEntraTokenVersion()` before constructing
the authentication object. The guard:

1. Checks whether the `iss` claim host is `login.microsoftonline.com` or `sts.windows.net`.
   Non-Microsoft issuers pass through unchanged.
2. If the issuer is Microsoft Entra, requires the `ver` claim to equal `"2.0"`.
3. If `ver` is absent or not `"2.0"`, logs a WARN with the issuer and the actual `ver` value,
   then throws `IllegalArgumentException`.

The `IllegalArgumentException` is caught by the two Spring-layer converters and wrapped in
`OAuth2AuthenticationException(INVALID_TOKEN)` so Spring Security handles it cleanly:

- `OidcTokenAuthenticationConverter` — already wrapped `IllegalArgumentException`; no change.
- `OidcUserAuthenticationConverter` — added the same try-catch as part of this port.

### Why fail fast rather than accept and map

Accepting a v1 token and mapping whatever claims happen to be present produces silent
misidentification (wrong user, missing groups, empty tenants). A hard failure with a WARN
message is operationally safer: it surfaces immediately in the logs and points the operator
at the specific token version misconfiguration rather than requiring correlation of downstream
authorization failures.

### Why domain layer, not Spring layer

`LazyTokenClaimsConverter` is the single point where raw token claims become a
`CamundaAuthentication`. Placing the guard here means it applies regardless of which
Spring-layer converter invokes it. The `IllegalArgumentException` is consistent with the
converter's existing contract (it already throws `IllegalArgumentException` when neither
`sub` nor `azp` is present).

## Consequences

**Positive**

- Microsoft Entra misconfiguration (v1 app registration) fails immediately with a clear WARN
  log message instead of silently producing incorrect authentication state.
- Non-Microsoft IdPs (Keycloak, Auth0, etc.) are completely unaffected.
- The guard is in the domain layer and exercises through all existing and future token-claims
  conversion paths.

**Negative / accepted trade-offs**

- Operators with an Entra app registration still on v1 will see authentication failures after
  upgrading to 8.10. This is intentional: v1 tokens have never worked correctly with CSL's
  identity model; the change makes the failure visible instead of hiding it.

## Alternatives Considered

- **Accept v1 tokens and map available claims.** Rejected — produces silent misidentification
  that is hard to diagnose; correctness cannot be guaranteed without the full v2 claim set.
- **Optional config flag to enable/disable the guard.** Rejected — there is no legitimate
  CSL use case for v1 Entra tokens; an opt-out would only serve to hide misconfiguration.
- **Validate in a post-conversion step.** Rejected — the converter is the natural single
  point of enforcement; a separate validator would require wiring to every converter call site.
