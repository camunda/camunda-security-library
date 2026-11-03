# ADR-0043: Revoke the refresh token when a web session expires

**DRI**: Timothy Cline

**Deciders**: Timothy Cline (timcline)

**Status**: Accepted (1.3.0)

**Purpose**: Defines when CSL revokes the refresh token of a session that ends without logout.

**Audience**: CSL maintainers, and teams that run Hub or the Orchestration Cluster with OIDC.

## Context

[ADR-0036](0036-revoke-refresh-token-on-oidc-logout.md) revokes the refresh token of a session at
logout. Many sessions end without a logout. The idle timeout of
[ADR-0020](0020-configurable-activity-driven-session-idle-timeout.md) expires them. The session
store then deletes them, and the refresh token stays valid at the provider until it expires. A
copy of that token can still get new access tokens.

The expiry has no browser request. A periodic task deletes most expired sessions, and a request
that finds its session expired deletes the rest.

## Decision

**D1. CSL revokes the refresh token when it deletes an expired web session.**
This applies to the periodic deletion and to a request that finds its session expired. A session
that CSL deletes because its login became invalid is not revoked. Its tokens are already rejected.

**D2. CSL reads the token from the stored session, and sends it only to its own provider.**
The expiry has no request, so CSL reads the token from the session data. Two scopes can use one
provider name for different providers. CSL sends the token only to a provider with the same client
and the same token endpoint as the session. If no provider matches, or the providers that match
have different revocation settings, CSL does not revoke. An opt-out of one scope always applies.

**D3. CSL revokes in the background, and never waits for the provider.**
The session is deleted at once, and the request goes to a queue of fixed size. If the queue is
full, for example while the provider is down, CSL drops the request and writes one warning.

**D4. Logout and expiry send the same revocation request.**
Both use the same client authentication, time limits and log redaction. A provider that accepts
one accepts the other.

## Alternatives considered

- **End the provider session on expiry.** This needs a browser redirect, and the expiry has no
  browser. [ADR-0031](0031-oidc-max-age-in-saas.md) rejected it for the same reason.
- **Revoke before the delete, and wait for the result.** A slow or unreachable provider would stop
  the periodic deletion and delay the request of the user.

## Consequences

- A session that times out no longer leaves a valid refresh token at the provider.
- If the provider is down for a long time, some tokens stay valid until they expire, as before.
- A host without the CSL webapp chains, and a session kept only in memory, revoke only at logout.

## Source

- [Revoke the refresh token when an expired web session is deleted (#790)](https://github.com/camunda/camunda-security-library/issues/790)
