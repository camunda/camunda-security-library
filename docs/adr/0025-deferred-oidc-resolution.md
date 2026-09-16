---
status: Accepted
---

# ADR-0025: Deferred OIDC resolution at first use

**Deciders**: Sebastian Bathke

## Status

Accepted. Supersedes the resolution lifecycle of
[ADR-0006](0006-multi-idp-oidc-configuration.md) and
[ADR-0007](0007-oidc-user-info-enabled-toggle.md), see [Supersedes](#supersedes). Every other
decision of both records stays in force.

## Context

Both records resolved OIDC discovery while the application context started. An identity provider
that did not answer therefore stopped the start, for 30 seconds per provider, because Spring's
`ClientRegistrations` gives no hook to shorten that timeout. One unreachable provider stopped a
cluster with several providers, and it stopped requests that need no provider. Recovery needed a
restart.

An identity provider that starts beside the cluster, or that is behind a proxy that is not ready
yet, is an ordinary condition. What lifecycle keeps such a deployment serving every request it can
serve?

## Decision

Each resolution step that needs the network runs at its first use: `LazyClientRegistrationRepository`
per registration lookup, `DeferredJwtDecoder` per decoder, `DeferredOidcClaimsProvider` per UserInfo
mapping. `DeferredOidcResolution` runs each step, throws the original failure again, and rate-limits
the warning to one per minute for each provider and scope.

A step keeps its result after a successful attempt only, and holds no lock across the attempt. A
lock would hold each other caller for the complete timeout of the attempt that runs, and the request
threads would run out. Two callers therefore each make their own attempt, and the first result wins.

A configuration error that needs no network still stops the start: the repository validates each
provider block, and the cluster decoder checks the issuer requirement of a deployment with several
providers.

## Supersedes

| Superseded statement | Record | Now |
|---|---|---|
| The provider map is wrapped in an `InMemoryClientRegistrationRepository` | ADR-0006 | `LazyClientRegistrationRepository`, which is iterable as the decoder switch requires |
| A registration that resolves no JWK Set URI fails at startup | ADR-0006 | The same failure reaches the first token decode |
| The claims provider builds the `issuer → userInfoUri` map at construction time | ADR-0007 | It builds the map at the first claims lookup |
| An augmentation config that can never augment fails fast at construction time | ADR-0007 | It fails each request that needs augmented claims |

## Consequences

- A cluster starts while a provider is unreachable, serves every request that needs no such
  provider, and recovers without a restart.
- An unreachable provider costs the discovery timeout per request, instead of once per start. The
  rate limit keeps the log readable, and it holds state for a bounded number of subjects.
- A failure that only the network detects reaches the operator as a warning, and not as a failed
  start. The warning names the provider, its issuer and the scope for that reason.

## Alternatives considered

- **Shorten the discovery timeout.** Rejected. The only hook is
  `ClientRegistrations.fromOidcConfiguration(Map)`, which moves discovery and its error handling
  into the library, and the start still fails.
- **Retry in the background.** Rejected. The application would serve requests with a chain that is
  not ready, and each retry needs its own failure model.
- **Resolve once under a single-flight lock.** Rejected. A burst of requests for an unreachable
  provider exhausts the request threads. A duplicate attempt costs one discovery request.
