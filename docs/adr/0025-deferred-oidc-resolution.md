---
status: Accepted
---

# ADR-0025: Deferred OIDC resolution at first use

**Deciders**: Sebastian Bathke

## Status

Accepted. Supersedes the resolution lifecycle of
[ADR-0006](0006-multi-idp-oidc-configuration.md) and
[ADR-0007](0007-oidc-user-info-enabled-toggle.md); see
[What this record supersedes](#what-this-record-supersedes). Every other decision of both records
stays in force: the additive configuration shape, the registration-count switch to the issuer-aware
decoder, the composite JWK source, and both UserInfo mechanisms.

## Context

ADR-0006 resolved each `ClientRegistration` while the application context started, and ADR-0007
built the `issuer → userInfoUri` map while it built the claims provider. Both steps make a network
request for a provider that configures `issuer-uri`, because OIDC discovery reads the metadata
document of the issuer.

An identity provider that does not answer therefore stopped the start of the application. Spring's
`ClientRegistrations` holds a `RestTemplate` with a 30-second connect timeout and a 30-second read
timeout, and it offers no hook to shorten either, so one unreachable provider held the start for 30
seconds and then failed it. A deployment in that state needed a restart after the provider answered
again, and a Kubernetes rollout kept restarting a pod that could not pass its readiness probe. One
unreachable provider also stopped a cluster that had several providers, and it stopped requests that
needed no provider at all.

The deployments that hit this are ordinary: an identity provider that starts beside the cluster, an
identity provider behind a proxy that is not ready yet, and a network policy that opens late. What
resolution lifecycle keeps such a deployment serving every request it can serve?

## Decision

Each OIDC resolution step that needs the network runs at its first use, and not while the
application starts.

- `LazyClientRegistrationRepository` resolves one registration per lookup, and keeps a registration
  after a successful lookup only. A lookup after a failed one therefore makes a new attempt.
- `DeferredJwtDecoder` builds the access-token decoder at the first token decode, at the cluster
  level and per scope.
- `DeferredOidcClaimsProvider` builds the `issuer → userInfoUri` map at the first claims lookup.
- `DeferredOidcResolution` runs each such step, throws the original exception again, and writes one
  warning per minute for each subject. A subject names the step and the providers it covers, for
  example `the OIDC access-token decoder for provider(s) 'keycloak' (issuer https://idp/realms/c8)`.

No step holds a lock across the network request. Two callers that resolve the same registration,
decoder or mapping at the same time each make their own attempt, and the first result wins. A lock
would hold one caller for the complete 30-second timeout of the other caller, which is the failure
the record removes. Spring's `SupplierJwtDecoder` holds the initialization lock of
`SingletonSupplier` across its supplier, which is why `DeferredJwtDecoder` replaces it.

A configuration error that needs no network still stops the start. The constructor of the repository
validates each provider block, and the cluster decoder checks the issuer requirement that a
deployment with several providers must meet, against the configuration the library built its
registrations from.

## What this record supersedes

| Superseded statement | Record | Now |
|---|---|---|
| The merged provider map is wrapped in an `InMemoryClientRegistrationRepository` | ADR-0006, decision | `LazyClientRegistrationRepository`, which resolves a registration at its first lookup and is iterable as the decoder switch requires |
| A registration that resolves no JWK Set URI fails at startup | ADR-0006, decision and consequences | The same failure reaches the first token decode |
| The claims provider builds the `issuer → userInfoUri` map at construction time | ADR-0007, decision | It builds the map at the first claims lookup |
| An augmentation config that can never augment fails fast at provider-construction time | ADR-0007, decision, rationale and alternatives | It fails each request that needs augmented claims, because a failed build is not cached |

Both records keep their startup statements about configuration that needs no network: a blank
`registrationId`, an empty provider map, and a missing `issuer-uri` on a deployment with several
providers still fail the start.

## Consequences

- A cluster starts while an identity provider is unreachable, and it serves every request that
  needs no such provider. A request that needs one fails with a server error, and the deployment
  recovers without a restart as soon as the provider answers.
- An unreachable provider costs the discovery timeout on each request that needs it, instead of
  once per start. The rate limit keeps the log readable, and it holds state for a bounded number of
  subjects.
- A misconfiguration that only the network can detect reaches the operator at the first request
  instead of at the start, so the operator reads a log entry rather than a failed start. The subject
  of the warning names the provider and its issuer for that reason.
- A host that supplies its own `ClientRegistrationRepository` keeps its own resolution behaviour.
  The library names the host repository in a failure subject, because the configuration of the
  library does not describe the registrations of that repository.

## Alternatives considered

- **Keep the eager resolution and shorten the discovery timeout.** Rejected. `ClientRegistrations`
  offers no hook for the timeout. The only way to shorten it is
  `ClientRegistrations.fromOidcConfiguration(Map)`, which moves the discovery request, its parsing
  and its error handling into the library. A shorter timeout also still fails the start.
- **Keep the eager resolution and retry in the background.** Rejected. The application would serve
  requests with a chain that is not ready, and each retry would need its own failure model. The
  first-use attempt gives the same recovery with no scheduler and no extra state.
- **Resolve eagerly, and fall back to a chain that rejects every request.** Rejected. A cluster with
  several providers would lose the providers that answer, and the operator would see a healthy
  application that rejects valid credentials.
- **Resolve once under a single-flight lock.** Rejected. The lock holds each other caller for the
  complete timeout of the attempt that runs, so a burst of requests for an unreachable provider
  exhausts the request threads. A duplicate attempt on a reachable provider costs one discovery
  request, which is the cheaper trade.
