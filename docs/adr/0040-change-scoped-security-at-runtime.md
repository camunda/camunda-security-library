---
status: Proposed
---

# ADR-0040: Change a scope's security at runtime, one scope and one generation at a time

**Deciders**: Matthew Kavanagh

## Status

Proposed — built as a proof of concept on `csl-poc-runtime-security`; to be reviewed with the
Physical Tenants at Scale DRI before it is accepted.

## Context

[ADR-0013](0013-camunda-security-scope-provider-spi.md) builds a scope's API and webapp chains
once, while the application context starts. Two needs of the Orchestration Cluster's physical
tenants break that assumption:

- **Tenant lifecycle.** A tenant is added, changed or removed while the cluster runs. Its chains
  must appear, change or go away without a restart, and a change may switch the authentication
  method, the identity providers, their clients, audiences or claim mapping.
- **Dynamic secrets.** A client secret or `private_key_jwt` keystore is rotated in a secret store
  and must take effect without a restart and without a configuration change.

Several framework facts constrain the answer:

- `FilterChainProxy` fixes its list of chains once the context is up; no chain bean can be added
  later.
- Spring Security's shared `ObjectPostProcessor` keeps every `DisposableBean` it post-processes —
  every `GenericFilterBean` filter of every chain — until the context closes, through a private
  list with no API to remove from it.
- A `ClientRegistration` is immutable and carries the client secret; an `OAuth2AuthorizedClient`
  stored in a session keeps the registration of its login, and Spring refreshes and revokes its
  tokens with exactly that registration.
- Several application-wide caches are keyed by configuration rather than by scope: discovery
  documents by issuer (`ScopedClientRegistrationFactory`), session access-token decoders by
  provider settings (`OidcUserAuthenticationConverter`, ADR-0033).
- [ADR-0025](0025-deferred-oidc-resolution.md) defers every network step to first use, so building
  a scope never fails because a provider is unreachable; the degraded-scope proposal (drafted as
  "ADR-0023: degrade a scope whose IdP is unreachable", not merged) handled that case at startup
  only, until a restart.

A spike (`spike/hot-reload-scoped-chains`) proved chains can be swapped, but reloaded every scope
at once, swapped a scope's two chains in two steps, kept sessions across a change of identity
provider, covered BASIC scopes only, and released retired filters by reflecting on Spring
Security's private fields.

What runtime contract lets a host add, change and remove one scope — OIDC included — atomically,
without leaking, and with a defined effect on the scope's sessions?

## Decision

### The port

`ScopedSecurityReloadPort` (`core/port/in`), implemented by `ScopedSecurityReloadService`
(`spring-boot-starter`, package `io.camunda.security.spring.scope`) and registered as a bean
whenever a `CamundaSecurityScopeProvider` bean exists:

| Method | Effect |
|---|---|
| `apply(descriptor)` / `apply(descriptor, UnreachableIdentityProviderPolicy)` | Adds the scope, or replaces it |
| `remove(basePath)` | Stops serving it; its paths answer 404 |
| `rotateCredentials(descriptor)` | Replaces credentials only, keeps sessions; rejects any other change |
| `refreshCredentials(basePath)` | Reads key material again (keystore replaced in place), keeps sessions |
| `reloadAll()` | Reads every provider and applies the difference |

Each call returns a `ScopeReloadResult` (`api/model/scope`): an outcome (`ADDED`, `REPLACED`,
`CREDENTIALS_ROTATED`, `CREDENTIALS_REFRESHED`, `UNCHANGED`, `REMOVED`, `ABSENT`,
`KEPT_PREVIOUS`, `FAILED`), the generation now served, the duration and the failure, if any. The
scope providers remain the source of truth: `reloadAll()` and a restart read them.

### Generations and slots

A scope is a `ScopeSlot` per normalized base path holding one volatile `ScopeGeneration`: the
scope's API chain, webapp chain, OIDC client stacks and the objects built for them. A change
builds the next generation off to the side, under the slot's lock, and publishes it with one
write. Changes to different scopes run in parallel. A removed scope publishes a tombstone whose
chains claim the whole base path and answer 404.

A startup scope keeps its two chain beans; each is a `ScopeChainView` of the slot. Every scope
added later is served by one registered `ScopeDispatchingSecurityFilterChain`, which finds the
slot by looking each leading path prefix up in a map, so a request costs the same with one scope
as with thousands. `FilterChainProxy` asks a chain `matches(request)` and then `getFilters()`
without the request; both chain types pin the generation that matched for the `getFilters()` call
that follows, so a request runs the filters of exactly the generation that claimed it.

### Ownership instead of reflection

`ScopeObjectPostProcessorInstaller`, a bean post-processor, replaces Spring Security's shared
`objectPostProcessor` bean with a `ScopeCapturingObjectPostProcessor` that delegates to it. While
a generation is built, the wrapper initializes and autowires each object exactly as the shared
processor does, and hands it to the generation's `ScopeObjects` instead of keeping it. A retired
generation destroys its objects and leaves nothing behind in framework state.

### The OIDC client stack of a generation

`ScopedOidcClients` holds what a scope's OIDC chains share: the `LazyClientRegistrationRepository`,
a `CurrentRegistrationAuthorizedClientRepository` that rebinds a session's authorized client to
the registration the scope serves now, the `OAuth2AuthorizedClientManager`, the login token
endpoint and `ScopedAssertionJwks`, the generation's cache of `private_key_jwt` signing keys.
Login, refresh and revocation token requests of a scope therefore authenticate with the scope's
current credentials. The scoped login chain uses this token endpoint instead of the host's
`OidcTokenEndpointCustomizer`, which keeps applying to the primary chain.

When a generation retires, `ScopeRetirement` evicts the discovery documents of issuers no served
scope configures any more, and — when the scope's authentication changed or it was removed — the
session access-token decoders of its registrations.

### Sessions

`ScopeFingerprints` digests the scope's `AuthenticationConfiguration` twice: over every property
except credentials (client secret, keystore path, passwords and alias), and over everything. A
property added to the configuration model later counts as authentication-relevant until it is
listed as a credential.

The scope's session repository is wrapped in a `ScopeAuthenticationBoundSessionRepository`. A new
session records the authentication digest of the generation serving the request that creates it
(the generation's first filter, `ScopeGenerationMarkerFilter`, makes it known to the thread); a
session read under a different digest is deleted and reported absent, and with it go its security
context and its authorized clients and refresh tokens. A credential-only change keeps the digest
and therefore the sessions. Other scopes' sessions are never read with this scope's digest.

### An identity provider that cannot be reached

Before a new generation replaces a live one, `IdentityProviderCheck` resolves every OIDC provider
it configures. If one cannot be resolved, the policy decides: `KEEP_PREVIOUS` (the default) keeps
the live generation and returns `KEPT_PREVIOUS`; `APPLY` publishes anyway, and requests that need
the provider fail with a server error until it answers, then recover with no further change
(ADR-0025). A scope that has no live generation always applies. Other scopes are never affected.

### Why these particular boundaries

- **One generation per scope, not per chain.** A scope's API and webapp chains, session filter and
  client stack must change together, or a client can observe a new API chain beside an old webapp
  chain. One volatile write is the cheapest way to make that impossible.
- **Per scope, not per world.** Rebuilding every scope for one tenant's change costs time linear
  in the number of tenants and puts every tenant at risk of one tenant's failure.
- **Slots are never dropped.** A tombstone keeps a removed tenant failing closed with 404 even
  where the host disabled the catch-all chain; the index is bounded by distinct base paths.
- **Sessions bound to the configuration, checked on read.** A host-owned durable store need not
  support deleting by scope, and nodes of a cluster derive the same digest from the same
  configuration.
- **Keep the previous chain by default.** A tenant whose new provider is unreachable keeps
  working; a host that is withdrawing trust from a provider asks for `APPLY` explicitly.

## Consequences

**Positive**

- A tenant is added, changed or removed without a restart; changing one costs a few milliseconds
  and touches no other tenant.
- A request is served by one generation of a scope; a removed scope answers 404.
- No retired generation stays reachable, without CSL reading framework state.
- A rotated client secret or signing key is used by the next token request, and existing sessions
  continue.

**Negative / accepted trade-offs**

- A change applies to the node it is called on. A host with several nodes must call it on each;
  until all have, nodes serve different generations, and a session created under the new
  configuration is ended by a node still serving the old one.
- Scoped login chains no longer apply the host's `OidcTokenEndpointCustomizer`; what it adds to the
  token request (for example an instrumented HTTP client) needs a scope-aware hook.
- Host state built from the scope configuration outside CSL — per-tenant claim converters, UserInfo
  claim providers — is not rebuilt by this port.
- Sessions of a removed scope stay in a host-owned store until its own expiry, unusable. A scope
  removed and added again with an identical configuration accepts them again.
- The wrapper relies on Spring Security naming its shared processor bean `objectPostProcessor`. If
  that changes, the scope's objects stay with the shared processor until the context closes; a
  warning names it and the leak tests fail.
- Spring Security's privilege evaluator keeps the authorization rules of each startup scope's first
  generation.

## Alternatives Considered

- **Remove retired filters from the shared post-processor by reflection.** Rejected — it ties CSL to
  private fields of Spring Security, and fails silently with an upgrade.
- **Reload every scope on each change.** Rejected — cost and failure risk grow with the number of
  tenants.
- **Delete a changed scope's sessions from its store.** Rejected — `SessionStorePort` has no
  scope-wide delete and the store may be the host's.
- **Keep sessions across every change.** Rejected — a session authenticated by a provider the
  scope no longer trusts would stay valid.
- **Serve startup scopes through the dispatching chain too.** Deferred — it changes the chain beans
  hosts and tests observe; the views give the same guarantees.
