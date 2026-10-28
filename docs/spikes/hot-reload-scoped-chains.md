# Spike: add, reconfigure and remove scopes at runtime

Branch: `spike/hot-reload-scoped-chains`. Not production-ready; no ADR yet.

## What it does

`ScopedSecurityChainReloader.reload()` re-reads every `CamundaSecurityScopeProvider` and applies
the result without a restart:

| Scope state | Behaviour |
|---|---|
| Present at startup, still contributed | Chains rebuilt and swapped into the existing `OrderedSecurityFilterChainWrapper`s |
| Present at startup, no longer contributed | Wrappers swapped to a deny chain answering 404 |
| Not present at startup, now contributed | Served by `DynamicScopedSecurityFilterChain` (one per API/webapp order) |
| Added at runtime, no longer contributed | Dropped from the dynamic chain; falls through to the host's catch-all |

`FilterChainProxy` fixes its chain list once the context is up, which is why runtime-added scopes
go through a single always-registered dispatching chain instead of getting their own beans.

## Leak handling

- Spring Security's shared `ObjectPostProcessor` retains every `DisposableBean` (every
  `GenericFilterBean` filter) it post-processes until the context closes. `RetiredFilterReleaser`
  removes the filters of replaced or dropped chains from its private `disposableBeans` and
  `smartSingletons` lists **by reflection**.
- The session filter and `ScopedWebSessionRepositoryFactory` repository of a removed scope are
  evicted (`evict(basePath)`), so the expiry sweep stops visiting them.
- A failed `reload()` leaves live chains untouched and releases what it built.
- `ScopedSecurityChainReloadTest` proves it: removed scopes' chains and filters are garbage
  collected, and the retained-filter list does not grow across reloads (it fails without the
  release step).

## Known limits

1. **Reflection into Spring Security.** `RetiredFilterReleaser` depends on the private field names
   `disposableBeans` / `smartSingletons` (verified on Spring Security 7.1.1). A rename skips the
   release with a WARN; the leak test then fails.
2. **Not atomic.** Each wrapper swap and each published dynamic map is a separate step. A request
   can briefly see a new API chain with the old webapp chain, or scopes updated one after another.
3. **Removed startup scopes stay registered.** Their wrappers cannot be unregistered; they hold a
   small deny chain and answer 404, unlike removed runtime-added scopes (catch-all).
4. **Partial build failure.** Filters post-processed before a build fails midway are not reachable
   from any chain, so they stay in Spring Security's list.
5. **Host session stores.** Expired sessions of a removed scope stay in the host's store; CSL
   stops sweeping it.
6. **Sessions survive reconfiguration.** The per-scope session filter and store are kept when a
   scope stays, so a session remains valid after the scope's authentication method or IdP changed.
   Needs a decision.
7. **Observability.** A runtime-added scope runs inside one dispatcher filter, so Spring
   Security's per-filter observations are coarser than for startup scopes.
8. **No trigger.** Nothing calls `reload()`; the host must (event, endpoint or polling).
9. **Test coverage.** Basic authentication only. OIDC scopes (client registrations, JWT decoders,
   `OAuth2AuthorizedClientManager`) are not covered, so OIDC-specific leaks are unverified. No
   concurrent-request test during a swap.
10. **Process.** A new public reload API plus the reflection workaround need an ADR before this
    leaves spike status.
