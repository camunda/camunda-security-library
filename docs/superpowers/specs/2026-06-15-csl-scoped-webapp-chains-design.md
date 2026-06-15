# Scoped Webapp Security Chains & Per-Scope Web Sessions — Solution Design

**Issue:** [camunda/camunda#54897](https://github.com/camunda/camunda/issues/54897) (Physical Tenants Identity — Slice 3) · epic [camunda/product-hub#3600](https://github.com/camunda/product-hub/issues/3600)
**Date:** 2026-06-15
**Status:** For alignment — CSL DRI + OC/identity squad
**Builds on:** [ADR-0025](../../adr/0025-camunda-security-scope-provider-spi.md) (the `CamundaSecurityScopeProvider` SPI + scoped **API** chain), [ADR-0023](../../adr/0023-oidc-bearer-tokens-on-api-chain-only.md) (bearer on the API chain only; session honoured on the API chain), [ADR-0017](../../adr/0017-session-store-port-and-web-session-ownership.md) (`SessionStorePort` + CSL session lifecycle). This is the webapp follow-up flagged "out of scope" in the API-slice design.

---

## 1. Problem

Slice 1 gave every Physical Tenant (PT) its own **API** `SecurityFilterChain`, built by CSL from a `ScopedSecurityDescriptor` (a `basePath` + a merged `AuthenticationConfiguration`) and isolated structurally by a per-scope issuer-aware decoder. Slice 3 is the **webapp** half: each PT needs an interactive `oauth2Login` (or, in BASIC mode, form-login) chain behind its prefix `/physical-tenants/<id>`, with login, logout, the multi-IdP picker — and, the genuinely heavier part, **session + cookie isolation** so that:

1. a browser session minted for tenant A is never presented to, or usable on, tenant B;
2. the per-PT session is **also honoured on the PT's API chain**, so the SPA's XHR calls to `<basePath>/v2/**` authenticate off the session — exactly as they do implicitly today on the unprefixed chains (ADR-0023);
3. the SPA itself, served under the prefix, bootstraps and loads assets correctly.

**Hard constraint (unchanged from Slice 1):** CSL stays ignorant of physical tenants. The OC↔CSL contract — the `ScopedSecurityDescriptor` — **does not change**. CSL gains a scoped *webapp* chain primitive; everything webapp-specific (login/picker/redirect/logout URLs, cookie name + `Path`) is **derived from `basePath`**.

## 2. Approach

**Symmetry with the API slice.** ADR-0025 already factored CSL's chain assembly into reusable, scope-agnostic builders and a registrar that turns each descriptor into a chain. Slice 3 adds the webapp sibling:

- A **`ScopedWebappSecurityChainBuilder`** that mirrors `ScopedApiSecurityChainBuilder` — it prefixes `SecurityPathPort.webappPaths()` with `basePath` and assembles the `oauth2Login` / form-login chain. CSL's own `OidcWebappSecurityConfiguration` / `BasicAuthWebappSecurityConfiguration` re-base on it, so the chain shape stays a single source of truth.
- The existing **registrar** (`ScopedApiChainRegistrar`, ADR-0025) is extended to register **both** an API and a webapp chain per descriptor, method-driven (the cluster is single-mode).
- **Per-scope session components** (a `SessionRepositoryFilter` + a `DefaultCookieSerializer` with cookie `Path = basePath`, plus a session-reading `SecurityContextRepository`) are built **once per descriptor** and shared by *both* that descriptor's webapp and API chains. This is what carries the session from the login chain to the API chain.

Isolation is **structural**, the webapp analogue of the API slice's per-scope decoder:

- **In the browser** — the session and CSRF cookies are scoped to `Path = basePath`, so the browser only ever sends tenant A's cookies to tenant A's prefix. They cannot collide with the unprefixed cluster chain at `Path = /`.
- **At rest** — the host's `SessionStorePort` adapter routes each PT's sessions to that PT's **isolated secondary-storage schema** (see §6, Decision 5).

The webapp-specific concerns CSL cannot own (serving the SPA under a prefix, partitioning the session store) stay in OC and require **no contract change** — they hang off the same per-PT context OC already resolves.

## 3. Responsibility split

**CSL owns (generic, scope-agnostic — never learns "physical tenant"):**

- `ScopedWebappSecurityChainBuilder`: from a descriptor, build the webapp chain on `pathPort.webappPaths()` prefixed with `basePath` —
  - OIDC: `oauth2Login` with the scope's `ClientRegistration`s (the PT's assigned providers only); the multi-IdP picker at `<basePath>/login` (the `DefaultLoginPageGeneratingFilter` fix from #269); the OAuth2 redirect URI at `<basePath>/sso-callback`; logout at `<basePath>/logout`; the delegating entry point (bearer→401, browser→IdP/login) per ADR-0023.
  - BASIC: form-login at `<basePath>/login` (204 + CSRF header on success, mirroring CSL's primary `BasicAuthWebappSecurityConfiguration` — not `httpBasic`, which is the API chain's mechanism) backed by the existing `UserDetailsPort` (ADR-0021), whose adapter resolves the PT from request context.
- A **prefix-aware `OAuth2AuthorizationRequestResolver`** so `<basePath>/oauth2/authorization/<id>` and the `<basePath>/sso-callback` redirect resolve correctly (Spring's default matcher mishandles a multi-segment prefix — the PoC hit this; relates to the resolver lifted in [the 2026-05-20 design](2026-05-20-csl-oidc-authorization-request-resolver-design.md)).
- **Per-scope session + cookie isolation**, derived from `basePath`: a per-scope `SessionRepositoryFilter` + `DefaultCookieSerializer` (cookie `Path = basePath`, name a sanitized derivation of `basePath` — see §4) + CSRF cookie scoped to `basePath`. Built **once per descriptor**, injected into both the webapp and API chain of that scope.
- Extend the **scoped API chain** to honour the per-scope session (install the shared session components; keep `SessionCreationPolicy.NEVER` so it reads-but-never-creates). This extends ADR-0023's "session honoured on the API chain" property to per-scope sessions; bearer stays the API chain's other accepted credential.
- Extend `ScopedApiChainRegistrar` to register both chains per descriptor.

**OC owns (host policy — descriptor already supplied by `PhysicalTenantScopeProvider`, unchanged):**

- **SPA serving under the prefix** — productionise the PoC's set: base-href / context-path rewrite, asset + cluster-endpoint URL mapping, `client-config.js` rewrite, webapp-controller dual-routing. None of this touches CSL or the auth boundary; it makes the served SPA work under `/physical-tenants/<id>/<webapp>`.
- A **PT-partitioning `SessionStorePort` adapter** (Decision 5): the `SessionStoreAdapter` holds a per-PT `PersistentWebSessionClient` map, resolves the PT from request context for request-scoped ops, and **fans out** across all PT stores for the context-free background deletion sweep. Each PT's sessions live in that PT's isolated schema.
- BASIC-mode per-PT user resolution via the `UserDetailsPort` adapter (already the agreed pattern).

CSL's vocabulary stays "the host contributed some scoped chains, each with a base path and an auth config." It never learns what they are for.

## 4. The contract (unchanged)

```java
public interface CamundaSecurityScopeProvider {     // api/context/  — unchanged
  List<ScopedSecurityDescriptor> get();
}

public record ScopedSecurityDescriptor(             // api/model/config/  — unchanged
    String basePath, AuthenticationConfiguration authentication) {}
```

Everything the webapp chain needs is derived:

| Webapp concern            | Derived from `basePath`                         |
|---------------------------|-------------------------------------------------|
| Webapp matchers           | `basePath + pathPort.webappPaths()`             |
| Login / picker            | `basePath + /login`                             |
| OAuth2 redirect URI       | `basePath + /sso-callback`                      |
| OAuth2 authorization      | `basePath + /oauth2/authorization/<id>`         |
| Logout                    | `basePath + /logout`                            |
| Session cookie            | name `camunda-session-` + sanitize(`basePath`), `Path = basePath` |
| CSRF cookie               | `X-CSRF-TOKEN`, `Path = basePath`               |
| Providers offered/accepted| the descriptor's `authentication` (assigned only) |

**Cookie-name derivation.** The session cookie name is `camunda-session-` + **sanitize(`basePath`)**: strip the leading `/` and replace each run of characters outside `[A-Za-z0-9-]` with a single `-` (e.g. `/physical-tenants/tenanta` → `camunda-session-physical-tenants-tenanta`). A distinct *name* — not just a distinct `Path` — is required because the primary unprefixed `camunda-session` at `Path = /` (kept for the `default`/cluster surface) would otherwise be sent alongside the scoped cookie on nested paths, leaving two same-named cookies with undefined resolution. The registrar's existing duplicate-`basePath` rejection is extended to also reject any two scopes whose sanitized cookie names collide, keeping the mapping injective without an opaque hash suffix.

Because the descriptor is surface-agnostic, the **same object** drives the API chain (Slice 1) and the webapp chain (Slice 3). CSL builds both from it; OC is unchanged either way.

## 5. How isolation holds

- **Session cookie `Path`** — the session cookie is `Path = basePath`; the browser sends it only on requests under `<basePath>`. Tenant A's session cookie is never transmitted to tenant B. It also does not collide with the unprefixed cluster chain's `camunda-session` at `Path = /`, because the per-scope cookie has a distinct name *and* a narrower path.
- **Session honoured on the PT API chain, in-scope only** — `<basePath>/v2/**` is nested under `<basePath>`, so the browser sends the per-scope cookie there; the shared per-scope `SessionRepositoryFilter` resolves the session and the API chain reads its `SecurityContext`. A request to a *different* PT's `/v2` carries no usable cookie and falls back to bearer-or-401. (The production routing flip to `/physical-tenants/<id>/v2/**` is what nests the API surface inside the cookie scope; the PoC's old `/v2/physical-tenants/<id>/**` scheme — outside the cookie `Path` — is gone.)
- **At rest** — the `SessionStorePort` adapter routes each PT's sessions to that PT's isolated schema, so session data is isolated and lifecycle-managed (decommission a PT ⇒ drop its schema ⇒ its sessions are gone). Defence-in-depth beyond the cookie boundary.
- **OIDC providers** — the webapp chain's `ClientRegistration`s are the PT's `assigned` providers only (the merged `AuthenticationConfiguration`); the picker offers only that PT's IdPs and the ID-token validation accepts only them.
- **CSRF** — the CSRF cookie is `Path = basePath`, so multi-tab logout / token rotation stays within one tenant.

## 6. Decisions

1. **Session isolation lives in CSL, derived from `basePath`.** A per-scope `SessionRepositoryFilter` + cookie serializer is built once per descriptor and shared by the scope's webapp and API chains. *Alternative — rely on the servlet `HttpSession`*: rejected, the container's `JSESSIONID` can't be `Path`/name-scoped per chain. *Alternative — OC builds and contributes the session components*: rejected, it would change the contract and re-introduce host-side chain assembly (the drift risk ADR-0025 closed).

2. **The contract does not change.** All webapp specifics are derived from `basePath`. *Alternative — grow the descriptor with cookie/redirect/login fields*: rejected, it leaks surface concerns into the host contract for no gain.

3. **The registrar builds both chains per descriptor, method-driven.** Every PT is a full tenant (API + webapp). *Alternative — a descriptor flag selecting which surfaces to build*: deferred (YAGNI); add only if an API-only scope consumer appears.

4. **The scoped API chain honours the per-scope session.** This extends ADR-0023's model per-scope; bearer remains the API chain's other credential and the webapp chain stays login/session-only. No conflict with ADR-0023 — it is the same property applied to a per-scope session.

5. **Durable per-PT sessions: route in the `SessionStoreAdapter` (host), to per-PT isolated schemas.** The adapter holds a `Map<ptId, PersistentWebSessionClient>` built from OC's existing per-PT config resolution; request-scoped `get`/`upsert`/`delete` resolve the PT from request context; the background deletion sweep (`getAll`→`delete`, no request context — ADR-0017's `WebSessionDeletionTask`) **fans out** across all PT clients. *Alternative — make `PersistentWebSessionClient` PT-aware*: rejected — it leaks the PT/request-context concept down into the `search-client` / `db-rdbms` modules (an inverted dependency), duplicates routing across both backend impls, and the background sweep has no request context to route from. Routing at the adapter keeps the storage clients "one client = one store" and concentrates PT-context resolution in the one OC boundary that exists for it (mirrors the `UserDetailsPort` adapter). The `SessionStorePort` contract is **unchanged** (no tenant parameter). *Open sub-question for review: routing the id-only `delete`/`get` on background threads — encode the PT in the session id (routable without context) vs. fan-out/try-all.*

6. **SPA-serving rewrites stay in OC.** CSL never serves the SPA or learns the PT URL scheme; the rewrites are pure host webapp-serving concerns.

## 7. Prerequisites & sequencing

**Already landed** (were Slice-1 prerequisites): the issuer-aware decoder ([#221](https://github.com/camunda/camunda-security-library/issues/221) / ADR-0020), the multi-IdP picker fix ([#269](https://github.com/camunda/camunda-security-library/issues/269)), the `UserDetailsPort` ([#372](https://github.com/camunda/camunda-security-library/issues/372) / ADR-0021), the scope-provider SPI + scoped API chain (ADR-0025), and the tenant-first routing flip ([camunda/camunda#54651](https://github.com/camunda/camunda/issues/54651)). The `providers.assigned` selection lands in [camunda/camunda#55227](https://github.com/camunda/camunda/pull/55227).

**Track A — CSL (lands first):** `ScopedWebappSecurityChainBuilder` + the prefix-aware authorization-request resolver; per-scope session/cookie components shared across a descriptor's webapp+API chains; extend the registrar to build both; re-base CSL's own webapp chains on the builder; extend the scoped API chain to honour the per-scope session. Contract-tested for the no-provider and disjoint-scope paths. Publish `-SNAPSHOT`, then an alpha before the OC PR is review-ready.

**Track B — OC (consumes the alpha):** the PT-partitioning `SessionStoreAdapter`; productionise the SPA-serving rewrites; BASIC-mode per-PT form-login. Integration-tested: cross-tenant session rejection (a session minted for A is unusable on B's webapp and API surfaces), per-PT login/logout against two Keycloak realms, and the SPA loading under the prefix.

## 8. Out of scope

- Changes to the `ScopedSecurityDescriptor` / `CamundaSecurityScopeProvider` contract.
- A single tenant-aware dispatching chain (ADR-0025 keeps this a deferred future optimisation; N chains stay).
- Cross-PT single-sign-on or shared sessions — PTs are fully isolated by design.
- Optimize.
