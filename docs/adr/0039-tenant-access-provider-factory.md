---
status: Accepted
---

# ADR-0039: TenantAccessProvider selection via a core-owned factory

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

72661d8 moved `DefaultTenantAccessProvider` and `TenantOwnedEntity` into
`core` (see ADR security/002 in camunda/camunda for the full relocation
decision), but left the disabled counterpart,
`DisabledTenantAccessProvider`, behind in the monorepo's search module. The
enabled/disabled selection is still expressed as a ternary in the
monorepo's Spring `@Bean` method, naming both a `core` type
(`DefaultTenantAccessProvider`) and a monorepo type
(`DisabledTenantAccessProvider`) side by side — split ownership for what is
otherwise a single decision (which implementation backs multi-tenancy
checks).

camunda-security-library#592 proposed collapsing this into a single
CSL-side factory, `TenantAccessProvider.of(cslProperties, checker)`, so the
monorepo's bean method becomes a simple delegation. That literal signature
does not fit: `CamundaSecurityLibraryProperties` lives in
`spring-boot-starter`, while `TenantAccessProvider` lives in `core`, and
`core` must not depend on `spring-boot-starter` — that would invert the
module dependency direction the whole library is built on.

## Decision

1. **Move `DisabledTenantAccessProvider` into `core.authz`**, alongside
   `DefaultTenantAccessProvider`. Behavior-preserving: it returns
   `TenantAccess.wildcard(null)` from all three `TenantAccessProvider`
   methods, matching the monorepo original byte-for-byte.

2. **Add a static factory, `TenantAccessProvider.of(boolean
   multiTenancyChecksEnabled)`, on the interface itself**, selecting
   between the two implementations. It takes a plain `boolean`, not the
   monorepo's `CamundaSecurityLibraryProperties` or any other
   `spring-boot-starter` type — callers extract the flag from their own
   configuration before calling. This keeps the factory usable from
   non-Spring consumers too, consistent with `AuthorizationPortsFactory`'s
   existing plain-Java-factory precedent in this package.

## Consequences

- The monorepo's `tenantAccessProvider` `@Bean` method becomes
  `TenantAccessProvider.of(cslProperties.getMultiTenancy().isChecksEnabled())`
  — no more naming a monorepo-local disabled implementation.
- The equivalent `ResourceAccessProvider`/`AuthorizationChecker` pair
  (`DefaultResourceAccessProvider`/`DisabledResourceAccessProvider`) is
  **not** addressed here: it depends on
  `ResourcePropertyMatcherRegistry` → `UserTaskPropertyMatcher` →
  `io.camunda.search.entities.UserTaskEntity`, a monorepo search-domain
  type with no CSL equivalent. Moving it would require relocating that
  matcher framework and its entity dependency first — the same category of
  blocker `TenantOwnedEntity` posed for the tenant pair, but larger in
  scope. Tracked separately; out of scope for camunda-security-library#592.

## Alternatives Considered

- **`TenantAccessProvider.of(cslProperties, checker)`** (the issue's literal
  proposal) — rejected: inverts `core`'s dependency direction onto
  `spring-boot-starter`.
- **Factory in `spring-boot-starter` instead of `core`** — would fit the
  module direction, but every other `@Bean` in that module constructs core
  types directly with no factory indirection (see
  `AuthorizationConfiguration`, `AuthorizationCheckerConfiguration`); adding
  one here for a two-way ternary would be inconsistent ceremony. A
  boolean-based `core` factory is simpler and matches existing precedent.
