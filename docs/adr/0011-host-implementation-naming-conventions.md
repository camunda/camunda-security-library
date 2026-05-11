---
status: Accepted
supersedes: 0007-resource-permission-port-and-authorization-repository.md (naming sub-section only)
---

# ADR-0011: Host implementation naming conventions

## Status

Accepted

## Context

The CSL's hexagonal architecture splits extension points across three categories:

1. **Inbound ports** in `core/port/in/` — library-internal contracts the library implements
   (typically in `spring-boot-starter/`) and that library callers (filters, services) invoke
   against. Host override of an inbound port is an escape hatch, not the normal extension shape;
   when needed the library default backs off via `@ConditionalOnMissingBean`. Example:
   `ResourcePermissionPort` (default `ResourcePermissionService`).
2. **Outbound ports (core)** in `core/port/out/` — framework-free contracts the library calls and
   hosts implement. Examples: `SecurityPathPort`, `AuthorizationRepositoryPort`,
   `AdminUserPresencePort`.
3. **Outbound ports (servlet-coupled)** in `io.camunda.security.spring.spi.*` — outbound ports
   whose signatures speak `jakarta.servlet` types and therefore can't live in `core` per
   [ADR-0006](0006-central-security-filter-chains.md). Examples: `WebAppProviderPort`,
   `WebAppAccessDeniedHandlerPort`, `AdminUserMissingHandlerPort`.

[ADR-0007](0007-resource-permission-port-and-authorization-repository.md) introduced a "Naming"
sub-section that codified the `*Port` / `*Service` / `*Adapter` convention, but:

- the sub-section is anchored inside an ADR titled around a specific port pair, so adopters writing
  host code for any other port don't think to look there,
- it pre-dates the servlet-coupled outbound ports from
  [ADR-0009](0009-web-app-authorization-spis.md) and
  [ADR-0010](0010-admin-user-setup-spis.md) and therefore says nothing about them,
- its placement reads as scoped to one port pair even though the table itself is universal.

Adopters writing host code today must infer the convention by reading existing implementations.
Newer extension points have no documented convention at all.

## Decision

Establish a single naming-convention ADR covering all three extension-point categories.

### Interface naming (library code)

| Category | Location | Interface suffix |
|---|---|---|
| Inbound port | `core/port/in/` | `*Port` |
| Outbound port (core) | `core/port/out/` | `*Port` |
| Outbound port (servlet-coupled) | `io.camunda.security.spring.spi.*` | `*Port` |

All three categories use the `*Port` suffix. The suffix marks an architectural role —
a library-defined contract crossing the hexagonal boundary — not a package location. The split
between `core/port/out/` and `io.camunda.security.spring.spi.*` is purely about framework
coupling: `jakarta.servlet` types can't live in `core` per
[ADR-0006](0006-central-security-filter-chains.md), so servlet-coupled outbound ports live in the
starter module instead. Their role and naming convention are otherwise identical to core ports.

### Implementation naming

| Category | Library-supplied default | Host implementation |
|---|---|---|
| Inbound port | `*Service` (in `spring-boot-starter/`) | `*Service` (host overrides) |
| Outbound port (core) | none (host must register) | `*Adapter` (host code) |
| Outbound port (servlet-coupled) | when supplied, a strategy-prefixed `*Adapter` (e.g. `Redirecting*Adapter`); some ports ship no default and the host must register | `*Adapter` (host code) |

### Examples

| Interface | Library default | Host implementation |
|---|---|---|
| `ResourcePermissionPort` (inbound) | `ResourcePermissionService` | host's own `*Service` if needed |
| `AuthorizationRepositoryPort` (outbound, core) | — | `AuthorizationRepositoryAdapter`, `HubAuthorizationRepositoryAdapter` |
| `SecurityPathPort` (outbound, core) | — | `SecurityPathAdapter` |
| `AdminUserPresencePort` (outbound, core) | — | `AdminUserPresenceAdapter` |
| `WebAppProviderPort` (outbound, servlet-coupled) | — | `WebAppAdapter` |
| `WebAppAccessDeniedHandlerPort` (outbound, servlet-coupled) | `RedirectingWebAppAccessDeniedAdapter` | host's own `*Adapter` |
| `AdminUserMissingHandlerPort` (outbound, servlet-coupled) | `RedirectingAdminUserMissingAdapter` | host's own `*Adapter` |

### Why `*Adapter` for host implementations of outbound ports

By the hex naming pattern, anything a host writes to satisfy a library-defined outbound port is
an "adapter" — it adapts host infrastructure to the library's contract. The rule applies equally
to core ports and servlet-coupled ports: the host role is identical, only the package location
differs.

Library-supplied defaults use the same `*Adapter` suffix for symmetry with host implementations.
The descriptive verb prefix (`Redirecting`) distinguishes which default behaviour the adapter
ships; multiple defaults in the future (e.g. `JsonErrorBody*Adapter`) would carry their own
semantic prefix.

## Consequences

**Positive**

- One ADR to cite from adopter guides for naming of host implementations across every
  extension-point category.
- ADR-0007's naming sub-section becomes a focused statement about its port pair; the broader
  normative force moves here.
- Adopters writing new host code for any future port or SPI have an unambiguous rule before
  opening the IDE.
- The library-supplied default-naming pattern (descriptive verb-prefixed names for
  servlet-coupled port defaults) is codified rather than ad-hoc.

**Negative / accepted trade-offs**

- One more ADR to keep current as the extension surface evolves. The cost is small (a single
  table update per new category).
- ADR-0007's "Naming" sub-section is now partially superseded. The table is preserved in place so
  historical links don't break; readers chasing the convention from there land on the same rule
  via a forward pointer.

## Alternatives Considered

- **Leave the convention inside ADR-0007.** Rejected — ADR-0007 is titled around one port pair, so
  adopters writing host code for unrelated extension points don't think to look there. The
  sub-section also doesn't cover the servlet-coupled outbound ports.
- **Embed the convention in each per-port ADR (0007, 0009, 0010, future ones).** Rejected —
  duplicates the rule, drift risk, no single source of truth.
- **Inline the rule only in the adopter guide.** Rejected — adopter guides describe how to adopt;
  ADRs codify why and what. The rule should be normative, not just documentary.
