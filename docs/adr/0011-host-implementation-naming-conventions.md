---
status: Accepted
supersedes: 0007-resource-permission-port-and-authorization-repository.md (naming sub-section only)
---

# ADR-0011: Host implementation naming conventions

## Status

Accepted

## Context

The CSL's hexagonal architecture splits extension points across three categories:

1. **Inbound ports** in `core/port/in/` — library-internal contracts the library implements and that
   library callers (filters, services) invoke against. Example: `ResourcePermissionPort`.
2. **Outbound ports** in `core/port/out/` — contracts the library calls and hosts implement.
   Examples: `SecurityPathPort`, `AuthorizationRepositoryPort`, `AdminUserPresencePort`.
3. **Starter SPIs** in `io.camunda.security.spring.spi.*` — extension points whose signatures speak
   `jakarta.servlet` types and therefore live outside `core` per
   [ADR-0006](0006-central-security-filter-chains.md). Examples: `WebAppProvider`,
   `WebAppAccessDeniedHandler`, `AdminUserMissingHandler`.

[ADR-0007](0007-resource-permission-port-and-authorization-repository.md) introduced a "Naming"
sub-section that codified the `*Port` / `*Service` / `*Adapter` convention, but:

- the sub-section is anchored inside an ADR titled around a specific port pair, so adopters writing
  host code for any other port don't think to look there,
- it pre-dates the starter SPIs from [ADR-0009](0009-web-app-authorization-spis.md) and
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
| Outbound port | `core/port/out/` | `*Port` |
| Starter SPI | `io.camunda.security.spring.spi.*` | descriptive name (no `*Port` suffix) — e.g. `WebAppProvider`, `AdminUserMissingHandler` |

The `*Port` suffix is reserved for `core/port/{in,out}/` interfaces. Starter SPIs deliberately drop
the suffix because they live outside `core` per [ADR-0006](0006-central-security-filter-chains.md);
naming them `*Port` would falsely imply they participate in the hexagonal core.

### Implementation naming

| Category | Library-supplied default | Host implementation |
|---|---|---|
| Inbound port | `*Service` (in `spring-boot-starter/`) | `*Service` (host overrides) |
| Outbound port | none (host must register) | `*Adapter` (host code) |
| Starter SPI | descriptive name (e.g. `Redirecting*Handler`) — semantic verb prefix conveys behaviour | `*Adapter` (host code) |

### Examples

| Interface | Library default | Host implementation |
|---|---|---|
| `ResourcePermissionPort` (inbound) | `ResourcePermissionService` | host's own `*Service` if needed |
| `AuthorizationRepositoryPort` (outbound) | — | `OcAuthorizationRepositoryAdapter`, `HubAuthorizationRepositoryAdapter` |
| `SecurityPathPort` (outbound) | — | `OcSecurityPathAdapter` |
| `AdminUserPresencePort` (outbound) | — | `OcAdminUserPresenceAdapter` |
| `WebAppProvider` (starter SPI) | — | `OcWebAppAdapter` |
| `WebAppAccessDeniedHandler` (starter SPI) | `RedirectingWebAppAccessDeniedHandler` | host's own `*Adapter` |
| `AdminUserMissingHandler` (starter SPI) | `RedirectingAdminUserMissingHandler` | host's own `*Adapter` |

### Why `*Adapter` for starter SPI host implementations

By the hex naming pattern, anything a host writes to satisfy a library-defined extension point is
an "adapter" — it adapts host infrastructure to the library's contract. Starter SPIs are not
strictly hexagonal-`core` ports, but the host role is identical: implement a library-defined
contract using host-specific machinery. Using the same `*Adapter` suffix gives adopters one rule
across the entire extension surface.

The library-supplied defaults for starter SPIs use descriptive verb-prefixed names
(`Redirecting*Handler`) rather than `*Adapter` because they aren't adapting host machinery — they
ship a complete behaviour the host can adopt as-is or override. The descriptive name signals what
the default does at a glance.

## Consequences

**Positive**

- One ADR to cite from adopter guides for naming of host implementations across every
  extension-point category.
- ADR-0007's naming sub-section becomes a focused statement about its port pair; the broader
  normative force moves here.
- Adopters writing new host code for any future port or SPI have an unambiguous rule before
  opening the IDE.
- The library-supplied default-naming pattern (descriptive verb-prefixed names for starter SPI
  defaults) is codified rather than ad-hoc.

**Negative / accepted trade-offs**

- One more ADR to keep current as the extension surface evolves. The cost is small (a single
  table update per new category).
- ADR-0007's "Naming" sub-section is now partially superseded. The table is preserved in place so
  historical links don't break; readers chasing the convention from there land on the same rule
  via a forward pointer.

## Alternatives Considered

- **Leave the convention inside ADR-0007.** Rejected — ADR-0007 is titled around one port pair, so
  adopters writing host code for unrelated extension points don't think to look there. The
  sub-section also doesn't cover starter SPIs.
- **Embed the convention in each per-port ADR (0007, 0009, 0010, future ones).** Rejected —
  duplicates the rule, drift risk, no single source of truth.
- **Inline the rule only in the adopter guide.** Rejected — adopter guides describe how to adopt;
  ADRs codify why and what. The rule should be normative, not just documentary.
