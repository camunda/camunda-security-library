---
status: Accepted
---

# ADR-0041: Limit a membership with conditions

**Deciders**: Ben Sheppard (Ben-Sheppard), Patrick Wunderlich (p-wunderlich), Timothy Cline (timcline), Ana Vinogradova (ana-vinogradova-camunda), Joaquín Felici (joaquinfelici)

## Status

Accepted (8.11)

## Context

Memberships are global: a role's members get its permissions on every resource it covers. Hub needs
memberships limited to some resources, such as "editor, but only in workspace Payments".

## Decision

**D1. A membership can be limited by conditions on the resource being accessed.**
A conditional membership applies only to resources that meet all its conditions. A condition names a
resource attribute and a set of values, and matches when the resource shares at least one value.

**D2. The concept is called a condition, in the API, the code and the product.**
One name everywhere. "Scope" already means tenant isolation in CSL
([ADR-0013](0013-camunda-security-scope-provider-spi.md)).

**D3. Only role memberships carry conditions at first.**
Roles carry the permissions; group and tenant memberships can adopt the same model later.

**D4. Anything that can't be evaluated denies.**
That includes unknown attributes, operands or condition types, a missing mapping, a read error, and
a resource without the attribute. Disabling authorization still allows every check.

**D5. Conditional memberships are kept apart from global memberships.**
Code that doesn't know about conditions sees only global memberships, so it can't over-grant.

**D6. A condition may compare against the caller only for trusted attributes.**
Username and client ID always; group and tenant IDs only when resolved from the host's identity
store. When they come from a token claim, the condition denies.

**D7. The set of attributes is fixed by CSL.**
Hosts can't add attributes, so CSL can check each host's mappings at startup, as
[ADR-0008](0008-authz-enum-ownership-and-layered-usage.md) keeps the other authorization enums.

**D8. Conditions on direct grants, and sending conditional memberships to OC, come later.**
A later conditional direct grant must be a new record type: old code that ignores an extra field
would read it as unrestricted. Until then, conditional memberships stay in the host that owns them.

## Consequences

- One model covers any restriction Hub needs, such as workspace or process application.
- Existing readers of memberships need no change: they see only global memberships.
- Each host maps every attribute it supports; a missing mapping denies rather than grants.
- A new kind of condition needs a CSL release.

## Alternatives Considered

- **A single scope pair per membership.** Rejected — it fits one restriction per membership.
- **An open, host-defined set of attributes.** Rejected — CSL couldn't check hosts' mappings.
