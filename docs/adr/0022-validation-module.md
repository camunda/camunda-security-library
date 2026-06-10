---
status: Accepted
---

# ADR-0022: Dedicated `validation` module for entity validators

**Deciders**: Patrick Wunderlich (p-wunderlich)

## Status

Accepted

## Context

OC's `security/security-validation` module owns validators for entities (User, Group,
Role, Tenant, MappingRule, Authorization, ClusterVariable) that are defined and owned
by CSL. Keeping them in OC means every CSL adopter must either re-implement the same
logic or vendor it, leading to drift. Increment 16 (#246) moves these validators into
CSL so any host inherits consistent constraint enforcement out of the box.

The question this ADR answers: where in CSL should the validators live — inside the
existing `api` module, or in a new dedicated `validation` module?

## Decision

**A new `validation` module** (`camunda-security-library-validation`) is introduced
alongside `api`, `core`, and `spring-boot-starter`.

The validators are plain POJOs with no Spring annotations. They depend only on
`camunda-security-library-api` (for `EntityType`, `AuthorizationScope`) and on
`commons-validator` (Apache Commons Validator, for email validation in
`UserValidator`).

The package is kept as `io.camunda.security.validation` — identical to OC's current
package — so OC consumers need **no Java import changes**, only a Maven artifact
rename.

Spring bean wiring for `IdentifierValidator` (which requires runtime-configurable
regex patterns from host properties) remains in OC's `CamundaSecurityConfiguration`.
CSL makes no Spring auto-configuration changes; the validators are framework-free.

## Consequences

**Positive**

- Every CSL adopter gets consistent entity validation without duplicating logic.
- OC's `security-validation` module becomes a thin pass-through, then disappears.
- The `api` module keeps its zero-runtime-dependency posture.
- Same package name means zero Java import changes in OC consumers.

**Negative / accepted trade-offs**

- CSL gains one more module; build time increases marginally.
- `commons-validator` is added to CSL's dependency graph. The library is stable and
  widely used; the added surface is acceptable.

## Alternatives Considered

### Embed validators in the `api` module

- **Rejected:** `api` is intentionally runtime-dependency-free (zero non-test deps
  today). Adding `commons-validator` would break that posture and blur the boundary
  between public model types and validation logic.

### Embed validators in the `core` module

- **Rejected:** `core` holds framework-free domain logic and port interfaces.
  Validators are utilities, not ports or domain services. Mixing them into `core`
  would make the module's purpose less clear and pull in `commons-validator` alongside
  the domain.

### Keep validators in OC, expose via CSL API only

- **Rejected:** validators would remain duplicated across every host. The goal of
  Increment 16 is to own them in CSL, not to publish an API wrapper over OC logic.
