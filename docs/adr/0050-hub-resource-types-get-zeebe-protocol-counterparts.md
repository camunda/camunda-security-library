# ADR-0050: Hub resource types get Zeebe-protocol counterparts, not a host-only category

**DRI**: Ben Sheppard (Ben-Sheppard)

**Deciders**: Ben Sheppard (Ben-Sheppard)

**Status**: Accepted (1.2.3)

**Purpose**: Record that Hub-only authorization resource types are added to the CSL enums with
matching Zeebe-protocol counterparts, under the existing ADR-0008 model, rather than by introducing
a host-only type category that would amend ADR-0008.

**Audience**: CSL maintainers, and Hub and Orchestration Cluster engineers who add resource types.

## Context

Hub moves its access decisions to CSL. It needs resource types that only Hub uses, such as
`WORKSPACE`, `PROJECT` and `FILE` (issue
[#813](https://github.com/camunda/camunda-security-library/issues/813)).

[ADR-0008](0008-authz-enum-ownership-and-layered-usage.md) makes the CSL `ResourceType` and
`PermissionType` enums the canonical catalogue. The Zeebe engine keeps its own protocol enums for
serialization stability, and the `AuthzModelMapper` in the Orchestration Cluster bridges the two.
A new value is therefore a two-step add: the CSL enum, and the Zeebe protocol enum with its SBE
schema change and mapper entry.

Issue #813 (question 1) asked how a type that only Hub uses fits this model. Two options were on
the table: add the type to both enums as ADR-0008 already requires, or let CSL hold "host-only"
types that have no Zeebe counterpart, which would amend ADR-0008.

## Decision

- **D1.** A Hub resource type is added to the CSL enums (`AuthorizationResourceType` and
  `ResourceType`) and also gets a Zeebe-protocol counterpart. CSL does not introduce a host-only
  type category. ADR-0008 stands.
- **D2.** The Zeebe-protocol enum value, its SBE schema change and the `AuthzModelMapper` entry are
  host work in `camunda/camunda`. They are out of CSL's own scope and are tracked by
  [camunda/camunda#66943](https://github.com/camunda/camunda/issues/66943). This CSL change adds
  only the enum values.
- **D3.** This ADR records the choice. It does not supersede ADR-0008.

## Alternatives considered

- **Host-only types (amend ADR-0008).** Let a type live only in the CSL enums with no Zeebe
  counterpart. Rejected: it splits the catalogue into mapped and unmapped types, the Orchestration
  Cluster must still know every type to reject the Hub-only ones for its own resources (#813), and
  ADR-0008's drivers — Hub needs a complete catalogue, the engine keeps serialization stability —
  are met without the split. The cost of the chosen option is the per-type two-step add and a CSL
  release for each type, which the issue accepts.

## Consequences

- One catalogue model holds for every type. The Orchestration Cluster can enumerate and validate
  all types, including the Hub-only ones it rejects for its own resources.
- Each Hub type stays a two-step add: the CSL enum here, and the Zeebe protocol enum, SBE schema
  and mapper in the host. A CSL release gates each type, as #813 notes.
- ADR-0008 is unchanged.

## Source

- Issue [#813](https://github.com/camunda/camunda-security-library/issues/813), question 1.
- [ADR-0008](0008-authz-enum-ownership-and-layered-usage.md).
- [camunda/camunda#66943](https://github.com/camunda/camunda/issues/66943) (Orchestration Cluster
  work).
