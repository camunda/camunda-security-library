# ADR-0051: The filter is the source of truth for a resource-access result

**DRI**: Ben Sheppard (Ben-Sheppard)

**Deciders**: Ben Sheppard (Ben-Sheppard), Lukas Taake (mrm1st3r), Timothy Cline (timcline)

**Status**: Accepted (1.4.0)

**Purpose**: Defines how a `ResourceAccess` result represents access when the list filter holds conditional grants.

**Audience**: CSL maintainers, and OC and Hub engineers who read a `ResourceAccess`.

## Context

A grant is a permission to access a resource. A conditional grant applies only when a resource meets
a condition, for example "workspace = payments" (ADR-0041).

The method `resolveResourceAccess` returns a `ResourceAccess`. This type has two parts. The old part
has three fields: `allowed`, `wildcard`, and an `authorization` that holds a list of resource IDs.
The new part is `filter()`. `ConditionalResourceAccessProvider` puts conditional grants in the
filter.

The old fields can state two things only: a fixed list of resource IDs, or every resource. They
cannot state a condition. So the old fields cannot describe a conditional grant.

Today a caller whose only grant is conditional gets `allowed = true`, `wildcard = false`, and an
empty list of IDs. A host that reads the old fields and not `filter()` reads an empty list of IDs as
"no limit". So the host shows every resource. This result fails open. A result that fails open lets a
reader allow too much. The review of [#815](https://github.com/camunda/camunda-security-library/pull/815)
found this.

No host has this fault today. OC registers no `ResourceAttributeExtractor`, so OC never uses this
provider. Hub does not read the result yet, and Hub will read `filter()`. The fault is a safety gap
in the type.

## Decision

**D1. The filter is the single source of truth.**
`resolveResourceAccess` builds the filter first. The old fields derive from the filter. Before this
decision, the constructor derived the filter from the old fields, and the provider set the IDs
apart. Two representations could disagree. Now one representation decides.

**D2. The old fields hold only the part of the filter that they can express.**
The derivation has these cases:

- A `None` filter: `allowed = false`, and no IDs.
- An `All` filter: `allowed = true`, `wildcard = true`.
- An `AnyOf` filter with a term that names resource IDs and no condition: `allowed = true`, and the
  old IDs hold those IDs.
- An `AnyOf` filter with conditional terms only: `allowed = false`, and the old IDs are empty.

**D3. A conditional-only result reads as denied through the old fields.**
A host that reads the old fields shows nothing for this result. This fails closed. A host that reads
`filter()` applies the condition and shows the right resources.

**D4. A denied result can carry an `AnyOf` filter.**
This changes the earlier invariant that a denied result must carry a `None` filter. Only
`ConditionalResourceAccessProvider` creates a denied result with an `AnyOf` filter. The filter holds
the conditional access that the old fields cannot express.

**D5. A new consumer reads `filter()` and does not act on `allowed` alone.**
`allowed` now means "the old fields describe some access". It does not mean "the caller has some
access". A consumer that wants conditional grants reads `filter()`. The Javadoc of `ResourceAccess`
states this rule.

## Alternatives considered

A reserved resource ID in the old list. The provider puts an ID that no store grants. An old host
filters by this ID and matches nothing, so it fails closed. This needs no change to the type. We
rejected it because the reserved ID can leak into a host query and confuse it.

Keep the current behavior and document it. We rejected it because a host that does not know
`filter()` still reads the old fields and still fails open. Documentation does not stop a fail-open
result.

## Consequences

- A host that reads only the old fields never over-grants. It under-grants, or it shows nothing.
- A host that reads `filter()` gets the full access, including conditional grants.
- The meaning of `allowed` is now "expressible in the old fields". A reader must not treat it as
  "has any access".
- OC is not affected, because OC uses no extractor. Hub reads `filter()` when it adopts the
  provider.

## Source

- [PR #815](https://github.com/camunda/camunda-security-library/pull/815), review by mrm1st3r.
- [ADR-0041](0041-conditional-memberships.md): conditional memberships.
