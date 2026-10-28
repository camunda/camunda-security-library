---
status: Accepted
---

# ADR-0041: Limit a membership with conditions

**Deciders**: Ben Sheppard (Ben-Sheppard), Patrick Wunderlich (p-wunderlich), Timothy Cline (timcline), Ana Vinogradova (ana-vinogradova-camunda), Joaquín Felici (joaquinfelici)

## Status

Accepted

## Context

A principal's memberships are global today. A user who is a member of a role has that role's
permissions on every resource the role's authorizations cover. Hub needs a membership that applies
only to some resources, for example "editor, but only in workspace W"
([#743](https://github.com/camunda/camunda-security-library/issues/743), part of
[#742](https://github.com/camunda/camunda-security-library/issues/742)).

[camunda-hub#30035](https://github.com/camunda/camunda-hub/issues/30035) compared two approaches and
prototyped both on the
[`hub-authz-prototype`](https://github.com/camunda/camunda-security-library/tree/hub-authz-prototype)
branch:

1. **Scoped role memberships** ([f1cae97](https://github.com/camunda/camunda-security-library/commit/f1cae97)):
   a membership carries a `(scopeType, scopeId)` pair.
2. **Conditional memberships** ([09ea736](https://github.com/camunda/camunda-security-library/commit/09ea7368b63dcc907c64329a096bf48b29b2a5f0)):
   a membership carries a list of conditions on attributes of the resource being accessed.

Approach 2 was chosen in the identity-at-scale workshop. This ADR records that model and the rules
around it that every later task depends on: the API change
([#745](https://github.com/camunda/camunda-security-library/issues/745)), the list filter
([#748](https://github.com/camunda/camunda-security-library/issues/748)) and the Hub resource types
([#747](https://github.com/camunda/camunda-security-library/issues/747)).

Several constraints come from existing decisions:

- "Scope" already names tenant isolation in CSL ([ADR-0013](0013-camunda-security-scope-provider-spi.md)),
  so the concept needs another name.
- Memberships load lazily ([ADR-0005](0005-lazy-load-authentication-memberships.md)).
- `AuthorizationCheckPort` is the single inbound authorization port
  ([ADR-0014](0014-unified-authz-framework-in-core.md)), and `AuthorizationCondition` already exists
  in `core/auth/condition`.
- Authorization enums are owned centrally ([ADR-0008](0008-authz-enum-ownership-and-layered-usage.md)).

What model limits a membership to some resources, what is it called in the API, code and product,
which memberships and grants may carry it, and which rules keep it from widening access?

## Decision

### The concept is called a condition

A membership is either **global** or **conditional**: it carries conditions on the resource being
accessed. "Condition" is the name in the CSL API, in the code, and in product-facing wording such as
Hub's policy model, the REST API and the docs. One name everywhere means no mapping between what
users read and what the API returns.

A list of conditions reads as "all of these must hold", which is how they're evaluated. It covers
both a condition on where a resource is (`WORKSPACE ∈ {payments}`) and one relative to the caller
(`ASSIGNEE ∈ Principal(USERNAME)`). A UI shows the concrete condition, for example "Reviewer in
workspace Payments", rather than the generic name.

### Model

```java
record ConditionalMembership(MembershipType type, String id, List<MembershipCondition> conditions)
record MembershipCondition(ResourceAttribute attribute, Operand operand)
sealed interface Operand permits Operand.Values, Operand.Principal
```

- `MembershipCondition` rather than `Condition`, to stay clear of the existing
  `AuthorizationCondition`.
- `ResourceAttribute` and `PrincipalAttribute` are closed enums in `api`, as in the prototype.
- A membership with no conditions is global, and stays in the existing representation.
- A membership with several conditions applies only when all of them are met (AND).
- A condition is met when the resource and the operand have at least one value in common (OR within
  the condition). Both sides are sets, because some attributes hold several values.
- A resource that has no value for the attribute doesn't meet the condition. An empty value counts
  as no value. Counting a missing attribute as a match would apply a membership limited to one
  workspace to every resource outside a workspace.

For example, Alice has a role membership with one condition, and is in the groups `{audit, dev}`:

| Condition | Resource and its values | Met? |
|---|---|---|
| `WORKSPACE ∈ {payments, lending}` | Process application in Payments: `{payments}` | Yes, `payments` is shared |
| `WORKSPACE ∈ {payments, lending}` | Process application in HR: `{hr}` | No |
| `CANDIDATE_GROUPS ∈ Principal(GROUP_IDS)` | Task offered to `{finance, audit}` | Yes, `audit` is shared |
| `CANDIDATE_GROUPS ∈ Principal(GROUP_IDS)` | Task offered to `{finance}` | No |
| `WORKSPACE ∈ {payments}` | Decision definition in no workspace: no value | No, so the membership doesn't apply |

### First delivery: role memberships only

The type is general, but only role memberships carry conditions in the first delivery. Roles carry
the permissions, so a conditional role membership is enough for Hub's workspace case. Group and
tenant memberships can adopt the same type later without a new model.

### Fail closed

Anything the evaluator can't interpret denies: an unknown attribute, operand or condition type, a
resource type with no registered extractor, and an extractor that throws or returns an undeclared
attribute. The prototype's registry already rejects undeclared attributes at construction.

Two existing allow paths are outside this rule:

- With authorization disabled (`camunda.security.authorizations.enabled=false`), every check allows.
  That is the explicit off switch and stays as it is.
- With authorization enabled, a check with no resource IDs or no property names still allows. That is
  a defect, fixed separately in
  [#749](https://github.com/camunda/camunda-security-library/issues/749).

### Conditional memberships never appear in the id lists

Every reader of `authenticatedRoleIds` and the other id lists on `CamundaAuthentication` takes them
to mean "the principal has these memberships everywhere". None of those readers knows about
conditions. So the id lists hold global memberships only, and conditional memberships go in a
separate component that only condition-aware code reads.

For example, Alice is a global Viewer, and a Reviewer only in the Payments workspace:

```
authenticatedRoleIds   = [viewer]
conditionalMemberships = [reviewer, WORKSPACE ∈ {payments}]
```

A check that doesn't know about conditions sees only `viewer`, so it can't give Alice Reviewer
rights in the HR workspace. If `reviewer` were in `authenticatedRoleIds`, that check would allow it.
A reader that misses the new component denies instead of over-granting.

### Role ids come only from role memberships

`authenticatedRoleIds` holds the IDs of role entities that own grants, resolved through
`MembershipPort`. It never holds authorities taken from the token.

Today `JwtGrantedAuthoritiesAuthenticationConverter` fills it with the token's Spring authorities.
A token with `roles: ["admin"]` then gets every grant owned by the stored role `admin`, so whoever
controls the token's content picks the role entities ([camunda-hub#30035](https://github.com/camunda/camunda-hub/issues/30035)).
That's the same trust problem as a principal operand read from a claim, and it grows once Hub's
roles carry workspace conditions.

That converter therefore stops filling `authenticatedRoleIds`. A host that relies on roles from the
token maps them to store roles itself, or carries them in a separate field that the authorization
check doesn't read as role IDs. Changing the converter is follow-up work.

### Principal operands only for trusted attributes

Memberships accept both operands. A `Principal` operand lets a membership express a condition
relative to the caller, for example a role that applies only to tasks where `ASSIGNEE ∈ Principal(USERNAME)`.

A `Principal` operand may refer only to attributes backed by the identity store: `USERNAME` and
`CLIENT_ID` always, and `GROUP_IDS` and `TENANT_IDS` only when the host reads them from its identity
store. Raw token claims are never an operand. When a host takes group or tenant IDs from a token
claim, a condition on that attribute fails closed, because a forged or misconfigured claim could
otherwise satisfy it.

### Attribute catalogue

The attributes a condition can use are a fixed list: the `ResourceAttribute` enum in CSL. A host
can't add its own. Adding an attribute is a change to CSL, reviewed by the Identity team, as
[ADR-0008](0008-authz-enum-ownership-and-layered-usage.md) does for the other authorization enums.
This replaces the open catalogue in the PDP plan (task 5.1.3).

A fixed list lets CSL check each host's mappings at startup. Each resource type declares the
attributes it supports, and the extractor registry rejects an extractor that declares an attribute
its resource type doesn't support.

If hosts could define their own attributes, CSL couldn't check their mappings at all. Say Hub adds
`PROJECT` and gives Alice the membership `editor, PROJECT ∈ {apollo}`. A check that runs where
nothing maps `PROJECT` can't tell whether a resource belongs to `apollo`, so the fail-closed rule
denies. Access isn't widened, but Alice's membership quietly grants nothing there, and nobody finds
out until she reports it.

Each host maps every attribute it supports twice: in a `ResourceAttributeExtractor` for single
checks, and in its `ResourceAccessFilterTranslator` for list queries. A host that maps an attribute
in only one of the two denies it in the other, so a drift between the two can only narrow access.

### Direct authorizations: out of the first delivery

Only memberships carry conditions. Conditions on direct authorizations need their own compatibility
design and get their own ADR. When they come, they must use a new type, not a new field on
`Authorization`, so a reader that ignores conditions can't read a conditional grant as unconditional.

### Membership resolution is decoupled from claim conversion

Conditional memberships are resolved through `MembershipPort` and exposed on `CamundaAuthentication`
as a lazy component, keeping ADR-0005's lazy loading. They aren't resolved inside
`LazyTokenClaimsConverter`, as the prototype does, because authorization must not depend on how a
token's claims are converted
([camunda-hub#30035](https://github.com/camunda/camunda-hub/issues/30035)).

### Relation to the policy change-set (#729)

In the first delivery, conditional memberships are host-local: Hub stores and evaluates them, and
they aren't fanned out to OC. The change-set's membership identity
([#729](https://github.com/camunda/camunda-security-library/pull/729)) stays as it is. Adding
conditions to that identity needs its own ADR and a `MembershipPort` change, as #729 itself notes.

### Relation to other ADRs

- [ADR-0008](0008-authz-enum-ownership-and-layered-usage.md): `ResourceAttribute` follows the same
  ownership rule. Whether Hub-only resource types are added is decided in
  [#747](https://github.com/camunda/camunda-security-library/issues/747).
- [ADR-0014](0014-unified-authz-framework-in-core.md): single checks and the list filter
  ([#748](https://github.com/camunda/camunda-security-library/issues/748)) both go through
  `AuthorizationCheckPort`.
- [ADR-0013](0013-camunda-security-scope-provider-spi.md): tenant isolation stays separate. This
  doesn't rule out a tenant attribute later.

## Consequences

**Positive**

- One model covers any restriction Hub needs, such as workspace or process application, without a
  new membership type per restriction.
- Readers that don't know about conditions stay safe: they see only global memberships.
- Each rule that could widen access fails closed.

**Negative / accepted trade-offs**

- Each host maps every attribute twice, in an extractor and a query translation.
- Group and tenant memberships, and direct authorizations, can't carry conditions yet.
- Conditional memberships don't reach OC until a later ADR adds them to the change-set.
- The closed attribute catalogue means a new kind of condition needs a CSL release.
- A host that takes group or tenant IDs from a token claim, as OC can, can't use `GROUP_IDS` or
  `TENANT_IDS` as a principal operand: those conditions deny.
- `JwtGrantedAuthoritiesAuthenticationConverter` can no longer feed token authorities into
  `authenticatedRoleIds`. Hosts that use it, such as SaaS deployments that read roles from a claim,
  need a migration.

## Alternatives Considered

- **Call the concept a "context".** Rejected — a context reads as a place, but a membership's
  conditions can also be relative to the caller, such as "tasks assigned to me". A list of contexts
  also reads as "any of these", while conditions are combined with AND.
- **Call the concept a "scope".** Rejected — "scope" already means tenant isolation in CSL
  ([ADR-0013](0013-camunda-security-scope-provider-spi.md)).
- **Call the concept a "governance boundary".** Rejected — it names Hub's first use case, not the
  model, and doesn't fit a condition relative to the caller.
- **Use "condition" in the code and "context" in product wording.** Rejected — the API is part of
  the product, so two names would need a mapping in every doc, answer and integration.
- **Scoped role memberships, a `(scopeType, scopeId)` pair on the membership.** Rejected — it fits
  one restriction per membership and one attribute per restriction, and "scope" already means
  tenant isolation in CSL.
- **Conditions on direct authorizations in the first delivery.** Rejected for now — it needs its own
  compatibility design, and memberships are enough for Hub's first use case.
- **An open, host-defined attribute catalogue.** Rejected — nothing would check that a host maps
  the attributes it uses, so a membership could silently grant nothing, and ADR-0008 keeps
  authorization enums owned centrally.
- **Resolve conditional memberships inside `LazyTokenClaimsConverter`.** Rejected — it couples
  authorization to claim conversion.
