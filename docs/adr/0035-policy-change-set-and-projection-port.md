---
status: Proposed
---

# ADR-0035: Policy change-set model and `PolicyProjectionPort`

**Deciders**: Patrick Wunderlich

## Status

Proposed. Scoped to the proof of concept for Hub to Orchestration Cluster (OC) policy fan-out. It can change when the PoCs report back.

## Context

Several PoCs need one contract for the fan-out of policy from Hub to the OCs. A pull mechanism outside CSL fetches policy changes from Hub, either as deltas or as a full snapshot. An adapter outside CSL pushes them to the broker as engine commands. CSL has to supply two things: a transport-ready model of the policy changes, and the outbound port that the pull code calls.

The shape follows [the unified policy model](../vision/unified-policy-model.md) and [the policy version change sets](../vision/policy-version-change-sets.md). It extends the shipped vocabulary (`AuthorizationOwnerType`, `AuthorizationResourceType`, `PermissionType`, `AuthorizationResourceMatcher`, `EntityType`) and does not invent a new one. The link to the unified policy model resolves once PR #645 lands.

## Decision

**Model.** `io.camunda.security.api.model.policy` holds plain records: `PolicyChangeSet(policyVersion, kind, upserts, deletions)` with the entities `PolicyTenant`, `PolicyRole`, `PolicyGroup`, `PolicyMappingRule`, `PolicyMembership` and `PolicyAuthorization`. The `Policy` prefix avoids a clash with `authz.Authorization`. Memberships are entities of their own, so a single membership can be deleted. Users and clients are not entities: they appear only as members and as authorization owners, as in OC under OIDC.

**Jackson-friendly records, host-owned wrapper.** A change set is the payload of a wrapper event that the PoCs own (event ID, timestamp, target cluster). `api` stays free of Jackson. The records have only canonical constructors, no static factories and no `get*`/`is*` helpers, so a plain `ObjectMapper` round-trips them without annotations or mixins. Validation lives in the compact constructors and therefore also runs on incoming JSON. Missing lists become empty lists.

**SNAPSHOT and DELTA.** A SNAPSHOT is the authoritative full state, but only over entities that the projection itself created earlier. It never removes bootstrap entities such as the default roles, nor users or clients, so it cannot lock out the admin. A SNAPSHOT has no deletions. A DELTA applies exactly the listed upserts and deletions. The puller guarantees contiguous versions and fetches a SNAPSHOT when it finds a gap, so there is no `baseVersion`. Applying a `policyVersion` twice must be harmless.

**Canonical memberships.** Only the pairs that the engine accepts are allowed, in one direction: roles take users, clients, mapping rules and groups; groups take users, clients and mapping rules; tenants take users, clients, mapping rules, groups and roles. The reverse form (a role in a group) is rejected.

**Identity of authorizations and deletes.** `PolicyAuthorizationKey` (owner, resource type, matcher, resource ID, property name) identifies an authorization, validated per matcher like `AuthorizationScope`. A change set holds at most one authorization per key, and its permission set is the complete set for that key. The adapter reconciles an upsert to exactly this set and removes every engine authorization that matches the key on a delete, so no Hub-ID to engine-key table is needed. Memberships are deleted by their four components.

**Apply order.** Upsert tenants, roles, groups and mapping rules; upsert memberships; upsert authorizations; delete authorizations; delete memberships; delete mapping rules, groups, roles and tenants. The adapter enforces it, CSL does not run it. The engine cascades deletes of tenants, roles, groups and mapping rules to their memberships and owned authorizations, so Hub need not list them.

**The port.** `PolicyProjectionPort.apply(PolicyChangeSet)` is an outbound port in `core/port/out`. Host adapters implement it, for example by pushing engine commands. It throws on failure and the caller retries the same version. It is not named `EngineCommandPort`, because the contract carries policy state and not engine commands, and another projection, such as Optimize, can use it later. The `EngineCommandPort` mentions in the architecture docs stay as design vocabulary, and `PolicyProjectionPort` is its PoC realisation.

## Out of scope

No `(scopeType, scopeId)` on assignments: that needs its own ADR and a `MembershipPort` change. No inbound API or service: `PolicyApplyPort`, `PolicyPort`, `OutboxPort` and `PolicyRepositoryPort` stay as they are. No user or client entities. No wire format, event envelope or transport: the PoCs own them.

## Consequences

**Positive**

- The PoCs share one model and one port, and they can serialize the model with Jackson as it is.
- Invalid payloads fail at the deserialization boundary.
- A projection to the engine, or later to another system, needs no knowledge of Hub internals.

**Negative / accepted trade-offs**

- Without scope on assignments, the model cannot yet express targeted role assignments.
- The "created by the projection" rule for snapshots needs state in the adapter.
- The model is a PoC contract and may change once the PoCs report back.
