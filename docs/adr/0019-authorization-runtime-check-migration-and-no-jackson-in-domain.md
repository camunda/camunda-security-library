---
status: Accepted
---

# ADR-0019: Migrate OC's `Authorization<T>` runtime check spec to CSL as `RequiredAuthorization<T>`; keep the CSL domain Jackson-free

**Deciders**: @p-wunderlich

## Status

Accepted

## Context

Two CSL concerns converge in this decision.

### A new class to migrate, and a name collision

CSL already owns a record called `Authorization` in `api/model/authz/`. It is the **granted-authorization record** returned by `AuthorizationRepositoryPort`: `(ResourceType, resourceId, Set<PermissionType>)`. The library aggregates these records across a principal's identities to answer permission questions. Renaming this record is technically possible but would touch every OC implementer of `AuthorizationRepositoryPort.findAuthorizations()` plus their tests — disproportionate churn for the migration this ADR is about, and orthogonal to the migration itself.

Separately, OC carries `io.camunda.security.auth.Authorization<T>` — a **runtime authorization check spec**: a generic record (`AuthorizationResourceType`, `PermissionType`, resource IDs, optional `Function<T,String>` ID supplier, optional `Predicate<T>` condition, transitive flag) used by ~170 production and test sites across the engine, REST controllers, and security checkers to express *"this caller needs this kind of access on this kind of resource"*. Following [ADR-0016](0016-authz-enum-ownership-and-layered-usage.md) — which places the authoritative authz enums in CSL — this runtime check spec belongs in CSL too. The problem is the name collision with CSL's existing `Authorization` record.

We disambiguate by giving the migrated class a *different* name in CSL: `RequiredAuthorization<T>`, landing in `io.camunda.security.core.auth`. It pairs symmetrically with the existing `Authorization` (the implicitly *granted* record) and is free of collisions in either repo. The wrapper and composition layers immediately above it — `AuthorizationCheck` (enable/disable wrapper) and `AuthorizationCondition` (AND/OR composition) — are already taken in OC for those very different responsibilities.

### Jackson on a CSL domain record

OC's `Authorization<T>` carries Jackson annotations: `@JsonAutoDetect(ANY)`, four `@JsonProperty("snake_case")` renames, and two `@JsonIgnore` markers on the non-serializable `Function`/`Predicate` fields. The annotations exist to support **one** runtime path: MsgPack serialization of the `authorizationCheck` field on `BatchOperationCreationRecord`, written by `BrokerCreateBatchOperationRequest` and read back in `BatchOperationCreationCreateProcessor`. Both endpoints share OC's `MsgPackConverter`.

Prior to this decision CSL guardrails permitted `jackson-annotations` in the domain (runtime Jackson was forbidden). In practice **no CSL production code uses any Jackson annotation today** — the carve-out is unused. Migrating the runtime check spec with annotations intact would introduce the first Jackson coupling in `core/` or `api/`, against the spirit of the framework-free domain.

OC has already solved the equivalent problem for `CamundaAuthentication`: `MsgPackConverter` registers a `CamundaAuthenticationMixin` that supplies snake-case `@JsonProperty` names and `@JsonIgnore` markers on the host-side `ObjectMapper`, leaving the CSL record untouched. This ADR answers: how should CSL name and place the migrated runtime authorization check spec, and how can CSL keep its domain free of Jackson dependencies?

## Decision

1. **Migrate OC's `Authorization<T>` into CSL as `io.camunda.security.core.auth.RequiredAuthorization<T>`** (in the `core` module, not `api`, because the type carries `Function<T,String>` and `Predicate<T>` — runtime check semantics, not a public data shape). CSL's existing `Authorization` record in `api/model/authz/` stays put.

2. **Strip all Jackson annotations during the move.** The migrated class has no `@JsonAutoDetect`, no `@JsonProperty`, no `@JsonIgnore`, and no `com.fasterxml.jackson.*` imports.

3. **OC registers a `RequiredAuthorizationMixin` in `MsgPackConverter`** alongside the existing `CamundaAuthenticationMixin`. The mixin declares the same `@JsonAutoDetect(ANY)`, the four `@JsonProperty("snake_case")` renames, and `@JsonIgnore` on `resourceIdSupplier()` and `condition()`. Wire format on the `BatchOperationCreationRecord.authorizationCheck` field is unchanged.

4. **Tighten the CSL guardrail to forbid all Jackson in the domain.** `.claude/docs/guardrails.md` drops the *"(jackson-annotations are permitted)"* carve-out. The ArchUnit rules `CORE_MUST_NOT_DEPEND_ON_JACKSON_RUNTIME` and `API_MUST_NOT_DEPEND_ON_JACKSON_RUNTIME` are renamed to `*_MUST_NOT_DEPEND_ON_JACKSON` and tightened to reject the entire `com.fasterxml.jackson..` package (no annotation-package exception).

## Why `RequiredAuthorization`

The class is the *atom* on which OC's authorization-check vocabulary is built: `AuthorizationCondition` holds a list of these and composes them with AND/OR; `AuthorizationCheck` wraps an enabled/disabled `AuthorizationCondition`; `AuthorizationChecker` evaluates the whole thing against the runtime context. Naming the atom after what callers *use* it for — "the authorization the caller is required to have" — keeps the existing surrounding vocabulary readable without forcing renames on the wrappers.

`RequiredAuthorization` pairs with CSL's existing (implicitly granted) `Authorization`, mirroring the conceptual duality at the heart of every authorization check: *required* (what the caller needs) vs *granted* (what the caller actually has).

## Alternatives Considered

### Option A (chosen): Migrate `Authorization<T>` as `RequiredAuthorization<T>`; strip Jackson; mixin on OC

- **Pro:** No churn on CSL's existing `Authorization` (granted) record or its consumers. CSL domain stays Jackson-free in fact, not just in spirit. ArchUnit and guardrails enforce the policy mechanically. Wire format unchanged via OC mixin.
- **Con:** OC's ~170 callers update both the import path *and* the type name (`Authorization<…>` → `RequiredAuthorization<…>`). The wrappers `AuthorizationCondition` / `AuthorizationCheck` / `AuthorizationChecker` carry the rename through their internals.

### Option B: Rename CSL's existing `Authorization` to `GrantedAuthorization`; keep the migrated class named `Authorization`

- **Pro:** The migrated class keeps its existing OC name; callers only swap imports.
- **Con:** Renames a stable, already-shipped CSL public type. Every OC implementer of `AuthorizationRepositoryPort.findAuthorizations()` plus all their tests need updating, on top of the ~170 callers of the migrated class. The two renames compound; one of them is unnecessary.

### Option C: Migrate `Authorization<T>` with annotations intact

- **Pro:** Smallest CSL diff for the Jackson concern. No OC change beyond the import swap.
- **Con:** Introduces the first Jackson coupling in CSL domain code. The guardrails technically allow it today, but adopting it sets a precedent and erodes the framework-free property of `core`/`api`. No follow-up cleanup is planned, so the annotations persist indefinitely. Option A makes the policy mechanical via the tightened guardrail.

## Consequences

**Positive**

- The CSL `core`/`api` modules are guaranteed Jackson-free at compile time. Adopters consume the public types without any Jackson coupling on the classpath.
- The mixin pattern is consistent across `CamundaAuthentication` and `RequiredAuthorization`: both records live in CSL annotation-free; both have host-side mixins in OC's `MsgPackConverter`.
- The `Authorization` / `RequiredAuthorization` pair establishes a clear vocabulary — *granted* (data shape returned by repositories) vs *required* (runtime check spec evaluated against the granted set).

**Negative / accepted trade-offs**

- When `RequiredAuthorization<T>` gains or loses a record component, OC's `RequiredAuthorizationMixin` must be updated to match. Tests in OC's `JsonSerializableToJsonTest` and a `RequiredAuthorization<?>` round-trip in `MsgPackConverterAuthenticationCompatibilityTest` (or a sibling) anchor this: a divergence between record components and mixin will surface as a test failure on the serialized JSON shape.
- Any future host that wants a custom JSON shape for a CSL type must follow the same pattern (host-side mixin) — adding annotations directly to a CSL record is no longer permitted.
- The CSL release that introduces `RequiredAuthorization<T>` must precede the OC integration PR. OC's mixin registration and the ~170 import-and-type-rename updates depend on the new CSL package; until OC picks up the new artifact, OC's existing `io.camunda.security.auth.Authorization` continues to serve.
