# ADR-0050: Hosts own the authorization type catalogues; CSL reasons over abstract resource and permission types

**DRI**: Ben Sheppard (Ben-Sheppard)

**Deciders**: Ben Sheppard (Ben-Sheppard), Bojan Mudric (bmudric)

**Status**: Proposed. On acceptance, this ADR supersedes [ADR-0008](0008-authz-enum-ownership-and-layered-usage.md).

**Purpose**: Defines which layer owns the resource-type and permission-type catalogues, and how CSL evaluates authorization without knowledge of the concrete types.

**Audience**: CSL maintainers, and OC and Hub engineers who define or use authorization types.

## Context

[ADR-0008](0008-authz-enum-ownership-and-layered-usage.md) made CSL the canonical owner of the `AuthorizationResourceType` and `PermissionType` enums in `io.camunda.security.api.model.authz`. The goal was a complete, host-independent set of values, so that Hub operators can maintain authorization rules. The engine record protocol keeps its own enums, and `AuthzModelMapper` bridges them.

This ownership has a cost. The CSL enums hold host and engine vocabulary, for example `PROCESS_DEFINITION`, `BATCH`, `USER_TASK`, and `CREATE_BATCH_OPERATION_*`. Each new value needs an edit and a version bump in the CSL enum and in the mirrored engine enum. CSL core knows host concepts. This breaks the CSL rule that core holds no host concept — core uses only an opaque scope key, and the host maps it ([ADR-0013](0013-camunda-security-scope-provider-spi.md), [ADR-0009](0009-session-store-port-and-web-session-ownership.md), [ADR-0019](0019-authorization-check-latency-metric.md)). Hub onboarding ([#813](https://github.com/camunda/camunda-security-library/issues/813)) adds more host types to CSL, so the leak grows.

The check mechanism does not need the concrete types. `AuthorizationService` and `AuthorizationChecker` match the resource type and the permission as keys. They do not test specific values. Only `TENANT` has special behaviour, and `TENANT` is a CSL policy-model concept.

This decision reverses the central rule of ADR-0008. It therefore supersedes ADR-0008.

### Background: the mirrored enums

Today the resource type and the permission type exist in two copies. CSL holds one copy in `AuthorizationResourceType` and `PermissionType`. The engine record protocol holds the other copy in `camunda/camunda`. `AuthzModelMapper` converts between them by the enum name (`valueOf(value.name())`). The `AuthzModelMapperTest` parity tests fail if the two copies differ.

The engine copy has a reason to exist. The engine writes authorization records to storage (RocksDB), and exporters read them into ES, OS, or RDBMS. The engine enum is a storage contract, so it must stay stable and independent of the CSL release schedule. The match by name lets the two enums keep a different order and evolve apart, as long as the names stay equal.

The cost is the duplicate permission list. To add one resource type, you write the full definition in CSL and the same permission list again in the engine enum. The constant name is one line, but the permission list is long. Since May 2026, every change to the CSL enums was an OC type or an OC permission, about one each month, and each change needed two repositories and a release. No change touched a shared type.

The check mechanism does not need the concrete types. So CSL can own the mechanism and let the host own the catalogue. This is Option 4 of the options that the team reviewed, and it is the decision below. ADR-0008 rejected a similar no-catalogue direction (its Option C, "CSL uses string constants"). The reason was that CSL does not enumerate all values, so Hub cannot maintain the rules. That objection no longer holds. OC publishes its catalogue, and Hub validates its rules against it (D4), so Hub gets a complete set without a CSL catalogue.

## Decision

**D1. CSL owns the mechanism, not the catalogues.**
CSL evaluates a `RequiredAuthorization` against the granted `AuthorizationScope`s over an abstract resource type and an abstract permission type. CSL does not define the host resource types or permission types. This reverses ADR-0008, which made CSL the canonical owner of both enums.

**D2. The abstract types are host-supplied contracts, matched by name.**
CSL defines an abstract resource-type contract and an abstract permission-type contract. Host catalogues supply the concrete values. Each contract is a marker interface that the host enums implement. The existing `AuthorizationResourceType` and `PermissionType` implement the contracts too, so the first step stays additive. CSL compares and stores `name()` values only. Two contract values with the same `name()` are the same type for the check, even when they come from different enums. Java enums cannot override `equals` and `hashCode`, so an object match fails across enums, and the `name()` rule is the fix. [#880](https://github.com/camunda/camunda-security-library/issues/880) implements this shape.

**D3. CSL keeps the types that CSL owns.**
CSL keeps a type if CSL owns the entity, not only if CSL logic needs it. The CSL-owned types are the Unified Policy Model types (`TENANT`, `ROLE`, `GROUP`, `USER`, `MAPPING_RULE`, `AUTHORIZATION`, and `ORGANIZATION`) and `COMPONENT` with `ACCESS`. CSL authors these entities, so they are CSL types, not exceptions. The ownership test replaces the earlier "keep only if CSL logic needs it" test, which let a later review move an owned entity such as `ROLE` to a host. Two owned types also carry CSL logic. `AuthorizationService` has `TENANT`-specific behaviour (the tenant rejection). `WebAppAuthorizationCheckFilter` asks the check port for `ACCESS` on the resolved web app as a `COMPONENT` resource ([ADR-0014](0014-unified-authz-framework-in-core.md) §10). CSL keeps the permission types that its owned types need, for example the CRUD actions on `TENANT`.

**D4. Hosts own their catalogues and the supported-permission metadata.**
OC owns the engine resource types, the matching permission types, and the typed builder helpers (`processDefinition()`, `userTask()`, and the others). The engine protocol enum in `camunda-security-protocol` is the single source of the OC types, and it implements the CSL contract from D2. `camunda-security-protocol` already depends on `camunda-security-library-api`, so the OC types need no new enum and no new mapping. The `resourceType → supported PermissionType` mapping travels with the resource type. The host owns this mapping for host types, and CSL keeps it only for its owned types. `AuthorizationResourceType#getSupportedPermissionTypes()` and `buildResourcePermissionsMap()` move to the host side for host types.

Hub owns only the types that only Hub uses. Hub does not own the OC types. In the `oc-managed` strategy, Hub authors policies for OC, so Hub uses the OC types through the catalogue that OC publishes. Hub keeps the type names as opaque values and validates them against that catalogue.

**D5. The migration is staged.**
The first step adds the contracts in CSL ([#880](https://github.com/camunda/camunda-security-library/issues/880)) and keeps the existing enums, so it can be additive if the chosen contract shape allows it. Later steps remove the host types from CSL and move them to OC (camunda/camunda#67685). CSL releases between the steps stay compatible. On acceptance, the status of ADR-0008 changes to `Superseded by ADR-0050`, per the supersession process in [docs/workflows/adr.md](../workflows/adr.md).

**D6. Two rules enforce the ownership, one for each direction.**
A host type must not leak into CSL core. An ArchUnit rule in the CSL build enforces this. The rule covers all of `io.camunda.security.core..`, as the existing `DomainArchTest` does for the protocol boundary, not only `core.authz`. The wider scope also covers the requirement builders in `core.auth` (`RequiredAuthorization`), which hold the typed helpers (`processDefinition()`, `userTask()`) until D4 moves them to the host side. The core classes depend only on the abstract contracts from D2 and the CSL enums that carry the owned types. They do not depend on a concrete host enum or on `camunda-security-protocol`. A host must use the CSL constants for the owned types. ArchUnit cannot check this, because the CSL build does not see the host code. CSL ships a contract test that each host runs in its build. The test makes sure that each owned type maps once from a host constant with the same name. It also makes sure that no other host constant uses a CSL name. The ArchUnit rule works because the migration splits the owned types and the host types into different Java types. ArchUnit checks type dependencies, not single enum constants.

## Open points

These need a decision in the next revision, with @p-wunderlich and @StevePascoe. The shared-kernel approach above (owned types as CSL constants, name-based matching, the host contract test) needs their sign-off before the ADR moves to Accepted.

- How OC publishes its catalogue to Hub: runtime registration, or a versioned schema file.
- What OC does with an unknown type when the Hub policy and the OC cluster run different versions. One option is to skip the authorization and log a warning. The other is to reject the whole snapshot. A skip denies more access than the Hub policy shows. A reject also blocks the next changes, which include revocations.
- The host-supplied registry that converts a name into a type. Configuration binding needs it, because `ConfiguredAuthorization` binds the enums by name and Spring cannot bind an interface. Persistence and the Hub snapshots also need it.

## Alternatives considered

- **Delegate the permission metadata only.** The engine enum keeps only names, and gets its permissions from CSL through the mapper. This removes most of the duplicate code, but it keeps the catalogues and the leak in CSL. It is a short-term fix, not an ownership fix.
- **Combine into one enum.** Delete the engine copies and use the CSL types everywhere. This is a very large migration, and it ties the engine wire format to the CSL release schedule.
- **Generate the engine enums from CSL.** This removes the duplication but adds build complexity.
- **Move resource types only, and keep ADR-0008 for permissions.** This leaves `PermissionType` CSL-owned, so the same leak and the same Hub problem stay for permissions. It also only partly supersedes ADR-0008. A split ownership (host resource types, CSL permission types) is harder to explain than one rule.

## Consequences

- CSL core and api hold no host resource type and no host permission type. The opaque-scope-key rule now also covers the authorization types.
- Hub onboarding adds no types to CSL. Hub owns only the Hub types, and Hub uses the OC catalogue for the OC types. This replaces the Hub rationale in ADR-0008.
- The mapping in `camunda/camunda` covers only the shared CSL types. `AuthzModelMapper` no longer maps every type and every permission, so the `AuthzModelMapperTest` parity burden gets small.
- CSL loses the typed builder helpers for host types. OC keeps them on its side.
- The engine keeps its own typed enums for enforcement. They do not become string-typed.
- OC callers that use the typed builder methods change when the host types move (camunda/camunda#67685).
- [#813](https://github.com/camunda/camunda-security-library/issues/813) is reshaped: Hub types go to the Hub host, not to CSL.

## Source

- Supersedes [ADR-0008](0008-authz-enum-ownership-and-layered-usage.md).
- Issues: [#880](https://github.com/camunda/camunda-security-library/issues/880), camunda/camunda#67685, [#813](https://github.com/camunda/camunda-security-library/issues/813), [#793](https://github.com/camunda/camunda-security-library/issues/793)
- Related ADRs: [ADR-0013](0013-camunda-security-scope-provider-spi.md), [ADR-0009](0009-session-store-port-and-web-session-ownership.md), [ADR-0019](0019-authorization-check-latency-metric.md)
