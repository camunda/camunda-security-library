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

This decision reverses the central rule of ADR-0008. It therefore supersedes ADR-0008. The background and the options are in the summary at https://claude.ai/artifact/6CqNtjKbE7V7zDYNsXqWF2

## Decision

**D1. CSL owns the mechanism, not the catalogues.**
CSL evaluates a `RequiredAuthorization` against the granted `AuthorizationScope`s over an abstract resource type and an abstract permission type. CSL does not define the host resource types or permission types. This reverses ADR-0008, which made CSL the canonical owner of both enums.

**D2. The abstract types are host-supplied contracts, matched by name.**
CSL defines an abstract resource-type contract and an abstract permission-type contract. Host catalogues supply the concrete values. CSL compares them by name. The concrete shape of each contract is an implementation choice for [#880](https://github.com/camunda/camunda-security-library/issues/880). A marker interface that host enums implement keeps compile-time safety, and it lets the existing `AuthorizationResourceType` and `PermissionType` implement the contracts, so the first step can stay additive. An opaque value, for example a string, is simpler but changes every call site at once.

**D3. CSL keeps only the types that it reasons about.**
`TENANT` stays, because `AuthorizationService` has `TENANT`-specific behaviour (the tenant rejection). `COMPONENT` and `ACCESS` stay, because CSL's own `WebAppAuthorizationCheckFilter` reasons about them — it asks the check port for `ACCESS` on the resolved web app as a `COMPONENT` resource ([ADR-0014](0014-unified-authz-framework-in-core.md) §10). CSL keeps the permission types that its own retained types need, for example the CRUD actions on `TENANT`. Review the other policy-model resource types (`ROLE`, `GROUP`, `USER`, `MAPPING_RULE`, `AUTHORIZATION`, `ORGANIZATION`) and their permissions. Keep one only if CSL logic needs it, not for completeness.

**D4. Hosts own their catalogues and the supported-permission metadata.**
OC owns the engine resource types, the matching permission types, and the typed builder helpers (`processDefinition()`, `userTask()`, and the others). The `resourceType → supported PermissionType` mapping travels with the resource type. The host owns this mapping for host types, and CSL keeps it only for its retained types. `AuthorizationResourceType#getSupportedPermissionTypes()` and `buildResourcePermissionsMap()` move to the host side for host types. The engine keeps its own enforcement enums. Hub owns its own catalogues later.

**D5. The migration is staged.**
The first step adds the contracts in CSL ([#880](https://github.com/camunda/camunda-security-library/issues/880)) and keeps the existing enums, so it can be additive if the chosen contract shape allows it. Later steps remove the host types from CSL and move them to OC (camunda/camunda#67685). CSL releases between the steps stay compatible. On acceptance, the status of ADR-0008 changes to `Superseded by ADR-0050`, per the supersession process in [docs/workflows/adr.md](../workflows/adr.md).

## Alternatives considered

- **Delegate the permission metadata only.** The engine enum keeps only names, and gets its permissions from CSL through the mapper. This removes most of the duplicate code, but it keeps the catalogues and the leak in CSL. It is a short-term fix, not an ownership fix.
- **Combine into one enum.** Delete the engine copies and use the CSL types everywhere. This is a very large migration, and it ties the engine wire format to the CSL release schedule.
- **Generate the engine enums from CSL.** This removes the duplication but adds build complexity.
- **Move resource types only, and keep ADR-0008 for permissions.** This leaves `PermissionType` CSL-owned, so the same leak and the same Hub problem stay for permissions. It also only partly supersedes ADR-0008. A split ownership (host resource types, CSL permission types) is harder to explain than one rule.

## Consequences

- CSL core and api hold no host resource type and no host permission type. The opaque-scope-key rule now also covers the authorization types.
- Hub onboarding adds no types to CSL. Hub gets a complete set from its own catalogue, not from CSL. This replaces the Hub rationale in ADR-0008.
- The cross-repo mirror and its `AuthzModelMapperTest` parity burden move into `camunda/camunda`, or go away.
- CSL loses the typed builder helpers for host types. OC keeps them on its side.
- The engine keeps its own typed enums for enforcement. They do not become string-typed.
- OC callers that use the typed builder methods change when the host types move (camunda/camunda#67685).
- [#813](https://github.com/camunda/camunda-security-library/issues/813) is reshaped: Hub types go to the Hub host, not to CSL.

## Source

- Background and the options: https://claude.ai/artifact/6CqNtjKbE7V7zDYNsXqWF2
- Supersedes [ADR-0008](0008-authz-enum-ownership-and-layered-usage.md).
- Issues: [#880](https://github.com/camunda/camunda-security-library/issues/880), camunda/camunda#67685, [#813](https://github.com/camunda/camunda-security-library/issues/813), [#793](https://github.com/camunda/camunda-security-library/issues/793)
- Related ADRs: [ADR-0013](0013-camunda-security-scope-provider-spi.md), [ADR-0009](0009-session-store-port-and-web-session-ownership.md), [ADR-0019](0019-authorization-check-latency-metric.md)
