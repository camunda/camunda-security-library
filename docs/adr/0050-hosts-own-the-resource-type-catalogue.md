# ADR-0050: Hosts own the authorization resource-type catalogue; CSL reasons over an abstract resource type

**DRI**: Ben Sheppard (Ben-Sheppard)

**Deciders**: Ben Sheppard (Ben-Sheppard), Bojan Mudric (bojan-mudric)

**Status**: Proposed

**Purpose**: Defines which layer owns the resource-type catalogue, and how CSL evaluates authorization without knowledge of the concrete resource types.

**Audience**: CSL maintainers, and OC and Hub engineers who define or use resource types.

## Context

CSL's `api` module owns `AuthorizationResourceType`. This enum holds OC and engine resource types, for example `PROCESS_DEFINITION`, `BATCH`, and `USER_TASK`. The engine record protocol holds a second, almost identical enum. Each new value needs an edit and a version bump in both places.

This duplicate has a deeper cause. CSL core knows host resource types. This breaks the CSL rule that core holds no host concept. Core uses only an opaque scope key, and the host maps it ([ADR-0013](0013-camunda-security-scope-provider-spi.md), [ADR-0009](0009-session-store-port-and-web-session-ownership.md), [ADR-0019](0019-authorization-check-latency-metric.md)). Hub onboarding ([#813](https://github.com/camunda/camunda-security-library/issues/813)) adds more host types to CSL, so the leak grows.

The check mechanism does not need the concrete types. `AuthorizationService` and `AuthorizationChecker` match the resource type as a key. They do not test specific values. Only `TENANT` has special behaviour, and `TENANT` is a CSL policy-model concept. The background and the options are in the summary at https://claude.ai/artifact/6CqNtjKbE7V7zDYNsXqWF2

## Decision

**D1. CSL owns the mechanism, not the catalogue.**
CSL evaluates a `RequiredAuthorization` against the granted `AuthorizationScope`s over an abstract resource type. CSL does not define the host resource types.

**D2. The abstract resource type is a host-supplied contract, matched by name.**
CSL defines an abstract resource-type contract. Host catalogues supply the concrete values. CSL compares them by name. The concrete shape of the contract is an implementation choice for [#880](https://github.com/camunda/camunda-security-library/issues/880). A marker interface that host enums implement keeps compile-time safety, and it lets the existing `AuthorizationResourceType` implement the contract, so the first step can stay additive. An opaque value, for example a string, is simpler but changes every call site at once.

**D3. CSL keeps only the resource types that it reasons about.**
`TENANT` stays, because `AuthorizationService` has `TENANT`-specific behaviour (the tenant rejection). Review the other policy-model entities (`ROLE`, `GROUP`, `USER`, `MAPPING_RULE`, `AUTHORIZATION`, `ORGANIZATION`). Keep one only if CSL logic needs it, not for completeness.

**D4. Hosts own their catalogues.**
OC owns the engine resource types and the typed builder helpers (`processDefinition()`, `userTask()`, and the others). The engine protocol enum and the OC catalogue both stay in `camunda/camunda`, so the mirror becomes one repository concern with no cross-repo superset. Hub owns its own types later.

**D5. The migration is staged.**
The first step adds the contract in CSL ([#880](https://github.com/camunda/camunda-security-library/issues/880)) and keeps the existing enum, so it can be additive if the chosen contract shape allows it. Later steps remove the host types from CSL and move them to OC (camunda/camunda#67685). CSL releases between the steps stay compatible.

## Alternatives considered

- **Delegate the permission metadata only.** The engine enum keeps only names, and gets its permissions from CSL through the mapper. This removes most of the duplicate code, but it keeps the catalogue and the leak in CSL. It is a short-term fix, not an ownership fix.
- **Combine into one enum.** Delete the engine copy and use the CSL type everywhere. This is a very large migration, and it ties the engine wire format to the CSL release schedule.
- **Generate the engine enum from CSL.** This removes the duplication but adds build complexity for a small enum.

## Consequences

- CSL core and api hold no host resource type. The opaque-scope-key rule now also covers resource types.
- Hub onboarding adds no resource types to CSL.
- The cross-repo mirror and its `AuthzModelMapperTest` parity burden move into `camunda/camunda`, or go away.
- CSL loses the typed builder helpers for host types. OC keeps them on its side.
- The engine keeps its own typed enum for enforcement. It does not become string-typed.
- OC callers that use the typed builder methods change when the host types move (camunda/camunda#67685).
- [#813](https://github.com/camunda/camunda-security-library/issues/813) is reshaped: Hub types go to the Hub host, not to CSL.

## Source

- Background and the options: https://claude.ai/artifact/6CqNtjKbE7V7zDYNsXqWF2
- Issues: [#880](https://github.com/camunda/camunda-security-library/issues/880), camunda/camunda#67685, [#813](https://github.com/camunda/camunda-security-library/issues/813), [#793](https://github.com/camunda/camunda-security-library/issues/793)
- Related ADRs: [ADR-0013](0013-camunda-security-scope-provider-spi.md), [ADR-0009](0009-session-store-port-and-web-session-ownership.md), [ADR-0019](0019-authorization-check-latency-metric.md)
