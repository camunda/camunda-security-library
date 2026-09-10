---
status: Accepted
---

# ADR-0008: CSL authz enums as the canonical source for Service, Search, Exporter, and Persistence layers

**Deciders**: @p-wunderlich, @Ben-Sheppard, @megglos

## Status

Accepted

## Context

The Camunda authorization model centres on two enums — `ResourceType` and `PermissionType` — that describe what resources exist and what operations can be performed on them. Before this decision, both enums lived exclusively in the Zeebe protocol module (`io.camunda.zeebe.protocol.record.value.AuthorizationResourceType` / `PermissionType`) inside OC (the `camunda` monorepo). CSL imported them from there, which created an inward dependency from a foundational library to a host application.

Three forces drove the change:

1. **Hub rule maintenance.** The Hub component needs a complete, stable set of all possible `ResourceType` and `PermissionType` values so that operators can maintain authorization rules. The source of truth must live in a host-independent library (CSL), not inside a host's protocol module.
2. **Serialization stability in Zeebe.** The existing Zeebe protocol enums are part of the RocksDB state-machine serialization and the log-stream schema. Renaming or removing values requires an entry in `ignored-changes.json` (revapi) and carries risk of silent data corruption or incompatibility across rolling upgrades. Replacing them at the engine layer would require careful migration work that is out of scope for this iteration.

### What "layer" means here

The Camunda monorepo is organized into horizontal layers. From innermost to outermost:

| Layer | Examples |
|---|---|
| Engine | Zeebe broker, state-machine, processor, log-stream |
| Persistence | RDBMS writers, RocksDB state, `*Writer` / `*Store` classes |
| Exporter | Elasticsearch / OpenSearch / RDBMS exporters |
| Search / Query | `*DbReader`, query services, REST search handlers |
| Service | `*Services` (command and query orchestration) |

The decision applies to the **Persistence, Exporter, Search, and Service** layers. The **Engine layer** is explicitly excluded.

## Decision

**CSL owns the canonical enum values.** The `ResourceType` and `PermissionType` enums in `io.camunda.security.api.model.authz` are the authoritative source for all possible authorization resource types and permission types across the Camunda platform.

**Persistence, Exporter, Search, and Service layers use the CSL enums.** Any new code in these layers that handles authorization resource types or permission types imports and uses the CSL enums directly. The `AuthzModelMapper` in OC translates between the old Zeebe protocol enums and the CSL enums at the seam between the Engine layer and the layers above.

**The Zeebe engine layer keeps its existing enums.** `io.camunda.zeebe.protocol.record.value.AuthorizationResourceType` and the protocol-level `PermissionType` remain unchanged. This preserves RocksDB serialization stability and log-stream schema compatibility without requiring a revapi exception entry.

**Hosts map to their own implementations.** OC implements `AuthorizationScopeRepositoryPort` with adapters that read from their data store (RDBMS, Elasticsearch, etc.) and return CSL `Authorization` records carrying CSL enum values. The `AuthzModelMapper` is the single translation point between Zeebe protocol values and CSL values.

## Options Considered

### Option A (chosen): CSL owns enum values; engine keeps its own; mapper bridges the gap

- Service, Search, Exporter, and Persistence layers use CSL enums.
- Engine layer keeps Zeebe protocol enums.
- `AuthzModelMapper` translates at the engine/service boundary.
- **Pro:** Hub gets a stable, complete list of values from CSL. No revapi changes needed. Engine serialization is unaffected. CSL does not depend on Zeebe protocol.
- **Con:** Two enum hierarchies must stay in sync when new resource types or permissions are introduced. New values must be added to both CSL enums and the Zeebe protocol enums (the latter also requiring SBE schema changes).

### Option B: CSL enums used everywhere, including the engine

- Replace Zeebe protocol enums with CSL enums end to end.
- **Pro:** Single source of truth, no mapper needed.
- **Con:** Requires changes to the RocksDB serialization format and the log-stream schema. Existing Zeebe protocol values are part of SBE-encoded records; renaming or reordering them without a migration path risks data corruption across rolling upgrades. Requires revapi `ignored-changes.json` entries, and the migration is out of scope for this iteration.

### Option C: Keep old OC enums everywhere; CSL uses string constants

- CSL does not define enums; it uses `String` for resource type and permission type values.
- **Pro:** No serialization risk; minimal change.
- **Con:** CSL cannot enumerate all possible values, making Hub rule maintenance impossible. Loses type safety in CSL-internal code (filters, permission checks). Does not satisfy the primary driver of this decision.

## Consequences

**Positive:**
- CSL becomes a single, versioned catalogue of all authorization resource types and permissions. Hub and other consumers can derive the full rule space from CSL alone.
- Engine serialization stability is preserved without any revapi exception entries.

**Negative / ongoing obligations:**
- When a new `ResourceType` or `PermissionType` value is introduced, it must be added to **both** the CSL enum (`api/model/authz/`) **and** the Zeebe protocol enum (`zeebe/protocol/`), along with the SBE schema update and the `AuthzModelMapper` mapping. This is a two-step process that must be documented in contribution guides.
- The `AuthzModelMapper` in OC becomes load-bearing. It must be kept up to date as new values are added and must be covered by tests that assert completeness (i.e., every Zeebe protocol enum constant has a corresponding CSL mapping).
