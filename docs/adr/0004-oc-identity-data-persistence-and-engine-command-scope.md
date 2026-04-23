---
status: Accepted
---

# ADR-0004: Identity data persistence in the Orchestration Cluster

## Status

Accepted

## Context

After the OC Security Gateway Framework receives and applies a policy payload (`POLICY_SNAPSHOT`
or `POLICY_DIFF`), the resulting identity state (tenants, roles, groups, mapping rules,
authorizations — including their `scope_type`/`scope_id`) must be persisted in the OC so it can
be used for two distinct authorization purposes:

- **Command authorization (primary storage — RocksDB).** When a user or worker submits a command
  (e.g. create process instance, complete task), the Security Engine Framework inside the engine
  checks the identity state in primary storage to decide whether the command is authorized. Primary
  storage is the authoritative source for execution-time authorization decisions.
- **Query authorization (secondary storage — ES/OS/RDBMS).** When Operate, Tasklist, or the Admin
  UI queries data (e.g. list process instances, list tasks), the OC Security Gateway Framework
  applies authorization filters against the identity state held in secondary storage. Secondary
  storage is the authoritative source for read/query authorization decisions.

Both storage layers therefore need a consistent and up-to-date view of the identity state.
Neither can be omitted: removing primary storage breaks command authorization in the engine;
removing secondary storage breaks query authorization in the OC layer.

Two persistence paths are possible.

### Option 1 — OC Security Gateway Framework writes directly to secondary storage

The OC SGF writes identity state changes directly to secondary storage (ES/OS/RDBMS) after
applying a received policy payload, bypassing the engine and the exporter entirely.

**Problems identified:**

- **New write path, new consistency risks.** Primary storage (RocksDB, used for engine-level
  authorization) and secondary storage (used for query) would be written by two different paths.
  Keeping them consistent — especially after failures or re-applies — requires additional
  coordination logic.
- **Schema ownership.** The OC SGF would need to own and maintain secondary storage schemas for
  identity entities, duplicating schema management that currently lives in the engine/exporter
  layer.
- **Reset and re-apply.** Applying a `POLICY_SNAPSHOT` again must reset both primary and secondary
  storage to a consistent baseline. With two independent write paths, this is harder to make
  atomic and observable.
- **Secondary storage without primary.** The engine still needs identity state in RocksDB for
  engine-level authorization decisions. This means the OC SGF must also trigger engine commands to
  populate primary storage, resulting in two distinct write paths anyway.

### Option 2 — Route through engine commands and exporter (extend existing flow)

The OC SGF forwards identity state changes via the library's `PolicyPersistencePort`. The OC
adapter for this port translates them into commands to the engine. The engine's Security Engine
Framework processes the commands and persists the state in primary storage (RocksDB). The
existing exporter then picks up the identity records and writes them to secondary storage
(ES/OS/RDBMS), preserving the full flow as it exists today.

The port is named `PolicyPersistencePort` — generic at the library level — because the library is
shared across Hub and OC and must not carry OC-specific concepts like "engine" or "command" in its
public contract. The OC adapter implements the port by routing through engine commands; a future
Hub adapter would implement the same port differently.

To make this work correctly, the engine commands must carry the full scope metadata
(`scope_type`, `scope_id`), so that:

- The Security Engine Framework can persist scope-aware state in RocksDB.
- The exporter can write scope-aware records to secondary storage.
- Engine-level authorization decisions can apply the correct precedence
  (engine-scoped > tenant-scoped > ALL).

**Consequences:**

- A single consistent write path: primary and secondary storage are both populated via the
  engine/exporter flow, as today.
- The ES/OS/RDBMS schema must be extended to include scope fields on authorization records.
  This schema extension is required regardless of which option is chosen.
- The Security Engine Framework takes ownership of scope-aware persistence and authorization
  evaluation inside the engine.
- The exporter must be extended to handle scoped identity records.
- Reset semantics (re-applying a `POLICY_SNAPSHOT`) follow the same engine command path and can
  be made idempotent at the engine level.

## Decision

**Option 2 — route identity state through engine commands and the exporter.**

The OC Security Gateway Framework forwards identity state changes via the library's
`PolicyPersistencePort`. The OC adapter translates them into commands to the engine; the engine's
Security Engine Framework persists the state in primary storage (RocksDB), and the existing
exporter propagates it to secondary storage (ES/OS/RDBMS). Engine commands carry full scope
metadata (`scope_type`, `scope_id`) so that both storage layers hold a consistent, scope-aware view.

Option 1 — writing directly to secondary storage from the OC SGF — is rejected. Bypassing the
engine command path is counterproductive: the engine still needs identity state in primary storage
for command authorization, so any "shortcut" that skips engine commands still has to trigger them
to populate RocksDB. The net result is two write paths instead of one, with the consistency and
schema-ownership costs documented under Option 1.

Open questions identified during review — schema extensions for scope metadata in secondary
storage, whether primary storage also holds the originating `PolicyVersion` reference, and the
atomicity of `POLICY_SNAPSHOT` re-apply — are implementation details tracked alongside the unified
policy model work (camunda/camunda#51101) rather than blockers on this ADR.

## Alternatives Considered

See Option 1 and Option 2 in the Context section above.

## Consequences

- Engine and exporter are extended to handle scoped identity records.
- Secondary storage schemas (ES/OS/RDBMS) are extended with scope columns for authorization
  entities. This is a one-time schema migration applicable to both options.
- The Security Engine Framework takes on scope-aware authorization evaluation inside the engine.
- The exporter-based data flow is preserved, keeping operational behaviour consistent with the
  current system and avoiding a new direct-write path from the OC SGF to secondary storage.
