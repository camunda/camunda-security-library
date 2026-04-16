# Architecture

## Module / Package Map

The SGF is a multi-module Maven library. Modules will be added as implementation progresses — update this map when they are.

- `sgf-domain/` — Core domain models and business logic; zero framework dependencies
- `sgf-spring/` — Spring Security adapters, filters, OIDC support
- `sgf-spring-boot-starter/` — Auto-configuration with `@ConditionalOnMissingBean` overrides
- `sgf-integration-tests/` — Testcontainers-based integration tests (only built with `-Pintegration-tests`)

## Key Boundaries

- `sgf-domain/` has zero framework dependencies — no Spring annotations, no JPA, no HTTP types. Enforced by ArchUnit (see `DomainArchTest`).
- Adapters implement ports; they never call each other directly
- All dependencies point inward toward the domain — adapters depend on ports, ports are defined by the domain
- Inbound adapters translate HTTP concerns into domain language before calling ports; they must not contain business logic
- Outbound adapters must never leak infrastructure exceptions (JPA, SQL, HTTP client) into the domain

## Deployment Strategy Architecture

The SGF is embedded into host applications. Active capabilities are selected via a deployment strategy configuration property (not Spring profiles):

- `oc-standalone` — OC is the local source of truth for policy. Authoring and engine projection are active.
- `oc-managed` — OC receives policy from Hub. Read-only. Engine projection is active.
- `hub` — Hub is the central source of truth. Authoring and outbox dispatch are active.

AuthN and AuthZ enforcement is always active regardless of strategy. Strategy selection must be a first-class concept in auto-configuration — use `@ConditionalOnProperty` on strategy value, not ad-hoc feature flags.

## Unified Policy Model

Shared across Hub and all OCs:

- `Organization` — top-level boundary
- `Tenant` — logical isolation within an organization
- `Role` — named set of permissions
- `Group` — collection of principals
- `MappingRule` — maps external identity attributes to internal roles/groups
- `Principal` — user or machine identity
- `Authorization` — granted permission scoped to a resource

Authorization scope types: `ALL`, `TENANT`, `ENGINE`, `TENANT_ENGINE`.

## Data Flow

### Policy propagation (Hub → OC)

```
Policy change committed in Hub
  → PolicyVersion created (organization + cluster scoped)
  → Outbox event recorded in same transaction
  → Hub dispatcher sends POLICY_SNAPSHOT to target OC
  → OC Security Gateway Framework receives and applies snapshot
  → OC forwards identity state as engine commands (via EngineCommandPort)
  → Engine persists to primary storage (RocksDB)
  → Exporter writes to secondary storage (ES/OS/RDBMS)
```

### Request authorization (OC)

```
HTTP request
  → adapter/in/ (REST adapter — validates, translates to domain types)
  → port/in/ (use case interface)
  → domain/ (service — executes authorization logic against local policy projection)
  → port/out/ (outbound interface for policy/identity lookups)
  → adapter/out/ (persistence adapter — reads from local store)
```

## Where New Code Goes

- Domain logic → `sgf-domain/`
- New API endpoint → inbound adapter module; define the use case port in `port/in/` first
- New persistence operation → outbound adapter; define the port interface in `port/out/` first
- New external integration → outbound adapter; define the port interface in `port/out/` first
- New use case → define the port interface in `port/in/`, implement in domain service
- Auto-configuration → `sgf-spring-boot-starter/`

## What Not to Touch

- `sgf-domain/` must never import from adapter packages — define a port instead
- Ports are contracts; changing a port interface requires updating all adapter implementations
- ADRs in `docs/adr/` are historical records — do not modify decided ADRs. Add new ADRs for new decisions.
- Generated code (if any) — edit the source definitions, not the output
