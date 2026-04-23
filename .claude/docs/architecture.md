# Architecture

## Module / Package Map

The CSL is a multi-module Maven library. Modules will be added as implementation progresses — update this map when they are.

- `csl-domain/` — Core domain models and business logic; zero framework dependencies
- `csl-spring/` — Spring Security adapters, filters, OIDC support
- `csl-spring-boot-starter/` — Auto-configuration with `@ConditionalOnMissingBean` overrides
- `csl-integration-tests/` — Testcontainers-based integration tests (only built with `-Pintegration-tests`)

## Key Boundaries

- `csl-domain/` has zero framework dependencies — no Spring annotations, no JPA, no HTTP types. This boundary will be enforced by ArchUnit via `DomainArchTest` (planned in [#5](https://github.com/camunda/camunda-security-library/issues/5)).
- Inbound port implementations (`*PortImpl`) implement inbound ports; outbound adapter implementations (`*AdapterImpl`) implement outbound adapters. Implementations never call each other directly.
- All dependencies point inward toward the domain. Inbound ports and outbound adapters are contracts defined by the domain; implementations depend on these contracts, not the reverse.
- `*Port` contracts speak domain types only; transport translation is the caller's responsibility
- Outbound adapter implementations must never leak infrastructure exceptions (JPA, SQL, HTTP client) into the domain

## Deployment Strategy Architecture

The CSL is embedded into host applications. Active capabilities are selected via a deployment strategy configuration property (not Spring profiles):

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
  → OC Camunda Security Library receives and applies snapshot
  → OC forwards identity state as engine commands (via EngineCommandPort)
  → Engine persists to primary storage (RocksDB)
  → Exporter writes to secondary storage (ES/OS/RDBMS)
```

### Request authorization (OC)

```
Caller invokes a `*Port` method with domain types
  → port/ (`*Port` interface — the library's inbound entry point)
  → `*PortImpl` (domain service — executes authorization logic against local policy projection)
  → adapter/ (outbound `*Adapter` interface for policy/identity lookups)
  → `*AdapterImpl` (reads from local store)
```

## Where New Code Goes

- Domain logic → `csl-domain/`
- New inbound use case → define the `*Port` interface in `port/`, implement as `*PortImpl`
- New persistence operation → outbound adapter implementation (`*AdapterImpl`); define the outbound adapter interface (`*Adapter`) in `adapter/` first
- New external integration → outbound adapter implementation (`*AdapterImpl`); define the outbound adapter interface (`*Adapter`) in `adapter/` first
- New use case → define the business port interface (`*Port`) in `port/`, implement as `*PortImpl`
- Auto-configuration → `csl-spring-boot-starter/`

## What Not to Touch

- Domain contracts (`port/`, `adapter/`, and model records) must never import from `*PortImpl` / `*AdapterImpl` packages.
- `*Port` and `*Adapter` interfaces are contracts; changing a signature requires updating every `*PortImpl` or `*AdapterImpl` that satisfies it.
- ADRs in `docs/adr/` are historical records — do not modify decided ADRs. Add new ADRs for new decisions.
- Generated code (if any) — edit the source definitions, not the output
