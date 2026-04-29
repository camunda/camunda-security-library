# Architecture

## Module / Package Map

The CSL is a multi-module Maven library. Modules will be added as implementation progresses — update this map when they are.

- `core/` — Framework-free domain model, inbound ports, outbound adapter contracts. Zero Spring or zeebe-protocol dependencies (enforced by `DomainArchTest`).
- `api/` — Host-facing entry points layered on `core/`. Currently a placeholder.
- `spring-boot-starter/` — Spring Boot auto-configuration. Hosts include this artefact, set `camunda.security.*` properties, and the chains plus library-default beans (`JwtDecoder`, `ClientRegistrationRepository`, `OAuth2AuthorizedClientRepository`, `OAuth2AuthorizedClientManager`, default `AuthFailureHandler`) wire automatically. Every library-supplied bean has `@ConditionalOnMissingBean` so hosts override by registering their own.

## Key Boundaries

- `csl-domain/` has zero framework dependencies — no Spring annotations, no JPA, no HTTP types. This boundary will be enforced by ArchUnit via `DomainArchTest` (planned in [#5](https://github.com/camunda/camunda-security-library/issues/5)).
- Inbound port implementations (`*PortImpl`) implement inbound ports; outbound adapter implementations (`*AdapterImpl`) implement outbound adapters. Implementations never call each other directly.
- All dependencies point inward toward the domain. Inbound ports and outbound adapters are contracts defined by the domain; implementations depend on these contracts, not the reverse.
- `*Port` contracts speak domain types only; transport translation is the caller's responsibility
- Outbound adapter implementations must never leak infrastructure exceptions (JPA, SQL, HTTP client) into the domain

## Deployment Strategy Architecture

The CSL is embedded into host applications. Active capabilities are selected via configuration properties (not Spring profiles):

- **Authentication method**: `camunda.security.authentication.method=basic|oidc` selects the auth-mode chains.
- **API protection**: `camunda.security.authentication.unprotected-api=true|false` swaps the API protection chain for the dev-mode permit-all variant.
- **Deployment strategy** (`oc-standalone` / `oc-managed` / `hub`): planned for the policy work; **not currently consumed by the filter chain layer.** AuthN/AuthZ enforcement is always active regardless of strategy.

Auto-configuration uses `@ConditionalOnProperty` (or small `@Conditional` classes for chains that depend on more than one property). Library-supplied default beans (e.g., `JwtDecoder` from `camunda.security.authentication.oidc.*`) sit behind `@ConditionalOnMissingBean` so any host bean of the same type wins.

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

- Domain logic → `core/`
- New inbound use case → define the `*Port` interface in `core/port/`, implement as `*PortImpl` (typically in `spring-boot-starter/`)
- New persistence operation → outbound adapter implementation (`*AdapterImpl`); define the outbound adapter interface (`*Adapter`) in `core/adapter/` first
- New external integration → outbound adapter implementation (`*AdapterImpl`); define the outbound adapter interface (`*Adapter`) in `core/adapter/` first
- Auto-configuration, default beans, conditional activation → `spring-boot-starter/` (under `io.camunda.security.autoconfigure.spring.*`)

## What Not to Touch

- Domain contracts (`port/`, `adapter/`, and model records) must never import from `*PortImpl` / `*AdapterImpl` packages.
- `*Port` and `*Adapter` interfaces are contracts; changing a signature requires updating every `*PortImpl` or `*AdapterImpl` that satisfies it.
- ADRs in `docs/adr/` are historical records — do not modify decided ADRs. Add new ADRs for new decisions.
- Generated code (if any) — edit the source definitions, not the output
