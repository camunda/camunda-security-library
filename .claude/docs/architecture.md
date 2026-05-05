# Architecture

## Module / Package Map

The CSL is a multi-module Maven library. Modules will be added as implementation progresses — update this map when they are.

- `core/` — Framework-free domain model, inbound ports and outbound ports. For new code, contracts live under `port/in/` and `port/out/`. Zero Spring or zeebe-protocol dependencies (enforced by `DomainArchTest`).
- `api/` — Host-facing entry points layered on `core/`. Currently a placeholder.
- `spring-boot-starter/` — Spring Boot auto-configuration. Hosts include this artefact, set `camunda.security.*` properties, and the chains plus library-default beans (`JwtDecoder`, `ClientRegistrationRepository`, `OAuth2AuthorizedClientRepository`, `OAuth2AuthorizedClientManager`, default `AuthFailureHandler`) wire automatically. Every library-supplied bean has `@ConditionalOnMissingBean` so hosts override by registering their own.

## Key Boundaries

- `core/` has zero framework dependencies — no Spring annotations, no JPA, no HTTP types. This boundary will be enforced by ArchUnit via `DomainArchTest` (planned in [#5](https://github.com/camunda/camunda-security-library/issues/5)).
- Inbound port implementations are services; outbound adapters implement outbound ports. Implementations never call each other directly.
- All dependencies point inward toward the domain. Inbound and outbound ports are contracts defined by the domain; implementations depend on these contracts, not the reverse.
- `*Port` contracts speak domain types only; transport translation is the caller's responsibility
- Outbound adapter implementations must never leak infrastructure exceptions (JPA, SQL, HTTP client) into the domain
- Existing code may still use legacy `adapter/` contract packages and `*Impl` names. Do not refactor those names unless the work explicitly calls for it.

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

Authorization scope types: `ALL`, `TENANT`, `PHYSICAL_TENANT`.

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
  → `port/in/` (`*Port` interface — the library's inbound entry point)
  → `*Service` (domain service — executes authorization logic against local policy projection)
  → `port/out/` (outbound `*Port` interface for policy/identity lookups)
  → `*Adapter` (reads from local store or external systems)
```

## Where New Code Goes

- Domain logic → `core/`
- Public models and config → `api/model/` (adopters need to understand these)
- New inbound use case → define the `*Port` interface in `core/port/in/`, implement it as a responsibility-named service (typically in `spring-boot-starter/`)
- New persistence operation → define the outbound `*Port` interface in `core/port/out/` first, then implement it as an adapter
- New external integration → define the outbound `*Port` interface in `core/port/out/` first, then implement it as an adapter
- Configuration classes (non-record classes bound via `@ConfigurationProperties`):
  - **Data model** (plain, no Spring deps): `api/model/config/` — e.g., `AuthenticationConfiguration`, `OidcConfiguration`
  - **Spring binding logic**: `spring-boot-starter/` — @ConfigurationProperties binds `api/model/config/` classes
- Auto-configuration, default beans, conditional activation → `spring-boot-starter/` (under `io.camunda.security.autoconfigure.spring.*`)

## What Not to Touch

- Domain contracts (`port/in/`, `port/out/`, and model records) must never import from service or adapter implementation packages.
- `*Port` interfaces are contracts; changing a signature requires updating every service or adapter that satisfies it.
- ADRs in `docs/adr/` are historical records — do not modify decided ADRs. Add new ADRs for new decisions.
- Generated code (if any) — edit the source definitions, not the output
