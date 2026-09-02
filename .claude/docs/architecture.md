# Architecture

## Module / Package Map

The CSL is a multi-module Maven library. Modules will be added as implementation progresses — update this map when they are.

- `api/` — Public, host-facing surface: model records adopters consume (`api/model/`), context interfaces hosts implement (`api/context/`), and configuration records bound by Spring in the starter (`api/model/config/`). No dependencies on `core/`.
- `core/` — Framework-free domain logic and port interfaces. For new code, contracts live under `port/in/` and `port/out/`. Depends on `api/` so port signatures can speak the public model types directly. Zero Spring or zeebe-protocol dependencies (enforced by `DomainArchTest`).
- `spring-boot-starter/` — Spring configuration classes for filter chains, authentication beans, and related infrastructure. **No Spring Boot auto-configuration is registered by CSL** (see [ADR-0003](../../docs/adr/0003-no-spring-boot-auto-configuration.md)): there is no `AutoConfiguration.imports` file. Hosts opt in either by `@Import`ing individual configuration classes, or by activating the opt-in umbrella `CamundaSecurityAutoConfiguration` via `@ImportAutoConfiguration` / their own `AutoConfiguration.imports`. Every library-supplied bean has `@ConditionalOnMissingBean` so hosts can override individual beans without touching the configuration class.

## Key Boundaries

- `core/` has zero framework dependencies — no Spring annotations, no JPA, no HTTP types. This boundary will be enforced by ArchUnit via `DomainArchTest` (planned in [#5](https://github.com/camunda/camunda-security-library/issues/5)).
- Inbound port implementations are services; outbound adapters implement outbound ports. Implementations never call each other directly.
- Dependency direction: `core` → `api`. The public types live in `api/`; `core` ports import them. Implementations (services, adapters) depend on the port contracts, not the reverse.
- `*Port` contracts speak domain types only; transport translation is the caller's responsibility
- Outbound adapter implementations must never leak infrastructure exceptions (JPA, SQL, HTTP client) into the domain
- Existing code may still use legacy `adapter/` contract packages and `*Impl` names. Do not refactor those names unless the work explicitly calls for it.

## Deployment Strategy Architecture

The CSL is embedded into host applications. Active capabilities are selected via configuration properties (not Spring profiles):

- **Authentication method**: `camunda.security.authentication.method=basic|oidc` selects the auth-mode chains.
- **API protection**: `camunda.security.authentication.unprotected-api=true|false` swaps the API protection chain for the dev-mode permit-all variant.
- **Deployment strategy** (`oc-standalone` / `oc-managed` / `hub`): planned for the policy work; **not currently consumed by the filter chain layer.** AuthN/AuthZ enforcement is always active regardless of strategy.

**Important:** The CSL does not use Spring Boot auto-configuration (see [ADR-0003](../../docs/adr/0003-no-spring-boot-auto-configuration.md)). `@ConditionalOnProperty` annotations on configuration classes are present for future use but have no effect until the host explicitly `@Import`s the class. Nothing activates by simply adding the Maven dependency.

## Unified Policy Model

Shared across Hub and all OCs:

- `Organization` — top-level boundary
- `Tenant` — logical isolation within an organization
- `Role` — named set of permissions
- `Group` — collection of principals
- `MappingRule` — maps external identity attributes to internal roles/groups
- `Principal` — user or machine identity
- `Authorization` — granted permission scoped to a resource

Authorization levels: `ALL`, `TENANT`, `PHYSICAL_TENANT`.

### Permission Model: Resource -> Action

Every permission in CSL is expressed as a `Resource -> Action` pair — a resource type paired with
the operation a principal wants to perform on it. Two building blocks make up each side of the
pair:

- [`AuthorizationResourceType`](../../api/src/main/java/io/camunda/security/api/model/authz/AuthorizationResourceType.java)
  — the resource being acted on (e.g. `PROCESS_DEFINITION`, `USER_TASK`, `BATCH`). Each constant
  declares the set of `PermissionType`s that are meaningful for it via
  `getSupportedPermissionTypes()`.
- [`PermissionType`](../../api/src/main/java/io/camunda/security/api/model/authz/PermissionType.java)
  — the action being requested (e.g. `READ_PROCESS_INSTANCE`, `UPDATE_USER_TASK`,
  `CREATE_BATCH_OPERATION_CANCEL_PROCESS_INSTANCE`).

[`RequiredAuthorization<T>`](../../core/src/main/java/io/camunda/security/core/auth/RequiredAuthorization.java)
pairs the two into what a caller must have for an operation to be allowed, and optionally scopes
that requirement to specific resource instances:

- statically, via `resourceIds()` (a fixed list of IDs known up front)
- dynamically, via `resourceIdSupplier()` (a `Function<T, String>` that derives the ID from the
  runtime document, e.g. from a batch operation payload)
- by property, via `resourcePropertyNames()` (e.g. "does the caller's ID match the document's
  `assignee` field")

`RequiredAuthorization` only *describes* what is required — it carries no logic to grant or deny
anything. Evaluating a required authorization against what a principal actually has is the
checker's job, working against
[`Authorization`](../../api/src/main/java/io/camunda/security/api/model/authz/Authorization.java):
a granted record read from the host's authorization store, naming a resource type, a resource ID,
and the set of permission types the principal holds on it. A check passes when a granted
`Authorization` exists whose `resourceType` and `resourceId` match the `RequiredAuthorization`'s
target and whose `permissionTypes` contains the required `PermissionType`.

**Worked examples**, each built via `RequiredAuthorization.Builder`:

1. `PROCESS_DEFINITION -> READ_PROCESS_INSTANCE`, scoped to specific process definition IDs known
   up front:

   ```java
   RequiredAuthorization.of(b -> b.processDefinition().readProcessInstance().resourceIds(ids));
   ```

2. `USER_TASK -> UPDATE_USER_TASK`, with no static resource ID — the resource type shortcut
   (`userTask()`) and the permission type shortcut (`updateUserTask()`) are independent builder
   methods, so nothing stops pairing a permission with a resource type that doesn't declare it in
   its own `getSupportedPermissionTypes()` set; the builder does not validate the pairing:

   ```java
   RequiredAuthorization.of(b -> b.userTask().updateUserTask());
   ```

3. `BATCH -> CREATE_BATCH_OPERATION_CANCEL_PROCESS_INSTANCE`, scoped dynamically per document via
   `resourceIdSupplier` — the resource ID isn't known until the runtime document (`T`) is
   available:

   ```java
   RequiredAuthorization.<BatchOperationRequest>of(
       b -> b.batchOperation()
           .permissionType(PermissionType.CREATE_BATCH_OPERATION_CANCEL_PROCESS_INSTANCE)
           .resourceIdSupplier(BatchOperationRequest::processDefinitionId));
   ```

**Authorization levels and scoping.** A granted `Authorization`'s effective scope corresponds to
one of the three authorization levels:

- `ALL` — the grant applies cluster-wide, with no resource ID restriction (matched against the
  wildcard `resourceId`, `AuthorizationScope.WILDCARD`).
- `TENANT` — the grant is restricted to a specific logical tenant; the `resourceId` on the granted
  `Authorization` is that tenant's ID.
- `PHYSICAL_TENANT` — the grant is restricted to a specific physical tenant (engine); the
  `resourceId` is that engine's ID.

A `RequiredAuthorization` narrows a check the same way, on the *required* side: an empty/absent
`resourceIds()` accepts any granted scope (an `ALL`-level grant, or a wildcard), while populating
`resourceIds()` or `resourceIdSupplier()` demands a granted `Authorization` whose `resourceId`
actually matches — i.e. a `TENANT`- or `PHYSICAL_TENANT`-level grant for that specific ID. The two
sides — what's required and what's granted — meet at the resource ID: a required check with no ID
restriction is satisfied by any matching grant regardless of level, while a required check scoped
to a specific ID is only satisfied by a grant at `ALL` or one whose own `resourceId` matches.

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
- Configuration, default beans, conditional activation → `spring-boot-starter/` (under `io.camunda.security.spring.*`). Use plain `@Configuration`, not `@AutoConfiguration` — only the umbrella `CamundaSecurityAutoConfiguration` carries that annotation, and it is intentionally left out of `AutoConfiguration.imports`. Do not register library configuration classes in `AutoConfiguration.imports`; hosts opt in via `@Import` of individual classes or `@ImportAutoConfiguration(CamundaSecurityAutoConfiguration.class)`. When adding a new library configuration class, also add it to the umbrella's `@Import` list (and to `CamundaSecurityAutoConfigurationTest`).

## What Not to Touch

- Domain contracts (`port/in/`, `port/out/`, and model records) must never import from service or adapter implementation packages.
- `*Port` interfaces are contracts; changing a signature requires updating every service or adapter that satisfies it.
- ADRs in `docs/adr/` are historical records — do not modify decided ADRs. Add new ADRs for new decisions.
- Generated code (if any) — edit the source definitions, not the output
