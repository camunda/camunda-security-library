# Conventions

## Naming

Hexagonal architecture naming (replaces traditional controller/service/repo naming):

**Ports** — an interface is always a `Port`.

- Inbound port interfaces live in `port/in/`. They are the use-case contracts a host application (or any caller) invokes. Example: `GroupPort` with methods like `create(...)`.
- Outbound port interfaces live in `port/out/`. They are the contracts the domain needs the outside world to satisfy. Example: `GroupPersistencePort`, `IdpPort`, `EngineCommandPort`.

**Implementations**

- Inbound port implementations are named by responsibility, typically as `*Service`. Example: `GroupService` implementing `GroupPort`.
- Outbound port implementations are adapters, typically suffixed with `Adapter`. Example: `GroupPersistenceAdapter`, `IdpClientAdapter`.
- Never use `*Impl` as a naming convention for implementations.

**Other**

- Spring Data interfaces may keep the `Repository` suffix (e.g., `JpaRoleRepository extends JpaRepository`) since they are framework-generated — but the outbound adapter that wraps them should follow the naming above.
- Existing code may still contain legacy `*PortImpl`, `*AdapterImpl`, and `adapter/` contract packages. Do not refactor those names unless the work explicitly calls for it.

## Project-Specific Patterns

- For new core contracts, the hexagonal package structure is `domain/`, `port/in/`, `port/out/`
- Inbound port interfaces live in `port/in/`; their implementations are named by responsibility, typically `*Service`
- Outbound port interfaces live in `port/out/`; their implementations are adapters
- **Models:** always Java records (never mutable classes)
- **Config classes:** cannot be records (Spring `@ConfigurationProperties` needs mutability). Public configuration that adopters need to understand belongs in `api/model/config/`; Spring binding logic stays in `spring-boot-starter/`
- **RDBMS entities:** cannot be records (MyBatis/JPA needs setters)
- **Sealed by default:** all production classes must be `final` unless they are intentional extension points (SPIs, classes with `protected` methods, config properties classes, persistence entities)
- **Auto-configuration:** every library-supplied bean must have `@ConditionalOnMissingBean` so consumers can override by registering their own. `@AutoConfiguration` already implies `proxyBeanMethods = false` — do NOT add it explicitly. Each filter-chain auto-configuration registers in `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.
- **Property-driven activation:** chain auto-configurations gate on `camunda.security.authentication.*` via `@ConditionalOnProperty` (or a small `@Conditional` class when more than one property contributes to the decision). Avoid `@ConditionalOnProperty(enabled=true)` for features Spring Security already activates through bean presence — property gates are reserved for features with significant runtime side effects (e.g., the dev-mode unprotected-API chain).

## Error Handling

- Domain exceptions are defined and thrown in the domain layer — they carry business meaning (e.g., `PolicyNotFoundException`, `UnauthorizedAccessException`)
- Domain exceptions propagate out of `*Port` methods unchanged; callers are responsible for translating them to their transport. Transport-specific concerns never bleed into the domain.
- Do not leak infrastructure concerns (JPA exceptions, SQL errors, HTTP client errors) into the domain; outbound adapters must translate these into domain exceptions or domain-meaningful results

## Testing Patterns

- JUnit 5 for all tests
- Unit tests for domain logic: no Spring context required; instantiate classes directly
- Integration tests for adapters: use `@SpringBootTest` or Testcontainers to test real I/O
- Contract tests for APIs: Pact consumer-driven contracts
- ArchUnit tests enforce hexagonal boundary rules (see `DomainArchTest`)
- Auto-configuration tests use `ApplicationContextRunner` covering: activation conditions, bean creation, and `@ConditionalOnMissingBean` back-off
- All new classes must have corresponding tests before committing
