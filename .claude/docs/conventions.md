# Conventions

## Naming

Hexagonal architecture naming (replaces traditional controller/service/repo naming):

**Inbound (driving side)** — `Port` is always inbound.

- Interface — suffixed with `Port`, lives in `port/`. The inbound contract a host application (or any caller) invokes. Example: `GroupPort` with methods like `create(...)`.
- Implementation — suffixed with `PortImpl`. Contains business logic. Example: `GroupPortImpl` implementing `GroupPort`.

**Outbound (driven side)**

- Interface — suffixed with `Adapter`, lives in `adapter/`. The contract the domain needs the outside world to satisfy. The qualifier before `Adapter` indicates the kind of external system. Example: `GroupPersistenceAdapter` with methods like `store(...)`, `GroupKafkaAdapter`, `IdpClientAdapter`.
- Implementation — suffixed with `AdapterImpl`. Actually talks to the external system (JDBC, HTTP client, Kafka, …). Example: `GroupPersistenceAdapterImpl` implementing `GroupPersistenceAdapter`.

**Other**

- Spring Data interfaces may keep the `Repository` suffix (e.g., `JpaRoleRepository extends JpaRepository`) since they are framework-generated — but the outbound adapter implementation that wraps them follows the `*AdapterImpl` naming above.

## Project-Specific Patterns

- Hexagonal architecture package structure is enforced: `domain/`, `port/`, `adapter/`
- `*PortImpl` classes implement the inbound port interfaces defined in `port/`
- `*AdapterImpl` classes implement the outbound adapter interfaces defined in `adapter/`
- **Models:** always Java records (never mutable classes)
- **Config classes:** cannot be records (Spring `@ConfigurationProperties` needs mutability)
- **RDBMS entities:** cannot be records (MyBatis/JPA needs setters)
- **Sealed by default:** all production classes must be `final` unless they are intentional extension points (SPIs, classes with `protected` methods, config properties classes, persistence entities)
- **Auto-configuration:** every bean must have `@ConditionalOnMissingBean` for consumer overrides. `@AutoConfiguration` already implies `proxyBeanMethods = false` — do NOT add it explicitly.
- **No unnecessary property gates:** do not add `@ConditionalOnProperty(enabled=true)` for features that Spring Security activates through bean presence. Property gates are reserved for features with significant runtime side effects.
- **Read/write port separation:** read ports are always active, write ports activate based on deployment strategy

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
