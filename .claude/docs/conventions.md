# Conventions

## Naming

Hexagonal architecture naming (replaces traditional controller/service/repo naming):

- Inbound adapters handle HTTP — suffixed with `RestAdapter` (e.g., `PolicyRestAdapter`, annotated with `@RestController`)
- Domain services implement use case ports — suffixed with `Service` (e.g., `ApplyPolicyService` implementing `ApplyPolicyUseCase`)
- Outbound adapters handle persistence/external calls — suffixed with `PersistenceAdapter` or `ClientAdapter` (e.g., `PolicyPersistenceAdapter`, `IdpClientAdapter`)
- Use case port interfaces live in `port/in/` and are named as verbs or use cases (e.g., `AuthorizeRequestUseCase`, `ApplyPolicyUseCase`)
- Outbound port interfaces live in `port/out/` and are named after the operation (e.g., `LoadPolicyPort`, `SaveAuthorizationPort`)
- Spring Data interfaces may keep `Repository` suffix (e.g., `JpaRoleRepository extends JpaRepository`) since they are framework-generated — but the adapter that wraps them uses adapter naming

## Project-Specific Patterns

- Hexagonal architecture package structure is enforced: `domain/`, `port/in/`, `port/out/`, `adapter/in/`, `adapter/out/`
- Inbound adapters translate HTTP concepts (request bodies, path variables, HTTP status codes) into domain types before calling use case ports — no business logic in adapters
- Domain services implement use case port interfaces defined in `port/in/`
- Outbound adapters implement persistence port interfaces defined in `port/out/`
- **Models:** always Java records (never mutable classes)
- **Config classes:** cannot be records (Spring `@ConfigurationProperties` needs mutability)
- **RDBMS entities:** cannot be records (MyBatis/JPA needs setters)
- **Sealed by default:** all production classes must be `final` unless they are intentional extension points (SPIs, classes with `protected` methods, config properties classes, persistence entities)
- **Auto-configuration:** every bean must have `@ConditionalOnMissingBean` for consumer overrides. `@AutoConfiguration` already implies `proxyBeanMethods = false` — do NOT add it explicitly.
- **No unnecessary property gates:** do not add `@ConditionalOnProperty(enabled=true)` for features that Spring Security activates through bean presence. Property gates are reserved for features with significant runtime side effects.
- **Read/write port separation:** read ports are always active, write ports activate based on deployment strategy

## Error Handling

- Domain exceptions are defined and thrown in the domain layer — they carry business meaning (e.g., `PolicyNotFoundException`, `UnauthorizedAccessException`)
- Inbound adapters catch domain exceptions and translate them to appropriate HTTP responses (e.g., 404, 403) — HTTP status codes never bleed into the domain
- Do not leak infrastructure concerns (JPA exceptions, SQL errors, HTTP client errors) into the domain; outbound adapters must translate these into domain exceptions or domain-meaningful results

## Testing Patterns

- JUnit 5 for all tests
- Unit tests for domain logic: no Spring context required; instantiate classes directly
- Integration tests for adapters: use `@SpringBootTest` or Testcontainers to test real I/O
- Contract tests for APIs: Pact consumer-driven contracts
- ArchUnit tests enforce hexagonal boundary rules (see `DomainArchTest`)
- Auto-configuration tests use `ApplicationContextRunner` covering: activation conditions, bean creation, and `@ConditionalOnMissingBean` back-off
- All new classes must have corresponding tests before committing
