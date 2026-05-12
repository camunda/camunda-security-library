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
- **No auto-configuration by default:** Configuration classes in `spring-boot-starter/` are plain `@Configuration` classes activated by the host via explicit `@Import`. Do NOT create or modify `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` — nothing must activate by simply adding the dependency (see [ADR-0008](../../docs/adr/0008-no-spring-boot-auto-configuration.md)). The opt-in umbrella `CamundaSecurityAutoConfiguration` is the single exception: it is annotated `@AutoConfiguration` but deliberately left out of `AutoConfiguration.imports`; hosts activate it explicitly via `@ImportAutoConfiguration(CamundaSecurityAutoConfiguration.class)` or by listing it in their own imports file.
- **`@ConditionalOnMissingBean`:** Still required on every library-supplied default bean so that a host which imports a configuration class can override individual beans by registering their own. `@ConditionalOnProperty` annotations may be present on configuration classes for future use but have no activation effect in the current explicit-import model.
- Do NOT use `@AutoConfiguration` on individual library configuration classes — only the opt-in umbrella `CamundaSecurityAutoConfiguration` carries that annotation. Do NOT add `proxyBeanMethods = false` explicitly to `@Configuration` unless you have a specific proxying reason.

## Error Handling

- Domain exceptions are defined and thrown in the domain layer — they carry business meaning (e.g., `PolicyNotFoundException`, `UnauthorizedAccessException`)
- Domain exceptions propagate out of `*Port` methods unchanged; callers are responsible for translating them to their transport. Transport-specific concerns never bleed into the domain.
- Do not leak infrastructure concerns (JPA exceptions, SQL errors, HTTP client errors) into the domain; outbound adapters must translate these into domain exceptions or domain-meaningful results

## Testing Patterns

- JUnit 5 for all tests
- Mockito style: use `@ExtendWith(MockitoExtension.class)` with `@Mock` fields, and `@InjectMocks` for the unit under test when possible, instead of `Mockito.mock(...)`
- Unit tests for domain logic: no Spring context required; instantiate classes directly
- Integration tests for adapters: use `@SpringBootTest` or Testcontainers to test real I/O
- Contract tests for APIs: Pact consumer-driven contracts
- ArchUnit tests enforce hexagonal boundary rules (see `DomainArchTest`)
- Configuration class tests: use `ApplicationContextRunner` to verify that explicitly importing a configuration class creates the expected beans and that `@ConditionalOnMissingBean` back-off works when the host registers its own bean
- All new classes must have corresponding tests before committing
