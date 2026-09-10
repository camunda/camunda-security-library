# Guardrails

## Complexity Rules

IMPORTANT: Simplicity over cleverness — prefer the simplest solution that works. If introducing a new abstraction, explain why existing patterns don't work.

IMPORTANT: Functions should be small and focused. If a function is growing beyond 40 lines, extract meaningful helpers.

## Off-Limits Areas

IMPORTANT: Respect hexagonal architecture boundaries — domain contracts (interfaces in `port/in/` and `port/out/`, and domain model records) must not depend on frameworks or implementation classes. Implementations depend on contracts, not the reverse. If you find yourself importing an adapter class from a contract, stop and define an outbound `*Port` in `port/out/` instead.

IMPORTANT: ADRs in `docs/adr/` are historical records of decisions made. Do not substantively modify decided ADRs. Non-semantic editorial fixes are allowed only when they preserve the original decision, status, and rationale exactly (for example: spelling, grammar, formatting, link repair, or terminology normalization that does not change meaning). If a decision needs revisiting or an edit would change meaning, write a new ADR that supersedes the old one. ADR numbers may still be renumbered as part of a rare, explicitly declared consolidation pass — see [docs/workflows/adr.md](../../docs/workflows/adr.md#adrs-are-immutable).

YOU MUST NOT modify generated code directly — edit the source definitions instead.

## Verification Requirements

YOU MUST run tests before claiming a fix works.

YOU MUST write tests where there are logic branches — not blanket coverage for the sake of metrics.

YOU MUST run `mvn verify` before presenting work as complete. A clean run means no test failures and `BUILD SUCCESS`.

IMPORTANT: Do NOT create or modify `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` in CSL itself — nothing must activate from adding the Maven dependency alone (ADR-0003). The single permitted use of `@AutoConfiguration` in the library is the opt-in umbrella `io.camunda.security.spring.CamundaSecurityAutoConfiguration`, which is deliberately left out of `AutoConfiguration.imports` so hosts activate it explicitly (via `@ImportAutoConfiguration` or their own imports file). If you find yourself writing `@AutoConfiguration` on any other class, or registering anything in CSL's `AutoConfiguration.imports`, stop — see ADR-0003 and the conventions doc instead.

## Hard Rules

- IMPORTANT: Contract testing for all APIs — use Pact consumer-driven contracts
- IMPORTANT: Unit tests for domain logic, integration tests for adapters, contract tests for API boundaries
- YOU MUST NOT add unused dependencies. Every dependency in `pom.xml` must be actively used. If you remove usage of a dependency, remove the dependency itself.
- IMPORTANT: Follow clean code principles — meaningful names, small focused functions, no duplication, clear intent over comments
- YOU MUST NOT use `System.out.print`, `System.out.println`, or `System.err.print` — use SLF4J (`LOG.debug/info/warn/error`)
- YOU MUST include entity identifiers (e.g. organisation ID, tenant ID, principal ID) and the operation name in `ERROR` and `WARN` log statements so failures are diagnosable in production without a debugger.
- YOU MUST NOT log secrets, tokens, passwords, or PII at any log level.
- IMPORTANT: All production classes must be `final` unless they are intentional extension points
- IMPORTANT: All domain model classes must be records — no mutable model classes
- YOU MUST NOT introduce Spring, Jakarta Servlet, or Jackson dependencies into the domain module — neither runtime (`jackson-databind`, `jackson-core`) nor annotations (`jackson-annotations`). Domain records stay free of serialization concerns; if a host needs custom JSON shape for a CSL type, it registers a Jackson mixin on its own `ObjectMapper` (see ADR-0014 and OC's `MsgPackConverter.CamundaAuthenticationMixin` for the precedent).
- **Configuration classes:** Public config data models (non-record classes with getters/setters) must be placed in `api/model/config/` to expose them in the public contract. Spring `@ConfigurationProperties` binding logic stays in `spring-boot-starter/`. This keeps the config model framework-agnostic and available to all adopters.
