# Guardrails

## Complexity Rules

IMPORTANT: Simplicity over cleverness — prefer the simplest solution that works. If introducing a new abstraction, explain why existing patterns don't work.

IMPORTANT: Functions should be small and focused. If a function is growing beyond 40 lines, extract meaningful helpers.

## Off-Limits Areas

IMPORTANT: Respect hexagonal architecture boundaries — domain must not depend on frameworks or adapters. All dependencies point inward. If you find yourself importing an adapter class into the domain, stop and define a port interface instead.

IMPORTANT: ADRs in `docs/adr/` are historical records of decisions made. Do not modify decided ADRs. If a decision needs revisiting, write a new ADR that supersedes the old one.

YOU MUST NOT modify generated code directly — edit the source definitions instead.

## Verification Requirements

YOU MUST run tests before claiming a fix works.

YOU MUST write tests where there are logic branches — not blanket coverage for the sake of metrics.

YOU MUST run `mvn verify` before presenting work as complete. A clean run means no test failures and `BUILD SUCCESS`.

IMPORTANT: If you touch auto-configuration, verify with `ApplicationContextRunner` tests covering activation conditions, bean creation, and `@ConditionalOnMissingBean` back-off.

## Hard Rules

- IMPORTANT: Contract testing for all APIs — use Pact consumer-driven contracts
- IMPORTANT: Unit tests for domain logic, integration tests for adapters, contract tests for API boundaries
- YOU MUST NOT add unused dependencies. Every dependency in `pom.xml` must be actively used. If you remove usage of a dependency, remove the dependency itself.
- IMPORTANT: Follow clean code principles — meaningful names, small focused functions, no duplication, clear intent over comments
- YOU MUST NOT use `System.out.print`, `System.out.println`, or `System.err.print` — use SLF4J (`LOG.debug/info/warn/error`)
- IMPORTANT: All production classes must be `final` unless they are intentional extension points
- IMPORTANT: All domain model classes must be records — no mutable model classes
- YOU MUST NOT introduce Spring, Jakarta Servlet, or Jackson runtime dependencies into the domain module (jackson-annotations are permitted)
