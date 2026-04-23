# Security Gateway Framework (SGF)

A unified identity and authorization library for the Camunda 8 platform. The SGF is embedded as a hexagonal Spring Boot library into host applications (Hub, Orchestration Clusters) — it is not a standalone service.

## Stack

- Java 21 / Spring Boot 4 / Spring Web MVC / Maven 3.9
- Architecture: Hexagonal (ports and adapters)
- Testing: JUnit 5, Mockito, AssertJ, ArchUnit, Testcontainers, Pact
- Formatting: Google Java Format (Spotless)

## Architecture

Hexagonal (ports and adapters). The domain has zero framework dependencies — enforced by ArchUnit.

All persistence, IdP clients, engine commands, and outbox delivery sit behind port interfaces defined in the library core. Host applications (Hub, OC) provide adapter implementations. No host-specific code leaks into the library domain.

### Deployment Strategies

Active capabilities are selected via a deployment strategy configuration property (not Spring profiles):

| Strategy | Policy Authority | Authoring | Outbox Dispatch | Engine Projection |
|---|---|---|---|---|
| `oc-standalone` | OC (local SoT) | Yes | No | Yes |
| `oc-managed` | Receives from Hub | No (read-only) | No | Yes |
| `hub` | Hub (central SoT) | Yes | Yes | No |

Authentication and authorization enforcement is always active in every strategy.

### Unified Policy Model

Shared across Hub and all OCs: `Organization`, `Tenant`, `Role`, `Group`, `MappingRule`, `Principal` (User + Machine), `Authorization`. Scope types: `ALL`, `TENANT`, `ENGINE`, `TENANT_ENGINE`.

## Key Conventions

- **Models:** always Java records (never mutable classes)
- **Config classes:** cannot be records (Spring `@ConfigurationProperties` needs mutability)
- **Sealed by default:** all production classes must be `final` unless they are intentional extension points
- **Auto-configuration:** every bean must have `@ConditionalOnMissingBean` for consumer overrides
- **No `System.out.print`:** use SLF4J (`LOG.debug/info/warn/error`)
- **All new classes must have tests**

### Naming

- Inbound adapters: suffixed with `RestAdapter` (annotated `@RestController`)
- Domain services: suffixed with `Service` (implementing use case ports)
- Outbound adapters: suffixed with `PersistenceAdapter` or `ClientAdapter`
- Use case ports: named as verbs in `port/in/` (e.g., `PlaceOrderUseCase`)
- Outbound ports: named after the operation in `port/out/` (e.g., `LoadOrderPort`)

### Error Handling

- Domain exceptions carry business meaning and are defined in the domain layer
- Inbound adapters translate domain exceptions to HTTP responses
- Outbound adapters must never leak infrastructure exceptions into the domain

### Testing

- Unit tests for domain logic (no Spring context)
- Integration tests for adapters (`@SpringBootTest` or Testcontainers)
- Contract tests for APIs (Pact consumer-driven contracts)
- ArchUnit tests enforce hexagonal boundaries
- All new classes must have corresponding tests

## Key Commands

Commands will be documented as the build is established. Expect standard Maven conventions:

```
mvn clean install
mvn test
mvn test -pl <module> -Dtest=ClassName#methodName
mvn verify
```

## Workflow

- Branch naming: `<type>/<short-description>` (e.g., `feat/add-policy-model`)
- Commit format: Conventional Commits — `<type>(<scope>): <subject>`
- Squash-merge to keep main history clean
- A pre-push hook will enforce quality gates before code reaches the remote

## Agent Workflows

Common AI-assisted workflows are documented in `docs/workflows/` and are usable by any agent:

| Workflow | File | Triggers |
|---|---|---|
| Creating bug issues | `docs/workflows/bug-issues.md` | "track this bug", "this is broken", "the behavior should be X" |
| Creating feature issues | `docs/workflows/feature-issues.md` | "we should be able to", "add support for", "I want to be able to" |
| Creating task issues | `docs/workflows/tasks.md` | "track this task", "break this into tasks", "we need to implement X" |
| Documenting code | `docs/workflows/documenting-code.md` | "document this", "add docs for", "write documentation for" |

Claude Code users can invoke these as slash commands (`/bug`, `/feature`, `/task`, `/docs`) via `.claude/skills/`. Other agents should read the `docs/workflows/` files directly when triggered.

### Features vs tasks

- **Feature** — a user-facing outcome ("users should be able to bulk-assign roles"). Often too large to deliver in a single reviewable PR.
- **Task** — a small, self-contained, independently mergeable unit of implementation work. Can be standalone, or one of several tasks that together deliver a feature. Each task must be safe to merge on its own without breaking the codebase.

When a feature is too large to land in a single small PR, break it into tasks and link them from the feature's Implementation Plan section.

### What makes an issue work for cold-start resolution

Every issue created via these workflows must be **self-contained** — a fresh session with no prior context must be able to read it and deliver a complete, correct result.

The **Location in Code** and **Acceptance Criteria** fields are what make the difference between an issue that requires a conversation and one that an agent can resolve cold. Be specific. "Fix the bug" is not an acceptance criterion. "Authorizations with scope_type=ENGINE are persisted during snapshot apply and a unit test covers this path" is.

## ADRs

Architecture decisions are documented in `docs/adr/`. Read these before making changes that touch architectural boundaries.

When a change involves a significant design choice, create a new ADR. Err on the side of writing one. Write an ADR when introducing new modules/ports/adapters, choosing between approaches, changing data flow or storage patterns, or adding/replacing dependencies. Number sequentially — check `docs/adr/` for the latest number.
