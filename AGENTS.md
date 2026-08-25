# Camunda Security Library (CSL)

A unified identity and authorization library for the Camunda 8 platform. The CSL is embedded as a hexagonal Spring Boot library into host applications (Hub, Orchestration Clusters) — it is not a standalone service.

## Stack

- Java 21 / Spring Boot 4 / Spring Web MVC / Maven 3.9
- Architecture: Hexagonal (ports and adapters)
- Testing: JUnit 5, Mockito, AssertJ, ArchUnit, Testcontainers, Pact
- Formatting: Google Java Format (Spotless)

## Architecture

Hexagonal (ports and adapters). The domain has zero framework dependencies — enforced by ArchUnit.

All persistence, IdP clients, engine commands, and outbox delivery sit behind outbound `*Port` contracts defined in the library core. Host applications (Hub, OC) provide outbound adapter implementations. No host-specific code leaks into the library domain.

Public consumer-facing types are exposed from the `api` module:

- `api/model`: public models used by adopters (for example authentication context records)
- `api/context`: public context/helper contracts used by adopters (for example holders/providers/converters)

### Deployment Strategies

Active capabilities are selected via a deployment strategy configuration property (not Spring profiles):

| Strategy | Policy Authority | Authoring | Outbox Dispatch | Engine Projection |
|---|---|---|---|---|
| `oc-standalone` | OC (local SoT) | Yes | No | Yes |
| `oc-managed` | Receives from Hub | No (read-only) | No | Yes |
| `hub` | Hub (central SoT) | Yes | Yes | No |

Authentication and authorization enforcement is always active in every strategy.

> **Note:** Some docs/ADRs use an `oc-` prefix (`oc-standalone`, `oc-managed`). A rename to the shorter names (`standalone`, `managed`) is planned.

### Unified Policy Model

Shared across Hub and all OCs: `Organization`, `Tenant`, `Role`, `Group`, `MappingRule`, `Principal` (User + Machine), `Authorization`. Authorization levels: `ALL`, `TENANT`, `PHYSICAL_TENANT`.

In CSL, a policy is the effective access configuration derived from those building blocks. Iteration one models roles/groups/mapping rules/principals/authorizations directly; introduce a first-class `Policy` aggregate only if future requirements require it.

## Key Conventions

- **Models:** always Java records (never mutable classes)
- **Config classes:** cannot be records (Spring `@ConfigurationProperties` needs mutability)
- **Sealed by default:** all production classes must be `final` unless they are intentional extension points
- **No auto-configuration by default:** Configuration classes in `spring-boot-starter/` are plain `@Configuration` classes that host applications activate by explicit `@Import`. Do NOT register classes in CSL's own `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` — nothing must activate automatically from adding the dependency. The single exception is the opt-in umbrella `CamundaSecurityAutoConfiguration`, which is annotated `@AutoConfiguration` but deliberately left out of `AutoConfiguration.imports`; hosts activate it explicitly via `@ImportAutoConfiguration(CamundaSecurityAutoConfiguration.class)` or by listing it in their own imports file. See ADR-0006.
- **`@ConditionalOnMissingBean`:** every library-supplied default bean must have `@ConditionalOnMissingBean` so a host that imports the configuration can still override individual beans.
- **No `System.out.print`:** use SLF4J (`LOG.debug/info/warn/error`)
- **All new classes must have tests**

### Naming

An interface is always a `Port`. Use `port/in/` for inbound ports and `port/out/` for outbound ports. `Adapter` is reserved for implementations of outbound ports.

- Inbound port interfaces: suffixed with `Port`, in `port/in/` (e.g., `GroupPort`)
- Inbound port implementations (business logic): named by responsibility, typically `*Service` (e.g., `GroupService`)
- Outbound port interfaces: suffixed with `Port`, in `port/out/` (e.g., `GroupPersistencePort`, `IdpPort`)
- Outbound port implementations (external-system I/O): suffixed with `Adapter` (e.g., `GroupPersistenceAdapter`, `IdpClientAdapter`)
- Never use `*Impl` as a naming convention for implementations
- Existing code may still contain legacy `*PortImpl`, `*AdapterImpl`, and `adapter/` contract packages until explicitly refactored
- **`core` has no notion of a physical tenant** — only an opaque *scope* key that a host maps to
  its own concept (a physical tenant, a base path, etc.); `core` never learns what a scope means.
  Host-facing types that assemble or resolve something per scope are conventionally prefixed
  `Scoped*` (e.g. `ScopedSessionStorePortProvider`, `ScopedWebSessionRepositoryFactory`,
  `ScopedAuthorizationCheckPortFactory`). Don't introduce tenant-flavored names (`*TenantPort`,
  `*PhysicalTenant*`) in `core` — that's the host's vocabulary, not the library's. See ADR-0016,
  ADR-0012, ADR-0022.

### Error Handling

- Domain exceptions carry business meaning and are defined in the domain layer
- Domain exceptions propagate out of `*Port` methods unchanged; callers are responsible for translating them to their transport
- Outbound adapter implementations must never leak infrastructure exceptions into the domain

### Logging

Good logs are the first line of defence when diagnosing production failures. Every change
that touches observable behaviour must leave enough signal to reconstruct what happened
without a debugger attached.

**Level discipline:**
- `DEBUG` — detailed flow tracing; expect it to be disabled in production. Use for
  operation entry/exit, intermediate state, and retry attempts.
- `INFO` — significant lifecycle events (e.g. snapshot applied, auth chain selected,
  strategy activated). Should be sparse enough to scan at a glance.
- `WARN` — recoverable unexpected conditions; the system continued but something was off.
- `ERROR` — failures requiring attention. Always include the exception and enough context
  to identify the affected entity.

**What to include in every non-trivial log statement:**
- The relevant entity identifiers (e.g. organisation ID, tenant ID, principal ID,
  strategy name) — as structured MDC fields where the module already uses MDC, otherwise
  inline in the message.
- The operation being attempted when a failure occurs, not just the exception class.

**What to avoid:**
- Secrets, tokens, passwords, or any PII — never log these at any level.
- `INFO`/`WARN`/`ERROR` in tight loops — use `DEBUG` with an `isDebugEnabled()` guard.
- Silent catch blocks — if you catch and do not rethrow, log at least at `WARN` with
  context explaining what was swallowed and why.

### Testing

- Unit tests for domain logic (no Spring context)
- Integration tests for adapters (`@SpringBootTest` or Testcontainers)
- Contract tests for APIs (Pact consumer-driven contracts)
- ArchUnit tests enforce hexagonal boundaries
- Mockito style: use `@ExtendWith(MockitoExtension.class)` with `@Mock` fields; use `@InjectMocks` when possible for the unit under test; avoid `Mockito.mock(...)` in new tests
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

### User documentation

CSL is a library, but changes to it can surface as user-visible behaviour in the host
applications it is embedded in (security configuration, authentication flows, OIDC
settings, error responses, supported property values).

Before completing any PR:
1. Check whether the change affects anything a host-application operator or end-user
   would observe or configure.
2. If it does, identify the relevant section in
   [camunda/camunda-docs](https://github.com/camunda/camunda-docs) and add a note to
   the PR description: which page needs updating and what the update should say.
3. If the docs change is well-scoped (e.g. a new config property or changed default),
   include a concrete proposed diff or wording — don't leave it as "docs TBD".

Reviewers should treat a missing docs note for a user-visible change as a blocker,
the same way they would treat a missing test.

## Agent Workflows

Common AI-assisted workflows are documented in `docs/workflows/` and are usable by any agent:

| Workflow | File | Triggers |
|---|---|---|
| Orientation tour | `docs/workflows/tour.md` | "tour", "show me around", "what can I do here", "I'm new here" |
| Creating bug issues | `docs/workflows/bug-issues.md` | "track this bug", "this is broken", "the behavior should be X" |
| Creating feature issues | `docs/workflows/feature-issues.md` | "we should be able to", "add support for", "I want to be able to" |
| Creating task issues | `docs/workflows/tasks.md` | "track this task", "break this into tasks", "we need to implement X" |
| Documenting code | `docs/workflows/documenting-code.md` | "document this", "add docs for", "write documentation for" |
| Writing ADRs | `docs/workflows/adr.md` | "create an ADR", "document this decision", or before any architectural change |

Claude Code users can invoke these as slash commands (`/tour`, `/bug`, `/feature`, `/task`, `/docs`, `/adr`) via `.claude/skills/`. Other agents should read the `docs/workflows/` files directly when triggered. `/tour` is the recommended starting point for anyone new to the repo — it links out to everything else.

### Features vs tasks

- **Feature** — a user-facing outcome ("users should be able to bulk-assign roles"). Often too large to deliver in a single reviewable PR.
- **Task** — a small, self-contained, independently mergeable unit of implementation work. Can be standalone, or one of several tasks that together deliver a feature. Each task must be safe to merge on its own without breaking the codebase.

When a feature is too large to land in a single small PR, break it into tasks and link them from the feature's Implementation Plan section.

### What makes an issue work for cold-start resolution

Every issue created via these workflows must be **self-contained** — a fresh session with no prior context must be able to read it and deliver a complete, correct result.

The **Location in Code** and **Acceptance Criteria** fields are what make the difference between an issue that requires a conversation and one that an agent can resolve cold. Be specific. "Fix the bug" is not an acceptance criterion. "Authorizations with authorization_level=PHYSICAL_TENANT are persisted during snapshot apply and a unit test covers this path" is.

## ADRs

Architecture decisions are documented in `docs/adr/`. Read these before making changes that touch architectural boundaries.

ADR-writing is part of the standard implementation flow, not an optional add-on. **Default to writing one** for any change that introduces a new module/port/adapter/SPI, picks between viable approaches, alters data flow or storage patterns, adds or replaces a dependency, or establishes a project-wide convention. Bug fixes and style-only changes do not need an ADR.

Each new ADR carries a `Deciders` line listing the people who agreed the change. The full process — when an ADR is required, the body template, the immutability rule — lives in [docs/workflows/adr.md](docs/workflows/adr.md) (Claude Code: `/adr`). Number sequentially against the highest existing entry in `docs/adr/`. Also add a link to the new ADR in [docs/architecture/09-architecture-decisions.md](docs/architecture/09-architecture-decisions.md) (§9.1).
