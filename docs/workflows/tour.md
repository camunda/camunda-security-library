# Tour of the Camunda Security Library

The Camunda Security Library (CSL) is the unified identity and authorization library for the Camunda 8 platform — embedded as a hexagonal Spring Boot library into Hub and Orchestration Clusters.

This tour is the single entry point for understanding what you can do here: slash commands, documentation map, architecture, current milestones, and conventions. Come back for detail when you need it.

## For agents running this workflow

- If the user asks broadly ("tour", "show me around", "what can I do here"), walk through the whole tour.
- If they ask narrowly ("what slash commands exist?", "where's the architecture doc?"), answer from the relevant section and point to the rest.
- Keep it scannable — tables and short bullets, not essays.

## Slash commands

Five AI-agent workflows live in this repo. Four create well-structured GitHub issues; one is this tour. Every workflow is defined in `docs/workflows/` and exposed as a Claude Code skill in `.claude/skills/`.

| Command | Use when | Workflow doc |
|---|---|---|
| `/feature` | You want a new capability ("we should be able to...", "add support for...") | [feature-issues.md](feature-issues.md) |
| `/task` | A small, independently mergeable unit of work | [tasks.md](tasks.md) |
| `/bug` | Something is broken; expected behavior isn't happening | [bug-issues.md](bug-issues.md) |
| `/docs` | Document code, modules, features, or architecture | [documenting-code.md](documenting-code.md) |
| `/tour` | This tour — orientation only | [tour.md](tour.md) |

The four issue-creating workflows all produce self-contained issues — a fresh agent session can read them and deliver without further conversation. Shared helpers (setting issue types, native sub-issue linking, how to link files in issue bodies) live in [github-issue-operations.md](github-issue-operations.md).

## Documentation map

Read these in order if you're new. `CLAUDE.md` and everything it `@`-includes (`AGENTS.md` plus the `.claude/docs/*` files) auto-load into Claude Code sessions. ADRs are extra reading when you're working near architectural boundaries.

| File | What it covers |
|---|---|
| [CLAUDE.md](../../CLAUDE.md) | Entry point; points to everything else |
| [AGENTS.md](../../AGENTS.md) | Stack, architecture summary, conventions, workflows |
| [.claude/docs/architecture.md](../../.claude/docs/architecture.md) | Module layout, hexagonal boundaries, data flow, deployment strategies |
| [.claude/docs/conventions.md](../../.claude/docs/conventions.md) | Naming, records, auto-configuration rules, error handling, testing |
| [.claude/docs/commands.md](../../.claude/docs/commands.md) | Build, test, verify commands |
| [.claude/docs/workflow.md](../../.claude/docs/workflow.md) | Branch naming, commit format, PR process, ADR triggers |
| [.claude/docs/guardrails.md](../../.claude/docs/guardrails.md) | Hard rules — what you must and must not do |
| [docs/adr/](../adr/) | Architecture Decision Records — read before touching architectural boundaries |

## Architecture in thirty seconds

- **Hexagonal (ports and adapters).** `core` (domain) has zero framework dependencies. Adapters and implementations depend on `core`, never the reverse.
- **Deployment strategies.** Active capabilities are selected by a configuration property — `oc-standalone`, `oc-managed`, `hub`. Not Spring profiles.
- **One library, many hosts.** The same library embeds into Hub and OC. Host-specific code lives in `*AdapterImpl` beans; nothing host-specific leaks into `core`.
- **Naming.** Inbound `*Port` interfaces live in `core/port/`; outbound `*Adapter` interfaces live in `core/adapter/`. Hosts supply `*AdapterImpl` beans; domain services are `*PortImpl`.
- **Auth is always on.** Authentication and authorization enforcement are active in every deployment strategy.

See [architecture.md](../../.claude/docs/architecture.md) for the full picture.

## Milestone ladder

Work is tracked as GitHub Milestones. Each delivers a vertical slice — the library supports functionality X; OC and Hub both consume it via adapter implementations.

Current milestones (with what's open and closed): [GitHub Milestones](https://github.com/camunda/camunda-security-library/milestones).

## Working here

- **Branches:** `<type>/<short-description>` — lowercase, hyphen-separated. Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`.
- **Commits:** Conventional Commits — `<type>(<scope>): <subject>`. Subject max 72 characters, imperative mood, no trailing period.
- **PRs:** title follows conventional-commits format; squash-merge.
- **Before every commit:** `mvn verify` must pass — no flaky tests, no skipped tests.
- **Architectural change?** Write an ADR in [docs/adr/](../adr/). See [workflow.md](../../.claude/docs/workflow.md) for when it applies.
- **Linking files in issue bodies:** use clickable GitHub blob URLs, not plain paths — see [github-issue-operations.md](github-issue-operations.md).

## Where to go next

- **Picking up work:** find an open issue in a milestone and start there.
- **Proposing new work:** invoke `/feature`, `/task`, or `/bug` depending on shape.
- **Unsure which:** the "Features vs tasks" section in [AGENTS.md](../../AGENTS.md) is the decision rule.
- **Architectural change:** read the relevant ADRs in [docs/adr/](../adr/) first; write a new one if you're changing a boundary.
